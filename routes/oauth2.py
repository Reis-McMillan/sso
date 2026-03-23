import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from config import config
from database import get_session
from models.authorization_code import AuthorizationCode
from models.consent import Consent
from models.identity import Identity
from models.oauth2_client import OAuthClient
from models.oauth2_session import OAuth2Session
from models.refresh_token import RefreshToken
from utils.client_auth import authenticate_client
from utils.cookie import decrypt_cookie
from utils.jwt import create_id_token, create_signed_jwt
from utils.pkce import verify_code_challenge

logger = logging.getLogger("sso.oauth2")

router = APIRouter(tags=["OAuth2"])

templates = Jinja2Templates(directory="templates")


def _get_authenticated_identity(
    request: Request, session: Session
) -> Identity | None:
    """Try to authenticate user from cookies (browser flow)."""
    token = request.cookies.get(config.ENCRYPT_COOKIE_NAME)
    token_iv = request.cookies.get(f"{config.ENCRYPT_COOKIE_NAME}_iv")
    if not token or not token_iv:
        return None

    try:
        decrypted = decrypt_cookie(token, token_iv)
    except Exception:
        return None

    identity = Identity.get(session, decrypted["email"])
    if (
        not identity
        or identity.auth_key != decrypted["auth_key"]
        or datetime.now(timezone.utc) > identity.expires
    ):
        return None

    return identity


def _build_error_redirect(redirect_uri: str, error: str, description: str, state: str | None = None):
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}", status_code=302
    )


@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    state: str | None = Query(None),
    nonce: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
    session: Session = Depends(get_session),
):
    # Validate client
    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # Validate redirect_uri (exact match required)
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # Validate response_type
    if response_type != "code":
        return _build_error_redirect(
            redirect_uri, "unsupported_response_type",
            "Only 'code' response type is supported", state
        )

    # Parse and validate scopes
    requested_scopes = scope.split()
    if "openid" not in requested_scopes:
        return _build_error_redirect(
            redirect_uri, "invalid_scope",
            "The 'openid' scope is required", state
        )
    for s in requested_scopes:
        if s not in client.allowed_scopes:
            return _build_error_redirect(
                redirect_uri, "invalid_scope",
                f"Scope '{s}' is not allowed for this client", state
            )

    # Validate PKCE
    if code_challenge and code_challenge_method != "S256":
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "Only S256 code_challenge_method is supported", state
        )

    # Public clients must use PKCE
    if client.is_public and not code_challenge:
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "Public clients must use PKCE", state
        )

    # Check if user is authenticated
    identity = _get_authenticated_identity(request, session)

    if not identity:
        # Store authorize params and redirect to login
        oauth2_session = OAuth2Session(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        session.add(oauth2_session)
        session.commit()
        session.refresh(oauth2_session)

        return templates.TemplateResponse("login.html", {
            "request": request,
            "oauth2_session_id": oauth2_session.session_id,
            "client_name": client.client_name,
        })

    # Check consent
    consent = Consent.get(session, identity.email, client_id)
    if consent and consent.covers_scopes(requested_scopes):
        # Consent already granted, issue code
        return _issue_authorization_code(
            session, identity, client, redirect_uri,
            requested_scopes, state, nonce,
            code_challenge, code_challenge_method,
        )

    # Generate CSRF token for consent form
    csrf_token = secrets.token_urlsafe(32)
    # Store in an oauth2 session for validation
    oauth2_session = OAuth2Session(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    session.add(oauth2_session)
    session.commit()
    session.refresh(oauth2_session)

    return templates.TemplateResponse("consent.html", {
        "request": request,
        "client_name": client.client_name,
        "scopes": requested_scopes,
        "oauth2_session_id": oauth2_session.session_id,
        "csrf_token": csrf_token,
    })


@router.post("/authorize/consent")
async def authorize_consent(
    request: Request,
    oauth2_session_id: str = Form(...),
    consent_action: str = Form(...),
    session: Session = Depends(get_session),
):
    # Look up session
    oauth2_session = OAuth2Session.get_by_session_id(session, oauth2_session_id)
    if not oauth2_session or oauth2_session.is_expired():
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    # Verify user is authenticated
    identity = _get_authenticated_identity(request, session)
    if not identity:
        raise HTTPException(status_code=401, detail="Not authenticated")

    redirect_uri = oauth2_session.redirect_uri
    state = oauth2_session.state

    if consent_action != "approve":
        # Clean up session
        session.delete(oauth2_session)
        session.commit()
        return _build_error_redirect(
            redirect_uri, "access_denied",
            "The user denied the authorization request", state
        )

    # Look up client
    client = OAuthClient.get_by_client_id(session, oauth2_session.client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Client not found")

    requested_scopes = oauth2_session.scope.split()

    # Store consent
    Consent.grant(session, identity.email, client.client_id, requested_scopes)

    # Clean up session
    nonce = oauth2_session.nonce
    code_challenge = oauth2_session.code_challenge
    code_challenge_method = oauth2_session.code_challenge_method
    session.delete(oauth2_session)
    session.commit()

    return _issue_authorization_code(
        session, identity, client, redirect_uri,
        requested_scopes, state, nonce,
        code_challenge, code_challenge_method,
    )


def _issue_authorization_code(
    session: Session,
    identity: Identity,
    client: OAuthClient,
    redirect_uri: str,
    scopes: list[str],
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> RedirectResponse:
    auth_time = identity.last_auth_time or datetime.now(timezone.utc)

    auth_code = AuthorizationCode(
        client_id=client.client_id,
        identity_email=identity.email,
        redirect_uri=redirect_uri,
        scopes=scopes,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        auth_time=auth_time,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=config.AUTHORIZATION_CODE_TTL),
    )
    session.add(auth_code)
    session.commit()
    session.refresh(auth_code)

    params = {"code": auth_code.code}
    if state:
        params["state"] = state

    logger.info(
        "Authorization code issued for %s (client: %s)",
        identity.email,
        client.client_id,
    )
    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}", status_code=302
    )


@router.post("/token")
async def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    session: Session = Depends(get_session),
):
    # Authenticate client
    client = authenticate_client(request, session, client_id, client_secret)
    if not client:
        raise HTTPException(
            status_code=401,
            detail="invalid_client",
            headers={"WWW-Authenticate": "Basic"},
        )

    if grant_type == "authorization_code":
        return await _handle_authorization_code_grant(
            session, client, code, redirect_uri, code_verifier
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token_grant(session, client, refresh_token)
    else:
        raise HTTPException(status_code=400, detail="unsupported_grant_type")


async def _handle_authorization_code_grant(
    session: Session,
    client: OAuthClient,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> JSONResponse:
    if not code:
        raise HTTPException(status_code=400, detail="Code is required")

    auth_code = AuthorizationCode.get_by_code(session, code)
    if not auth_code:
        raise HTTPException(status_code=400, detail="invalid_grant")

    # Validate
    if auth_code.used:
        # Potential replay attack — revoke all tokens for this authorization
        logger.warning("Authorization code replay detected: %s", code)
        raise HTTPException(status_code=400, detail="invalid_grant")

    if auth_code.is_expired():
        raise HTTPException(status_code=400, detail="invalid_grant")

    if auth_code.client_id != client.client_id:
        raise HTTPException(status_code=400, detail="invalid_grant")

    if auth_code.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="invalid_grant")

    # Verify PKCE
    if auth_code.code_challenge:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Code verifier is required")
        if not verify_code_challenge(
            code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
        ):
            raise HTTPException(status_code=400, detail="invalid_grant")

    # Mark code as used
    auth_code.mark_used(session)

    # Look up identity for roles
    identity = Identity.get(session, auth_code.identity_email)
    roles = [r.value if hasattr(r, "value") else r for r in identity.roles] if identity else []

    # Generate access token
    access_token = create_signed_jwt(auth_code.identity_email, roles)

    # Generate ID token
    id_token = create_id_token(
        email=auth_code.identity_email,
        client_id=client.client_id,
        nonce=auth_code.nonce,
        auth_time=auth_code.auth_time,
        access_token=access_token,
        roles=roles,
    )

    # Generate refresh token
    rt = RefreshToken(
        client_id=client.client_id,
        identity_email=auth_code.identity_email,
        scopes=auth_code.scopes,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=config.REFRESH_TOKEN_TTL),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    logger.info(
        "Tokens issued for %s (client: %s)",
        auth_code.identity_email,
        client.client_id,
    )

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": config.JWT_EXPIRY,
        "id_token": id_token,
        "refresh_token": rt.token,
    })


async def _handle_refresh_token_grant(
    session: Session,
    client: OAuthClient,
    refresh_token_value: str | None,
) -> JSONResponse:
    if not refresh_token_value:
        raise HTTPException(status_code=400, detail="Refresh token is required")

    rt = RefreshToken.get_by_token(session, refresh_token_value)
    if not rt:
        raise HTTPException(status_code=400, detail="invalid_grant")

    if rt.revoked or rt.is_expired():
        raise HTTPException(status_code=400, detail="invalid_grant")

    if rt.client_id != client.client_id:
        raise HTTPException(status_code=400, detail="invalid_grant")

    # Look up identity for roles
    identity = Identity.get(session, rt.identity_email)
    if not identity:
        raise HTTPException(status_code=400, detail="invalid_grant")
    roles = [r.value if hasattr(r, "value") else r for r in identity.roles]

    # Generate new access token
    access_token = create_signed_jwt(rt.identity_email, roles)

    # Generate new ID token
    auth_time = identity.last_auth_time or datetime.now(timezone.utc)
    id_token = create_id_token(
        email=rt.identity_email,
        client_id=client.client_id,
        nonce=None,
        auth_time=auth_time,
        access_token=access_token,
        roles=roles,
    )

    # Rotate refresh token
    new_rt = RefreshToken(
        client_id=client.client_id,
        identity_email=rt.identity_email,
        scopes=rt.scopes,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=config.REFRESH_TOKEN_TTL),
    )
    session.add(new_rt)
    session.flush()

    rt.revoke(session, replaced_by=new_rt.token)

    logger.info(
        "Tokens refreshed for %s (client: %s)",
        rt.identity_email,
        client.client_id,
    )

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": config.JWT_EXPIRY,
        "id_token": id_token,
        "refresh_token": new_rt.token,
    })
