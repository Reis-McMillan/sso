import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session
import jwt

from config import config
from database import get_session
from models.authorization_code import AuthorizationCode
from models.consent import Consent
from models.external_token import ExternalToken
from models.identity import Identity
from models.oauth2_client import OAuthClient
from models.oauth2_session import OAuth2Session
from models.refresh_token import RefreshToken
from models.scope import Scope
from utils.browser_auth import get_browser_identity
from utils.client_auth import authenticate_client
from utils.jwt import create_id_token, create_signed_jwt, get_public_key_pem
from utils.pkce import verify_code_challenge

logger = logging.getLogger("verys.oauth2")

router = APIRouter(tags=["OAuth2"])

templates = Jinja2Templates(directory="templates")


def _get_authenticated_identity(
    request: Request, session: Session
) -> Identity | None:
    """Try to authenticate user from cookies (browser flow)."""
    return get_browser_identity(request, session)


def _build_error_redirect(redirect_uri: str, error: str, description: str, state: str | None = None):
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}", status_code=302
    )


def _find_missing_federation_provider(
    session: "Session", identity_email: str, federation_scopes: dict[str, list[str]]
) -> str | None:
    """Check if user has valid external tokens for all federation providers.

    Returns the first provider_id that is missing a token, or None if all are present.
    A provider is considered missing if there is no token record or no refresh token
    (the access token can be refreshed later via /federation/tokens).
    """
    for provider_id, scope_names in federation_scopes.items():
        ext_token = ExternalToken.get(session, identity_email, provider_id)
        if not ext_token or not ext_token.refresh_token_encrypted:
            return provider_id
    return None


def _redirect_to_federation(
    session: "Session",
    provider_id: str,
    scope_names: list[str],
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> RedirectResponse:
    """Store OAuth2 session and redirect to federation initiate."""
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

    params = {
        "provider_id": provider_id,
        "scope_names": " ".join(scope_names),
        "oauth2_session_id": oauth2_session.session_id,
    }
    return RedirectResponse(
        url=f"/federation/initiate?{urlencode(params)}", status_code=302
    )


@router.get("/authorize")
@router.post("/authorize")
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
    prompt: str | None = Query(None),
    max_age: int | None = Query(None),
    request_obj: str | None = Query(None, alias="request"),
    request_uri: str | None = Query(None),
    session: Session = Depends(get_session),
):
    # Validate client
    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # Validate redirect_uri (exact match required)
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # Reject request objects — not supported (OIDCC-3.1.2.6)
    if request_obj is not None:
        return _build_error_redirect(
            redirect_uri, "request_not_supported",
            "Request objects are not supported", state
        )
    if request_uri is not None:
        return _build_error_redirect(
            redirect_uri, "request_uri_not_supported",
            "Request URI is not supported", state
        )

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

    # Validate scopes exist in the database and partition into OIDC vs federation
    federation_scopes = {}  # provider_id -> [scope_name, ...]
    for s in requested_scopes:
        scope_record = Scope.get_by_name(session, s)
        if not scope_record:
            return _build_error_redirect(
                redirect_uri, "invalid_scope",
                f"Unknown scope '{s}'", state
            )
        if scope_record.provider_id:
            federation_scopes.setdefault(scope_record.provider_id, []).append(s)

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

    # Parse prompt parameter
    prompt_values = set(prompt.split()) if prompt else set()

    # "none" must not be combined with other values
    if "none" in prompt_values and len(prompt_values) > 1:
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "prompt=none cannot be combined with other values", state
        )

    # Check if user is authenticated
    # prompt=login forces re-authentication — ignore existing session
    if "login" in prompt_values:
        identity = None
    else:
        identity = _get_authenticated_identity(request, session)

    # max_age: if the user's last authentication is older than max_age seconds,
    # force re-authentication (treat as if not authenticated)
    if identity and max_age is not None:
        auth_time = identity.last_auth_time or datetime.min.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - auth_time).total_seconds()
        if elapsed > max_age:
            identity = None

    if not identity:
        if "none" in prompt_values:
            return _build_error_redirect(
                redirect_uri, "login_required",
                "User is not authenticated and prompt=none was requested", state
            )

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
            "issuer": config.ISSUER,
        })

    # Check consent
    consent = Consent.get(session, identity.email, client_id)
    has_consent = consent and consent.covers_scopes(requested_scopes)

    # prompt=consent forces the consent screen even if already granted
    if has_consent and "consent" not in prompt_values:
        # Check if federation scopes need external tokens before issuing code
        missing_provider = _find_missing_federation_provider(
            session, identity.email, federation_scopes
        )
        if missing_provider:
            return _redirect_to_federation(
                session, missing_provider, federation_scopes[missing_provider],
                client_id, redirect_uri, response_type, scope, state, nonce,
                code_challenge, code_challenge_method,
            )

        # Consent already granted and all external tokens present, issue code
        return _issue_authorization_code(
            session, identity, client, redirect_uri,
            requested_scopes, state, nonce,
            code_challenge, code_challenge_method,
        )

    if "none" in prompt_values:
        return _build_error_redirect(
            redirect_uri, "consent_required",
            "User has not consented and prompt=none was requested", state
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
        csrf_token=csrf_token,
    )
    session.add(oauth2_session)
    session.commit()
    session.refresh(oauth2_session)

    # Build scope details for the consent template
    scope_details = []
    for s in requested_scopes:
        scope_record = Scope.get_by_name(session, s)
        if scope_record:
            scope_details.append({
                "name": s,
                "description": scope_record.description,
                "provider_id": scope_record.provider_id,
            })
        else:
            scope_details.append({"name": s, "description": s, "provider_id": None})

    return templates.TemplateResponse("consent.html", {
        "request": request,
        "client_name": client.client_name,
        "scopes": requested_scopes,
        "scope_details": scope_details,
        "oauth2_session_id": oauth2_session.session_id,
        "csrf_token": csrf_token,
        "issuer": config.ISSUER,
    })


@router.post("/authorize/consent")
async def authorize_consent(
    request: Request,
    oauth2_session_id: str = Form(...),
    consent_action: str = Form(...),
    csrf_token: str = Form(...),
    session: Session = Depends(get_session),
):
    # Look up session
    oauth2_session = OAuth2Session.get_by_session_id(session, oauth2_session_id)
    if not oauth2_session or oauth2_session.is_expired():
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    # Verify CSRF token
    if not oauth2_session.csrf_token or not secrets.compare_digest(
        csrf_token, oauth2_session.csrf_token
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

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

    # Check if federation scopes need external tokens
    federation_scopes = {}
    for s in requested_scopes:
        scope_record = Scope.get_by_name(session, s)
        if scope_record and scope_record.provider_id:
            federation_scopes.setdefault(scope_record.provider_id, []).append(s)

    missing_provider = _find_missing_federation_provider(
        session, identity.email, federation_scopes
    )
    if missing_provider:
        # Keep the session alive for the federation callback to resume
        return _redirect_to_federation(
            session, missing_provider, federation_scopes[missing_provider],
            oauth2_session.client_id, redirect_uri,
            oauth2_session.response_type, oauth2_session.scope, state,
            oauth2_session.nonce, oauth2_session.code_challenge,
            oauth2_session.code_challenge_method,
        )

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
    subject_token: str | None = Form(None),
    subject_token_type: str | None = Form(None),
    audience: str | None = Form(None),
    session: Session = Depends(get_session),
):
    # Authenticate client
    client = authenticate_client(request, session, client_id, client_secret)
    if not client:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "Client authentication failed"},
            headers={"WWW-Authenticate": "Basic"},
        )

    if grant_type == "authorization_code":
        return await _handle_authorization_code_grant(
            session, client, code, redirect_uri, code_verifier
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token_grant(session, client, refresh_token)
    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        return await _handle_token_exchange_grant(
            session, client, subject_token, subject_token_type, audience
        )
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type", "error_description": "Supported grant types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:token-exchange"},
        )


async def _handle_authorization_code_grant(
    session: Session,
    client: OAuthClient,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> JSONResponse:
    if not code:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Code is required"},
        )

    auth_code = AuthorizationCode.get_by_code(session, code)
    if not auth_code:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code not found"},
        )

    # Validate
    if auth_code.used:
        # Potential replay attack — revoke all tokens for this authorization (RFC 6749 §4.1.2)
        logger.warning("Authorization code replay detected: %s", code)
        RefreshToken.revoke_all_for_user_client(
            session, auth_code.identity_email, auth_code.client_id
        )
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code has already been used"},
        )

    if auth_code.is_expired():
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code has expired"},
        )

    if auth_code.client_id != client.client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Client mismatch"},
        )

    if auth_code.redirect_uri != redirect_uri:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
        )

    # Verify PKCE
    if auth_code.code_challenge:
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Code verifier is required"},
            )
        if not verify_code_challenge(
            code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
        ):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid code verifier"},
            )

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

    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
            "id_token": id_token,
            "refresh_token": rt.token,
            "scope": " ".join(auth_code.scopes),
        },
        headers={"Cache-Control": "no-store"},
    )


async def _handle_refresh_token_grant(
    session: Session,
    client: OAuthClient,
    refresh_token_value: str | None,
) -> JSONResponse:
    if not refresh_token_value:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Refresh token is required"},
        )

    rt = RefreshToken.get_by_token(session, refresh_token_value)
    if not rt:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Refresh token not found"},
        )

    if rt.revoked or rt.is_expired():
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Refresh token is revoked or expired"},
        )

    if rt.client_id != client.client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Client mismatch"},
        )

    # Look up identity for roles
    identity = Identity.get(session, rt.identity_email)
    if not identity:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Identity not found"},
        )
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

    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
            "id_token": id_token,
            "refresh_token": new_rt.token,
            "scope": " ".join(rt.scopes),
        },
        headers={"Cache-Control": "no-store"},
    )


async def _handle_token_exchange_grant(
    session: Session,
    client: OAuthClient,
    subject_token: str | None,
    subject_token_type: str | None,
    audience: str | None,
):
    if not subject_token:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "subject_token is required"},
        )

    if subject_token_type and subject_token_type != "urn:ietf:params:oauth:token-type:access_token":
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Only access_token subject_token_type is supported"},
        )

    if not audience:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "audience is required"},
        )

    # Validate the subject token
    try:
        decoded = jwt.decode(
            subject_token,
            key=get_public_key_pem(),
            algorithms=["EdDSA"],
            audience=config.ISSUER,
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Invalid or expired subject token"},
        )

    # Verify target audience is a registered client
    target_client = OAuthClient.get_by_client_id(session, audience)
    if not target_client:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_target", "error_description": "Audience is not a registered OAuth client"},
        )

    # Look up identity for roles
    identity = Identity.get(session, decoded["sub"])
    if not identity:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Identity not found"},
        )
    roles = [r.value if hasattr(r, "value") else r for r in identity.roles]

    target_consent = Consent.get(session, identity.email, target_client.client_id)
    if not target_consent:
        return JSONResponse(
            status_code=403,
            content={
                "error": "access_denied",
                "error_description": "User has not consented to target client.",
            }
        )

    # Issue new access token scoped to the target audience
    access_token = create_signed_jwt(identity.email, roles, audience=audience)

    logger.info(
        "Token exchange: %s exchanged token for audience %s (via client: %s)",
        identity.email, audience, client.client_id,
    )

    return JSONResponse(
        content={
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
        },
        headers={"Cache-Control": "no-store"},
    )