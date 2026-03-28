import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session

from config import config
from database import get_session
from models.external_provider import ExternalProvider
from models.external_token import ExternalToken
from models.federation_session import FederationSession
from models.oauth2_session import OAuth2Session
from models.scope import Scope
from utils.cookie import decrypt_cookie
from utils.encryption import encrypt_field
from utils.jwt import get_public_key_pem

logger = logging.getLogger("sso.federation")

router = APIRouter(prefix="/federation", tags=["Federation"])


def _get_authenticated_identity_email(request: Request) -> str | None:
    """Extract authenticated user email from cookies."""
    token = request.cookies.get(config.ENCRYPT_COOKIE_NAME)
    token_iv = request.cookies.get(f"{config.ENCRYPT_COOKIE_NAME}_iv")
    if not token or not token_iv:
        return None
    try:
        decrypted = decrypt_cookie(token, token_iv)
        return decrypted["email"]
    except Exception:
        return None


@router.get("/initiate")
async def initiate_federation(
    request: Request,
    provider_id: str = Query(...),
    scope_names: str = Query(...),
    oauth2_session_id: str | None = Query(None),
    session: Session = Depends(get_session),
):
    """Start upstream OAuth2 flow with an external provider."""
    identity_email = _get_authenticated_identity_email(request)
    if not identity_email:
        raise HTTPException(status_code=401, detail="Not authenticated")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")

    # Resolve SSO scope names to provider scopes
    requested_scope_names = scope_names.split()
    provider_scopes = set()
    for name in requested_scope_names:
        scope = Scope.get_by_name(session, name)
        if scope and scope.provider_id == provider_id:
            provider_scopes.update(scope.provider_scopes)

    if not provider_scopes:
        raise HTTPException(status_code=400, detail="No valid provider scopes for requested scope names")

    # Create federation session to track the flow
    fed_session = FederationSession(
        identity_email=identity_email,
        provider_id=provider_id,
        scopes_requested=requested_scope_names,
        oauth2_session_id=oauth2_session_id,
    )
    session.add(fed_session)
    session.commit()
    session.refresh(fed_session)

    # Build redirect to upstream provider
    callback_uri = f"{config.ISSUER}/federation/callback/{provider_id}"
    params = {
        "client_id": provider.client_id,
        "redirect_uri": callback_uri,
        "response_type": "code",
        "scope": " ".join(sorted(provider_scopes)),
        "state": fed_session.session_id,
        "access_type": "offline",
        "prompt": "consent",
    }

    redirect_url = f"{provider.authorization_endpoint}?{urlencode(params)}"
    logger.info(
        "Federation initiated: %s -> %s for %s",
        identity_email, provider_id, requested_scope_names,
    )
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/callback/{provider_id}")
async def federation_callback(
    request: Request,
    provider_id: str,
    code: str = Query(...),
    state: str = Query(...),
    session: Session = Depends(get_session),
):
    """Receive callback from upstream provider and exchange code for tokens."""
    # Validate state
    fed_session = FederationSession.get_by_session_id(session, state)
    if not fed_session or fed_session.is_expired():
        raise HTTPException(status_code=400, detail="Invalid or expired federation session")

    if fed_session.provider_id != provider_id:
        raise HTTPException(status_code=400, detail="Provider mismatch")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    # Exchange code for tokens
    callback_uri = f"{config.ISSUER}/federation/callback/{provider_id}"
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            provider.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            },
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        logger.error(
            "Token exchange failed for %s with %s: %s",
            fed_session.identity_email, provider_id, token_response.text,
        )
        raise HTTPException(status_code=502, detail="Failed to exchange code with upstream provider")

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    token_type = token_data.get("token_type", "Bearer")
    scope_str = token_data.get("scope", "")

    if not access_token:
        raise HTTPException(status_code=502, detail="No access token in upstream response")

    expires_at = None
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Store tokens
    ExternalToken.upsert(
        session,
        identity_email=fed_session.identity_email,
        provider_id=provider_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=token_type,
        expires_at=expires_at,
        scopes_granted=scope_str.split() if scope_str else [],
    )

    logger.info(
        "External tokens stored for %s from %s",
        fed_session.identity_email, provider_id,
    )

    # Clean up federation session
    oauth2_session_id = fed_session.oauth2_session_id
    session.delete(fed_session)
    session.commit()

    # If chained from a downstream authorize flow, redirect back to /authorize
    if oauth2_session_id:
        oauth2_sess = OAuth2Session.get_by_session_id(session, oauth2_session_id)
        if oauth2_sess and not oauth2_sess.is_expired():
            params = {
                "response_type": oauth2_sess.response_type,
                "client_id": oauth2_sess.client_id,
                "redirect_uri": oauth2_sess.redirect_uri,
                "scope": oauth2_sess.scope,
            }
            if oauth2_sess.state:
                params["state"] = oauth2_sess.state
            if oauth2_sess.nonce:
                params["nonce"] = oauth2_sess.nonce
            if oauth2_sess.code_challenge:
                params["code_challenge"] = oauth2_sess.code_challenge
            if oauth2_sess.code_challenge_method:
                params["code_challenge_method"] = oauth2_sess.code_challenge_method

            logger.info(
                "Federation complete, resuming OAuth2 flow for %s",
                fed_session.identity_email,
            )
            return RedirectResponse(
                url=f"/authorize?{urlencode(params)}", status_code=302
            )

    return JSONResponse({"detail": "Federation complete", "provider": provider_id})


@router.get("/tokens")
async def get_external_tokens(
    request: Request,
    provider_id: str = Query(...),
    session: Session = Depends(get_session),
):
    """Serve external access tokens to downstream clients.

    Requires a valid Bearer JWT. Returns only the access token, never the refresh token.
    Automatically refreshes expired tokens if a refresh token is available.
    """
    # Extract user from Bearer JWT
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token_str = auth_header[7:]
    try:
        public_key_pem = get_public_key_pem()
        decoded = pyjwt.decode(
            token_str,
            public_key_pem,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    identity_email = decoded.get("sub")
    if not identity_email:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")

    # Look up external token
    ext_token = ExternalToken.get(session, identity_email, provider_id)
    if not ext_token:
        raise HTTPException(status_code=404, detail="No external token found for this provider")

    # Auto-refresh if expired
    if ext_token.is_expired() and ext_token.refresh_token:
        ext_token = await _refresh_external_token(session, ext_token)
        if not ext_token:
            raise HTTPException(status_code=502, detail="Failed to refresh external token")

    return JSONResponse(
        content={
            "access_token": ext_token.access_token,
            "token_type": ext_token.token_type,
            "expires_at": ext_token.expires_at.isoformat() if ext_token.expires_at else None,
            "provider_id": provider_id,
        },
        headers={"Cache-Control": "no-store"},
    )


async def _refresh_external_token(
    session: Session, ext_token: ExternalToken
) -> ExternalToken | None:
    """Refresh an expired external access token using the stored refresh token."""
    provider = ExternalProvider.get_by_provider_id(session, ext_token.provider_id)
    if not provider:
        return None

    refresh_token = ext_token.refresh_token
    if not refresh_token:
        return None

    async with httpx.AsyncClient() as client:
        response = await client.post(
            provider.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            },
            headers={"Accept": "application/json"},
        )

    if response.status_code != 200:
        logger.error(
            "External token refresh failed for %s from %s: %s",
            ext_token.identity_email, ext_token.provider_id, response.text,
        )
        return None

    token_data = response.json()
    new_access_token = token_data.get("access_token")
    if not new_access_token:
        return None

    expires_at = None
    expires_in = token_data.get("expires_in")
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Some providers rotate refresh tokens
    new_refresh_token = token_data.get("refresh_token", refresh_token)

    return ExternalToken.upsert(
        session,
        identity_email=ext_token.identity_email,
        provider_id=ext_token.provider_id,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type=token_data.get("token_type", "Bearer"),
        expires_at=expires_at,
        scopes_granted=ext_token.scopes_granted,
    )
