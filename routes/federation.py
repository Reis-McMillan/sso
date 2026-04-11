import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session

from config import config
from database import get_session
from middleware.authenticated import authenticate_user
from models.authorization_code import AuthorizationCode
from models.external_provider import ExternalProvider
from models.external_token import ExternalToken
from models.federation_session import FederationSession
from models.identity import Identity
from models.oauth2_client import OAuthClient
from models.oauth2_session import OAuth2Session
from utils.browser_auth import get_browser_identity


logger = logging.getLogger("verys.federation")

router = APIRouter(prefix="/federation", tags=["Federation"])


@router.get("/initiate")
async def initiate_federation(
    request: Request,
    provider_id: str = Query(...),
    oauth2_session_id: str | None = Query(None),
    redirect_uri: str | None = Query(None),
    session: Session = Depends(get_session),
):
    """Start upstream OAuth2 flow with an external provider."""
    identity = get_browser_identity(request, session)
    if not identity:
        raise HTTPException(status_code=401, detail="Not authenticated")
    identity_id = identity.id

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")

    provider_scopes = set(provider.scopes) if provider.scopes else set()

    if not provider_scopes:
        raise HTTPException(status_code=400, detail="No scopes configured for this provider")

    # Create federation session to track the flow
    fed_session = FederationSession(
        identity_id=identity_id,
        provider_id=provider_id,
        oauth2_session_id=oauth2_session_id,
        redirect_uri=redirect_uri,
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
        "Federation initiated: identity %s -> %s",
        identity_id, provider_id,
    )
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/callback/{provider_id}")
async def federation_callback(
    request: Request,
    provider_id: str,
    code: str | None = Query(None),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
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

    # Handle error from upstream provider (user cancelled, no account, etc.)
    if error is not None:
        logger.warning(
            "Federation error from %s for identity %s: %s - %s",
            provider_id, fed_session.identity_id, error, error_description,
        )

        # Capture fields before deleting the session
        identity_id = fed_session.identity_id
        failed_scope_names = list(fed_session.scopes_requested)
        oauth2_session_id = fed_session.oauth2_session_id
        client_redirect_uri = fed_session.redirect_uri

        session.delete(fed_session)
        session.commit()

        # If chained from OAuth2 flow, issue auth code with reduced scopes
        if oauth2_session_id:
            oauth2_sess = OAuth2Session.get_by_session_id(session, oauth2_session_id)
            if oauth2_sess and not oauth2_sess.is_expired():
                identity = Identity.get_by_id(session, identity_id)
                client = OAuthClient.get_by_client_id(session, oauth2_sess.client_id)

                if identity and client:
                    full_scopes = oauth2_sess.scope.split()
                    granted_scopes = [s for s in full_scopes if s not in failed_scope_names]

                    auth_time = identity.last_auth_time or datetime.now(timezone.utc)
                    auth_code = AuthorizationCode(
                        client_id=client.client_id,
                        identity_email=identity.email,
                        redirect_uri=oauth2_sess.redirect_uri,
                        scopes=granted_scopes,
                        nonce=oauth2_sess.nonce,
                        code_challenge=oauth2_sess.code_challenge,
                        code_challenge_method=oauth2_sess.code_challenge_method,
                        auth_time=auth_time,
                        expires_at=datetime.now(timezone.utc)
                        + timedelta(seconds=config.AUTHORIZATION_CODE_TTL),
                    )
                    session.add(auth_code)

                    redirect_uri = oauth2_sess.redirect_uri
                    state_param = oauth2_sess.state

                    session.delete(oauth2_sess)
                    session.commit()
                    session.refresh(auth_code)

                    params = {"code": auth_code.code}
                    if state_param:
                        params["state"] = state_param

                    logger.info(
                        "Federation failed for identity %s, issuing auth code with reduced scopes: %s",
                        identity_id, granted_scopes,
                    )
                    return RedirectResponse(
                        url=f"{redirect_uri}?{urlencode(params)}", status_code=302
                    )

        if client_redirect_uri:
            return RedirectResponse(url=client_redirect_uri, status_code=302)

        return JSONResponse(
            status_code=400,
            content={
                "error": "federation_failed",
                "error_description": error_description or f"Upstream provider {provider_id} returned: {error}",
                "provider_id": provider_id,
            },
        )

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from provider")

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
            "Token exchange failed for identity %s with %s: %s",
            fed_session.identity_id, provider_id, token_response.text,
        )
        raise HTTPException(status_code=502, detail="Failed to exchange code with upstream provider")

    token_data = token_response.json()
    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    token_type = token_data.get("token_type", "Bearer")
    scope_str = token_data.get("scope", "")

    if not access_token:
        raise HTTPException(status_code=502, detail="No access token in upstream response")

    # Fetch subject from provider's userinfo endpoint
    if not provider.userinfo_endpoint:
        raise HTTPException(status_code=502, detail="Provider has no userinfo endpoint configured")

    async with httpx.AsyncClient() as userinfo_client:
        userinfo_response = await userinfo_client.get(
            provider.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_response.status_code != 200:
        logger.error(
            "Userinfo request failed for identity %s from %s: %s",
            fed_session.identity_id, provider_id, userinfo_response.text,
        )
        raise HTTPException(status_code=502, detail="Failed to fetch userinfo from upstream provider")

    subject = userinfo_response.json().get("sub")
    if not subject:
        raise HTTPException(status_code=502, detail="Userinfo response missing sub claim")

    expires_at = None
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Store tokens
    ExternalToken.upsert(
        session,
        identity_id=fed_session.identity_id,
        provider_id=provider_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=token_type,
        expires_at=expires_at,
        scopes_granted=scope_str.split() if scope_str else [],
        subject=subject,
    )

    logger.info(
        "External tokens stored for identity %s from %s",
        fed_session.identity_id, provider_id,
    )

    # Clean up federation session
    oauth2_session_id = fed_session.oauth2_session_id
    client_redirect_uri = fed_session.redirect_uri
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
                "Federation complete, resuming OAuth2 flow for identity %s",
                fed_session.identity_id,
            )
            return RedirectResponse(
                url=f"/authorize?{urlencode(params)}", status_code=302
            )

    if client_redirect_uri:
        return RedirectResponse(url=client_redirect_uri, status_code=302)

    return JSONResponse({"detail": "Federation complete", "provider": provider_id})


@router.get("/providers", dependencies=[Depends(authenticate_user)])
async def list_user_providers(
    request: Request,
    session: Session = Depends(get_session),
):
    """List external providers the user has linked tokens for."""
    identity_id = request.state.identity.id
    tokens = ExternalToken.get_all_for_user(session, identity_id)
    return [
        {"provider_id": t.provider_id, "subject": t.subject}
        for t in tokens
    ]


@router.get("/tokens", dependencies=[Depends(authenticate_user)])
async def get_external_tokens(
    request: Request,
    provider_id: str = Query(...),
    subject: str = Query(...),
    session: Session = Depends(get_session),
):
    """Serve external access tokens to downstream clients.

    Requires a valid Bearer JWT. Returns only the access token, never the refresh token.
    Automatically refreshes expired tokens if a refresh token is available.
    """
    identity_id = request.state.identity.id

    # Look up external token
    ext_token = ExternalToken.get(session, identity_id, provider_id, subject)
    if not ext_token:
        raise HTTPException(status_code=404, detail="No external token found for this provider")

    # Auto-refresh if expired
    if ext_token.is_expired() and ext_token.refresh_token:
        refreshed = await _refresh_external_token(session, ext_token)
        if not refreshed:
            # Upstream rejected the refresh token — delete stale record
            session.delete(ext_token)
            session.commit()
            return JSONResponse(
                status_code=401,
                content={
                    "error": "reauthorization_required",
                    "error_description": "External token refresh failed. User must re-authorize with the provider.",
                    "provider_id": provider_id,
                },
                headers={"Cache-Control": "no-store"},
            )
        ext_token = refreshed

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
            "External token refresh failed for identity %s from %s: %s",
            ext_token.identity_id, ext_token.provider_id, response.text,
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
        identity_id=ext_token.identity_id,
        provider_id=ext_token.provider_id,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type=token_data.get("token_type", "Bearer"),
        expires_at=expires_at,
        scopes_granted=ext_token.scopes_granted,
        subject=ext_token.subject,
    )

# to-do implement route to delete token
@router.delete('{}')
async def delete_external_token():
    pass