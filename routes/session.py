import logging

import jwt as pyjwt
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from config import config
from database import get_session
from models.oauth2_client import OAuthClient
from models.refresh_token import RefreshToken
from utils.jwt import get_public_key_pem

logger = logging.getLogger("sso.session")

router = APIRouter(tags=["Session"])

templates = Jinja2Templates(directory="templates")


@router.get("/end-session")
async def end_session(
    request: Request,
    id_token_hint: str | None = Query(None),
    post_logout_redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
    session: Session = Depends(get_session),
):
    # Try to identify user from id_token_hint
    identity_email = None
    client_id = None
    if id_token_hint:
        try:
            public_key_pem = get_public_key_pem()
            decoded = pyjwt.decode(
                id_token_hint,
                public_key_pem,
                algorithms=["EdDSA"],
                options={"verify_aud": False, "verify_exp": False},
            )
            identity_email = decoded.get("sub")
            client_id = decoded.get("aud")
        except pyjwt.InvalidTokenError:
            pass

    # Revoke refresh tokens if we identified the user
    if identity_email and client_id:
        RefreshToken.revoke_all_for_user_client(session, identity_email, client_id)
        logger.info("Revoked refresh tokens for %s (client: %s)", identity_email, client_id)

    # Clear SSO cookies
    response = None

    if post_logout_redirect_uri and client_id:
        # Validate the redirect URI belongs to the client
        client = OAuthClient.get_by_client_id(session, client_id)
        if client and post_logout_redirect_uri in client.redirect_uris:
            url = post_logout_redirect_uri
            if state:
                url = f"{url}?state={state}"
            response = RedirectResponse(url=url, status_code=302)

    if response is None:
        response = templates.TemplateResponse("logout.html", {
            "request": request,
        })

    # Clear cookies
    response.delete_cookie(key=config.ENCRYPT_COOKIE_NAME, path="/")
    response.delete_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", path="/")

    logger.info("Session ended for %s", identity_email or "unknown")
    return response


@router.post("/token/revoke")
async def revoke_token(
    request: Request,
    session: Session = Depends(get_session),
):
    form = await request.form()
    token_value = form.get("token")
    if not token_value:
        return {"active": False}

    rt = RefreshToken.get_by_token(session, token_value)
    if rt:
        rt.revoke(session)
        logger.info("Token revoked for %s", rt.identity_email)

    # Per RFC 7009, always return 200 even if token not found
    return {"active": False}
