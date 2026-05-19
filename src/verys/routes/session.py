import logging
from pathlib import Path

import jwt as pyjwt
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from verys.config import config
from verys.database import get_session
from verys.models.oauth2_client import OAuthClient
from verys.models.refresh_token import RefreshToken
from verys.modules.jwt import get_public_key_pem

logger = logging.getLogger("verys.session")

router = APIRouter(tags=["Session"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


@router.get("/end-session")
async def end_session(
    request: Request,
    id_token_hint: str | None = Query(None),
    post_logout_redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
    session: Session = Depends(get_session),
):
    # Try to identify user from id_token_hint
    identity_id = None
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
            sub = decoded.get("sub")
            if sub is not None:
                try:
                    identity_id = int(sub)
                except (TypeError, ValueError):
                    identity_id = None
            client_id = decoded.get("aud")
        except pyjwt.InvalidTokenError:
            pass

    # Revoke refresh tokens if we identified the user
    if identity_id and client_id:
        RefreshToken.revoke_all_for_user_client(session, identity_id, client_id)
        logger.info("Revoked refresh tokens for identity %s (client: %s)", identity_id, client_id)

    # Clear Verys cookies
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
        response = templates.TemplateResponse(request, "logout.html", {})

    # Clear cookies
    response.delete_cookie(key=config.ENCRYPT_COOKIE_NAME, path="/")
    response.delete_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", path="/")

    logger.info("Session ended for identity %s", identity_id or "unknown")
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
        logger.info("Token revoked for identity %s", rt.identity_id)

    # Per RFC 7009, always return 200 even if token not found
    return {"active": False}
