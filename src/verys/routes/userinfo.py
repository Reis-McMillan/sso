import logging

import jwt as pyjwt
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from verys.models.identity import Identity
from verys.modules.http import json_error
from verys.modules.jwt import get_public_key_pem
from verys.config import config

logger = logging.getLogger("verys.userinfo")


async def userinfo(request: Request):
    session = request.state.session

    # Accept token from Authorization header or POST body (access_token field)
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(None, 1)[1]
    elif request.method == "POST":
        form = await request.form()
        token = form.get("access_token")

    if not token:
        return json_error("Missing access token", status_code=401)

    try:
        decoded = pyjwt.decode(
            token,
            get_public_key_pem(),
            algorithms=["EdDSA"],
            audience=config.ISSUER,
        )
    except pyjwt.ExpiredSignatureError as e:
        logger.warning("Expired token getting user info: %s", e)
        return json_error("Token expired", status_code=401)
    except pyjwt.InvalidTokenError as e:
        logger.warning("Invalid token getting user info: %s", e, exc_info=True)
        return json_error("Invalid token", status_code=401)

    sub = decoded.get("sub")
    if not sub:
        logger.warning("Subject missing while getting user info", exc_info=True)
        return json_error("Invalid token: missing subject", status_code=401)

    try:
        identity_id = int(sub)
    except (TypeError, ValueError) as e:
        logger.warning("Invalid subject data type while getting user info: %s", e)
        return json_error("Invalid token: bad subject", status_code=401)

    identity = Identity.get_by_id(session, identity_id)
    if not identity:
        return json_error("Identity not found", status_code=401)

    token_scopes = set(decoded.get("scopes") or [])

    claims = {"sub": str(identity.id)}

    if "email" in token_scopes:
        claims["email"] = identity.email
        claims["email_verified"] = identity.email_verified

    if "profile" in token_scopes:
        claims["given_name"] = identity.first_name
        claims["family_name"] = identity.last_name
        claims["name"] = f"{identity.first_name} {identity.last_name}"
        claims["origination"] = identity.origination.isoformat() if identity.origination else None

    roles = decoded.get("roles")
    if roles:
        claims["roles"] = roles

    return JSONResponse(claims)


routes = [
    Route("/userinfo", userinfo, methods=["GET", "POST"]),
]
