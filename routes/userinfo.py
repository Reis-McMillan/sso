import logging

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from database import get_session
from models.identity import Identity
from utils.jwt import get_public_key_pem
from config import config

logger = logging.getLogger("verys.userinfo")

router = APIRouter(tags=["UserInfo"])

security = HTTPBearer(auto_error=False)


@router.get("/userinfo")
@router.post("/userinfo")
async def userinfo(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    session: Session = Depends(get_session),
):
    # Accept token from Authorization header or POST body (access_token field)
    token = None
    if credentials:
        token = credentials.credentials
    elif request.method == "POST":
        form = await request.form()
        token = form.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        public_key_pem = get_public_key_pem()
        decoded = pyjwt.decode(
            token,
            public_key_pem,
            algorithms=["EdDSA"],
            audience=config.ISSUER,
        )
    except pyjwt.ExpiredSignatureError as e:
        logger.warning("Expired token getting user info: %s", e)
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError as e:
        logger.warning(
            "Invalid token getting user info: %s",
            e,
            exc_info=True
        )
        raise HTTPException(status_code=401, detail="Invalid token")

    sub = decoded.get("sub")
    if not sub:
        logger.warning(
            "Subject missing while getting user info",
            exc_info=True
        )
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")

    try:
        identity_id = int(sub)
    except (TypeError, ValueError) as e:
        logger.warning(
            "Invalid subject data type while getting user info: %s", e)
        raise HTTPException(status_code=401, detail="Invalid token: bad subject")

    identity = Identity.get_by_id(session, identity_id)
    if not identity:
        raise HTTPException(status_code=401, detail="Identity not found")

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
