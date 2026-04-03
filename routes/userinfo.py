import logging

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from utils.jwt import get_public_key_pem

logger = logging.getLogger("verys.userinfo")

router = APIRouter(tags=["UserInfo"])

security = HTTPBearer(auto_error=False)


@router.get("/userinfo")
@router.post("/userinfo")
async def userinfo(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
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
            options={"verify_aud": False},
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = decoded.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")

    # Build claims based on what's available
    # The scopes were encoded into the access token's audience/context
    # For simplicity, return all claims the token carries
    claims = {"sub": email}

    # email scope claims
    claims["email"] = email
    claims["email_verified"] = True

    # profile scope claims
    roles = decoded.get("roles")
    if roles:
        claims["roles"] = roles

    return JSONResponse(claims)
