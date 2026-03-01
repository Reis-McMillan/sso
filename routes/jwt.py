from datetime import datetime, timezone
import logging
from sqlmodel import Session
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from config import config
from database import get_session
from models.identity import Identity
from utils.jwt import create_signed_jwt

logger = logging.getLogger("sso.jwt")


router = APIRouter(prefix="/jwt", tags=["jwt"])

@router.get("/")
async def get_jwt(
    request: Request = None,
    session: Session = Depends(get_session)
):
    email = request.state.auth_cache.email
    r = Identity.get(session, email)
    if not r:
        logger.warning("Identity not found: %s (refresh)", email)
        raise HTTPException(status_code=404, detail="Identity not found")   

    token = create_signed_jwt(r.email, r.roles)
    response = JSONResponse(content={"token": token})
    response.set_cookie(
        key="jwt",
        value=token,
        max_age=config.JWT_EXPIRY,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return response