from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr
import logging

from database import get_session
from models.identity import Identity
from models.oauth2_session import OAuth2Session
from config import config
from routes.verification import send_verification_email

logger = logging.getLogger('verys.registration')

class RegistrationBody(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    oauth2_session_id: str | None = None

router = APIRouter(prefix="/register", tags=["Registration"])


@router.post('/', status_code=201)
async def register(
    body: RegistrationBody,
    session: Session = Depends(get_session)
):
    # If an OAuth2 session was passed through, validate it up-front so the
    # caller learns immediately if the flow has expired and can restart cleanly.
    if body.oauth2_session_id:
        oauth2_sess = OAuth2Session.get_by_session_id(session, body.oauth2_session_id)
        if not oauth2_sess or oauth2_sess.is_expired():
            raise HTTPException(
                status_code=400,
                detail="OAuth2 session is invalid or expired. Restart the sign-in flow.",
            )

    try:
        expiry_dt = datetime.now(tz=timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
        identity = Identity.new(
            session,
            body.first_name,
            body.last_name,
            body.email,
            key=Identity.make_auth_key(),
            expires=expiry_dt,
        )
    except IntegrityError:
        logger.warning(
            "Failed to create identity for %s... identity already exists",
            body.email,
        )
        raise HTTPException(
            status_code=400,
            detail="An account already exists for this email."
        )

    await send_verification_email(session, identity.email)

    content = {
        "message": "Registration complete. Check your email for a verification code.",
        "email": identity.email,
    }
    if body.oauth2_session_id:
        content["oauth2_session_id"] = body.oauth2_session_id

    return JSONResponse(status_code=201, content=content)