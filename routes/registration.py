from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr

from database import get_session
from models.identity import Identity
from config import config
from routes.verification import send_verification_email


class RegistrationBody(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr

router = APIRouter(prefix="/register", tags=["Registration"])


@router.post('/', status_code=201)
async def register(
    body: RegistrationBody,
    session: Session = Depends(get_session)
):
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
        raise HTTPException(
            status_code=400,
            detail="An account already exists for this email."
        )

    await send_verification_email(session, identity.email)

    return JSONResponse(
        status_code=201,
        content={
            "message": "Registration complete. Check your email for a verification code.",
            "email": identity.email,
        }
    )