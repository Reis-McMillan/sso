# routes/verification.py
import logging
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlmodel import Session
from datetime import datetime, timedelta, timezone
import aiosmtplib
from email.message import EmailMessage
import humanize
from pydantic import ValidationError

from database import get_session
from models.verification import Verification
from models.identity import Identity
from config import config
from utils.cookie import encrypt_cookie

logger = logging.getLogger("sso.verification")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

router = APIRouter(prefix="/verification", tags=["Verification"])

@router.get("/", status_code=200)
async def verify_code(
    email: str = Query(...),
    code: str = Query(...),
    session: Session = Depends(get_session)
):
    try:
        v_entry = Verification.verify(session, email, int(code), config.VERIFY_DELTA)
        if not v_entry:
            logger.warning("Verification failed: invalid or expired code for %s", email)
            raise HTTPException(status_code=404, detail="Invalid or expired code")
    except ValidationError as e:
        logger.warning("Verification failed: validation error for %s - %s", email, e)
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        logger.warning("Verification failed: value error for %s - %s", email, e)
        raise HTTPException(status_code=404, detail=str(e))

    r = Identity.get(session, email)

    if not r or r.expires < datetime.now(timezone.utc):
        new_key = Identity.make_auth_key()
        expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
        if r:
            r = Identity.update(session, email, new_key=new_key, new_expires=expiry_dt)
        else:
            r = Identity.new(session, email, new_key, expiry_dt)

    logger.info("Verification successful: %s (identity %s)", email, "updated" if r else "created")
    value, iv = encrypt_cookie(r.email, r.auth_key)
    max_age = int(config.AUTHENTICATION_TTL)
    cookie_opts = {
        "httponly": True,
        "secure": True,
        "samesite": "strict",
        "max_age": max_age,
        "path": "/",
    }
    response = Response(status_code=200)
    response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
    response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
    logger.info("Cookie issued for %s", r.email)
    return response


@router.post("/", status_code=201)
async def handle_verification(
    email: str = Query(...),
    session: Session = Depends(get_session)
):
    vcode = Verification.make_code()

    # Process and send email
    Verification.make_entry(session, email, vcode)

    ttl_delta = timedelta(seconds=config.VERIFY_DELTA)
    identity_ttl_str = humanize.precisedelta(ttl_delta, minimum_unit="minutes")

    # Load templates and replace placeholders
    text_template = (TEMPLATE_DIR / "verification.txt").read_text()
    html_template = (TEMPLATE_DIR / "verification.html").read_text()

    replacements = {
        "${code}": str(vcode),
        "${identity_ttl}": identity_ttl_str,
    }

    final_text = text_template
    final_html = html_template
    for placeholder, value in replacements.items():
        final_text = final_text.replace(placeholder, value)
        final_html = final_html.replace(placeholder, value)

    message = EmailMessage()
    message['Subject'] = "Verify your email address"
    message['From'] = config.VERIFY_FROM_ADDR
    message['To'] = email
    message.add_alternative(final_text, subtype='text')
    message.add_alternative(final_html, subtype='html')

    debug_addr = getattr(config, 'VERIFY_DEBUG_ADDR', None)
    if debug_addr:
        message['Bcc'] = debug_addr
        recipients = [email, debug_addr]
    else:
        recipients = email

    try:
        await aiosmtplib.send(
            message,
            hostname=config.SMTP_ENDPOINT,
            port=config.SMTP_PORT,
            username=config.USERNAME_SMTP,
            password=config.PASSWORD_SMTP,
            start_tls=True,
            recipients=recipients,
        )
        Verification.email_sent_at(session, email, datetime.now(timezone.utc))
        logger.info("Verification email sent to %s", email)
    except Exception as e:
        logger.error("Email send failed for %s: %s", email, e)
        raise HTTPException(status_code=500, detail="Email service failed.")

    return Response(status_code=201)
