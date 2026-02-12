# routes/verification.py
from pathlib import Path
from urllib.parse import urlencode
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

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

router = APIRouter(prefix="/verification", tags=["Verification"])

@router.post("/", status_code=201)
async def handle_verification(
    email: str = Query(...),
    code: str | None = Query(None),
    session: Session = Depends(get_session)
):
    if email and code:
        try:
            v_entry = Verification.verify(session, email, int(code), config.VERIFY_DELTA)
            if not v_entry:
                raise HTTPException(status_code=404, detail="Invalid or expired code")
        except ValidationError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        r = Identity.get(session, email)
        new_key = Identity.make_auth_key()
        expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)

        if r:
            Identity.update(session, email, new_key, expiry_dt)
        else:
            Identity.new(session, email, new_key, expiry_dt)

        return {
            "auth_key": new_key,
            "authentication_ttl": config.AUTHENTICATION_TTL
        }

    if email and not code:
        vcode = Verification.make_code()

        # Process and send email
        Verification.make_entry(session, email, vcode)

        ttl_delta = timedelta(seconds=config.AUTHENTICATION_TTL)
        identity_ttl_str = humanize.precisedelta(ttl_delta, minimum_unit="minutes")

        verification_url = f"{config.VERIFY_BASE_URL}/verification?{urlencode({'email': email, 'code': str(vcode)})}"

        # Load templates and replace placeholders
        text_template = (TEMPLATE_DIR / "verification.txt").read_text()
        html_template = (TEMPLATE_DIR / "verification.html").read_text()

        replacements = {
            "${code}": str(vcode),
            "${identity_ttl}": identity_ttl_str,
            "${verification_url}": verification_url,
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
        
        if config.VERIFY_DEBUG_ADDR:
            message['Bcc'] = config.VERIFY_DEBUG_ADDR
            recipients = [email, config.VERIFY_DEBUG_ADDR]
        else:
            recipients = email

        try:
            await aiosmtplib.send(
                message,
                hostname=config.EMAIL_HOST,
                port=config.EMAIL_PORT,
                username=config.USERNAME_SMTP,
                password=config.PASSWORD_SMTP,
                start_tls=True,
                recipients=recipients,
            )
            Verification.email_sent_at(session, email, datetime.now(timezone.utc))
        except Exception as e:
            raise HTTPException(status_code=500, detail="Email service failed.")

        return Response(status_code=201)

    raise HTTPException(status_code=400, detail="Requires email query string.")