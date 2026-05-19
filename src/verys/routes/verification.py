# routes/verification.py
import logging
from pathlib import Path
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import RedirectResponse
from sqlmodel import Session
from datetime import datetime, timedelta, timezone
import aiosmtplib
from email.message import EmailMessage
import humanize
from pydantic import ValidationError

from verys.database import get_session
from verys.models.verification import Verification
from verys.models.identity import Identity
from verys.models.oauth2_session import OAuth2Session
from verys.config import config
from verys.modules.cookie import encrypt_cookie

logger = logging.getLogger("verys.verification")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

router = APIRouter(prefix="/verification", tags=["Verification"])

@router.get("", status_code=200)
async def verify_code(
    email: str = Query(...),
    code: str = Query(...),
    oauth2_session: str | None = Query(None),
    session: Session = Depends(get_session)
):
    try:
        v_entry = Verification.verify(session, email, int(code), config.VERIFY_TTL)
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
    if not r:
        logger.warning("Verification failed: no identity for %s", email)
        raise HTTPException(status_code=404, detail="No account exists for this email")

    # If the identity has expired, refresh the session key & expiry. Verification
    # renews browser sessions; email_verified, once set, stays set.
    if r.expires < datetime.now(timezone.utc):
        new_key = Identity.make_auth_key()
        expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
        r = Identity.update(session, email, new_key=new_key, new_expires=expiry_dt)

    r.last_auth_time = datetime.now(timezone.utc)
    r.email_verified = True
    session.add(r)
    session.commit()
    session.refresh(r)

    logger.info("Verification successful: %s", email)
    value, iv = encrypt_cookie(r.email, r.auth_key)
    max_age = int(config.AUTHENTICATION_TTL)
    cookie_opts = {
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": max_age,
        "path": "/",
    }
    if config.COOKIE_DOMAIN:
        cookie_opts["domain"] = config.COOKIE_DOMAIN

    # If this verification was part of an OAuth2 flow, redirect back to /authorize
    if oauth2_session:
        oauth2_sess = OAuth2Session.get_by_session_id(session, oauth2_session)
        if oauth2_sess and not oauth2_sess.is_expired():
            params = {
                "response_type": oauth2_sess.response_type,
                "client_id": oauth2_sess.client_id,
                "redirect_uri": oauth2_sess.redirect_uri,
                "scope": oauth2_sess.scope,
            }
            if oauth2_sess.state:
                params["state"] = oauth2_sess.state
            if oauth2_sess.nonce:
                params["nonce"] = oauth2_sess.nonce
            if oauth2_sess.code_challenge:
                params["code_challenge"] = oauth2_sess.code_challenge
            if oauth2_sess.code_challenge_method:
                params["code_challenge_method"] = oauth2_sess.code_challenge_method

            # Clean up the session
            session.delete(oauth2_sess)
            session.commit()

            response = RedirectResponse(
                url=f"/authorize?{urlencode(params)}", status_code=302
            )
            response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
            response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
            logger.info("OAuth2 flow: redirecting %s back to /authorize", r.email)
            return response

    response = Response(status_code=200)
    response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
    response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
    logger.info("Cookie issued for %s", r.email)
    return response


async def send_verification_email(session: Session, email: str) -> None:
    """Generate a verification code for the given email and send it.

    Raises HTTPException(500) if the email send fails.
    """
    vcode = Verification.make_code()
    Verification.make_entry(session, email, vcode)

    ttl_delta = timedelta(seconds=config.VERIFY_TTL)
    identity_ttl_str = humanize.precisedelta(ttl_delta, minimum_unit="minutes")

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
        logger.error("Email send failed for %s: %s", email, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Email service failed.")


@router.post("", status_code=201)
async def handle_verification(
    email: str = Query(...),
    oauth2_session: str | None = Query(None),
    session: Session = Depends(get_session)
):
    identity = Identity.get(session, email)
    if not identity:
        params = {"email": email}
        if oauth2_session:
            params["oauth2_session"] = oauth2_session
        logger.info(
            "POST /verification: no identity for %s — redirecting to /register/",
            email,
        )
        return RedirectResponse(
            url=f"/register/?{urlencode(params)}", status_code=302
        )

    await send_verification_email(session, email)
    return Response(status_code=201)
