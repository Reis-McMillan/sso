from datetime import datetime, timezone

from fastapi import Request
from sqlmodel import Session

from config import config
from models.identity import Identity
from utils.cookie import decrypt_cookie


def get_browser_identity(request: Request, session: Session) -> Identity | None:
    """Identify user from token/token_iv cookies during the authorize flow."""
    token = request.cookies.get(config.ENCRYPT_COOKIE_NAME)
    token_iv = request.cookies.get(f"{config.ENCRYPT_COOKIE_NAME}_iv")
    if not token or not token_iv:
        return None

    try:
        decrypted = decrypt_cookie(token, token_iv)
    except Exception:
        return None

    identity = Identity.get(session, decrypted["email"])
    if (
        not identity
        or identity.auth_key != decrypted["auth_key"]
        or datetime.now(timezone.utc) > identity.expires
    ):
        return None

    return identity
