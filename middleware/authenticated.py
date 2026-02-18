import logging
from datetime import datetime, timezone
from fastapi import Request, HTTPException, Depends, Header
from sqlmodel import Session

from database import get_session
from models.identity import Identity
from utils.cookie import decrypt_cookie

logger = logging.getLogger("sso.auth")

async def authenticate_user(
    request: Request,
    x_auth_token: str = Header(None),
    x_init_vector: str = Header(None),
    session: Session = Depends(get_session)
) -> Identity:
    if not x_auth_token:
        logger.warning("Auth failed: missing auth token header")
        raise HTTPException(status_code=401, detail="No Auth header set")

    if not x_init_vector:
        logger.warning("Auth failed: missing init vector header")
        raise HTTPException(status_code=401, detail="No Init Vector header set")

    try:
        decrypted = decrypt_cookie(x_auth_token, x_init_vector)
    except Exception as e:
        logger.warning("Auth failed: cookie decryption error - %s", e)
        raise HTTPException(status_code=401, detail=str(e))

    try:
        identity = Identity.get(session, decrypted["email"])

        if (not identity or
            identity.auth_key != decrypted["auth_key"] or
            datetime.now(timezone.utc) > identity.expires):

            logger.warning("Auth failed: invalid or expired token for %s", decrypted["email"])
            raise HTTPException(status_code=401, detail="No valid authentication token found")

        request.state.auth_cache = identity
        logger.info("Authenticated %s", identity.email)

        return identity

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error("Auth error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
