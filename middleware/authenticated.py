import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import Request, HTTPException, Depends, Header
from sqlmodel import Session
import jwt

from database import get_session
from models.identity import Identity
from utils.cookie import decrypt_cookie
from utils.jwt import get_public_key_pem

logger = logging.getLogger("sso.auth")

async def authenticate_user_jwt(
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

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Auth error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    

async def authenticate_user(
    request: Request,
    authorization: str = Header(None),
) -> Identity:
    """
    Authenticate user via JWT token in Authorization header.
    Expected format: "Bearer <jwt_token>"
    """
    if not authorization:
        logger.warning("Auth failed: missing Authorization header")
        raise HTTPException(status_code=401, detail="No Authorization header set")

    # Extract Bearer token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Auth failed: invalid Authorization header format")
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Expected: Bearer <token>")

    jwt_token = parts[1]

    try:
        # Verify and decode JWT
        public_key_pem = get_public_key_pem()
        decoded = jwt.decode(
            jwt_token,
            public_key_pem,
            algorithms=["EdDSA"]
        )

        # Extract claims
        email = decoded.get('sub')
        roles = decoded.get('roles', [])

        if not email:
            logger.warning("Auth failed: JWT missing 'sub' claim")
            raise HTTPException(status_code=401, detail="Invalid token: missing subject")

        # Store identity in request state for later use
        request.state.auth_cache = SimpleNamespace(email=email, roles=roles)
        logger.info("Authenticated %s via JWT", email)

    except jwt.ExpiredSignatureError:
        logger.warning("Auth failed: JWT token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Auth failed: invalid JWT token - %s", e)
        raise HTTPException(status_code=401, detail="Invalid token")