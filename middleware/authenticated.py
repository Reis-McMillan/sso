import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import Request, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import Session
import jwt

from database import get_session
from models.identity import Identity
from utils.cookie import decrypt_cookie
from utils.jwt import get_public_key_pem

logger = logging.getLogger("sso.auth")

async def authenticate_user_jwt(
    request: Request,
    session: Session = Depends(get_session)
) -> Identity:
    
    auth_token = request.cookies.get('token', None)
    init_vector = request.cookies.get('token_iv', None)
    
    if not auth_token:
        logger.warning("Auth failed: missing auth token")
        raise HTTPException(status_code=401, detail="Missing auth token")

    if not init_vector:
        logger.warning("Auth failed: missing init vector")
        raise HTTPException(status_code=401, detail="Missing init vector")

    try:
        decrypted = decrypt_cookie(auth_token, init_vector)
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
    
security = HTTPBearer()
async def authenticate_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Identity:
    jwt_token = credentials.credentials

    try:
        # Verify and decode JWT
        public_key_pem = get_public_key_pem()
        decoded = jwt.decode(
            jwt_token,
            public_key_pem,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
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