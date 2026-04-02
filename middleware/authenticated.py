import logging
from types import SimpleNamespace
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from utils.jwt import get_public_key_pem

logger = logging.getLogger("sso.auth")

security = HTTPBearer(auto_error=False)


def try_authenticate(request: Request, credentials: HTTPAuthorizationCredentials | None) -> SimpleNamespace | None:
    """Try to authenticate from Bearer token. Returns None if not authenticated."""
    if not credentials:
        return None

    jwt_token = credentials.credentials
    try:
        public_key_pem = get_public_key_pem()
        decoded = jwt.decode(
            jwt_token,
            public_key_pem,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )

        email = decoded.get("sub")
        roles = decoded.get("roles", [])

        if not email:
            logger.warning("Auth failed: JWT missing 'sub' claim")
            return None

        identity = SimpleNamespace(email=email, roles=roles)
        request.state.identity = identity
        logger.info("Authenticated %s via JWT", email)
        return identity

    except jwt.ExpiredSignatureError:
        logger.warning("Auth failed: JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("Auth failed: invalid JWT token - %s", e)
        return None


async def authenticate_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> SimpleNamespace:
    """FastAPI dependency that requires a valid Bearer token."""
    identity = try_authenticate(request, credentials)
    if not identity:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return identity
