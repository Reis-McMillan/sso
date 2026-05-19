import logging
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from sqlmodel import Session

from verys.database import get_session
from verys.models.identity import Identity
from verys.config import config
from verys.modules.jwt import get_public_key_pem

logger = logging.getLogger("verys.auth")

security = HTTPBearer(auto_error=False)


def try_authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    session: Session,
) -> Identity | None:
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
            audience=config.ISSUER,
        )

        sub = decoded.get("sub")
        if not sub:
            logger.warning("Auth failed: JWT missing 'sub' claim")
            return None

        try:
            identity_id = int(sub)
        except (TypeError, ValueError):
            logger.warning("Auth failed: 'sub' claim is not a valid identity id: %s", sub)
            return None

        identity = Identity.get_by_id(session, identity_id)
        if not identity:
            logger.warning("Auth failed: no identity for id %s", identity_id)
            return None

        request.state.identity = identity
        request.state.token_scopes = decoded.get("scopes", [])
        logger.info("Authenticated %s via JWT", identity.email)
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
    session: Session = Depends(get_session),
) -> Identity:
    """FastAPI dependency that requires a valid Bearer token."""
    identity = try_authenticate(request, credentials, session)
    if not identity:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return identity
