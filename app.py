import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI

from config import config
from middleware.authenticated import authenticate_user
from middleware.logging import RequestLoggingMiddleware
from database import initialize_db, get_session
from models.oauth2_client import OAuthClient
from models.scope import Scope
from routes import identity, jwks, verification, discovery, oauth2, userinfo, session, clients, scopes, providers, federation
from utils.logging import setup_logging, shutdown_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    initialize_db()
    # Seed standard OIDC scopes
    for db_session in get_session():
        Scope.seed_oidc_scopes(db_session)
        # Seed SSO public client
        if not OAuthClient.get_by_client_id(db_session, config.SSO_CLIENT_ID):
            sso_client = OAuthClient(
                client_id=config.SSO_CLIENT_ID,
                client_name="SSO Client",
                redirect_uris=[config.SSO_CLIENT_REDIRECT_URI],
                allowed_scopes=["openid"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
                is_public=True,
            )
            db_session.add(sso_client)
            db_session.commit()
            logging.getLogger("sso").info("Seeded SSO public client: %s", config.SSO_CLIENT_ID)
    logging.getLogger("sso").info("SSO service starting")
    yield
    logging.getLogger("sso").info("SSO service shutting down")
    shutdown_logging()


app = FastAPI(lifespan=lifespan)

app.add_middleware(RequestLoggingMiddleware)

# Public endpoints
app.include_router(discovery.router)
app.include_router(jwks.router)
app.include_router(verification.router)
app.include_router(oauth2.router)
app.include_router(userinfo.router)
app.include_router(session.router)
app.include_router(federation.router)

# Protected endpoints
app.include_router(identity.router, dependencies=[Depends(authenticate_user)])
app.include_router(clients.router, dependencies=[Depends(authenticate_user)])
app.include_router(scopes.router, dependencies=[Depends(authenticate_user)])
app.include_router(providers.router, dependencies=[Depends(authenticate_user)])
