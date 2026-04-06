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
        # Seed Verys public client
        verys_client = OAuthClient.get_by_client_id(db_session, config.VERYS_CLIENT_ID)
        if not verys_client:
            verys_client = OAuthClient(
                client_id=config.VERYS_CLIENT_ID,
                client_name="Verys Client",
                redirect_uris=[config.VERYS_CLIENT_REDIRECT_URI],
                allowed_scopes=["openid"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
                is_public=True,
            )
            db_session.add(verys_client)
            db_session.commit()
            logging.getLogger("verys").info("Seeded Verys public client: %s", config.VERYS_CLIENT_ID)
        elif verys_client.redirect_uris != [config.VERYS_CLIENT_REDIRECT_URI]:
            verys_client.redirect_uris = [config.VERYS_CLIENT_REDIRECT_URI]
            db_session.commit()
            logging.getLogger("verys").info("Updated Verys public client redirect_uris: %s", config.VERYS_CLIENT_ID)
    logging.getLogger("verys").info("Verys service starting")
    yield
    logging.getLogger("verys").info("Verys service shutting down")
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
