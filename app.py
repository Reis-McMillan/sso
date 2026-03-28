import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI

from middleware.authenticated import authenticate_user, authenticate_user_jwt
from middleware.logging import RequestLoggingMiddleware
from database import initialize_db, get_session
from models.scope import Scope
from routes import identity, jwks, jwt, verification, discovery, oauth2, userinfo, session, clients, scopes, providers, federation
from utils.logging import setup_logging, shutdown_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    initialize_db()
    # Seed standard OIDC scopes
    for db_session in get_session():
        Scope.seed_oidc_scopes(db_session)
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
app.include_router(jwt.router, dependencies=[Depends(authenticate_user_jwt)])
app.include_router(identity.router, dependencies=[Depends(authenticate_user)])
app.include_router(clients.router, dependencies=[Depends(authenticate_user)])
app.include_router(scopes.router, dependencies=[Depends(authenticate_user)])
app.include_router(providers.router, dependencies=[Depends(authenticate_user)])
