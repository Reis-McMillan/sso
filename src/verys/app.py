import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from verys.config import config
from verys.middleware.authenticated import authenticate_user
from verys.middleware.logging import RequestLoggingMiddleware
from verys.database import initialize_db, get_session
from verys.models.oauth2_client import OAuthClient
from verys.models.scope import Scope
from verys.routes import identity, jwks, verification, discovery, oauth2, userinfo, session, clients, scopes, providers, federation, registration
from verys.modules.logging import setup_logging, shutdown_logging


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
                allowed_scopes=["openid", "email", "profile"],
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


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logging.getLogger("verys").exception(
        "Unhandled exception on %s %s", request.method, request.url.path
    )
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type']
)
app.add_middleware(RequestLoggingMiddleware)

# Public endpoints
app.include_router(discovery.router)
app.include_router(jwks.router)
app.include_router(registration.router)
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
