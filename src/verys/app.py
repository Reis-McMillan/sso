import logging
from contextlib import asynccontextmanager

from sqlmodel import Session
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from verys.config import config
from verys.database import engine, initialize_db, get_session
from verys.middleware.authenticated import BearerToken, on_auth_error
from verys.middleware.logging import RequestLoggingMiddleware
from verys.models import Scope, Role, OAuthClient
from verys.modules.logging import setup_logging, shutdown_logging
from verys.routes import (
    clients,
    discovery,
    federation,
    identity,
    jwks,
    oauth2,
    providers,
    registration,
    roles,
    scopes,
    session as session_routes,
    userinfo,
    verification,
)


@asynccontextmanager
async def lifespan(app: Starlette):
    setup_logging()
    initialize_db()
    for db_session in get_session():
        Role.seed_roles(db_session)
        Scope.seed_oidc_scopes(db_session)
        verys_client = OAuthClient.get_by_client_id(db_session, config.VERYS_CLIENT_ID)
        if not verys_client:
            verys_client = OAuthClient(
                client_id=config.VERYS_CLIENT_ID,
                client_name="Verys Client",
                redirect_uris=[config.VERYS_CLIENT_REDIRECT_URI],
                allowed_scopes=["openid", "email", "profile", "google", "microsoft"],
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


class DBSessionMiddleware:
    """Open one DB session per HTTP request, exposed as ``request.state.session``."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        with Session(engine) as db_session:
            scope.setdefault("state", {})["session"] = db_session
            await self.app(scope, receive, send)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger("verys").exception(
        "Unhandled exception on %s %s", request.method, request.url.path
    )
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


routes = [
    *discovery.routes,
    *jwks.routes,
    *registration.routes,
    *verification.routes,
    *oauth2.routes,
    *userinfo.routes,
    *session_routes.routes,
    *federation.routes,
    *identity.routes,
    *clients.routes,
    *scopes.routes,
    *providers.routes,
    *roles.routes,
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=config.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    ),
    Middleware(RequestLoggingMiddleware),
    Middleware(DBSessionMiddleware),
    Middleware(AuthenticationMiddleware, backend=BearerToken(), on_error=on_auth_error),
]

app = Starlette(
    lifespan=lifespan,
    routes=routes,
    middleware=middleware,
    exception_handlers={Exception: unhandled_exception_handler},
)
