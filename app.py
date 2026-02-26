import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI

from middleware.authenticated import authenticate_user, authenticate_user_jwt
from middleware.logging import RequestLoggingMiddleware
from database import initialize_db
from routes import identity, jwks, jwt, verification
from utils.logging import setup_logging, shutdown_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    initialize_db()
    logging.getLogger("sso").info("SSO service starting")
    yield
    logging.getLogger("sso").info("SSO service shutting down")
    shutdown_logging()


app = FastAPI(lifespan=lifespan)

app.add_middleware(RequestLoggingMiddleware)
app.include_router(identity.router, dependencies=[Depends(authenticate_user)])
app.include_router(jwks.router)
app.include_router(jwt.router, dependencies=[Depends(authenticate_user_jwt)])
app.include_router(verification.router)
