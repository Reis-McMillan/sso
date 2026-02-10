from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI

from database import initialize_db
from middleware.authenticated import authenticate_user
from routes import identity, verification


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(lifespan=lifespan)

app.include_router(identity.router, dependencies=[Depends(authenticate_user)])
app.include_router(verification.router)