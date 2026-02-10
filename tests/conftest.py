from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlmodel import SQLModel

from app import app
from database import initialize_db, get_session, engine
from models import Identity
from utils.cookie import encrypt_cookie

@pytest.fixture(scope="module")
def admin_creds():
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    return token, iv


@pytest.fixture(scope="module")
def service_user_creds():
    token, iv = encrypt_cookie('service@mcmlln.dev', 'jd vance erika kirk baby')
    return token, iv


@pytest.fixture(scope='module')
def session():
    initialize_db()

    session = next(get_session())

    Identity.new(
        session,
        'admin@mcmlln.dev',
        'paris_people',
        datetime.now(timezone.utc) + timedelta(days=30)
    )
    Identity.new(
        session,
        'service@mcmlln.dev',
        'jd vance erika kirk baby',
        datetime.now(timezone.utc) + timedelta(days=30)
    )
    Identity.update_roles(
        session,
        'admin@mcmlln.dev',
        ['admin']
    )
    Identity.update_roles(
        session,
        'service@mcmlln.dev',
        ['service-account']
    )

    yield session

    session.close()
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(scope='module')
def client(session):
    with TestClient(app) as client:
        yield client