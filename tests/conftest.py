from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlmodel import SQLModel

from verys.app import app
from verys.database import initialize_db, get_session, engine
from verys.models import Identity
from verys.modules.cookie import encrypt_cookie
from verys.modules.jwt import create_signed_jwt


@pytest.fixture(scope="module")
def admin_jwt(session):
    admin = Identity.get(session, 'admin@mcmlln.dev')
    return create_signed_jwt(admin, ['openid'])


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
    # Drop existing tables to ensure clean state
    SQLModel.metadata.drop_all(engine)
    # Recreate tables
    initialize_db()

    session = next(get_session())

    admin = Identity.new(
        session,
        'Admin',
        'User',
        'admin@mcmlln.dev',
        'paris_people',
        datetime.now(timezone.utc) + timedelta(days=30),
    )
    admin.email_verified = True
    session.add(admin)
    service = Identity.new(
        session,
        'Service',
        'Account',
        'service@mcmlln.dev',
        'jd vance erika kirk baby',
        datetime.now(timezone.utc) + timedelta(days=30),
    )
    service.email_verified = True
    session.add(service)
    session.commit()

    Identity.update(
        session,
        'admin@mcmlln.dev',
        new_roles=['admin']
    )
    Identity.update(
        session,
        'service@mcmlln.dev',
        new_roles=['service-account']
    )

    yield session

    session.close()
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(scope='module')
def client(session):
    with TestClient(app) as client:
        yield client