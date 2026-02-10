from datetime import datetime, timedelta, timezone
from pydantic import ValidationError
import pytest
from sqlalchemy.exc import IntegrityError

from models import Identity
from config import config

def test_transform_email():
    res = Identity.transform_email(' Bob72@example.com ')
    assert res == 'bob72@example.com'


def test_new(session):
    auth_key = Identity.make_auth_key()
    expires = datetime.now(timezone.utc) + timedelta(milliseconds=config.AUTHENTICATION_TTL)
    Identity.new(
        session,
        'Bob72@example.com',
        auth_key,
        expires
    )

    res = Identity.get(session, 'bob72@example.com')
    assert isinstance(res.id, int) == True
    assert res.email == 'bob72@example.com'
    assert res.auth_key == auth_key
    assert res.expires == expires
    assert res.origination <= datetime.now(timezone.utc)
    assert res.roles == ['default']
    assert res.closed == False


def test_duplicate(session):
    with pytest.raises(IntegrityError):
        Identity.new(
            session,
            'bob72@example.com',
            Identity.make_auth_key(),
            datetime.now(timezone.utc)
        )
    session.rollback()


def test_not_email(session):
    with pytest.raises(ValidationError):
        Identity.new(
            session,
            'not an email',
            Identity.make_auth_key(),
            datetime.now(timezone.utc)
        )


def test_get(session):
    res = Identity.get(session, 'boB72@example.com')
    assert isinstance(res.id, int) == True
    assert res.email == 'bob72@example.com'


def test_get_none(session):
    res = Identity.get(session, 'nothere@example.com')
    assert res is None


def test_update(session):
    new_auth_key = Identity.make_auth_key()
    res = Identity.update(
        session,
        'bob72@example.com',
        new_auth_key,
        datetime.now(timezone.utc))
    assert res.auth_key == new_auth_key
    assert res.expires <= datetime.now(timezone.utc)


def test_update_roles(session):
    res = Identity.update_roles(session, 'bob72@example.com', ['admin'])
    assert 'admin' in res.roles


def test_close(session):
    res = Identity.close(session, 'bob72@example.com')
    assert res.closed == True


def test_all(session):
    res = Identity.all(session)
    assert len(res) == 3
    assert res[0].email == 'admin@mcmlln.dev'