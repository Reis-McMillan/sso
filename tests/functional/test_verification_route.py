from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from verys.config import config
from verys.models import Verification, Identity


def _register(session, email: str):
    """Pre-create an Identity the way /register would have."""
    return Identity.new(
        session,
        'Test',
        'User',
        email,
        Identity.make_auth_key(),
        datetime.now(timezone.utc) + timedelta(days=30),
    )


def test_request_verification(client, session):
    _register(session, 'newuser@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock):
        res = client.post(
            '/verification',
            params={'email': 'newuser@example.com'}
        )
    assert res.status_code == 201


def test_request_verification_creates_entry(client, session):
    _register(session, 'entrycheck@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock):
        client.post(
            '/verification',
            params={'email': 'entrycheck@example.com'}
        )

    session.expire_all()
    from sqlmodel import select
    entry = session.exec(
        select(Verification).where(Verification.email == 'entrycheck@example.com')
    ).first()
    assert entry is not None
    assert entry.email == 'entrycheck@example.com'
    assert entry.email_sent is not None


def test_verify_valid_code(client, session):
    _register(session, 'verifytest@example.com')
    code = Verification.make_code()
    Verification.make_entry(session, 'verifytest@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'verifytest@example.com', 'code': str(code)}
    )
    assert res.status_code == 200
    assert config.ENCRYPT_COOKIE_NAME in res.cookies
    assert f"{config.ENCRYPT_COOKIE_NAME}_iv" in res.cookies


def test_verify_marks_email_verified(client, session):
    session.expire_all()
    identity = Identity.get(session, 'verifytest@example.com')
    assert identity is not None
    assert identity.email == 'verifytest@example.com'
    assert identity.email_verified is True


def test_verify_refreshes_expired_identity(client, session):
    # Pre-create an identity whose session key has expired
    identity = _register(session, 'existinguser@example.com')
    old_key = identity.auth_key
    identity.expires = datetime.now(timezone.utc) - timedelta(days=1)
    session.add(identity)
    session.commit()

    code = Verification.make_code()
    Verification.make_entry(session, 'existinguser@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'existinguser@example.com', 'code': str(code)}
    )
    assert res.status_code == 200
    assert config.ENCRYPT_COOKIE_NAME in res.cookies

    session.expire_all()
    identity = Identity.get(session, 'existinguser@example.com')
    assert identity.auth_key != old_key
    assert identity.email_verified is True


def test_verify_invalid_code(client, session):
    _register(session, 'invalidcode@example.com')
    code = Verification.make_code()
    Verification.make_entry(session, 'invalidcode@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'invalidcode@example.com', 'code': '000000'}
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Invalid or expired code'


def test_verify_expired_code(client, session):
    _register(session, 'expiredcode@example.com')
    code = Verification.make_code()
    entry = Verification.make_entry(session, 'expiredcode@example.com', code)
    entry.when = datetime.now(timezone.utc) - timedelta(hours=1)
    session.add(entry)
    session.commit()

    res = client.get(
        '/verification',
        params={'email': 'expiredcode@example.com', 'code': str(code)}
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Invalid or expired code'


def test_verify_nonexistent_email(client):
    res = client.get(
        '/verification',
        params={'email': 'nobody@example.com', 'code': '123456'}
    )
    assert res.status_code == 404


def test_verify_non_numeric_code(client):
    res = client.get(
        '/verification',
        params={'email': 'test@example.com', 'code': 'abc'}
    )
    assert res.status_code == 404


def test_email_send_failure(client, session):
    _register(session, 'fail@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock, side_effect=Exception('SMTP error')):
        res = client.post(
            '/verification',
            params={'email': 'fail@example.com'}
        )
    assert res.status_code == 500
    assert res.json()['error'] == 'Email service failed.'


def test_missing_email_post(client):
    res = client.post('/verification')
    assert res.status_code == 422


def test_missing_params_get(client):
    res = client.get('/verification')
    assert res.status_code == 422
