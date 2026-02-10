from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from config import config
from models import Verification, Identity


def test_request_verification(client, session):
    with patch('routes.verification.aiosmtplib.send', new_callable=AsyncMock):
        res = client.post(
            '/verification',
            params={'email': 'newuser@example.com'}
        )
    assert res.status_code == 201


def test_request_verification_creates_entry(client, session):
    with patch('routes.verification.aiosmtplib.send', new_callable=AsyncMock):
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
    code = Verification.make_code()
    Verification.make_entry(session, 'verifytest@example.com', code)

    res = client.post(
        '/verification',
        params={'email': 'verifytest@example.com', 'code': str(code)}
    )
    assert res.status_code == 201
    res_json = res.json()
    assert 'auth_key' in res_json
    assert res_json['authentication_ttl'] == config.AUTHENTICATION_TTL


def test_verify_creates_identity(client, session):
    session.expire_all()
    identity = Identity.get(session, 'verifytest@example.com')
    assert identity is not None
    assert identity.email == 'verifytest@example.com'


def test_verify_updates_existing_identity(client, session):
    old_key = Identity.make_auth_key()
    Identity.new(
        session,
        'existinguser@example.com',
        old_key,
        datetime.now(timezone.utc) - timedelta(days=1)
    )

    code = Verification.make_code()
    Verification.make_entry(session, 'existinguser@example.com', code)

    res = client.post(
        '/verification',
        params={'email': 'existinguser@example.com', 'code': str(code)}
    )
    assert res.status_code == 201
    res_json = res.json()
    assert res_json['auth_key'] != old_key


def test_verify_invalid_code(client, session):
    code = Verification.make_code()
    Verification.make_entry(session, 'invalidcode@example.com', code)

    res = client.post(
        '/verification',
        params={'email': 'invalidcode@example.com', 'code': '000000'}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'Invalid or expired code'


def test_verify_expired_code(client, session):
    code = Verification.make_code()
    entry = Verification.make_entry(session, 'expiredcode@example.com', code)
    entry.when = datetime.now(timezone.utc) - timedelta(hours=1)
    session.add(entry)
    session.commit()

    res = client.post(
        '/verification',
        params={'email': 'expiredcode@example.com', 'code': str(code)}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'Invalid or expired code'


def test_verify_nonexistent_email(client):
    res = client.post(
        '/verification',
        params={'email': 'nobody@example.com', 'code': '123456'}
    )
    assert res.status_code == 404


def test_verify_non_numeric_code(client):
    res = client.post(
        '/verification',
        params={'email': 'test@example.com', 'code': 'abc'}
    )
    assert res.status_code == 404


def test_email_send_failure(client, session):
    with patch('routes.verification.aiosmtplib.send', new_callable=AsyncMock, side_effect=Exception('SMTP error')):
        res = client.post(
            '/verification',
            params={'email': 'fail@example.com'}
        )
    assert res.status_code == 500
    assert res.json()['detail'] == 'Email service failed.'


def test_missing_email(client):
    res = client.post('/verification')
    assert res.status_code == 422
