import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from verys.models import Identity
from verys.modules.jwt import create_signed_jwt, _get_private_key
from verys.config import config


def test_userinfo_get(session, client):
    admin = Identity.get(session, 'admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid', 'email'], config.ISSUER)
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == str(admin.id)
    assert body['email'] == 'admin@mcmlln.dev'
    assert body['email_verified'] == True


def test_userinfo_post(session, client):
    admin = Identity.get(session, 'admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid'], config.ISSUER)
    res = client.post(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == str(admin.id)


def test_userinfo_includes_roles(session, client):
    admin = Identity.get(session, 'admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid'])
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    body = res.json()
    assert 'roles' in body
    assert 'admin' in body['roles']


def test_userinfo_no_auth(client):
    res = client.get('/userinfo')
    assert res.status_code == 401


def test_userinfo_invalid_token(client):
    res = client.get(
        '/userinfo',
        headers={'Authorization': 'Bearer invalid.jwt.token'},
    )
    assert res.status_code == 401


def test_userinfo_expired_token(session, client):
    admin = Identity.get(session, 'admin@mcmlln.dev')
    now = datetime.now(timezone.utc)
    payload = {
        'sub': str(admin.id),
        'roles': ['admin'],
        'iat': now - timedelta(minutes=10),
        'exp': now - timedelta(minutes=5),
    }
    token = pyjwt.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Token expired'


def test_userinfo_missing_sub(client):
    now = datetime.now(timezone.utc)
    payload = {
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5),
        'aud': config.ISSUER
    }
    token = pyjwt.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Invalid token: missing subject'
