import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from utils.jwt import create_signed_jwt, _get_private_key


def test_userinfo_get(client, admin_jwt):
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == 'admin@mcmlln.dev'
    assert body['email'] == 'admin@mcmlln.dev'
    assert body['email_verified'] == True


def test_userinfo_post(client, admin_jwt):
    res = client.post(
        '/userinfo',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == 'admin@mcmlln.dev'


def test_userinfo_includes_roles(client, admin_jwt):
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {admin_jwt}'},
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


def test_userinfo_expired_token(client):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': 'admin@mcmlln.dev',
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
    assert res.json()['detail'] == 'Token expired'


def test_userinfo_missing_sub(client):
    now = datetime.now(timezone.utc)
    payload = {
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5),
    }
    token = pyjwt.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Invalid token: missing subject'
