from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from sqlalchemy.exc import OperationalError
import jwt as jwt_lib

from fastapi.testclient import TestClient

from app import app
from database import get_session
from models import Identity
from utils.cookie import encrypt_cookie
from utils.jwt import create_signed_jwt, _get_private_key


# ──────────────────────────────────────────────
# authenticate_user_jwt (cookie auth, via /jwt/)
# ──────────────────────────────────────────────

def test_cookie_auth_success(session, client, admin_creds):
    token, iv = admin_creds
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 200
    assert 'token' in res.json()
    assert res.cookies.get('jwt') is not None


def test_cookie_auth_no_auth_token(client):
    res = client.get('/jwt/')
    assert res.status_code == 401
    assert res.json()['detail'] == 'No Auth header set'


def test_cookie_auth_no_init_vector(client, admin_creds):
    token, _ = admin_creds
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'No Init Vector header set'


def test_cookie_auth_decrypt_fails(client):
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': 'badhex', 'X-Init-Vector': 'badhex'}
    )
    assert res.status_code == 401


def test_cookie_auth_database_error(client, admin_creds):
    mock_session = MagicMock()
    mock_session.exec.side_effect = OperationalError("SELECT 1", {}, "connection refused")
    app.dependency_overrides[get_session] = lambda: mock_session

    token, iv = admin_creds
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 500

    app.dependency_overrides.clear()


def test_cookie_auth_identity_not_found(session, client):
    token, iv = encrypt_cookie('nonexistent@example.com', 'somekey')
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'No valid authentication token found'


def test_cookie_auth_key_mismatch(session, client):
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'wrong_key')
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'No valid authentication token found'


def test_cookie_auth_identity_expired(session, client):
    Identity.new(
        session,
        'expired@test.com',
        'testkey',
        datetime.now(timezone.utc) - timedelta(days=1)
    )
    token, iv = encrypt_cookie('expired@test.com', 'testkey')
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'No valid authentication token found'


# ──────────────────────────────────────────────
# authenticate_user (JWT bearer, via /identity)
# ──────────────────────────────────────────────

def test_jwt_auth_success(session, client, admin_jwt):
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'}
    )
    assert res.status_code == 200


def test_jwt_auth_no_authorization_header(client):
    res = client.get('/identity')
    assert res.status_code == 401
    assert res.json()['detail'] == 'Not authenticated'


def test_jwt_auth_bad_format(client):
    res = client.get(
        '/identity',
        headers={'Authorization': 'BadFormat token123'}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Not authenticated'


def test_jwt_auth_public_key_fails(session):
    with TestClient(app, raise_server_exceptions=False) as c:
        with patch('middleware.authenticated.get_public_key_pem', side_effect=Exception("key not found")):
            jwt_token = create_signed_jwt('admin@mcmlln.dev', ['admin'])
            res = c.get(
                '/identity',
                headers={'Authorization': f'Bearer {jwt_token}'}
            )
    assert res.status_code == 500


def test_jwt_auth_missing_sub_claim(client):
    now = datetime.now(timezone.utc)
    payload = {
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Invalid token: missing subject'


def test_jwt_auth_expired_signature(client):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': 'admin@mcmlln.dev',
        'roles': ['admin'],
        'iat': now - timedelta(minutes=10),
        'exp': now - timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Token expired'


def test_jwt_auth_invalid_token(client):
    res = client.get(
        '/identity',
        headers={'Authorization': 'Bearer invalid.jwt.token'}
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Invalid token'
