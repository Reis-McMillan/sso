from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from unittest.mock import MagicMock
from sqlalchemy.exc import OperationalError

from app import app
from config import config
from database import get_session
from models import Identity
from utils.cookie import encrypt_cookie

bob_token, bob_iv = encrypt_cookie('bob@example.com', 'bad_token')
dude_token, dude_iv = encrypt_cookie('thedude@mcmlln.dev', 'abides')

def test_no_auth_header(client):
    email = quote('bob@example.com')
    res = client.get(f'/identity/{email}')
    assert res.status_code == 401
    assert res.json()['detail'] == 'No Auth header set'


def test_no_init_vector(client):
    email = quote('bob@example.com')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': bob_token
        })
    assert res.status_code == 401
    assert res.json()['detail'] == 'No Init Vector header set'


def test_decrypt_error_bad_token(client):
    email = quote('bob@example.com')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': 'invalid',
            'X-Init-Vector': bob_iv
        })
    assert res.status_code == 401
    assert res.json()['detail'] == 'Odd-length string'


def test_decrypt_error_bad_iv(client):
    email = quote('bob@example.com')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': bob_token,
            'X-Init-Vector': 'invalid'
        }
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'Odd-length string'


def test_database_error(client):
    mock_session = MagicMock()
    mock_session.exec.side_effect = OperationalError("SELECT 69", {}, "kirked!")

    app.dependency_overrides[get_session] = lambda: mock_session

    email = quote('bob@example.com')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': bob_token,
            'X-Init-Vector': bob_iv
        }
    )
    assert res.status_code == 500
    assert res.json()['detail'] == (
        "(builtins.str) kirked!\n"
        "[SQL: SELECT 69]\n"
        "(Background on this error at: https://sqlalche.me/e/20/e3q8)"
    )

    app.dependency_overrides.clear()


def test_identity_not_found(session, client):
    # add identity now so that table exists
    # expired to prompt error next test
    Identity.new(
        session,
        'thedude@mcmlln.dev',
        'abides',
        datetime.now(timezone.utc) - timedelta(days=1)
    )

    email = quote('bob@example.com')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': bob_token,
            'X-Init-Vector': bob_iv
        }
    )
    assert res.status_code == 401
    assert res.json()['detail']  == 'No valid authentication token found'


def test_identity_expired(session, client):
    email = quote('thedude@mcmlln.dev')
    res = client.get(
        f'identity/{email}',
        headers={
            'X-Auth-Token': dude_token,
            'X-Init-Vector': dude_iv
        }
    )
    assert res.status_code == 401
    assert res.json()['detail'] == 'No valid authentication token found'


def test_good_auth(session, client):
    Identity.update(
        session,
        'thedude@mcmlln.dev',
        'abides',
        datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
    )
    email = quote('thedude@mcmlln.dev')
    res = client.get(
        f'/identity/{email}',
        headers={
            'X-Auth-Token': dude_token,
            'X-Init-Vector': dude_iv
        },
    )
    assert res.status_code == 200