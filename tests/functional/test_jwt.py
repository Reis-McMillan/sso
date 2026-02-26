from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from sqlalchemy.exc import OperationalError

from app import app
from database import get_session


def test_refresh_jwt(session, client, admin_creds):
    token, iv = admin_creds
    res = client.get(
        '/jwt/',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 200
    assert isinstance(res.text, str)
    assert len(res.text) > 0


def test_refresh_jwt_database_error(client, admin_creds):
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


def test_refresh_jwt_identity_not_found(session, client, admin_creds):
    token, iv = admin_creds
    with patch('routes.jwt.Identity') as MockIdentity:
        MockIdentity.get.return_value = None
        res = client.get(
            '/jwt/',
            headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
        )
    assert res.status_code == 404
    assert res.json()['detail'] == 'Identity not found'
