import base64
import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt

from verys.config import config
from verys.models.authorization_code import AuthorizationCode
from verys.models.consent import Consent
from verys.models.identity import Identity
from verys.models.oauth2_client import OAuthClient
from verys.models.refresh_token import RefreshToken
from verys.modules.client_auth import hash_client_secret
from verys.modules.cookie import encrypt_cookie
from verys.modules.jwt import get_public_key_pem


def _create_client_and_code(session, **code_overrides):
    """Helper that creates an OAuth2 client and a valid authorization code."""
    oa = OAuthClient(
        client_name="Token Test App",
        redirect_uris=["https://tokentest.example.com/callback"],
        allowed_scopes=["openid", "email", "profile"],
        client_secret_hash=hash_client_secret("token-test-secret"),
    )
    session.add(oa)
    session.commit()
    session.refresh(oa)

    now = datetime.now(timezone.utc)
    defaults = dict(
        client_id=oa.client_id,
        identity_email="admin@mcmlln.dev",
        redirect_uri="https://tokentest.example.com/callback",
        scopes=["openid", "email"],
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
    )
    defaults.update(code_overrides)

    auth_code = AuthorizationCode(**defaults)
    session.add(auth_code)
    session.commit()
    session.refresh(auth_code)

    return oa, auth_code


def _basic_auth_header(client_id, client_secret):
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def test_token_authorization_code(session, client):
    oa, auth_code = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 200
    body = res.json()
    assert 'access_token' in body
    assert 'id_token' in body
    assert 'refresh_token' in body
    assert body['token_type'] == 'Bearer'
    assert body['expires_in'] == config.JWT_EXPIRY

    # Verify access token
    public_key = get_public_key_pem()
    from verys.models import Identity
    admin = Identity.get(session, 'admin@mcmlln.dev')
    decoded = pyjwt.decode(body['access_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert decoded['sub'] == str(admin.id)
    assert decoded['iss'] == config.ISSUER

    # Verify ID token
    id_decoded = pyjwt.decode(body['id_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert id_decoded['sub'] == str(admin.id)
    assert id_decoded['aud'] == oa.client_id
    assert id_decoded['iss'] == config.ISSUER
    assert 'auth_time' in id_decoded
    assert 'at_hash' in id_decoded


def test_token_authorization_code_with_nonce(session, client):
    oa, auth_code = _create_client_and_code(session, nonce="test-nonce-value")

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 200
    body = res.json()

    public_key = get_public_key_pem()
    id_decoded = pyjwt.decode(body['id_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert id_decoded['nonce'] == 'test-nonce-value'


def test_token_authorization_code_post_auth(session, client):
    """Test client_secret_post authentication method."""
    oa, auth_code = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
            'client_id': oa.client_id,
            'client_secret': 'token-test-secret',
        },
    )
    assert res.status_code == 200
    assert 'access_token' in res.json()


def test_token_invalid_client(session, client):
    _, auth_code = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header("nonexistent", "bad-secret"),
    )
    assert res.status_code == 401


def test_token_wrong_client_secret(session, client):
    oa, auth_code = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "wrong-secret"),
    )
    assert res.status_code == 401


def test_token_invalid_code(session, client):
    oa, _ = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': 'nonexistent-code',
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_expired_code(session, client):
    oa, auth_code = _create_client_and_code(
        session,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_used_code(session, client):
    oa, auth_code = _create_client_and_code(session)
    auth_code.mark_used(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_wrong_redirect_uri(session, client):
    oa, auth_code = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://wrong.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_wrong_client_for_code(session, client):
    _, auth_code = _create_client_and_code(session)

    # Create a different client
    other = OAuthClient(
        client_name="Other Client",
        redirect_uris=["https://other.example.com/cb"],
        client_secret_hash=hash_client_secret("other-secret"),
    )
    session.add(other)
    session.commit()
    session.refresh(other)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(other.client_id, "other-secret"),
    )
    assert res.status_code == 400


def test_token_pkce_success(session, client):
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    oa, auth_code = _create_client_and_code(
        session,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
            'code_verifier': code_verifier,
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 200
    assert 'access_token' in res.json()


def test_token_pkce_wrong_verifier(session, client):
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    oa, auth_code = _create_client_and_code(
        session,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
            'code_verifier': 'wrong-verifier',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_pkce_missing_verifier(session, client):
    oa, auth_code = _create_client_and_code(
        session,
        code_challenge="some-challenge",
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_unsupported_grant_type(session, client):
    oa, _ = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'client_credentials',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


# ──────────────────────────────────────────────
# Refresh token grant
# ──────────────────────────────────────────────

def test_token_refresh(session, client):
    oa, auth_code = _create_client_and_code(session)

    # First get tokens via authorization_code
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    first_tokens = res.json()

    # Now refresh
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': first_tokens['refresh_token'],
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res2.status_code == 200
    body = res2.json()
    assert 'access_token' in body
    assert 'id_token' in body
    assert 'refresh_token' in body
    # Refresh token rotation: new token should differ
    assert body['refresh_token'] != first_tokens['refresh_token']


def test_token_refresh_revoked(session, client):
    oa, auth_code = _create_client_and_code(session)

    # Get tokens
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    tokens = res.json()

    # Revoke the refresh token
    rt = RefreshToken.get_by_token(session, tokens['refresh_token'])
    rt.revoke(session)

    # Try to use revoked token
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res2.status_code == 400


def test_token_refresh_invalid_token(session, client):
    oa, _ = _create_client_and_code(session)

    res = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': 'nonexistent-token',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    assert res.status_code == 400


def test_token_refresh_wrong_client(session, client):
    oa, auth_code = _create_client_and_code(session)

    # Get tokens
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa.client_id, "token-test-secret"),
    )
    tokens = res.json()

    # Create a different client
    other = OAuthClient(
        client_name="Other Refresh Client",
        redirect_uris=["https://other.example.com/cb"],
        client_secret_hash=hash_client_secret("other-secret"),
    )
    session.add(other)
    session.commit()
    session.refresh(other)

    # Try to use token with different client
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
        },
        headers=_basic_auth_header(other.client_id, "other-secret"),
    )
    assert res2.status_code == 400
