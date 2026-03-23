import base64
from datetime import datetime, timedelta, timezone

from models.oauth2_client import OAuthClient
from models.refresh_token import RefreshToken
from utils.client_auth import hash_client_secret
from utils.cookie import encrypt_cookie
from utils.jwt import create_id_token


def test_end_session_clears_cookies(session, client):
    # Set cookies first
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get('/end-session', follow_redirects=False)
    assert res.status_code == 200
    assert 'Logged Out' in res.text

    # Cookies should be cleared (set-cookie with max-age=0 or expires in the past)
    set_cookies = res.headers.get_list('set-cookie')
    cookie_names = [c.split('=')[0] for c in set_cookies]
    assert 'token' in cookie_names
    assert 'token_iv' in cookie_names

    client.cookies.clear()


def test_end_session_with_id_token_hint(session, client):
    oa = OAuthClient(
        client_name="Session Test App",
        redirect_uris=["https://session.example.com/callback"],
        allowed_scopes=["openid"],
        client_secret_hash=hash_client_secret("session-secret"),
    )
    session.add(oa)
    session.commit()
    session.refresh(oa)

    # Create a refresh token for this user+client
    rt = RefreshToken(
        client_id=oa.client_id,
        identity_email="admin@mcmlln.dev",
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    # Create id_token_hint
    id_token = create_id_token(
        email="admin@mcmlln.dev",
        client_id=oa.client_id,
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    res = client.get(
        '/end-session',
        params={'id_token_hint': id_token},
        follow_redirects=False,
    )
    assert res.status_code == 200

    # Verify the refresh token was revoked
    session.expire_all()
    found = RefreshToken.get_by_token(session, rt.token)
    assert found.revoked == True


def test_end_session_with_redirect(session, client):
    oa = OAuthClient(
        client_name="Redirect Session App",
        redirect_uris=["https://session-redirect.example.com/callback"],
        allowed_scopes=["openid"],
        client_secret_hash=hash_client_secret("redirect-session-secret"),
    )
    session.add(oa)
    session.commit()
    session.refresh(oa)

    id_token = create_id_token(
        email="admin@mcmlln.dev",
        client_id=oa.client_id,
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    res = client.get(
        '/end-session',
        params={
            'id_token_hint': id_token,
            'post_logout_redirect_uri': 'https://session-redirect.example.com/callback',
            'state': 'logout-state',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert 'session-redirect.example.com/callback' in res.headers['location']
    assert 'logout-state' in res.headers['location']


def test_end_session_redirect_invalid_uri(session, client):
    oa = OAuthClient(
        client_name="Invalid Redirect Session App",
        redirect_uris=["https://valid.example.com/callback"],
        allowed_scopes=["openid"],
        client_secret_hash=hash_client_secret("inv-redirect-secret"),
    )
    session.add(oa)
    session.commit()
    session.refresh(oa)

    id_token = create_id_token(
        email="admin@mcmlln.dev",
        client_id=oa.client_id,
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    # Use a redirect URI that's NOT registered
    res = client.get(
        '/end-session',
        params={
            'id_token_hint': id_token,
            'post_logout_redirect_uri': 'https://evil.example.com/callback',
        },
        follow_redirects=False,
    )
    # Should NOT redirect — show logout page instead
    assert res.status_code == 200
    assert 'Logged Out' in res.text


def test_end_session_no_params(client):
    res = client.get('/end-session', follow_redirects=False)
    assert res.status_code == 200
    assert 'Logged Out' in res.text


def test_token_revoke(session, client):
    rt = RefreshToken(
        client_id="revoke-route-client",
        identity_email="admin@mcmlln.dev",
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    res = client.post(
        '/token/revoke',
        data={'token': rt.token},
    )
    assert res.status_code == 200

    session.expire_all()
    found = RefreshToken.get_by_token(session, rt.token)
    assert found.revoked == True


def test_token_revoke_nonexistent(client):
    res = client.post(
        '/token/revoke',
        data={'token': 'nonexistent-token'},
    )
    # Per RFC 7009, always return 200
    assert res.status_code == 200


def test_token_revoke_no_token(client):
    res = client.post('/token/revoke', data={})
    assert res.status_code == 200
