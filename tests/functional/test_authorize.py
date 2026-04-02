from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from models.consent import Consent
from models.oauth2_client import OAuthClient
from models.oauth2_session import OAuth2Session
from utils.client_auth import hash_client_secret
from utils.cookie import encrypt_cookie


def _create_test_client(session, client_name="Auth Test App", redirect_uri="https://authtest.example.com/callback", scopes=None):
    """Helper to create a test OAuth2 client directly in the DB."""
    oa_client = OAuthClient(
        client_name=client_name,
        redirect_uris=[redirect_uri],
        allowed_scopes=scopes or ["openid", "email", "profile"],
        client_secret_hash=hash_client_secret("test-secret"),
    )
    session.add(oa_client)
    session.commit()
    session.refresh(oa_client)
    return oa_client


def test_authorize_invalid_client_id(client):
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': 'nonexistent',
            'redirect_uri': 'https://example.com/cb',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400
    assert 'Invalid client_id' in res.json()['detail']


def test_authorize_invalid_redirect_uri(session, client):
    oa = _create_test_client(session, "Redirect Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://evil.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400
    assert 'Invalid redirect_uri' in res.json()['detail']


def test_authorize_unsupported_response_type(session, client):
    oa = _create_test_client(session, "Response Type Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'token',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'unsupported_response_type'


def test_authorize_missing_openid_scope(session, client):
    oa = _create_test_client(session, "Scope Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_scope'


def test_authorize_scope_not_allowed(session, client):
    oa = _create_test_client(session, "Scope Limit Test", scopes=["openid"])
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_scope'


def test_authorize_unauthenticated_shows_login(session, client):
    oa = _create_test_client(session, "Login Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    # Should return the login HTML page (200)
    assert res.status_code == 200
    assert 'Sign In' in res.text
    assert 'Login Test' in res.text


def test_authorize_authenticated_shows_consent(session, client):
    oa = _create_test_client(session, "Consent Test")

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert 'Authorize Application' in res.text
    assert 'Consent Test' in res.text

    # Clean up cookies
    client.cookies.clear()


def test_authorize_with_existing_consent_redirects(session, client):
    oa = _create_test_client(session, "Pre-consented Test")

    # Pre-grant consent
    Consent.grant(session, "admin@mcmlln.dev", oa.client_id, ["openid"])

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
            'state': 'mystate123',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'mystate123'

    client.cookies.clear()


def test_authorize_consent_approve(session, client):
    oa = _create_test_client(session, "Approve Consent Test")

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    # Create an oauth2 session with CSRF token
    csrf = 'test-csrf-approve'
    oauth2_sess = OAuth2Session(
        client_id=oa.client_id,
        redirect_uri='https://authtest.example.com/callback',
        response_type='code',
        scope='openid email',
        state='consent-state',
        csrf_token=csrf,
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess.session_id,
            'consent_action': 'approve',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'consent-state'

    client.cookies.clear()


def test_authorize_consent_deny(session, client):
    oa = _create_test_client(session, "Deny Consent Test")

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    csrf = 'test-csrf-deny'
    oauth2_sess = OAuth2Session(
        client_id=oa.client_id,
        redirect_uri='https://authtest.example.com/callback',
        response_type='code',
        scope='openid',
        state='deny-state',
        csrf_token=csrf,
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess.session_id,
            'consent_action': 'deny',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'access_denied'

    client.cookies.clear()


def test_authorize_consent_expired_session(session, client):
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': 'nonexistent-session-id',
            'consent_action': 'approve',
            'csrf_token': 'doesnt-matter',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400

    client.cookies.clear()


def test_authorize_consent_unauthenticated(session, client):
    oa = _create_test_client(session, "Unauth Consent Test")
    csrf = 'test-csrf-unauth'
    oauth2_sess = OAuth2Session(
        client_id=oa.client_id,
        redirect_uri='https://authtest.example.com/callback',
        response_type='code',
        scope='openid',
        csrf_token=csrf,
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    # No cookies set
    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess.session_id,
            'consent_action': 'approve',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 401


def test_authorize_public_client_requires_pkce(session, client):
    oa = OAuthClient(
        client_name="PKCE Required Test",
        redirect_uris=["https://authtest.example.com/callback"],
        allowed_scopes=["openid"],
        is_public=True,
        token_endpoint_auth_method="none",
    )
    session.add(oa)
    session.commit()
    session.refresh(oa)

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa.client_id,
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_request'
    assert 'PKCE' in parsed['error_description'][0]

    client.cookies.clear()
