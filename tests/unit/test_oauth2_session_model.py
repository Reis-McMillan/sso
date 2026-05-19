from datetime import datetime, timedelta, timezone

from verys.models.oauth2_session import OAuth2Session, OAUTH2_SESSION_TTL


def test_create(session):
    oauth2_sess = OAuth2Session(
        client_id="session-test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid email",
        state="random-state",
        nonce="random-nonce",
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    assert isinstance(oauth2_sess.id, int)
    assert len(oauth2_sess.session_id) > 0
    assert oauth2_sess.client_id == "session-test-client"
    assert oauth2_sess.scope == "openid email"
    assert oauth2_sess.state == "random-state"
    assert oauth2_sess.nonce == "random-nonce"


def test_get_by_session_id(session):
    oauth2_sess = OAuth2Session(
        client_id="lookup-test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid",
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    found = OAuth2Session.get_by_session_id(session, oauth2_sess.session_id)
    assert found is not None
    assert found.id == oauth2_sess.id


def test_get_by_session_id_not_found(session):
    found = OAuth2Session.get_by_session_id(session, "nonexistent-session")
    assert found is None


def test_is_not_expired(session):
    oauth2_sess = OAuth2Session(
        client_id="test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid",
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    assert oauth2_sess.is_expired() == False


def test_is_expired(session):
    oauth2_sess = OAuth2Session(
        client_id="test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid",
        created_at=datetime.now(timezone.utc) - timedelta(seconds=OAUTH2_SESSION_TTL + 1),
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    assert oauth2_sess.is_expired() == True


def test_with_pkce(session):
    oauth2_sess = OAuth2Session(
        client_id="pkce-test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid",
        code_challenge="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        code_challenge_method="S256",
    )
    session.add(oauth2_sess)
    session.commit()
    session.refresh(oauth2_sess)

    assert oauth2_sess.code_challenge == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert oauth2_sess.code_challenge_method == "S256"


def test_cleanup_expired(session):
    # Create an expired session
    expired = OAuth2Session(
        client_id="cleanup-test-client",
        redirect_uri="https://example.com/callback",
        response_type="code",
        scope="openid",
        created_at=datetime.now(timezone.utc) - timedelta(seconds=OAUTH2_SESSION_TTL + 60),
    )
    session.add(expired)
    session.commit()
    session.refresh(expired)
    expired_id = expired.session_id

    OAuth2Session.cleanup_expired(session)

    found = OAuth2Session.get_by_session_id(session, expired_id)
    assert found is None
