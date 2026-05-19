from datetime import datetime, timedelta, timezone

from verys.models.authorization_code import AuthorizationCode


def test_create(session):
    now = datetime.now(timezone.utc)
    code = AuthorizationCode(
        client_id="test-client-id",
        identity_email="user@example.com",
        redirect_uri="https://example.com/callback",
        scopes=["openid", "email"],
        nonce="test-nonce",
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
    )
    session.add(code)
    session.commit()
    session.refresh(code)

    assert isinstance(code.id, int)
    assert len(code.code) == 64  # 32 bytes hex
    assert code.client_id == "test-client-id"
    assert code.identity_email == "user@example.com"
    assert code.scopes == ["openid", "email"]
    assert code.nonce == "test-nonce"
    assert code.used == False


def test_get_by_code(session):
    codes = session.exec(
        __import__('sqlmodel', fromlist=['select']).select(AuthorizationCode)
    ).all()
    first = codes[0]

    found = AuthorizationCode.get_by_code(session, first.code)
    assert found is not None
    assert found.id == first.id


def test_get_by_code_not_found(session):
    found = AuthorizationCode.get_by_code(session, "nonexistent-code")
    assert found is None


def test_is_expired(session):
    now = datetime.now(timezone.utc)
    code = AuthorizationCode(
        client_id="test-client-id",
        identity_email="user@example.com",
        redirect_uri="https://example.com/callback",
        auth_time=now,
        expires_at=now - timedelta(seconds=10),
    )
    session.add(code)
    session.commit()
    session.refresh(code)

    assert code.is_expired() == True


def test_is_not_expired(session):
    now = datetime.now(timezone.utc)
    code = AuthorizationCode(
        client_id="test-client-id",
        identity_email="user@example.com",
        redirect_uri="https://example.com/callback",
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
    )
    session.add(code)
    session.commit()
    session.refresh(code)

    assert code.is_expired() == False


def test_mark_used(session):
    now = datetime.now(timezone.utc)
    code = AuthorizationCode(
        client_id="test-client-id",
        identity_email="user@example.com",
        redirect_uri="https://example.com/callback",
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
    )
    session.add(code)
    session.commit()
    session.refresh(code)

    assert code.used == False
    code.mark_used(session)

    found = AuthorizationCode.get_by_code(session, code.code)
    assert found.used == True


def test_with_pkce(session):
    now = datetime.now(timezone.utc)
    code = AuthorizationCode(
        client_id="test-client-id",
        identity_email="user@example.com",
        redirect_uri="https://example.com/callback",
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method="S256",
    )
    session.add(code)
    session.commit()
    session.refresh(code)

    assert code.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert code.code_challenge_method == "S256"
