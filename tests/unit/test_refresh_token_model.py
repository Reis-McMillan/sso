from datetime import datetime, timedelta, timezone

from verys.models.refresh_token import RefreshToken


def test_create(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid", "email"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    assert isinstance(rt.id, int)
    assert len(rt.token) == 96  # 48 bytes hex
    assert rt.client_id == "test-client-id"
    assert rt.identity_id == 1
    assert rt.scopes == ["openid", "email"]
    assert rt.revoked == False
    assert rt.replaced_by is None


def test_get_by_token(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    found = RefreshToken.get_by_token(session, rt.token)
    assert found is not None
    assert found.id == rt.id


def test_get_by_token_not_found(session):
    found = RefreshToken.get_by_token(session, "nonexistent-token")
    assert found is None


def test_is_expired(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    assert rt.is_expired() == True


def test_is_not_expired(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    assert rt.is_expired() == False


def test_revoke(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    rt.revoke(session)

    found = RefreshToken.get_by_token(session, rt.token)
    assert found.revoked == True
    assert found.replaced_by is None


def test_revoke_with_replacement(session):
    rt = RefreshToken(
        client_id="test-client-id",
        identity_id=1,
        scopes=["openid"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.refresh(rt)

    rt.revoke(session, replaced_by="new-token-value")

    found = RefreshToken.get_by_token(session, rt.token)
    assert found.revoked == True
    assert found.replaced_by == "new-token-value"


def test_revoke_all_for_user_client(session):
    # Create multiple active tokens
    for _ in range(3):
        rt = RefreshToken(
            client_id="revoke-test-client",
            identity_id=2,
            scopes=["openid"],
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        session.add(rt)
    session.commit()

    RefreshToken.revoke_all_for_user_client(
        session, 2, "revoke-test-client"
    )

    from sqlmodel import select

    tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.identity_id == 2,
            RefreshToken.client_id == "revoke-test-client",
        )
    ).all()
    assert all(t.revoked for t in tokens)
