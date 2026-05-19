from datetime import datetime, timezone

from verys.models.consent import Consent


def test_grant(session):
    consent = Consent.grant(
        session,
        identity_email="consent@example.com",
        client_id="consent-test-client",
        scopes=["openid", "email"],
    )

    assert isinstance(consent.id, int)
    assert consent.identity_email == "consent@example.com"
    assert consent.client_id == "consent-test-client"
    assert consent.scopes == ["openid", "email"]
    assert consent.granted_at <= datetime.now(timezone.utc)


def test_get(session):
    found = Consent.get(session, "consent@example.com", "consent-test-client")
    assert found is not None
    assert found.scopes == ["openid", "email"]


def test_get_not_found(session):
    found = Consent.get(session, "nobody@example.com", "no-client")
    assert found is None


def test_covers_scopes(session):
    consent = Consent.get(session, "consent@example.com", "consent-test-client")
    assert consent.covers_scopes(["openid"]) == True
    assert consent.covers_scopes(["openid", "email"]) == True
    assert consent.covers_scopes(["openid", "profile"]) == False


def test_grant_updates_existing(session):
    # Grant with new scopes should update the existing record
    consent = Consent.grant(
        session,
        identity_email="consent@example.com",
        client_id="consent-test-client",
        scopes=["openid", "email", "profile"],
    )

    assert consent.scopes == ["openid", "email", "profile"]

    # Verify only one record exists
    found = Consent.get(session, "consent@example.com", "consent-test-client")
    assert found.id == consent.id
    assert found.scopes == ["openid", "email", "profile"]


def test_multiple_clients(session):
    Consent.grant(
        session,
        identity_email="consent@example.com",
        client_id="another-client",
        scopes=["openid"],
    )

    c1 = Consent.get(session, "consent@example.com", "consent-test-client")
    c2 = Consent.get(session, "consent@example.com", "another-client")

    assert c1 is not None
    assert c2 is not None
    assert c1.id != c2.id
