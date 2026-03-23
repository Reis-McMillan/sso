from datetime import datetime, timezone

from models.oauth2_client import OAuthClient


def test_create(session):
    client = OAuthClient(
        client_name="Test App",
        redirect_uris=["https://example.com/callback"],
        allowed_scopes=["openid", "email"],
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    assert isinstance(client.id, int)
    assert len(client.client_id) > 0
    assert client.client_name == "Test App"
    assert client.redirect_uris == ["https://example.com/callback"]
    assert client.allowed_scopes == ["openid", "email"]
    assert client.grant_types == ["authorization_code", "refresh_token"]
    assert client.response_types == ["code"]
    assert client.token_endpoint_auth_method == "client_secret_basic"
    assert client.is_public == False
    assert client.created_at <= datetime.now(timezone.utc)


def test_get_by_client_id(session):
    clients = OAuthClient.all(session)
    first = clients[0]

    found = OAuthClient.get_by_client_id(session, first.client_id)
    assert found is not None
    assert found.id == first.id
    assert found.client_name == first.client_name


def test_get_by_client_id_not_found(session):
    found = OAuthClient.get_by_client_id(session, "nonexistent-id")
    assert found is None


def test_all(session):
    clients = OAuthClient.all(session)
    assert len(clients) >= 1


def test_create_public_client(session):
    client = OAuthClient(
        client_name="Public SPA",
        redirect_uris=["http://localhost:3000/callback"],
        is_public=True,
        token_endpoint_auth_method="none",
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    assert client.is_public == True
    assert client.token_endpoint_auth_method == "none"
    assert client.client_secret_hash is None


def test_create_with_owner(session):
    client = OAuthClient(
        client_name="Owned App",
        redirect_uris=["https://owned.example.com/cb"],
        owner_email="admin@mcmlln.dev",
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    assert client.owner_email == "admin@mcmlln.dev"


def test_multiple_redirect_uris(session):
    client = OAuthClient(
        client_name="Multi Redirect",
        redirect_uris=[
            "https://app.example.com/callback",
            "https://app.example.com/auth/callback",
        ],
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    assert len(client.redirect_uris) == 2


def test_default_scopes(session):
    client = OAuthClient(
        client_name="Default Scopes App",
        redirect_uris=["https://default.example.com/cb"],
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    assert client.allowed_scopes == ["openid"]
