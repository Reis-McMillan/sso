from utils.jwt import create_signed_jwt


def test_create_client(admin_jwt, client):
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Test OIDC App',
            'redirect_uris': ['https://testapp.example.com/callback'],
            'allowed_scopes': ['openid', 'email', 'profile'],
        }
    )
    assert res.status_code == 201
    body = res.json()
    assert 'client_id' in body
    assert 'client_secret' in body
    assert body['client_name'] == 'Test OIDC App'
    assert body['redirect_uris'] == ['https://testapp.example.com/callback']
    assert body['allowed_scopes'] == ['openid', 'email', 'profile']
    assert body['is_public'] == False


def test_create_public_client(admin_jwt, client):
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Public SPA',
            'redirect_uris': ['http://localhost:3000/callback'],
            'is_public': True,
            'token_endpoint_auth_method': 'none',
        }
    )
    assert res.status_code == 201
    body = res.json()
    assert 'client_secret' not in body
    assert body['is_public'] == True


def test_create_client_no_admin(client, session):
    from models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {jwt}'},
        json={
            'client_name': 'Unauthorized App',
            'redirect_uris': ['https://bad.example.com/cb'],
        }
    )
    assert res.status_code == 403


def test_list_clients(admin_jwt, client):
    res = client.get(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body, list)
    assert len(body) >= 2  # created in previous tests


def test_list_clients_no_admin(client, session):
    from models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.get(
        '/clients/',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403


def test_get_client(admin_jwt, client):
    # First create one to get a known client_id
    create_res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Get Test App',
            'redirect_uris': ['https://get.example.com/cb'],
        }
    )
    client_id = create_res.json()['client_id']

    res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['client_id'] == client_id
    assert body['client_name'] == 'Get Test App'
    assert 'client_secret' not in body  # secret should never be returned


def test_get_client_not_found(admin_jwt, client):
    res = client.get(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404


def test_update_client(admin_jwt, client):
    # Create a client
    create_res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Update Test App',
            'redirect_uris': ['https://update.example.com/cb'],
        }
    )
    client_id = create_res.json()['client_id']

    res = client.put(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Updated App Name',
            'redirect_uris': ['https://updated.example.com/cb', 'https://updated2.example.com/cb'],
        }
    )
    assert res.status_code == 200

    # Verify update
    get_res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    body = get_res.json()
    assert body['client_name'] == 'Updated App Name'
    assert len(body['redirect_uris']) == 2


def test_update_client_not_found(admin_jwt, client):
    res = client.put(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'client_name': 'Nope'}
    )
    assert res.status_code == 404


def test_delete_client(admin_jwt, client):
    # Create a client to delete
    create_res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Delete Me',
            'redirect_uris': ['https://delete.example.com/cb'],
        }
    )
    client_id = create_res.json()['client_id']

    res = client.delete(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200

    # Verify deleted
    get_res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert get_res.status_code == 404


def test_delete_client_not_found(admin_jwt, client):
    res = client.delete(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
