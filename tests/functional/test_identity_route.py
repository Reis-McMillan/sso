from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import jwt

from models import Identity
from utils.jwt import create_signed_jwt


def test_all(admin_jwt, client):
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'}
    )
    assert res.status_code == 200
    assert len(res.json()) == 2


def test_all_no_admin(client, session):
    Identity.new(
        session,
        'abella.danger@pornhub.com',
        'missionary',
        datetime.now(timezone.utc) + timedelta(days=1)
    )
    jwt = create_signed_jwt('abella.danger@pornhub.com', ['default'])
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {jwt}'}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_create(admin_jwt, client):
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    url_safe_email = quote('stewie.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


def test_create_duplicate(admin_jwt, client):
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    assert res.status_code == 400


def test_create_with_expires(admin_jwt, client):
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'peter.griffin@quahog.com', 'expires': expires}
    )
    url_safe_email = quote('peter.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


def test_create_no_admin(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    jwt = create_signed_jwt(id.email, id.roles)
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {jwt}'},
        params={'email': 'louis.griffin@quahog.com'}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_get_admin(admin_jwt, client):
    email = quote('stewie.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    res_json = res.json()
    assert res_json['email'] == 'stewie.griffin@quahog.com'
    assert 'default' in res_json['roles']
    assert len(res_json['roles']) == 1
    assert res_json['closed'] == False


def test_get_not_found(admin_jwt, client):
    email = quote('louis.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'Identity not found'


def test_get_not_admin(client):
    """Test that admin can request their own identity as a JWT"""
    email = quote('admin@mcmlln.dev')
    jwt = create_signed_jwt('jeevacation@gmail.com', roles=['default'])
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_update(admin_jwt, client):
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{email}'


def test_update_no_admin(client, session):
    jwt = create_signed_jwt('jeevacation@gmail.com', roles=['default'])
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_update_no_params(admin_jwt, client):
    """Test that update without any parameters still succeeds (returns current state)"""
    email = quote('stewie.griffin@quahog.com')
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={}
    )
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{email}'


def test_update_no_id(admin_jwt, client):
    email = quote('louis.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'No Identity found.'


def test_delete(admin_jwt, client):
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 204


def test_delete_no_id(admin_jwt, client):
    email = quote('nonexistent@example.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
    assert res.json()['detail'] == "Identity not found"


def test_delete_not_admin(client, session):
    jwt = create_signed_jwt('jeevacation@gmail.com', roles=['default'])
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['detail'] == "Not authorized to perform this action."


def test_logout(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    old_auth_key = id.auth_key
    jwt = create_signed_jwt('stewie.griffin@quahog.com', ['default'])
    res = client.post(
        '/identity/logout',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 201

    session.expire_all()
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    assert id.auth_key != old_auth_key


def test_admin_logout(admin_jwt, client):
    email = quote('stewie.griffin@quahog.com')
    res = client.post(
        f'identity/{email}/logout',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 201


def test_admin_logout_no_id(admin_jwt, client):
    email = quote('peter.griffin@quahog.com')
    res = client.post(
        f'identity/{email}/logout',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404


def test_logout_not_admin(client, session):
    jwt = create_signed_jwt('jeevacation@gmail.com', ['default'])
    email = quote('stewie.griffin@quahog.com')
    res = client.post(
        f'/identity/{email}/logout',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['detail'] == "Not authorized to perform this action."
