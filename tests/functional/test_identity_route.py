from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from config import config
from models import Identity
from utils.cookie import encrypt_cookie, decrypt_cookie


def test_all(admin_creds, client):
    token, iv = admin_creds
    res = client.get(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
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
    token, iv = encrypt_cookie('abella.danger@pornhub.com', 'missionary')
    res = client.get(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_create(admin_creds, client):
    token, iv = admin_creds
    res = client.post(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    url_safe_email = quote('stewie.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


def test_create_duplicate(admin_creds, client):
    token, iv = admin_creds
    res = client.post(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    assert res.status_code == 400


def test_create_with_expires(admin_creds, client):
    token, iv = admin_creds
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.post(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'email': 'peter.griffin@quahog.com', 'expires': expires}
    )
    url_safe_email = quote('peter.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


def test_create_no_admin(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    res = client.post(
        '/identity',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'email': 'louis.griffin@quahog.com'}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_get_admin(admin_creds, client):
    token, iv = admin_creds
    email = quote('stewie.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 200
    res_json = res.json()
    assert res_json['email'] == 'stewie.griffin@quahog.com'
    assert 'default' in res_json['roles']
    assert len(res_json['roles']) == 1
    assert res_json['closed'] == False


def test_get_admin_not_found(admin_creds, client):
    token, iv = admin_creds
    email = quote('louis.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'Identity not found'


def test_get_self(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    email = quote('stewie.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 200


def test_get_other_user(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    email = quote('peter.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_get_service_user_other(client):
    token, iv = encrypt_cookie('service@mcmlln.dev', 'jd vance erika kirk baby')
    email = quote('stewie.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_update(admin_creds, client):
    token, iv = admin_creds
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'expires': expires}
    )
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{email}'


def test_update_no_admin(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'expires': expires}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == 'Not authorized to perform this action.'


def test_update_no_expires(admin_creds, client):
    token, iv = admin_creds
    email = quote('stewie.griffin@quahog.com')
    res = client.put(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 422


def test_update_no_id(admin_creds, client):
    token, iv = admin_creds
    email = quote('louis.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv},
        params={'expires': expires}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == 'No Identity found.'


def test_delete(admin_creds, client):
    token, iv = admin_creds
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 204


def test_delete_no_id(admin_creds, client):
    token, iv = admin_creds
    email = quote('nonexistent@example.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 404
    assert res.json()['detail'] == "Identity not found"


def test_delete_not_admin(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == "Not authorized to perform this action."


def test_cookie(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    res = client.get(
        '/identity/cookie',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 200


def test_logout(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    old_auth_key = id.auth_key
    token, iv = encrypt_cookie(id.email, id.auth_key)
    res = client.post(
        '/identity/logout',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 201

    session.expire_all()
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    assert id.auth_key != old_auth_key


def test_admin_logout(admin_creds, client):
    token, iv = admin_creds
    email = quote('stewie.griffin@quahog.com')
    res = client.post(
        f'identity/{email}/logout',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 201


def test_admin_logout_no_id(admin_creds, client):
    token, iv = admin_creds
    email = quote('peter.griffin@quahog.com')
    res = client.post(
        f'identity/{email}/logout',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 404


def test_logout_not_admin(client, session):
    id = Identity.get(session, 'stewie.griffin@quahog.com')
    token, iv = encrypt_cookie(id.email, id.auth_key)
    email = quote('stewie.griffin@quahog.com')
    res = client.post(
        f'/identity/{email}/logout',
        headers={'X-Auth-Token': token, 'X-Init-Vector': iv}
    )
    assert res.status_code == 403
    assert res.json()['detail'] == "Not authorized to perform this action."
