from verys.config import config


def test_openid_configuration(client):
    res = client.get('/.well-known/openid-configuration')
    assert res.status_code == 200
    body = res.json()

    assert body['issuer'] == config.ISSUER
    assert body['authorization_endpoint'] == f'{config.ISSUER}/authorize'
    assert body['token_endpoint'] == f'{config.ISSUER}/token'
    assert body['userinfo_endpoint'] == f'{config.ISSUER}/userinfo'
    assert body['jwks_uri'] == f'{config.ISSUER}/.well-known/jwks.json'
    assert body['end_session_endpoint'] == f'{config.ISSUER}/end-session'
    assert body['revocation_endpoint'] == f'{config.ISSUER}/token/revoke'


def test_scopes_supported(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert 'openid' in body['scopes_supported']
    assert 'email' in body['scopes_supported']
    assert 'profile' in body['scopes_supported']


def test_response_types_supported(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert body['response_types_supported'] == ['code']


def test_grant_types_supported(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert 'authorization_code' in body['grant_types_supported']
    assert 'refresh_token' in body['grant_types_supported']


def test_signing_alg(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert body['id_token_signing_alg_values_supported'] == ['EdDSA']


def test_code_challenge_methods(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert body['code_challenge_methods_supported'] == ['S256']


def test_claims_supported(client):
    body = client.get('/.well-known/openid-configuration').json()
    required_claims = ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email']
    for claim in required_claims:
        assert claim in body['claims_supported']
