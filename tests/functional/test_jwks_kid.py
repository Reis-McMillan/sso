def test_jwks_has_kid(client):
    res = client.get('/.well-known/jwks.json')
    assert res.status_code == 200
    body = res.json()
    key = body['keys'][0]
    assert 'kid' in key
    assert len(key['kid']) > 0
