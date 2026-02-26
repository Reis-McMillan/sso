def test_jwks(client):
    res = client.get('/.well-known/jwks.json')
    assert res.status_code == 200
    body = res.json()
    assert 'keys' in body
    assert len(body['keys']) == 1
    key = body['keys'][0]
    assert key['kty'] == 'OKP'
    assert key['crv'] == 'Ed25519'
    assert key['use'] == 'sig'
    assert key['alg'] == 'EdDSA'
    assert 'x' in key
