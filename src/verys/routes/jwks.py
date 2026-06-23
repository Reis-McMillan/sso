import base64

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from verys.modules.jwt import _get_private_key, _get_kid


async def jwks(request: Request):
    public_key = _get_private_key().public_key()
    raw = public_key.public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "use": "sig",
        "alg": "EdDSA",
        "kid": _get_kid(),
    }
    return JSONResponse({"keys": [jwk]})


routes = [
    Route("/.well-known/jwks.json", jwks, methods=["GET"]),
]
