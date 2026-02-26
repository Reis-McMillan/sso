from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import base64

from utils.jwt import _get_private_key

router = APIRouter(tags=["JWKS"])


@router.get("/.well-known/jwks.json")
async def jwks():
    public_key = _get_private_key().public_key()
    raw = public_key.public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "use": "sig",
        "alg": "EdDSA",
    }
    return JSONResponse({"keys": [jwk]})
