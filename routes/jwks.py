from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

from utils.jwt import _get_private_key

router = APIRouter(tags=["JWKS"])


@router.get("/.well-known/jwks.json")
async def jwks(request: Request = None):
    if (not "admin" in request.state.auth_cache.roles
        or not "service-account" in request.state.auth_cache.roles):
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

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
