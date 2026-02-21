import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

from config import config

_private_key = None


def _get_private_key():
    global _private_key
    if _private_key is None:
        with open(config.JWT_PRIVATE_KEY_PATH, "rb") as f:
            _private_key = load_pem_private_key(f.read(), password=None)
    return _private_key


def get_public_key_pem() -> str:
    return _get_private_key().public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


def create_signed_jwt(email: str, roles: list[str]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "roles": roles,
        "iat": now,
        "exp": now + timedelta(seconds=config.JWT_EXPIRY),
    }
    return jwt.encode(payload, _get_private_key(), algorithm="EdDSA")
