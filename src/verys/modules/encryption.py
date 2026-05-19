import hmac
import hashlib
import binascii
import base64
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from verys.config import config

BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _get_key() -> bytes:
    return base64.b64decode(config.FIELD_ENCRYPTION_KEY)


def _compute_hmac(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(key, iv + ciphertext, hashlib.sha256).digest()


def encrypt_field(plaintext: str) -> str:
    """Encrypt a string field using AES-256-CBC with HMAC-SHA256 integrity.

    Returns a single hex-encoded string containing IV + ciphertext + HMAC.
    """
    key = _get_key()
    iv = secrets.token_bytes(BLOCK_SIZE)

    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(_pkcs7_pad(plaintext.encode("utf-8"))) + encryptor.finalize()

    mac = _compute_hmac(key, iv, ct)

    # Pack as: IV (16) + ciphertext (variable) + HMAC (32)
    packed = iv + ct + mac
    return binascii.hexlify(packed).decode()


def decrypt_field(encrypted: str) -> str:
    """Decrypt a hex-encoded field produced by encrypt_field().

    Verifies HMAC integrity before decrypting.
    """
    key = _get_key()
    raw = binascii.unhexlify(encrypted)

    # Minimum size: 16 (IV) + 16 (at least one block) + 32 (HMAC)
    if len(raw) < 64:
        raise ValueError("Encrypted field too short")

    iv = raw[:BLOCK_SIZE]
    mac = raw[-32:]
    ct = raw[BLOCK_SIZE:-32]

    # Verify HMAC before decrypting (constant-time comparison)
    expected_mac = _compute_hmac(key, iv, ct)
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("Field integrity check failed")

    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = _pkcs7_unpad(decryptor.update(ct) + decryptor.finalize())
    return plaintext.decode("utf-8")
