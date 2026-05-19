import sys
import hmac
import hashlib
import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

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


def _compute_hmac(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(key, iv + ciphertext, hashlib.sha256).digest()


# to be honest the benefit of encrypting an auth key
# is very marginal... this in no way stops a replay
# attack... it just hides the plaintext identity and 
# auth_key
def encrypt_cookie(email: str, auth_key: str) -> tuple[str, str]:
    payload = f"{email}{config.ENCRYPT_COOKIE_SEPARATOR}{auth_key}"
    key = base64.b64decode(config.ENCRYPT_COOKIE_KEY)
    iv = secrets.token_bytes(BLOCK_SIZE)

    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ct = encryptor.update(_pkcs7_pad(payload.encode())) + encryptor.finalize()

    # HMAC over IV + ciphertext for integrity verification
    mac = _compute_hmac(key, iv, ct)
    signed_ct = ct + mac

    return binascii.hexlify(signed_ct).decode(), binascii.hexlify(iv).decode()


def decrypt_cookie(cookie_payload: str, init_vector: str) -> dict:
    key = base64.b64decode(config.ENCRYPT_COOKIE_KEY)
    iv = binascii.unhexlify(init_vector)
    raw = binascii.unhexlify(cookie_payload)

    # Split ciphertext and HMAC (last 32 bytes = SHA-256 digest)
    if len(raw) < 32:
        raise ValueError("Token too short")
    ct, received_mac = raw[:-32], raw[-32:]

    # Verify HMAC before decrypting (constant-time comparison)
    expected_mac = _compute_hmac(key, iv, ct)
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("Token integrity check failed")

    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = _pkcs7_unpad(decryptor.update(ct) + decryptor.finalize()).decode('utf-8')

    parts = decrypted.split(config.ENCRYPT_COOKIE_SEPARATOR)
    if len(parts) != 2:
        raise ValueError('Token Decryption failed: length not equal to 2.')

    return {"email": parts[0], "auth_key": parts[1]}

def print_help():
    content = f"""
    cookie_util.py is a utility for encrypting or decrypting HTTP cookie payloads 
    as they are represented in a "X-Auth-Token" header value.
    
    Available arguments:
        decrypt <hex encoded HTTP COOKIE> <init vector>
        encrypt <email> <auth token>
        help - prints this message.
    """
    print(content)

def parse_args():
    args = sys.argv
    if len(args) < 2 or args[1] not in ['encrypt', 'decrypt', 'help']:
        if len(args) > 1:
            print(f"'{args[1]}' is not a valid argument.\n")
        print_help()
        return

    cmd = args[1]

    if cmd == 'encrypt':
        if len(args) != 4:
            print("Missing email and or token arguments.\n")
            print_help()
        else:
            print(encrypt_cookie(args[2], args[3]))

    elif cmd == 'decrypt':
        if len(args) != 4:
            print("Missing encrypted cookie value or init vector.\n")
            print_help()
        else:
            print(decrypt_cookie(args[2], args[3]))

    elif cmd == 'help':
        print_help()

if __name__ == "__main__":
    parse_args()