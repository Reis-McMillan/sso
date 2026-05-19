import base64
import hashlib


def verify_code_challenge(
    code_verifier: str, code_challenge: str, method: str
) -> bool:
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge
