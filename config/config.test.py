import base64
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://sso:sso@postgres:5432/sso")
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
SMTP_ENDPOINT = 'smtp.email.us-chicago-1.oci.oraclecloud.com'
SMTP_PORT = 587
VERIFY_DELTA = 5 * 60 # 5 minutes
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 # 60 days
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL', 'http://localhost:8081')
VERIFY_DEBUG_ADDR = 'reismcmillan19@gmail.com'
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = 'abcd1234abcd1234abcd1234abcd1234'
ENCRYPT_COOKIE_SEPARATOR = '|'
JWT_EXPIRY = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY_PATH = os.environ.get('JWT_PRIVATE_KEY_PATH')
LOGGING_ENABLED = False
OPENOBSERVE_ENDPOINT = os.environ.get('OPENOBSERVE_ENDPOINT')
_oo_user = os.environ.get('OPENOBSERVE_USER')
_oo_token = os.environ.get('OPENOBSERVE_TOKEN')
OPENOBSERVE_TOKEN = base64.b64encode(f"{_oo_user}:{_oo_token}".encode()).decode() if _oo_user and _oo_token else None