import base64
import os
from urllib.parse import quote_plus

def generate_safe_pg_url(user, password, host, port, db_name):
    """Generates a URL-safe Postgres connection string."""
    safe_password = quote_plus(password)
    return f"postgresql://{user}:{safe_password}@{host}:{port}/{db_name}"

DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_NAME = os.environ.get("DB_NAME")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DATABASE_URL = os.environ.get("DATABASE_URL") or generate_safe_pg_url(
    DB_USER, DB_PASSWORD, DB_HOST, 5432, DB_NAME
)
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
SMTP_ENDPOINT = 'smtp.email.us-chicago-1.oci.oraclecloud.com'
SMTP_PORT = 587
VERIFY_DELTA = 5 * 60 # 5 minutes
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 # 60 days
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL')
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = 'YWJjZDEyMzRhYmNkMTIzNGFiY2QxMjM0YWJjZDEyMzQ='
ENCRYPT_COOKIE_SEPARATOR = '|'
JWT_EXPIRY = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY')
ISSUER = 'http://localhost:8080'
AUTHORIZATION_CODE_TTL = 60  # seconds
REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60  # 30 days
ID_TOKEN_EXPIRY = 5 * 60  # 5 minutes
SUPPORTED_SCOPES = ['openid', 'profile', 'email']
LOGGING_ENABLED = True
OPENOBSERVE_ENDPOINT = os.environ.get('OPENOBSERVE_ENDPOINT')
_oo_user = os.environ.get('OPENOBSERVE_USER')
_oo_token = os.environ.get('OPENOBSERVE_TOKEN')
OPENOBSERVE_TOKEN = base64.b64encode(f"{_oo_user}:{_oo_token}".encode()).decode() if _oo_user and _oo_token else None
