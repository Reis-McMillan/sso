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
DATABASE_URL = generate_safe_pg_url(
    DB_USER, DB_PASSWORD, DB_HOST, 5432, DB_NAME
)
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
EMAIL_HOST = 'smtp.us-chicago-1.oraclecloud.com'
EMAIL_PORT = 465
VERIFY_DELTA = 5 * 60 # 5 minutes
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 # 60 days
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL')
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = os.environ.get('ENCRYPT_COOKIE_KEY')
ENCRYPT_COOKIE_SEPARATOR = '|'
JWT_EXPIRY = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY_PATH = os.environ.get('JWT_PRIVATE_KEY_PATH')