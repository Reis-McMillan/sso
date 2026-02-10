import os

DATABASE_URL = 'postgresql://sso:sso@localhost:5432/sso'
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
EMAIL_HOST = 'smtp.us-chicago-1.oraclecloud.com'
EMAIL_PORT = 465
VERIFY_DELTA = 5 * 60 * 1000 # 5 minutes in milliseconds
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 * 1000 # 60 days milliseconds
RUN_VERIFY_EXPIRED = False
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL', 'http://localhost:8000')
VERIFY_DEBUG_ADDR = 'reismcmillan19@gmail.com'
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = 'abcd1234abcd1234abcd1234abcd1234'
ENCRYPT_COOKIE_SEPARATOR = '|'
JWT_EXPIRY_SECONDS = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY_PATH = os.environ.get('JWT_PRIVATE_KEY_PATH')