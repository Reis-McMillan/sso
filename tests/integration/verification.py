"""Integration test for verification email delivery.

Not prefixed with test_ to prevent automatic pytest discovery.
Run directly: python tests/integration/verification.py

Requires USERNAME_SMTP and PASSWORD_SMTP environment variables to be set.
"""
import asyncio
import aiosmtplib
from email.message import EmailMessage

from config import config


async def test_email():
    message = EmailMessage()
    message['Subject'] = 'SSO Integration Test - Email Delivery'
    message['From'] = config.VERIFY_FROM_ADDR
    message['To'] = config.VERIFY_DEBUG_ADDR
    message.set_content(
        'This is a test email from the SSO integration test suite.\n'
        'If you are receiving this, email delivery is working correctly.'
    )

    response = await aiosmtplib.send(
        message,
        hostname=config.SMTP_ENDPOINT,
        port=config.SMTP_PORT,
        username=config.USERNAME_SMTP,
        password=config.PASSWORD_SMTP,
        start_tls=True,
    )
    print(f'Email delivered successfully to {config.VERIFY_DEBUG_ADDR}')
    print(f'Server response: {response}')


if __name__ == '__main__':
    asyncio.run(test_email())
