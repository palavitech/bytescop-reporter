"""Handler for account/forgot_password — sends password reset link."""

import os

from email_processor.handlers.base import BaseEventHandler

APP_URL = os.environ.get('APP_URL', 'https://bytescop.com')


class ForgotPasswordHandler(BaseEventHandler):
    """Sends the password reset link for self-service forgot password."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Reset your password — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        token = payload.get('reset_token', '')
        reset_url = f'{APP_URL}/reset-password?token={token}' if token else ''
        return {
            'name': payload.get('name', ''),
            'reset_url': reset_url,
            'mfa_enabled': payload.get('mfa_enabled', False),
        }
