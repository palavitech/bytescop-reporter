"""Handler for account/welcome — sends a welcome email after signup or invite acceptance."""

import os

from email_processor.handlers.base import BaseEventHandler

APP_URL = os.environ.get('APP_URL', 'https://bytescop.com')


class WelcomeHandler(BaseEventHandler):
    """Sends a warm welcome email when a user completes onboarding."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Welcome to BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'login_url': f'{APP_URL}/login',
        }
