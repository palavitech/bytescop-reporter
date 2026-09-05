"""Handler for account/password_changed — notifies user their password was changed."""

from email_processor.handlers.base import BaseEventHandler


class PasswordChangedHandler(BaseEventHandler):
    """Sends a security notification when a user changes their password."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your password was changed — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
        }
