"""Handler for membership/member_locked and membership/member_unlocked."""

from email_processor.handlers.base import BaseEventHandler


class MemberLockedHandler(BaseEventHandler):
    """Sends notification when a user's account is locked by an admin."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your account has been locked — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
        }


class MemberUnlockedHandler(BaseEventHandler):
    """Sends notification when a user's account is unlocked by an admin."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your account has been unlocked — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'login_url': payload.get('login_url', 'https://bytescop.com/login'),
        }
