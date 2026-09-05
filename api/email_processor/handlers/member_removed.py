"""Handler for membership/member_removed — notifies user they were removed from a tenant."""

from email_processor.handlers.base import BaseEventHandler


class MemberRemovedHandler(BaseEventHandler):
    """Sends notification when a user is removed from an organization."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'You have been removed from an organization — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'removed_by': payload.get('removed_by', ''),
        }
