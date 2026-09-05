"""Handlers for membership area events."""

import os

from email_processor.handlers.base import BaseEventHandler

APP_URL = os.environ.get('APP_URL', 'https://bytescop.com')


class MemberCreatedHandler(BaseEventHandler):
    """Handles member_created — sends invite email to the new user."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return "You've been invited to BytesCop-Reporter"

    def get_template_data(self, payload: dict) -> dict:
        token = payload.get('invite_token', '')
        invite_link = f'{APP_URL}/accept-invite?token={token}' if token else ''
        return {
            'email': payload['email'],
            'name': payload.get('name', ''),
            'tenant_id': payload.get('tenant_id', ''),
            'user_id': payload.get('user_id', ''),
            'invite_link': invite_link,
            'tenant_name': payload.get('tenant_name', ''),
        }


class MemberPromotedHandler(BaseEventHandler):
    """Handles member_promoted — notifies user they've been promoted to Owner."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        tenant = payload.get('tenant_name', 'BytesCop-Reporter')
        return f"You've been promoted to Owner \u2014 {tenant}"

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'email': payload.get('email', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'promoted_by': payload.get('promoted_by', ''),
        }


class MemberDemotedHandler(BaseEventHandler):
    """Handles member_demoted — notifies user their role changed from Owner to Member."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        tenant = payload.get('tenant_name', 'BytesCop-Reporter')
        return f"Your role has changed \u2014 {tenant}"

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'email': payload.get('email', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'demoted_by': payload.get('demoted_by', ''),
        }
