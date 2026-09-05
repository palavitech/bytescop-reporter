"""Handlers for tenant closure email events."""

import logging

from email_processor.handlers.base import BaseEventHandler

logger = logging.getLogger(__name__)


class ClosureConfirmHandler(BaseEventHandler):
    """Handles closure_confirm — sends confirmation code to tenant owner."""

    def get_recipient(self, payload: dict) -> str:
        return payload.get('email', '')

    def get_subject(self, payload: dict) -> str:
        return 'Confirm tenant closure — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'confirmation_code': payload.get('confirmation_code', ''),
            'data_export_choice': payload.get('data_export_choice', ''),
        }


class ClosureExecuteHandler(BaseEventHandler):
    """Handles closure_execute — notifies owner that closure is in progress."""

    def get_recipient(self, payload: dict) -> str:
        return payload.get('email', '')

    def get_subject(self, payload: dict) -> str:
        return 'Tenant closure in progress — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'confirmation_code': payload.get('confirmation_code', ''),
            'data_export_choice': payload.get('data_export_choice', ''),
        }


class ClosurePurgedHandler(BaseEventHandler):
    """Handles closure_purged — final deletion receipt."""

    def get_recipient(self, payload: dict) -> str:
        return payload.get('email', '')

    def get_subject(self, payload: dict) -> str:
        return 'Your tenant has been permanently deleted — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'closed_date': payload.get('closed_date', ''),
            'data_export_choice': payload.get('data_export_choice', ''),
        }
