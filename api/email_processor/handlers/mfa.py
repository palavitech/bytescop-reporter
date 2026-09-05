"""Handlers for account/mfa_* events — MFA lifecycle email notifications."""

from email_processor.handlers.base import BaseEventHandler


class MfaEnrolledHandler(BaseEventHandler):
    """User has enrolled (or re-enrolled after forced setup) MFA."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'MFA has been enabled on your account — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
        }


class MfaDisabledHandler(BaseEventHandler):
    """User has disabled their own MFA (self-service)."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'MFA has been disabled on your account — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
        }


class MfaDeviceChangedHandler(BaseEventHandler):
    """User has changed their authenticator device."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your MFA device has been changed — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
        }


class MfaBackupCodesRegeneratedHandler(BaseEventHandler):
    """User has regenerated their backup codes."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your MFA backup codes have been regenerated — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
        }


class MfaResetByAdminHandler(BaseEventHandler):
    """An admin has reset the user's MFA."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        return 'Your MFA has been reset by an administrator — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'admin_name': payload.get('admin_name', 'An administrator'),
            'admin_email': payload.get('admin_email', ''),
        }
