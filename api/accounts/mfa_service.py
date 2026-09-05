"""Core TOTP MFA logic: enroll, confirm, verify, disable, backup codes."""

import base64
import hashlib
import io
import logging
import secrets

import pyotp
import qrcode  # type: ignore[import-untyped]
from django.utils import timezone

from .mfa_crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger("bytescop.mfa")

ISSUER_NAME = "BytesCop-Reporter"
BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 8  # hex chars


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Return a new random base32 TOTP secret."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, email: str) -> str:
    """Build an ``otpauth://`` URI for authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=ISSUER_NAME)


def generate_qr_code_base64(uri: str) -> str:
    """Render a QR code as a base64 PNG data URI."""
    img = qrcode.make(uri, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def verify_totp_code(secret: str, code: str, user=None) -> bool:
    """Verify a 6-digit TOTP code (±1 window) with replay prevention.

    If *user* is provided, rejects codes whose time counter has already
    been used (stored in ``user.last_totp_at``).
    """
    import time
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return False

    # Replay prevention: reject if this time counter was already used
    current_counter = int(time.time()) // totp.interval
    if user is not None:
        if user.last_totp_at is not None and current_counter <= user.last_totp_at:
            return False
        user.last_totp_at = current_counter
        user.save(update_fields=["last_totp_at"])
    return True


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------

def generate_backup_codes() -> list[str]:
    """Generate a list of plaintext single-use recovery codes."""
    return [secrets.token_hex(BACKUP_CODE_LENGTH // 2) for _ in range(BACKUP_CODE_COUNT)]


def hash_backup_code(code: str) -> str:
    """PBKDF2-HMAC-SHA256 hash a backup code with a random salt.

    Returns ``salt$hash`` (both hex-encoded).
    """
    normalized = code.strip().lower().encode()
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", normalized, salt, iterations=600_000)
    return f"{salt.hex()}${dk.hex()}"


def _verify_backup_hash(code: str, stored: str) -> bool:
    """Check a code against a stored hash (salted or legacy unsalted)."""
    normalized = code.strip().lower().encode()
    if "$" in stored:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", normalized, salt, iterations=600_000)
        return secrets.compare_digest(dk.hex(), hash_hex)
    # Legacy unsalted SHA-256 fallback
    return secrets.compare_digest(
        hashlib.sha256(normalized).hexdigest(), stored
    )


def verify_and_consume_backup_code(user, code: str) -> bool:
    """Check a backup code against stored hashes; consume on match."""
    codes = list(user.mfa_backup_codes)
    for i, stored in enumerate(codes):
        if _verify_backup_hash(code, stored):
            codes.pop(i)
            user.mfa_backup_codes = codes
            user.save(update_fields=["mfa_backup_codes"])
            return True
    return False


# ---------------------------------------------------------------------------
# MFA event publishing
# ---------------------------------------------------------------------------

def publish_mfa_event(
    event_type: str,
    user,
    tenant=None,
    *,
    triggered_by: str = "self",
    admin_user=None,
) -> None:
    """Publish an MFA notification event to SNS.

    Args:
        event_type: One of mfa_enrolled, mfa_disabled, mfa_device_changed,
                    mfa_backup_codes_regenerated, mfa_reset_by_admin.
        user: The user whose MFA was affected.
        tenant: The tenant context (optional, used for tenant_name).
        triggered_by: "self" or "admin".
        admin_user: The admin User who performed the action (when triggered_by="admin").
    """
    from events.publisher import get_event_publisher

    payload = {
        "routing": ["notification"],
        "event_area": "account",
        "event_type": event_type,
        "tenant_id": str(tenant.pk) if tenant else "",
        "tenant_name": tenant.name if tenant else "",
        "user_id": str(user.pk),
        "email": user.email,
        "name": user.first_name or user.email,
        "triggered_by": triggered_by,
        "version": "1",
    }
    if admin_user:
        payload["admin_name"] = admin_user.get_full_name() or admin_user.email
        payload["admin_email"] = admin_user.email

    get_event_publisher().publish(payload)
    logger.info(
        "MFA event published: type=%s user=%s triggered_by=%s",
        event_type, user.pk, triggered_by,
    )


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def enroll_mfa(user) -> dict:
    """Start MFA enrollment: generate secret + QR + backup codes.

    Returns a dict with ``secret``, ``qr_code``, and ``backup_codes``
    (all plaintext, for one-time display to the user).
    The encrypted secret and hashed backup codes are persisted on the user
    but ``mfa_enabled`` stays False until ``confirm_enrollment()``.
    """
    secret = generate_totp_secret()
    uri = get_provisioning_uri(secret, user.email)
    qr = generate_qr_code_base64(uri)
    codes = generate_backup_codes()

    user.mfa_secret = encrypt_secret(secret)
    user.mfa_backup_codes = [hash_backup_code(c) for c in codes]
    user.save(update_fields=["mfa_secret", "mfa_backup_codes"])

    return {
        "secret": secret,
        "qr_code": qr,
        "backup_codes": codes,
    }


def confirm_enrollment(user, code: str) -> bool:
    """Verify the first TOTP code and activate MFA.

    Returns True on success, False if the code is invalid.
    """
    if not user.mfa_secret:
        return False

    secret = decrypt_secret(user.mfa_secret)
    if not verify_totp_code(secret, code):
        return False

    user.mfa_enabled = True
    user.mfa_enrolled_at = timezone.now()
    user.last_totp_at = None  # reset so first login verify isn't blocked
    user.save(update_fields=["mfa_enabled", "mfa_enrolled_at", "last_totp_at"])
    return True


def verify_mfa(user, code: str) -> bool:
    """Verify a TOTP code or backup code for an enrolled user."""
    if not user.mfa_enabled or not user.mfa_secret:
        return False

    secret = decrypt_secret(user.mfa_secret)

    # Try TOTP first
    if verify_totp_code(secret, code, user=user):
        return True

    # Fall back to backup code
    return verify_and_consume_backup_code(user, code)


def disable_mfa(user) -> None:
    """Clear all MFA fields, fully disabling MFA for the user."""
    user.mfa_secret = ""
    user.mfa_enabled = False
    user.mfa_backup_codes = []
    user.mfa_enrolled_at = None
    user.last_totp_at = None
    user.save(update_fields=[
        "mfa_secret", "mfa_enabled", "mfa_backup_codes", "mfa_enrolled_at",
        "last_totp_at",
    ])


def regenerate_backup_codes(user) -> list[str]:
    """Generate new backup codes, replacing the old set.

    Returns the plaintext codes for one-time display.
    """
    codes = generate_backup_codes()
    user.mfa_backup_codes = [hash_backup_code(c) for c in codes]
    user.save(update_fields=["mfa_backup_codes"])
    return codes
