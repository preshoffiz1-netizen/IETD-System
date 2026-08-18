"""
Mailbox management (Sections 8-10).

Handles mailbox CRUD, encrypted credential storage, and building a concrete
MailboxProvider instance for a Mailbox row. This is the *only* module that
should ever decrypt a mailbox credential.
"""

from __future__ import annotations

import json
import logging
import time

from flask import current_app

from app.extensions import db
from app.models import Mailbox, MailboxStatus, ProviderType
from app.providers import DemoProvider, GmailProvider, IMAPProvider
from app.services import audit_service
from app.utils.security import decrypt_secret, encrypt_secret

logger = logging.getLogger("ietds.services.mailbox")

# Refresh an OAuth access token this many seconds before it actually expires,
# so a scan that starts right at the boundary doesn't race an expired token.
_TOKEN_REFRESH_SKEW_SECONDS = 120


def create_imap_mailbox(*, organization_id: str, user_id: str, email_address: str,
                         imap_host: str, imap_port: int, imap_use_ssl: bool,
                         imap_username: str, password: str, display_name: str | None = None) -> Mailbox:
    mailbox = Mailbox(
        organization_id=organization_id,
        user_id=user_id,
        provider=ProviderType.IMAP,
        email_address=email_address,
        display_name=display_name or email_address,
        imap_host=imap_host,
        imap_port=imap_port,
        imap_use_ssl=imap_use_ssl,
        imap_username=imap_username or email_address,
        encrypted_password=encrypt_secret(password) if password else None,
        status=MailboxStatus.PENDING,
    )
    db.session.add(mailbox)
    db.session.commit()
    audit_service.log_event("mailbox_connected", user_id=user_id, organization_id=organization_id,
                             target_type="mailbox", target_id=mailbox.id,
                             metadata={"provider": "imap", "email": email_address})
    return mailbox


def create_demo_mailbox(*, organization_id: str, user_id: str) -> Mailbox:
    mailbox = Mailbox(
        organization_id=organization_id,
        user_id=user_id,
        provider=ProviderType.DEMO,
        email_address="demo@ietds.local",
        display_name="Demo Mailbox (synthetic data)",
        status=MailboxStatus.CONNECTED,
        monitoring_enabled=False,
    )
    db.session.add(mailbox)
    db.session.commit()
    return mailbox

def create_oauth_mailbox(*, organization_id: str, user_id: str, provider: str, email_address: str,
                          token: dict, display_name: str | None = None) -> Mailbox:
    mailbox = Mailbox(
        organization_id=organization_id,
        user_id=user_id,
        provider=provider,
        email_address=email_address,
        display_name=display_name or email_address,
        encrypted_oauth_token=encrypt_secret(json.dumps(token)),
        status=MailboxStatus.CONNECTED,
    )
    db.session.add(mailbox)
    db.session.commit()
    audit_service.log_event("mailbox_connected", user_id=user_id, organization_id=organization_id,
                             target_type="mailbox", target_id=mailbox.id,
                             metadata={"provider": provider, "email": email_address})
    return mailbox


def update_oauth_token(mailbox: Mailbox, token: dict) -> None:
    mailbox.encrypted_oauth_token = encrypt_secret(json.dumps(token))
    db.session.commit()


def get_decrypted_password(mailbox: Mailbox) -> str:
    if not mailbox.encrypted_password:
        return ""
    return decrypt_secret(mailbox.encrypted_password)


def get_decrypted_oauth_token(mailbox: Mailbox) -> dict:
    if not mailbox.encrypted_oauth_token:
        return {}
    return json.loads(decrypt_secret(mailbox.encrypted_oauth_token))


def _token_is_expired(token: dict) -> bool:
    obtained_at = token.get("obtained_at")
    expires_in = token.get("expires_in")
    if obtained_at is None or not expires_in:
        # No expiry info recorded (e.g. an older token) - let the provider try
        # and surface a normal auth error if it turns out to be stale.
        return False
    return time.time() >= (obtained_at + expires_in - _TOKEN_REFRESH_SKEW_SECONDS)


def _ensure_fresh_oauth_token(mailbox: Mailbox, token: dict) -> dict:
    """
    Gmail access tokens expire (~1 hour). If we're holding a refresh token and
    the access token is expired or about to be, silently refresh it and
    persist the new one - this is what makes continuous background monitoring
    keep working past the first hour, like any normal OAuth app.
    """
    if not token.get("refresh_token") or not _token_is_expired(token):
        return token

    try:
        if mailbox.provider == ProviderType.GMAIL:
            from app.providers.gmail_provider import refresh_access_token
            new_token = refresh_access_token(
                current_app.config["GMAIL_CLIENT_ID"],
                current_app.config["GMAIL_CLIENT_SECRET"],
                token["refresh_token"],
            )
        else:
            return token
    except Exception as exc:  # noqa: BLE001 - any refresh failure just falls back to the old token
        logger.warning("OAuth token refresh failed for mailbox %s: %s", mailbox.id, exc)
        return token

    # The refresh response usually omits refresh_token (it doesn't rotate) -
    # keep the one we already have unless a new one was issued.
    new_token.setdefault("refresh_token", token["refresh_token"])
    new_token["obtained_at"] = time.time()
    update_oauth_token(mailbox, new_token)
    return new_token


def build_provider(mailbox: Mailbox):
    """Instantiate the correct MailboxProvider for a Mailbox row, with decrypted credentials."""
    if mailbox.provider == ProviderType.IMAP:
        return IMAPProvider(mailbox, password=get_decrypted_password(mailbox))
    if mailbox.provider == ProviderType.GMAIL:
        token = _ensure_fresh_oauth_token(mailbox, get_decrypted_oauth_token(mailbox))
        return GmailProvider(mailbox, oauth_token=token)
    if mailbox.provider == ProviderType.DEMO:
        return DemoProvider(mailbox)
    raise ValueError(f"Unknown provider type: {mailbox.provider}")


def test_connection(mailbox: Mailbox):
    provider = build_provider(mailbox)
    result = provider.test_connection()
    mailbox.status = MailboxStatus.CONNECTED if result.success else MailboxStatus.ERROR
    mailbox.status_message = result.message
    db.session.commit()
    return result


def disconnect(mailbox: Mailbox, user_id: str) -> None:
    mailbox.status = MailboxStatus.DISCONNECTED
    mailbox.monitoring_enabled = False
    db.session.commit()
    audit_service.log_event("mailbox_disconnected", user_id=user_id, target_type="mailbox", target_id=mailbox.id)


def delete_mailbox(mailbox: Mailbox, user_id: str) -> None:
    mailbox_id = mailbox.id
    db.session.delete(mailbox)
    db.session.commit()
    audit_service.log_event("mailbox_deleted", user_id=user_id, target_type="mailbox", target_id=mailbox_id)


def set_monitoring(mailbox: Mailbox, enabled: bool, interval_minutes: int | None = None) -> None:
    mailbox.monitoring_enabled = enabled
    if interval_minutes:
        mailbox.scan_interval_minutes = interval_minutes
    db.session.commit()
