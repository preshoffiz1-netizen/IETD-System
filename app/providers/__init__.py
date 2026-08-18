from __future__ import annotations

from app.providers.base import (
    ConnectionResult,
    MailboxProvider,
    ProviderAuthError,
    ProviderCapabilityError,
    RawMessage,
)
from app.providers.demo_provider import DemoProvider
from app.providers.gmail_provider import GmailProvider
from app.providers.imap_provider import IMAPProvider

_PROVIDER_REGISTRY = {
    "imap": IMAPProvider,
    "gmail": GmailProvider,
    "demo": DemoProvider,
}


def get_provider_class(provider_key: str):
    return _PROVIDER_REGISTRY.get(provider_key)


def available_providers() -> list[str]:
    return list(_PROVIDER_REGISTRY.keys())


__all__ = [
    "MailboxProvider",
    "ConnectionResult",
    "RawMessage",
    "ProviderAuthError",
    "ProviderCapabilityError",
    "IMAPProvider",
    "GmailProvider",
    "DemoProvider",
    "get_provider_class",
    "available_providers",
]
