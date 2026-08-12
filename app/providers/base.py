"""
Provider abstraction (Section 5).

Every mailbox provider (generic IMAP, Gmail, Microsoft Graph, and any future
provider) implements this interface. The rest of the application -- the
scanner service, the detection engine, the UI -- only ever talks to a
`MailboxProvider`, never to `imaplib` or a vendor SDK directly. This is what
lets a Gmail mailbox and a generic IMAP mailbox flow through the exact same
ingestion pipeline.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional


@dataclass
class RawMessage:
    """A provider-agnostic representation of a fetched email, before parsing."""

    provider_uid: str
    message_id: Optional[str]
    raw_bytes: bytes
    folder: str = "INBOX"
    internal_date: Optional[datetime] = None


@dataclass
class ConnectionResult:
    success: bool
    message: str = ""
    detail: dict = field(default_factory=dict)


class ProviderCapabilityError(RuntimeError):
    """Raised when a caller requests an action a provider does not support."""


class ProviderAuthError(RuntimeError):
    """Raised when authentication/connection to the mailbox provider fails."""


class MailboxProvider(abc.ABC):
    """
    Abstract mailbox provider.

    CAPABILITIES documents, per Section 66, exactly what this provider can do so
    the UI can hide actions that are not actually supported rather than showing
    a button that silently fails.
    """

    provider_key: str = "base"

    CAPABILITIES = {
        "fetch_messages": False,
        "move_messages": False,
        "delete_messages": False,
        "create_folders": False,
        "server_side_filtering": False,
        "server_side_blocking": False,
        "mark_as_spam": False,
        "oauth": False,
        "push_notifications": False,
        "continuous_monitoring": False,
    }

    def __init__(self, mailbox):
        self.mailbox = mailbox

    # --- Lifecycle -------------------------------------------------------------------
    @abc.abstractmethod
    def connect(self) -> None:
        ...

    @abc.abstractmethod
    def disconnect(self) -> None:
        ...

    @abc.abstractmethod
    def test_connection(self) -> ConnectionResult:
        ...

    # --- Discovery ----------------------------------------------------------------------
    @abc.abstractmethod
    def list_folders(self) -> list[str]:
        ...

    @abc.abstractmethod
    def list_messages(self, folder: str = "INBOX", limit: int = 50) -> list[str]:
        """Return provider-native message identifiers (UIDs) in a folder."""

    @abc.abstractmethod
    def fetch_message(self, uid: str, folder: str = "INBOX") -> RawMessage:
        ...

    def fetch_new_messages(self, folder: str = "INBOX", since_uid: Optional[str] = None,
                            limit: int = 50) -> Iterable[RawMessage]:
        """
        Default implementation: list messages, filter anything at/below the
        watermark, fetch the rest. Providers may override for efficiency
        (e.g. Gmail history API, IMAP UID SEARCH).
        """
        uids = self.list_messages(folder=folder, limit=limit)
        for uid in uids:
            if since_uid and _uid_le(uid, since_uid):
                continue
            yield self.fetch_message(uid, folder=folder)

    # --- Mutating actions (post-delivery filtering, Section 7) --------------------------
    def move_message(self, uid: str, destination_folder: str, folder: str = "INBOX") -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support move_message")

    def delete_message(self, uid: str, folder: str = "INBOX") -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support delete_message")

    def mark_as_read(self, uid: str, folder: str = "INBOX") -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support mark_as_read")

    def mark_as_unread(self, uid: str, folder: str = "INBOX") -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support mark_as_unread")

    def create_folder(self, name: str) -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support create_folder")

    def search_messages(self, folder: str, criteria: dict) -> list[str]:
        raise ProviderCapabilityError(f"{self.provider_key} does not support search_messages")

    # --- Server-side / pre-delivery actions (Section 7B) --------------------------------
    def mark_as_spam(self, uid: str, folder: str = "INBOX") -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support server-side mark_as_spam")

    def apply_server_side_rule(self, rule_definition: dict) -> bool:
        raise ProviderCapabilityError(f"{self.provider_key} does not support server-side rules")

    def supports(self, capability: str) -> bool:
        return bool(self.CAPABILITIES.get(capability, False))


def _uid_le(uid_a: str, uid_b: str) -> bool:
    """Best-effort numeric UID comparison, falling back to string comparison."""
    try:
        return int(uid_a) <= int(uid_b)
    except (TypeError, ValueError):
        return uid_a <= uid_b
