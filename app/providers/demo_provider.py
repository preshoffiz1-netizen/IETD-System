"""
Demo provider (Section 50).

Feeds a fixed set of synthetic .eml fixtures through the exact same
ingestion/detection pipeline as a real mailbox, so the system can be
demonstrated end-to-end without connecting a real mailbox. All fixture data
is invented for demonstration and clearly labelled -- no real person's email
content is used.
"""

from __future__ import annotations

from app.providers.base import ConnectionResult, MailboxProvider, RawMessage
from app.utils.demo_fixtures import DEMO_MESSAGES


class DemoProvider(MailboxProvider):
    provider_key = "demo"

    CAPABILITIES = {
        "fetch_messages": True,
        "move_messages": True,
        "delete_messages": True,
        "create_folders": False,
        "server_side_filtering": False,
        "server_side_blocking": False,
        "mark_as_spam": False,
        "oauth": False,
        "push_notifications": False,
        "continuous_monitoring": True,
    }

    def connect(self) -> None:
        return None

    def disconnect(self) -> None:
        return None

    def test_connection(self) -> ConnectionResult:
        return ConnectionResult(success=True, message="Demo mode is always available.")

    def list_folders(self) -> list[str]:
        return ["INBOX"]

    def list_messages(self, folder: str = "INBOX", limit: int = 50) -> list[str]:
        return [m["uid"] for m in DEMO_MESSAGES][:limit]

    def fetch_message(self, uid: str, folder: str = "INBOX") -> RawMessage:
        for m in DEMO_MESSAGES:
            if m["uid"] == uid:
                return RawMessage(provider_uid=uid, message_id=m.get("message_id"),
                                   raw_bytes=m["raw"].encode("utf-8"), folder=folder)
        raise KeyError(f"Unknown demo message uid={uid}")

    def move_message(self, uid: str, destination_folder: str, folder: str = "INBOX") -> bool:
        return True  # no-op in demo mode

    def delete_message(self, uid: str, folder: str = "INBOX") -> bool:
        return True

    def mark_as_read(self, uid: str, folder: str = "INBOX") -> bool:
        return True

    def mark_as_unread(self, uid: str, folder: str = "INBOX") -> bool:
        return True
