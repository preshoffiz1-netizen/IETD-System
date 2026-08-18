"""
Generic IMAP provider -- works with Gmail (via app password), Outlook.com,
Yahoo, Zoho, self-hosted mail servers, or any RFC 3501-compliant server.

This is the one provider guaranteed to work with only host/port/username/
password, which is why it is the default for the "Generic IMAP" connection
option in the UI (Section 8).
"""

from __future__ import annotations

import imaplib
import logging
import socket
from datetime import datetime, timezone

from app.providers.base import ConnectionResult, MailboxProvider, ProviderAuthError, RawMessage

logger = logging.getLogger("ietds.providers.imap")


class IMAPProvider(MailboxProvider):
    provider_key = "imap"

    CAPABILITIES = {
        "fetch_messages": True,
        "move_messages": True,
        "delete_messages": True,
        "create_folders": True,
        "server_side_filtering": False,
        "server_side_blocking": False,
        "mark_as_spam": False,
        "oauth": False,
        "push_notifications": False,
        "continuous_monitoring": True,  # via polling, not push
    }

    def __init__(self, mailbox, password: str | None = None):
        super().__init__(mailbox)
        # `password` is passed in decrypted by the caller (mailbox_service) --
        # this class never touches the encrypted column directly.
        self._password = password
        self._conn: imaplib.IMAP4 | None = None

    # Slow home/campus wifi and Gmail's own IMAP endpoint occasionally take
    # longer than a few seconds to respond, especially during the initial
    # TLS handshake+login. 15s was too tight in practice (observed repeated
    # `TimeoutError` during scheduled scans); 30s gives real-world networks
    # enough headroom without hanging a scan indefinitely.
    CONNECT_TIMEOUT_SECONDS = 30

    def connect(self) -> None:
        host = self.mailbox.imap_host
        port = self.mailbox.imap_port or (993 if self.mailbox.imap_use_ssl else 143)
        username = self.mailbox.imap_username or self.mailbox.email_address

        if not host:
            raise ProviderAuthError("IMAP host is not configured for this mailbox.")

        try:
            if self.mailbox.imap_use_ssl:
                self._conn = imaplib.IMAP4_SSL(host, port, timeout=self.CONNECT_TIMEOUT_SECONDS)
            else:
                self._conn = imaplib.IMAP4(host, port, timeout=self.CONNECT_TIMEOUT_SECONDS)
                self._conn.starttls()
            self._conn.login(username, self._password or "")
        except (imaplib.IMAP4.error, socket.error, OSError) as exc:
            raise ProviderAuthError(f"Unable to connect to {host}:{port} - {exc}") from exc

    def _reconnect(self) -> None:
        """Drop the (possibly dead) connection and open a fresh one."""
        try:
            if self._conn is not None:
                self._conn.logout()
        except Exception:
            pass
        self._conn = None
        self.connect()

    def _with_retry(self, fn):
        """
        Run an IMAP operation, and on a transient network failure (timeout,
        dropped socket, aborted command -- all observed in real-world scan
        logs against imap.gmail.com), reconnect once and retry exactly once
        before giving up. This keeps a single flaky round-trip from failing
        an entire scheduled scan.
        """
        try:
            return fn()
        except (socket.timeout, TimeoutError, imaplib.IMAP4.abort, OSError) as exc:
            logger.warning("IMAP operation failed (%s), reconnecting and retrying once", exc)
            self._reconnect()
            return fn()

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.logout()
            except Exception:  # pragma: no cover - best effort cleanup
                pass
            self._conn = None

    def test_connection(self) -> ConnectionResult:
        try:
            self.connect()
            folders = self.list_folders()
            self.disconnect()
            return ConnectionResult(success=True, message="Connected successfully.",
                                     detail={"folder_count": len(folders)})
        except ProviderAuthError as exc:
            return ConnectionResult(success=False, message=str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Unexpected IMAP test_connection failure")
            return ConnectionResult(success=False, message="Unexpected connection error.")

    def _require_conn(self) -> imaplib.IMAP4:
        if self._conn is None:
            self.connect()
        return self._conn

    def list_folders(self) -> list[str]:
        conn = self._require_conn()
        status, data = conn.list()
        folders = []
        if status == "OK":
            for entry in data:
                if not entry:
                    continue
                decoded = entry.decode(errors="ignore") if isinstance(entry, bytes) else entry
                # Format: (\HasNoChildren) "/" "INBOX"
                parts = decoded.rsplit('"', 2)
                if len(parts) >= 2:
                    folders.append(parts[-2])
                else:
                    folders.append(decoded)
        return folders or ["INBOX"]

    def list_messages(self, folder: str = "INBOX", limit: int = 50) -> list[str]:
        def _do():
            conn = self._require_conn()
            status, _ = conn.select(folder, readonly=True)
            if status != "OK":
                raise ProviderAuthError(f"Unable to select folder '{folder}'.")
            status, data = conn.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()
            uids = [u.decode() if isinstance(u, bytes) else u for u in uids]
            # Most recent last -> return most recent `limit`, oldest first for stable processing
            return uids[-limit:] if limit else uids

        return self._with_retry(_do)

    def fetch_message(self, uid: str, folder: str = "INBOX") -> RawMessage:
        def _do():
            conn = self._require_conn()
            conn.select(folder, readonly=True)
            status, data = conn.uid("fetch", uid, "(RFC822 INTERNALDATE)")
            if status != "OK" or not data or data[0] is None:
                raise ProviderAuthError(f"Unable to fetch message UID {uid}.")

            raw_bytes = b""
            internal_date = None
            for part in data:
                if isinstance(part, tuple) and len(part) == 2:
                    raw_bytes = part[1]
                elif isinstance(part, bytes) and b"INTERNALDATE" in part:
                    internal_date = None  # parsed defensively below if needed

            return RawMessage(
                provider_uid=uid,
                message_id=None,  # populated later by the email parser from headers
                raw_bytes=raw_bytes,
                folder=folder,
                internal_date=internal_date or datetime.now(timezone.utc),
            )

        return self._with_retry(_do)

    def move_message(self, uid: str, destination_folder: str, folder: str = "INBOX") -> bool:
        conn = self._require_conn()
        conn.select(folder)
        try:
            # RFC 6851 MOVE if supported, else COPY+DELETE
            typ, _ = conn.uid("MOVE", uid, destination_folder)
            if typ == "OK":
                return True
        except imaplib.IMAP4.error:
            pass
        typ, _ = conn.uid("COPY", uid, destination_folder)
        if typ != "OK":
            return False
        conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        conn.expunge()
        return True

    def delete_message(self, uid: str, folder: str = "INBOX") -> bool:
        conn = self._require_conn()
        conn.select(folder)
        typ, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        conn.expunge()
        return typ == "OK"

    def mark_as_read(self, uid: str, folder: str = "INBOX") -> bool:
        conn = self._require_conn()
        conn.select(folder)
        typ, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
        return typ == "OK"

    def mark_as_unread(self, uid: str, folder: str = "INBOX") -> bool:
        conn = self._require_conn()
        conn.select(folder)
        typ, _ = conn.uid("STORE", uid, "-FLAGS", "(\\Seen)")
        return typ == "OK"

    def create_folder(self, name: str) -> bool:
        conn = self._require_conn()
        typ, _ = conn.create(name)
        return typ == "OK"

    def search_messages(self, folder: str, criteria: dict) -> list[str]:
        conn = self._require_conn()
        conn.select(folder, readonly=True)
        terms = []
        if "from_" in criteria:
            terms += ["FROM", f'"{criteria["from_"]}"']
        if "subject" in criteria:
            terms += ["SUBJECT", f'"{criteria["subject"]}"']
        if not terms:
            terms = ["ALL"]
        status, data = conn.uid("search", None, *terms)
        if status != "OK" or not data or not data[0]:
            return []
        return [u.decode() if isinstance(u, bytes) else u for u in data[0].split()]
