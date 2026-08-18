"""
IMAP provider tests using mocks -- no live credentials/server required
(Section 51: "Do not require live credentials for standard automated tests").
"""

import socket
from unittest.mock import MagicMock, patch

from app.providers.base import ProviderAuthError
from app.providers.imap_provider import IMAPProvider


class _FakeMailbox:
    imap_host = "imap.example.com"
    imap_port = 993
    imap_use_ssl = True
    imap_username = "user@example.com"
    email_address = "user@example.com"


def test_connect_raises_without_host():
    mailbox = _FakeMailbox()
    mailbox.imap_host = ""
    provider = IMAPProvider(mailbox, password="secret")
    try:
        provider.connect()
        assert False, "expected ProviderAuthError"
    except ProviderAuthError:
        pass


@patch("app.providers.imap_provider.imaplib.IMAP4_SSL")
def test_connect_success(mock_ssl_cls):
    mock_conn = MagicMock()
    mock_ssl_cls.return_value = mock_conn

    provider = IMAPProvider(_FakeMailbox(), password="secret")
    provider.connect()

    mock_ssl_cls.assert_called_once_with("imap.example.com", 993, timeout=30)
    mock_conn.login.assert_called_once_with("user@example.com", "secret")


@patch("app.providers.imap_provider.imaplib.IMAP4_SSL")
def test_list_messages_parses_uid_search_response(mock_ssl_cls):
    mock_conn = MagicMock()
    mock_conn.select.return_value = ("OK", [b"1"])
    mock_conn.uid.return_value = ("OK", [b"101 102 103"])
    mock_ssl_cls.return_value = mock_conn

    provider = IMAPProvider(_FakeMailbox(), password="secret")
    uids = provider.list_messages(limit=10)

    assert uids == ["101", "102", "103"]


@patch("app.providers.imap_provider.imaplib.IMAP4_SSL")
def test_test_connection_reports_failure_gracefully(mock_ssl_cls):
    mock_ssl_cls.side_effect = OSError("connection refused")

    provider = IMAPProvider(_FakeMailbox(), password="secret")
    result = provider.test_connection()

    assert result.success is False
    assert "connection refused" in result.message or result.message


@patch("app.providers.imap_provider.imaplib.IMAP4_SSL")
def test_fetch_message_reconnects_once_after_timeout(mock_ssl_cls):
    """
    Reproduces a real failure mode from testing against imap.gmail.com:
    a scheduled scan's fetch would occasionally hit `socket.timeout` mid-
    command and the whole scan would just fail. The provider should now
    transparently reconnect and retry exactly once instead of giving up.
    """
    good_conn = MagicMock()
    good_conn.select.return_value = ("OK", [b"1"])
    good_conn.uid.return_value = ("OK", [(b"1 (RFC822 {10}", b"raw-bytes"), b")"])

    bad_conn = MagicMock()
    bad_conn.select.side_effect = socket.timeout("timed out")

    # First connect() call (inside _require_conn) returns the connection that
    # times out; the reconnect triggered by _with_retry's except-branch
    # returns a healthy connection.
    mock_ssl_cls.side_effect = [bad_conn, good_conn]

    provider = IMAPProvider(_FakeMailbox(), password="secret")
    result = provider.fetch_message("1", folder="INBOX")

    assert mock_ssl_cls.call_count == 2  # one failed connect, one reconnect
    assert result.raw_bytes == b"raw-bytes"


@patch("app.providers.imap_provider.imaplib.IMAP4_SSL")
def test_fetch_message_raises_if_retry_also_fails(mock_ssl_cls):
    bad_conn = MagicMock()
    bad_conn.select.side_effect = socket.timeout("timed out")
    mock_ssl_cls.return_value = bad_conn

    provider = IMAPProvider(_FakeMailbox(), password="secret")
    try:
        provider.fetch_message("1", folder="INBOX")
        assert False, "expected the second timeout to propagate"
    except socket.timeout:
        pass
