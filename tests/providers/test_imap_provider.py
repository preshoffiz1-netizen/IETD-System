"""
IMAP provider tests using mocks -- no live credentials/server required
(Section 51: "Do not require live credentials for standard automated tests").
"""

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

    mock_ssl_cls.assert_called_once_with("imap.example.com", 993, timeout=15)
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
