"""
Gmail provider.

Uses Gmail's IMAP endpoint (imap.gmail.com:993) authenticated with OAuth 2.0
via the SASL XOAUTH2 mechanism, so the application never needs -- and never
requests -- the user's actual Google account password (Section 6). This
reuses all of the IMAP command logic from IMAPProvider (list/fetch/move/
delete/mark) and only overrides how the connection is authenticated.

OAuth setup requires GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET to be configured
(see .env.example); the authorization-code exchange happens in
app/routes/mailbox.py's OAuth callback route, and the resulting refresh
token is stored encrypted on the Mailbox record.
"""

from __future__ import annotations

import base64
import json
import logging

from app.providers.base import ConnectionResult, ProviderAuthError
from app.providers.imap_provider import IMAPProvider

logger = logging.getLogger("ietds.providers.gmail")

GMAIL_IMAP_HOST = "imap.gmail.com"
GMAIL_IMAP_PORT = 993
GMAIL_TOKEN_URI = "https://oauth2.googleapis.com/token"


class GmailProvider(IMAPProvider):
    provider_key = "gmail"

    CAPABILITIES = {
        "fetch_messages": True,
        "move_messages": True,
        "delete_messages": True,
        "create_folders": True,
        "server_side_filtering": True,   # Gmail filters/labels API (documented, optional)
        "server_side_blocking": False,
        "mark_as_spam": True,            # move to [Gmail]/Spam via IMAP
        "oauth": True,
        "push_notifications": True,      # Gmail Pub/Sub push (documented as future work)
        "continuous_monitoring": True,
    }

    def __init__(self, mailbox, oauth_token: dict | None = None):
        # oauth_token is the decrypted token dict: {access_token, refresh_token, expiry, ...}
        super().__init__(mailbox, password=None)
        self.mailbox.imap_host = GMAIL_IMAP_HOST
        self.mailbox.imap_port = GMAIL_IMAP_PORT
        self.mailbox.imap_use_ssl = True
        self._oauth_token = oauth_token or {}

    def _access_token(self) -> str:
        access_token = self._oauth_token.get("access_token")
        if not access_token:
            raise ProviderAuthError(
                "No Gmail OAuth access token available. Reconnect this mailbox via "
                "Settings > Mailboxes > Connect Gmail to complete the OAuth consent flow."
            )
        return access_token

    def connect(self) -> None:
        import imaplib

        host, port = GMAIL_IMAP_HOST, GMAIL_IMAP_PORT
        username = self.mailbox.email_address
        access_token = self._access_token()

        auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"

        try:
            self._conn = imaplib.IMAP4_SSL(host, port, timeout=self.CONNECT_TIMEOUT_SECONDS)
            self._conn.authenticate("XOAUTH2", lambda _: auth_string.encode())
        except imaplib.IMAP4.error as exc:
            raise ProviderAuthError(
                f"Gmail OAuth authentication failed: {exc}. The access token may have "
                "expired; refresh it and try again."
            ) from exc

    def test_connection(self) -> ConnectionResult:
        try:
            self.connect()
            folders = self.list_folders()
            self.disconnect()
            return ConnectionResult(success=True, message="Gmail connected via OAuth 2.0.",
                                     detail={"folder_count": len(folders)})
        except ProviderAuthError as exc:
            return ConnectionResult(success=False, message=str(exc))

    def mark_as_spam(self, uid: str, folder: str = "INBOX") -> bool:
        return self.move_message(uid, "[Gmail]/Spam", folder=folder)

    def apply_server_side_rule(self, rule_definition: dict) -> bool:
        """
        Gmail filter creation requires the Gmail REST API (gmail.settings.basic
        scope), which is a distinct capability from IMAP mail access. Documented
        as an optional extension point -- see docs/mailbox-integration.md.
        """
        raise NotImplementedError(
            "Server-side Gmail filter creation requires the Gmail REST API and the "
            "gmail.settings.basic OAuth scope; this deployment only requests IMAP "
            "mail-read/modify scopes. See docs/mailbox-integration.md for how to "
            "extend this."
        )


def build_authorization_url(client_id: str, redirect_uri: str, state: str) -> str:
    """Build the Google OAuth 2.0 consent URL (installed-app / web flow)."""
    import urllib.parse

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "https://mail.google.com/",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


def exchange_code_for_token(client_id: str, client_secret: str, redirect_uri: str, code: str) -> dict:
    """Exchange an OAuth authorization code for access/refresh tokens."""
    import requests

    response = requests.post(
        GMAIL_TOKEN_URI,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> dict:
    import requests

    response = requests.post(
        GMAIL_TOKEN_URI,
        data={
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def get_authenticated_email(access_token: str) -> str | None:
    """
    Look up the real Google account address behind an access token, via
    Google's OpenID userinfo endpoint. Used right after the OAuth callback so
    we store the *actual* mailbox that was authorized, not a guess -- the
    signed-in IETDS user and the Google account being connected are not
    necessarily the same address.
    """
    import requests

    try:
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        response.raise_for_status()
        return response.json().get("email")
    except requests.RequestException as exc:
        logger.warning("Failed to fetch Gmail userinfo after OAuth: %s", exc)
        return None
