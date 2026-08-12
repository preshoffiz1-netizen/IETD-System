"""
Microsoft 365 / Outlook provider via Microsoft Graph.

Unlike Gmail (which reuses IMAP), Outlook.com and Microsoft 365 mailboxes are
accessed here through the Microsoft Graph REST API directly, since Graph
exposes richer capabilities (message move/delete/categories, and -- with the
right permissions -- inbox rule creation) than IMAP alone. Authentication
uses OAuth 2.0 (MSAL authorization-code flow); the app never sees the user's
Microsoft password (Section 6).
"""

from __future__ import annotations

import logging

import requests

from app.providers.base import (
    ConnectionResult,
    MailboxProvider,
    ProviderAuthError,
    RawMessage,
)

logger = logging.getLogger("ietds.providers.microsoft")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPES = ["Mail.ReadWrite", "Mail.Send", "offline_access", "User.Read"]


class MicrosoftGraphProvider(MailboxProvider):
    provider_key = "microsoft"

    CAPABILITIES = {
        "fetch_messages": True,
        "move_messages": True,
        "delete_messages": True,
        "create_folders": True,
        "server_side_filtering": True,   # Graph "message rules" API
        "server_side_blocking": True,    # Graph inbox rules can block/redirect senders
        "mark_as_spam": True,
        "oauth": True,
        "push_notifications": True,      # Graph change notifications (documented, future work)
        "continuous_monitoring": True,
    }

    def __init__(self, mailbox, oauth_token: dict | None = None):
        super().__init__(mailbox)
        self._oauth_token = oauth_token or {}
        self._session: requests.Session | None = None

    def _headers(self) -> dict:
        access_token = self._oauth_token.get("access_token")
        if not access_token:
            raise ProviderAuthError(
                "No Microsoft OAuth access token available. Reconnect this mailbox via "
                "Settings > Mailboxes > Connect Microsoft 365 to complete the OAuth consent flow."
            )
        return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    def connect(self) -> None:
        self._session = requests.Session()
        self._session.headers.update(self._headers())
        # Cheap round trip to confirm the token actually works.
        resp = self._session.get(f"{GRAPH_BASE}/me/mailFolders/inbox", timeout=15)
        if resp.status_code == 401:
            raise ProviderAuthError("Microsoft Graph token rejected (401) - reconnect the mailbox.")
        resp.raise_for_status()

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def test_connection(self) -> ConnectionResult:
        try:
            self.connect()
            folders = self.list_folders()
            self.disconnect()
            return ConnectionResult(success=True, message="Microsoft 365 connected via Graph API.",
                                     detail={"folder_count": len(folders)})
        except (ProviderAuthError, requests.RequestException) as exc:
            return ConnectionResult(success=False, message=str(exc))

    def _require_session(self) -> requests.Session:
        if self._session is None:
            self.connect()
        return self._session

    def list_folders(self) -> list[str]:
        session = self._require_session()
        resp = session.get(f"{GRAPH_BASE}/me/mailFolders?$top=50", timeout=15)
        resp.raise_for_status()
        return [f["displayName"] for f in resp.json().get("value", [])] or ["Inbox"]

    def list_messages(self, folder: str = "INBOX", limit: int = 50) -> list[str]:
        session = self._require_session()
        folder_id = "inbox" if folder.upper() == "INBOX" else folder
        resp = session.get(
            f"{GRAPH_BASE}/me/mailFolders/{folder_id}/messages",
            params={"$top": limit, "$select": "id", "$orderby": "receivedDateTime desc"},
            timeout=15,
        )
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("value", [])]

    def fetch_message(self, uid: str, folder: str = "INBOX") -> RawMessage:
        session = self._require_session()
        resp = session.get(f"{GRAPH_BASE}/me/messages/{uid}/$value", timeout=20)
        resp.raise_for_status()
        raw_bytes = resp.content  # MIME (.eml) representation
        return RawMessage(provider_uid=uid, message_id=None, raw_bytes=raw_bytes, folder=folder)

    def move_message(self, uid: str, destination_folder: str, folder: str = "INBOX") -> bool:
        session = self._require_session()
        resp = session.post(
            f"{GRAPH_BASE}/me/messages/{uid}/move",
            json={"destinationId": destination_folder},
            timeout=15,
        )
        return resp.ok

    def delete_message(self, uid: str, folder: str = "INBOX") -> bool:
        session = self._require_session()
        resp = session.delete(f"{GRAPH_BASE}/me/messages/{uid}", timeout=15)
        return resp.ok

    def mark_as_read(self, uid: str, folder: str = "INBOX") -> bool:
        session = self._require_session()
        resp = session.patch(f"{GRAPH_BASE}/me/messages/{uid}", json={"isRead": True}, timeout=15)
        return resp.ok

    def mark_as_unread(self, uid: str, folder: str = "INBOX") -> bool:
        session = self._require_session()
        resp = session.patch(f"{GRAPH_BASE}/me/messages/{uid}", json={"isRead": False}, timeout=15)
        return resp.ok

    def mark_as_spam(self, uid: str, folder: str = "INBOX") -> bool:
        return self.move_message(uid, "junkemail", folder=folder)

    def create_folder(self, name: str) -> bool:
        session = self._require_session()
        resp = session.post(f"{GRAPH_BASE}/me/mailFolders", json={"displayName": name}, timeout=15)
        return resp.ok

    def search_messages(self, folder: str, criteria: dict) -> list[str]:
        session = self._require_session()
        folder_id = "inbox" if folder.upper() == "INBOX" else folder
        search_terms = []
        if "from_" in criteria:
            search_terms.append(f'from:{criteria["from_"]}')
        if "subject" in criteria:
            search_terms.append(f'subject:{criteria["subject"]}')
        resp = session.get(
            f"{GRAPH_BASE}/me/mailFolders/{folder_id}/messages",
            params={"$search": f'"{" ".join(search_terms)}"'} if search_terms else {},
            timeout=15,
        )
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("value", [])]

    def apply_server_side_rule(self, rule_definition: dict) -> bool:
        """Create a Graph inbox rule (message rule) -- e.g. block a sender."""
        session = self._require_session()
        resp = session.post(f"{GRAPH_BASE}/me/mailFolders/inbox/messageRules",
                             json=rule_definition, timeout=15)
        return resp.ok


def build_authorization_url(client_id: str, redirect_uri: str, tenant_id: str, state: str) -> str:
    import urllib.parse

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "response_mode": "query",
        "scope": " ".join(GRAPH_SCOPES),
        "state": state,
    }
    return (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        + urllib.parse.urlencode(params)
    )


def exchange_code_for_token(client_id: str, client_secret: str, redirect_uri: str,
                             tenant_id: str, code: str) -> dict:
    resp = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": " ".join(GRAPH_SCOPES),
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()
