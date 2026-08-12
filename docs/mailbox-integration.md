# Mailbox Integration

## Provider abstraction

`app/providers/base.py` defines `MailboxProvider`, an abstract interface with `connect()`,
`disconnect()`, `test_connection()`, `list_folders()`, `list_messages()`, `fetch_message()`,
`fetch_new_messages()`, `move_message()`, `delete_message()`, `mark_as_read()`,
`mark_as_unread()`, `create_folder()`, `search_messages()`, and provider-side extensions
`mark_as_spam()` / `apply_server_side_rule()`. Every concrete provider
(`IMAPProvider`, `GmailProvider`, `MicrosoftGraphProvider`, `DemoProvider`) implements this
same interface, so `scanner_service` and the detection engine never know or care which
provider a given mailbox uses.

## Capability model (Section 66)

Each provider class declares a `CAPABILITIES` dict:

```python
CAPABILITIES = {
    "fetch_messages": True, "move_messages": True, "delete_messages": True,
    "create_folders": True, "server_side_filtering": False, "server_side_blocking": False,
    "mark_as_spam": False, "oauth": False, "push_notifications": False,
    "continuous_monitoring": True,
}
```

`Mailbox.capabilities()` exposes this to templates, so the Mailboxes UI only shows an action
(or a claim about server-side filtering) when the connected provider actually supports it -
never a button that would silently fail.

| Capability | Generic IMAP | Gmail | Microsoft 365 (Graph) |
|---|---|---|---|
| Fetch / move / delete messages | Yes | Yes | Yes |
| Create folders | Yes | Yes | Yes |
| OAuth 2.0 | No (password/app password) | Yes | Yes |
| Server-side filtering / blocking | No | Filtering: partial* | Yes (Graph message rules) |
| Mark as spam (provider-native) | No | Yes (move to `[Gmail]/Spam`) | Yes (move to Junk Email) |
| Push notifications | No (polling only) | Documented, not implemented | Documented, not implemented |

\* Gmail filter *creation* via the REST API requires the `gmail.settings.basic` OAuth scope,
which this deployment does not request (it only requests `https://mail.google.com/` for IMAP
access). `GmailProvider.apply_server_side_rule()` raises `NotImplementedError` with an
explanation rather than silently pretending to succeed.

## Pre-delivery vs. post-delivery filtering (Section 7)

This distinction is stated explicitly in the UI and here, because it would be dishonest to
imply otherwise:

- **Post-delivery filtering** (always available, for every provider): the email arrives in the
  mailbox; IETDS fetches it, analyzes it, and can move it, quarantine it (in its own
  database), flag it, or delete it. This is what "IETDS will scan new messages and
  automatically quarantine detected threats" means in the Mailboxes UI.
- **Pre-delivery / server-side filtering**: the *provider itself* refuses or redirects the
  message before it ever reaches the mailbox. This requires provider support - generic IMAP
  has no such mechanism at all; Gmail and Microsoft 365 support it only through their
  respective REST APIs with additional OAuth scopes not requested by this deployment.

No part of this system claims universal pre-delivery blocking, and the Mailboxes page
communicates this per-connected-mailbox based on its provider's actual capabilities.

## Generic IMAP

`IMAPProvider` uses Python's standard `imaplib`. It supports SSL/TLS or STARTTLS, UID-based
`SEARCH`/`FETCH` (so message identity survives across sessions for deduplication), `MOVE`
(falling back to `COPY` + `STORE \Deleted` + `EXPUNGE` if the server doesn't support RFC 6851
`MOVE`), and standard flag operations. Any RFC 3501-compliant server works: Gmail (via app
password, though OAuth is preferred - see below), Outlook.com, Yahoo, Zoho, or a self-hosted
mail server.

## Gmail (OAuth 2.0)

`GmailProvider` extends `IMAPProvider` and overrides only how the connection authenticates: it
connects to `imap.gmail.com:993` and authenticates using the SASL `XOAUTH2` mechanism with an
OAuth 2.0 access token, instead of a password. This means all the IMAP command logic
(list/fetch/move/delete/mark) is reused unmodified. `app/providers/gmail_provider.py` also
contains the OAuth helper functions (`build_authorization_url`, `exchange_code_for_token`,
`refresh_access_token`) used by the `/mailboxes/oauth/gmail/*` routes. IETDS never asks for or
stores the user's actual Google account password.

## Microsoft 365 / Outlook (Microsoft Graph)

`MicrosoftGraphProvider` talks to `https://graph.microsoft.com/v1.0` directly over HTTPS
(not IMAP), because Graph exposes richer capabilities than IMAP alone (message rules,
categories, and richer folder operations) once the right scopes are granted. Authentication
uses the standard OAuth 2.0 authorization-code flow against
`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/`.

## Demo provider

`DemoProvider` returns a fixed set of ten synthetic `.eml` fixtures
(`app/utils/demo_fixtures.py`) through the exact same `RawMessage` interface as a real
provider, so demo mode exercises the *entire* real pipeline (parsing, detection, scoring,
classification, policy, quarantine) - it is not a separate mocked-up "demo view".

## Adding a new provider

1. Create `app/providers/<name>_provider.py` with a class extending `MailboxProvider` (or
   `IMAPProvider`, if the new provider also happens to speak IMAP).
2. Declare an accurate `CAPABILITIES` dict.
3. Register it in `app/providers/__init__.py`'s `_PROVIDER_REGISTRY`.
4. Nothing in `scanner_service`, the detection engine, or the templates needs to change - they
   only ever interact with the abstract interface and the capability model.
