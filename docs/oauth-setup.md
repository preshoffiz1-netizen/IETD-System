# Gmail OAuth Setup

"Connect with Google" on the Mailboxes page uses real OAuth 2.0 - IETDS never asks for or
stores your Gmail password. But OAuth requires that *someone* first register an application
with Google to get a client ID/secret - there is no way around this step, and no app (including
Gmail itself or any third-party mail client) can skip it. This is exactly what every real "Sign
in with Google" button in any commercial product is backed by.

This guide gets you real, working credentials in about 5 minutes. Once they're in your `.env`
file, the OAuth flow works end-to-end - no code changes needed.

(Microsoft 365/Outlook OAuth was implemented earlier in this project and later removed - see
`docs/limitations.md` and the appendix at the bottom of this file for why, and what re-adding
it would involve.)

## Gmail

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new project
   (or pick an existing one) - top-left project selector -> **New Project**.
2. Enable the Gmail API: **APIs & Services -> Library**, search "Gmail API", click **Enable**.
3. Configure the consent screen: **APIs & Services -> OAuth consent screen**.
   - User type: **External** (unless you have a Google Workspace org and want **Internal**).
   - Fill in the app name (e.g. "IETDS"), your email as support/developer contact.
   - Scopes: you don't need to add any here - IETDS requests `https://mail.google.com/` directly
     at authorization time.
   - Test users: while the app is in "Testing" publishing status (the default, and fine for a
     student project/demo), add every Gmail address you intend to connect as a **test user**
     here, or Google will refuse to authorize them.
4. Create credentials: **APIs & Services -> Credentials -> Create Credentials -> OAuth client ID**.
   - Application type: **Web application**.
   - Authorized redirect URIs: add exactly the value of `GMAIL_REDIRECT_URI` in your `.env`,
     e.g. `http://localhost:5000/mailboxes/oauth/gmail/callback` for local development. It must
     match character-for-character (including the port).
5. Copy the generated **Client ID** and **Client secret** into your `.env`:
   ```
   GMAIL_CLIENT_ID=xxxxxxxxxxxx.apps.googleusercontent.com
   GMAIL_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
   GMAIL_REDIRECT_URI=http://localhost:5000/mailboxes/oauth/gmail/callback
   ```
6. Restart the app (`python run.py`). The Mailboxes -> Connect -> Gmail tab will now show a
   green "Configured" badge and "Connect with Google" will work.

Notes:
- IETDS requests the `https://mail.google.com/` scope (full IMAP access via OAuth), which is
  what lets `GmailProvider` authenticate to `imap.gmail.com` with XOAUTH2 instead of a password.
- While your OAuth consent screen is in "Testing" status, tokens/refresh tokens are still fully
  functional for the test users you added - "Testing" only limits *who* can authorize, not what
  the app can do. Moving to "In production" requires a Google verification review if you request
  sensitive scopes broadly; not necessary for a local/demo deployment.
- If you ever see `invalid_grant` or `redirect_uri_mismatch`, the most common cause is the
  redirect URI in `.env` not matching the one registered in the Cloud Console exactly.

## What happens after you connect

- The authorization code IETDS receives is exchanged server-side for an access token and a
  refresh token (`exchange_code_for_token` in `app/providers/gmail_provider.py`); the refresh
  token is what lets background scanning keep working without you re-authorizing every hour.
- IETDS asks Google directly (the userinfo endpoint) which account was actually authorized,
  rather than assuming it matches your IETDS login email - so you can connect a different
  Gmail address than the one you registered IETDS with.
- Tokens are encrypted at rest (Fernet, `ENCRYPTION_KEY`) - see `docs/security.md`.
- Access tokens expire (~1 hour); `mailbox_service.build_provider()` checks the stored expiry
  before every connection and silently refreshes via the stored refresh token when needed, so
  scheduled scans keep working unattended. If the refresh token is ever revoked (e.g. you
  revoked IETDS's access in your Google account settings), reconnect the mailbox from the UI.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Not configured" badge stays after editing `.env` | App wasn't restarted - env vars are only read at startup. |
| `redirect_uri_mismatch` | The URI in `.env` doesn't exactly match what's registered in Google Cloud Console. Check scheme, host, port, and trailing slash. |
| "Access blocked: app has not completed verification" | Add your Google account as a test user on the OAuth consent screen, or stay within the same Google Cloud project's test-user list. |
| Mailbox shows connected but scans start failing after ~1 hour | Should now self-heal via the refresh-token flow above; if it doesn't, check `mailbox_service._ensure_fresh_oauth_token` logs for a refresh failure (usually a revoked grant - reconnect the mailbox). |

## Appendix: why Microsoft 365 / Outlook isn't included

A `MicrosoftGraphProvider` (Microsoft Graph REST API, OAuth 2.0 authorization-code flow,
built against the exact same `MailboxProvider` interface as Gmail) was implemented and tested
earlier in this project. It was removed from the final deployment because registering the
required Azure AD (Microsoft Entra ID) app needs an organizational tenant, and a personal
Microsoft account doesn't have one by default - App registrations in the Azure Portal simply
isn't available until a tenant exists. Two ways around that exist (create a free Entra ID
tenant, or join the Microsoft 365 Developer Program for a free sandbox tenant with a real test
mailbox), but provisioning either was outside this project's timeline. See
`docs/limitations.md` for the full explanation and `docs/mailbox-integration.md`'s "Adding a
new provider" section for what re-adding it later would involve - the provider abstraction was
specifically designed so this is a self-contained addition, not a rearchitecture.
