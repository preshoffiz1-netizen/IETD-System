# REST API

All endpoints are under `/api` and require an authenticated session (the same Flask-Login
session cookie used by the web UI) - there is no separate API token in this project, which
keeps things simple for a final-year build while still being a genuinely protected API: every
route enforces the same organization-scoped access control as the HTML routes.

## Authentication

```
POST /api/auth/login
Content-Type: application/json
{"email": "user@example.com", "password": "..."}
```

Returns `{"success": true, "user": {...}}` and sets the session cookie on success, or 401 on
failure. This endpoint is CSRF-exempt (JSON body, not a browser form) but still goes through
the same Argon2 password check as the HTML login form.

## Mailboxes

| Method | Path | Description |
|---|---|---|
| GET | `/api/mailboxes` | List mailboxes in the caller's organization, including capabilities. |
| POST | `/api/mailboxes/<id>/test` | Test the mailbox connection. |
| POST | `/api/mailboxes/<id>/scan` | Trigger a scan and return the resulting `ScanJob` summary. |

## Emails

| Method | Path | Description |
|---|---|---|
| GET | `/api/emails?classification=phishing&limit=50` | List emails, optionally filtered. |
| GET | `/api/emails/<id>` | Full email detail including score breakdown and triggered rules. |

## Quarantine

| Method | Path | Description |
|---|---|---|
| GET | `/api/quarantine` | List quarantine items. |
| POST | `/api/quarantine/<id>/release` | Release an item back to the inbox. |
| POST | `/api/quarantine/<id>/delete` | Permanently delete a quarantined email. |

## Rules

| Method | Path | Description |
|---|---|---|
| GET | `/api/rules` | List custom rules. |
| POST | `/api/rules` | Create a custom rule (JSON body: name, category, score, action, conditions[]). |
| PUT | `/api/rules/<id>` | Update a rule's fields. |
| DELETE | `/api/rules/<id>` | Delete a rule. |

## Dashboard / Reports

| Method | Path | Description |
|---|---|---|
| GET | `/api/dashboard/stats` | Same counts shown on the dashboard cards - real DB aggregates. |
| GET | `/api/reports` | Combined stats + top senders/domains/rules. |

## Health (unauthenticated)

`GET /api/health` returns a JSON liveness payload (application/database/background-worker
status) suitable for a load balancer or uptime monitor - the only endpoint in the app that
does not require login, by design.

## Access control

Every handler re-derives the caller's organization from `current_user.organization_id` and
compares it against the resource's `organization_id` before returning data or performing an
action - identical to the HTML routes, and covered by the same IDOR test suite
(`tests/security/test_idor.py`) plus `tests/integration/test_api.py`.
