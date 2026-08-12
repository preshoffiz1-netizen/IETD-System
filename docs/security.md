# Security

## Authentication and passwords

- Passwords are hashed with **Argon2** (`argon2-cffi`), the current recommended password
  hashing algorithm, via `app/utils/security.py`. Plaintext passwords are never stored or
  logged.
- Sessions use Flask-Login with `HttpOnly`, `SameSite=Lax` cookies; `Secure` is enabled
  automatically in the production config.
- `/login` and `/register` are rate-limited (Flask-Limiter) to slow down credential-stuffing
  and account-enumeration attempts.
- Disabled accounts (`User.is_active_flag = False`) cannot log in even with correct
  credentials.

## Authorization and IDOR protection

Every route that loads a mailbox, email, quarantine item, whitelist/blacklist entry, or custom
rule by ID re-checks that the resource's `organization_id` matches
`current_user.organization_id` before returning anything - the `admin` role grants extra
permissions *within* an organization (user management, threshold/policy changes) but never
crosses the organization boundary. This is enforced consistently across the HTML routes and
the JSON API, and regression-tested in `tests/security/test_idor.py`.

> **Development note, documented rather than hidden**: an earlier version of this access-check
> pattern read `if not current_user.is_admin and resource.organization_id != current_user.organization_id: abort(403)`,
> which meant an organization admin (who is only supposed to administer *their own*
> organization) could access *any* organization's mailboxes/emails/quarantine by guessing an
> ID, because the `is_admin` check short-circuited the organization comparison entirely. This
> was caught by this project's own IDOR test suite during development and fixed by removing
> the bypass - the check is now unconditional. This is exactly the kind of defect the "Security
> Tests: Unauthorized access, IDOR" requirement (Section 51) exists to catch, and it is
> recorded here rather than quietly removed from history, since demonstrating that testing
> caught a real bug is part of the point of a project like this.

## CSRF

Flask-WTF's `CSRFProtect` is enabled globally. Every state-changing form includes a
`csrf_token` hidden field; a POST without a valid token is rejected with 400. The one
exception is `POST /api/auth/login`, which is JSON-only (not a browser form submission) and is
explicitly exempted - it is still protected by rate limiting and normal password verification.

## Credential encryption at rest

Mailbox app passwords and OAuth tokens are encrypted with **Fernet** (symmetric,
authenticated encryption) before being written to the database, using `ENCRYPTION_KEY` from
the environment. Decryption happens only inside `app/services/mailbox_service.py`, immediately
before instantiating a provider - no other module reads these columns. Application secrets
(`SECRET_KEY`, `ENCRYPTION_KEY`, OAuth client secrets) live in environment variables
(`.env`, excluded from version control), never in source code.

## Untrusted email HTML

Email bodies are attacker-controlled input. `app/utils/security.sanitize_email_html()` runs
every HTML body through `bleach.clean()` with a strict tag/attribute allow-list before
rendering - `<script>`, event handler attributes (`onerror`, `onclick`, ...), `<iframe>`,
`javascript:` URIs, and (deliberately) inline `style` attributes are all stripped. `style` is
excluded specifically because sanitizing CSS safely requires bleach's optional
`css_sanitizer` (a `tinycss2` dependency); rather than allow unsanitized CSS through, the
attribute is dropped entirely. Covered by `tests/security/test_xss_and_html_sanitization.py`.

## SQL injection

All database access goes through the SQLAlchemy ORM with parameterized queries - there is no
raw, string-formatted SQL anywhere in the codebase. `tests/security/test_injection_and_auth_bypass.py`
confirms that injection-style payloads in the login form and search filters are treated as
literal data, not executed as SQL.

## File upload validation

CSV import for whitelist/blacklist entries validates the file extension and caps the read size
at 2MB before parsing, to avoid trivial resource-exhaustion or extension-spoofing issues.

## Attachment handling

Attachments are inspected only (filename, extension, MIME type, size, SHA-256 hash) - never
opened, executed, or passed to any interpreter. There is no sandboxing or antivirus scanning
in this project (see `docs/limitations.md`).

## Security headers

Set on every response (`app/__init__.py`): `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, a restrictive
`Content-Security-Policy`, and `Strict-Transport-Security` once cookies are marked secure.

## Error handling

Custom error handlers (400/401/403/404/429/500) render a generic message - raw exception
details and stack traces are never shown to the client; the 500 handler logs the full
traceback server-side via `current_app.logger.exception()`.

## Logging

Structured logging is configured in `app/__init__.py`. `app/services/audit_service.py`
explicitly scrubs any metadata key resembling `password`/`token`/`secret`/`encryption_key`
before writing an `AuditLog` row, and no module ever logs a decrypted credential.
