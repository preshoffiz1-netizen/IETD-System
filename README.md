# IETDS - Integrated Email Threat Detection System

**An Integrated Email Threat Detection System for Individuals and Small-Scale Organizations**

> Protecting every mailbox from spam, scams, and email-based threats.

IETDS is a rule-based email security web application built as a final-year Computer Science
project. It connects to a mailbox (generic IMAP, or Gmail via OAuth 2.0), scans incoming email,
and uses a transparent, explainable, weighted
rule-based detection engine to classify each message as **CLEAN**, **SUSPICIOUS**, **SPAM**,
**SCAM**, **PHISHING**, or **MALICIOUS_ATTACHMENT** - then quarantines, flags, or allows it
according to a configurable action policy.

This is a working application, not a mockup: every dashboard number comes from the database,
every detection decision is explainable (you can see exactly which rules fired and why), and
the whole thing runs locally with SQLite and no paid APIs.

## 1. Project Description

Email remains one of the most exploited attack vectors in cybersecurity, and individuals and
small organizations are disproportionately vulnerable because commercial email security
platforms (Microsoft Defender, Proofpoint, Cisco Secure Email, Barracuda) are proprietary,
subscription-based, and enterprise-oriented. IETDS closes that gap with a low-cost,
explainable, rule-based system that individuals and small teams can run themselves.

## 2. Objectives

1. Study existing email protection methods and their limitations.
2. Design and implement a low-cost, rule-based email threat detection system.
3. Implement the design as a working, testable web application.

## 3. Features

- Multi-provider mailbox connection: generic IMAP and Gmail (OAuth 2.0), plus a built-in Demo
  mode with synthetic test emails. (A Microsoft 365/Outlook Graph API provider was designed and
  implemented but removed from this deployment - see `docs/limitations.md`.)
- Full ingestion pipeline: fetch -> deduplicate -> parse -> analyze -> score -> classify ->
  act -> persist -> audit.
- Rule-based detection engine covering spam, scam, phishing, malicious URLs, dangerous
  attachments, header anomalies, and SPF/DKIM/DMARC authentication results.
- Transparent threat scoring with a full per-rule explanation for every classification.
- Configurable action/policy engine (allow / flag / quarantine / move-to-spam /
  move-to-folder / delete / notify) per classification.
- Quarantine management, whitelist/blacklist (with CSV import/export), and a visual custom
  rule builder for organization-specific detection logic.
- Dashboard with real charts (classification distribution, threats over time, score
  distribution, top senders/domains, most-triggered rules) and a recent-threats table.
- Reports with CSV/JSON export, a full audit log, and a system health page.
- Multi-mailbox, multi-user, organization-scoped, role-based (admin/user) architecture.
- REST API mirroring the web UI for programmatic access.
- Background scanning via APScheduler (no HTTP request ever blocks on a mailbox scan).
- Security: Argon2 password hashing, encrypted mailbox credentials at rest (Fernet),
  CSRF protection, secure cookies/headers, sanitized email HTML rendering, IDOR-safe
  organization-scoped access control, rate-limited auth endpoints.

## 4. Architecture

```
User
  |
  v
Web Application (Flask)
  |
  v
Mailbox Provider Layer  --  IMAPProvider / GmailProvider / DemoProvider
  |
  v
Email Ingestion (scanner_service) -> Email Parser (email_parser)
  |
  v
Detection Engine (app/detection/*_rules.py)
  +-- Sender / Header / Authentication (SPF, DKIM, DMARC)
  +-- Spam / Scam / Phishing keyword & pattern rules
  +-- URL analysis (IP URLs, shorteners, lookalike/punycode domains, display mismatch)
  +-- Attachment analysis (dangerous extensions, macros, double extensions)
  +-- Custom rules (Rule Builder, stored in the database)
  |
  v
Threat Scoring (scoring_service) -> Classification (classification_service)
  |
  v
Action / Policy Engine (policy_service)
  +-- Allow / Flag / Quarantine / Move-to-Spam / Move-to-Folder / Delete / Notify
  |
  v
Dashboard / Reports / Audit Logs / Quarantine UI
```

See `docs/architecture.md` for the full data-flow diagram and `docs/detection-engine.md` for
how the rule-based engine and scoring model work.

## 5. Technology Stack

| Layer | Choice |
|---|---|
| Backend | Python 3.11+, Flask |
| Database | SQLite (dev), SQLAlchemy ORM (PostgreSQL-ready) |
| Frontend | Server-rendered HTML/Jinja2, Bootstrap 5, Chart.js, vanilla JS |
| Background jobs | APScheduler (in-process; Celery+Redis-ready architecture) |
| Auth | Flask-Login, Argon2 password hashing, Flask-WTF CSRF protection |
| Mailbox integration | `imaplib` (generic IMAP + Gmail XOAUTH2) |
| Testing | pytest |
| Production server | gunicorn (WSGI) |

## 6. Requirements

- Python 3.11 or later
- pip
- (Optional) Redis, only if you later switch `SCHEDULER_BACKEND` to a Celery-based worker

## 7. Installation

```bash
git clone <your-repo-url> ietds
cd ietds
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 8. Environment Setup

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"          # -> paste into SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # -> paste into ENCRYPTION_KEY
```

Edit `.env` and fill in `SECRET_KEY` and `ENCRYPTION_KEY` at minimum. Everything else has a
sensible development default. See `.env.example` for the full list (Gmail OAuth credentials
are optional and only needed if you want to connect that provider).

## 9. Database Setup

The database is created automatically on first run (`db.create_all()` inside the application
factory), so no manual migration step is required for local development. Flask-Migrate is
wired up (`migrations/`) for anyone who wants to move to versioned migrations later:

```bash
flask --app wsgi:app db init      # first time only
flask --app wsgi:app db migrate -m "initial schema"
flask --app wsgi:app db upgrade
```

## 10. Running the App (development)

```bash
python run.py
```

Visit `http://127.0.0.1:5000`, register an account (this also creates your organization), and
either connect a real mailbox or add the **Demo mailbox** to see the system work end-to-end
with synthetic example emails immediately.

## 11. Connecting a Generic IMAP Mailbox

Go to **Mailboxes -> Connect Mailbox -> Generic IMAP** and provide the email address, an app
password (not your normal password, if your provider supports app passwords - Gmail and
Outlook both do), the IMAP host (e.g. `imap.gmail.com`, `outlook.office365.com`), port
(usually 993), and whether to use SSL/TLS. The password is encrypted (Fernet) before it is
stored.

## 12. Connecting Gmail (OAuth 2.0)

1. In the [Google Cloud Console](https://console.cloud.google.com/), create OAuth 2.0
   credentials (Web application) and add `http://localhost:5000/mailboxes/oauth/gmail/callback`
   as an authorized redirect URI.
2. Put the client ID/secret into `.env` as `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET`.
3. In IETDS, go to **Mailboxes -> Connect Mailbox -> Gmail -> Connect with Google**.

IETDS never asks for or stores your Google password - only an OAuth token, encrypted at rest.
Full walkthrough with screenshots-equivalent detail: `docs/oauth-setup.md`.

## 13. Running Background Workers

Background scanning is built into the Flask process via APScheduler - there is no separate
worker process to start for local development or a typical final-year-project demo. Enable
**Monitoring** on a mailbox from the Mailboxes page and it will be scanned automatically at
its configured interval (default 5 minutes). See `docs/architecture.md` for how to swap in a
Celery + Redis worker if you need horizontal scaling later.

## 14. Running Tests

```bash
pip install -r requirements.txt   # pytest is included
pytest                              # run everything
pytest tests/unit                   # rule/scoring/classification unit tests
pytest tests/integration            # auth, full pipeline, quarantine, API
pytest tests/security               # IDOR, XSS sanitization, CSRF, SQLi, auth bypass
pytest tests/providers               # mocked provider tests (no live credentials needed)
pytest --cov=app                    # with coverage
```

No test requires live mailbox credentials - provider tests mock `imaplib` / HTTP calls.

## 15. Demo Mode

Every account can add a **Demo mailbox** (Mailboxes -> Connect Mailbox -> Demo Mode) that is
pre-loaded with ten clearly-labelled synthetic emails covering every classification: clean
personal/business email, a newsletter, spam, two scam patterns (lottery/inheritance and
crypto investment), credential-theft phishing, a suspicious-URL message, a macro-enabled
malicious attachment, and a brand-impersonation/spoofing attempt. Click **Scan Now** to run
the full pipeline against them without connecting any real account. No real person's email
content is used anywhere in the demo fixtures.

## 15b. Super Admin Portal (platform owner only)

A separate, read-only "Super Admin" section of the app for the developer running the
deployment - not for regular end users, and not for acting on any individual user's mailbox
or email content. It shows: total organizations/users/mailboxes, emails scanned system-wide
(all-time and last 24h), which mailboxes are currently erroring, a cross-organization user
list, and a live tail of the app's own recent log lines (errors/warnings/info) straight from
the browser - no shell access needed to see what's going wrong.

Nobody gets this by default, including the account that registers first. Grant it explicitly:

```bash
flask --app run.py create-super-admin you@gmail.com      # local dev
flask --app wsgi:app create-super-admin you@gmail.com     # production
flask --app wsgi:app revoke-super-admin you@gmail.com     # to undo
```

There is deliberately no web route or UI toggle that can grant this - only that CLI command,
run directly on the machine - so a compromised account can never grant itself platform-wide
visibility. It's a completely separate flag (`User.is_super_admin`) from the existing
per-organization `is_admin`/role checks, kept in its own service module
(`app/services/superadmin_service.py`) with its own decorator
(`app/utils/decorators.py:super_admin_required`), specifically so it can never be satisfied by
loosening (or reusing) the org-scoped access control that the IDOR tests above depend on.

A super admin account is otherwise a completely ordinary account - same organization, own
mailboxes, own rules, everything else in the app works identically - so you can use one login
to both try IETDS as a real end user would and see the platform-wide picture.

## 16. Security Notes

- Passwords are hashed with Argon2 (never stored in plaintext).
- Mailbox passwords and OAuth tokens are encrypted at rest with Fernet (`ENCRYPTION_KEY`).
- CSRF protection is enabled on every state-changing form (Flask-WTF).
- Untrusted email HTML is sanitized (`bleach`) before being rendered - scripts, event
  handlers, iframes, and inline styles are stripped.
- Access control is organization-scoped and checked on every mailbox/email/quarantine/rule
  route - a user in one organization cannot read or act on another organization's data, and
  this is covered by automated IDOR tests (`tests/security/test_idor.py`).
- Auth endpoints are rate-limited; SQL access goes exclusively through the SQLAlchemy ORM
  (parameterized queries - no raw string-built SQL).
- The application never permanently deletes a dangerous email by default - only
  quarantine/flag/notify actions are enabled out of the box.

## 17. Limitations (stated honestly, per academic requirement)

- **Detection approach**: the core engine is rule-based, not machine learning. This is a
  deliberate design choice (see `docs/detection-engine.md`) favoring explainability,
  affordability, and low computational requirements over the marginal accuracy gains of ML
  approaches that require training data and ongoing retraining.
- **Pre-delivery vs. post-delivery filtering**: IETDS reliably provides *post-delivery*
  filtering for every provider (the email lands in the mailbox, IETDS scans it and takes
  action). True *pre-delivery/server-side* blocking (mail never reaching the inbox) is only
  available where the underlying provider exposes it (Gmail server-side filters) - generic IMAP
  has no such capability. The UI states this explicitly per mailbox (see the provider
  capability model in `app/providers/base.py`).
- **Gmail server-side filters**: creating actual Gmail inbox filters requires the
  `gmail.settings.basic` OAuth scope and the Gmail REST API, which this deployment does not
  request by default (it only requests IMAP mail access). Documented as an extension point.
- **Provider scope**: a Microsoft 365/Outlook provider (Graph API) was designed and fully
  implemented, but was removed from this deployment after Azure app-registration setup proved
  impractical to complete with a personal Microsoft account within the project timeline - see
  `docs/limitations.md` for the full explanation. Generic IMAP and Gmail OAuth are the two
  mailbox connection paths this project is tested against.
- **Scope**: this project is scoped to individual/small-organization use, tested primarily
  against a personal Gmail account, and does not target large-scale enterprise deployment.
- **Attachment analysis**: attachments are inspected (filename, extension, MIME type, hash)
  but never opened, executed, or scanned by an antivirus engine - there is no sandboxing.

## 18. Future Enhancements

- Optional machine-learning-assisted classification as a *complement* to (not replacement of)
  the rule-based engine, with the rule engine remaining the explainable baseline.
- Re-add a Microsoft 365/Outlook (Graph API) provider once a suitable Azure tenant is
  available - the abstraction (`MailboxProvider`) already supports adding it back as a
  self-contained module with no changes needed elsewhere (see `docs/mailbox-integration.md`
  "Adding a new provider").
- Gmail push notifications (Pub/Sub) instead of polling.
- Gmail REST API integration for genuine server-side filter creation.
- PDF report export (CSV/JSON are implemented; PDF is a natural next step via the existing
  report_service data).
- Celery + Redis worker backend for multi-instance horizontal scaling.

## 19. Project Structure

```
ietds/
    app/
        routes/        Flask blueprints (auth, dashboard, mailbox, emails, quarantine, ...)
        services/       Business logic (scanner, threat_engine, scoring, classification, ...)
        providers/      Mailbox provider abstraction (IMAP, Gmail, Demo)
        detection/       Rule-based detection engine (spam/scam/phishing/url/attachment/...)
        models/          SQLAlchemy models
        templates/       Jinja2 templates
        static/          CSS/JS
        utils/           Security, domain analysis, demo fixtures
        config.py
    tests/
        unit/ integration/ security/ providers/
    docs/                Architecture, detection engine, database, API, testing, deployment,
                         security, limitations, and Gmail OAuth setup documentation
    scripts/             Utility scripts (seed data, etc.)
    wsgi.py              Production entry point
    run.py               Local development entry point
    requirements.txt
    .env.example
    .gitignore
```

## 20. GitHub Instructions

This repository is GitHub-ready. To publish it:

```bash
git init
git add .
git commit -m "Initial implementation of IETDS"
git branch -M main
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
```

Before pushing, double-check `git status` shows no `.env`, `instance/*.db`, or other secrets
staged - `.gitignore` already excludes these, but it's worth a manual check on a project like
this.

## License

See `LICENSE`.
