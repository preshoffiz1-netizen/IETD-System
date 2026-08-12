# Architecture

## System overview

IETDS is a layered Flask application. Each layer only depends on the layer below it, which is
what makes the detection engine and the mailbox providers independently testable:

```
Routes (app/routes)             <- HTTP/JSON boundary, auth, CSRF, IDOR checks
    |
Services (app/services)         <- Business logic: scanning, scoring, classification, policy
    |
Detection (app/detection)       <- Pure, stateless rule-based detectors
    |
Providers (app/providers)       <- Mailbox access abstraction (IMAP/Gmail/Microsoft/Demo)
    |
Models (app/models)             <- SQLAlchemy ORM / persistence
```

## Data flow: one scan, end to end

1. A scan is triggered (`POST /mailboxes/<id>/scan`, the API equivalent, or the APScheduler
   dispatch tick for monitored mailboxes) and calls `scanner_service.run_scan(mailbox)`.
2. A `ScanJob` row is created (`queued` -> `connecting` -> `scanning` -> `analyzing` ->
   `completed`/`failed`), so scan history and real-time status are always queryable.
3. `mailbox_service.build_provider(mailbox)` instantiates the correct `MailboxProvider`
   subclass with decrypted credentials.
4. `provider.fetch_new_messages()` returns `RawMessage` objects (provider-agnostic: raw MIME
   bytes + a UID) for anything newer than `mailbox.last_uid_scanned`.
5. For each message: `email_parser.parse_raw_message()` turns the raw bytes into a
   `ParsedEmail` (sender, subject, body, URLs, attachments, SPF/DKIM/DMARC results).
6. A `dedup_key` (Message-ID if present, else provider UID) is checked against existing
   `Email` rows for that mailbox - duplicates are skipped (Section 53).
7. An `EmailContext` is built (parsed email + the organization's whitelist/blacklist sets).
   If the sender is whitelisted, the email is force-classified CLEAN and the pipeline
   short-circuits (whitelist always overrides detection, per Section 30).
8. `threat_engine.analyze()` runs every built-in rule (`app/detection/*_rules.py`) plus every
   enabled custom rule for the organization, returning a list of `RuleResult`.
9. `scoring_service.calculate_score()` aggregates those results into a `ScoreBreakdown` (one
   score per category: sender/subject/body/url/attachment/header/authentication/spam/scam/
   phishing, plus a total).
10. `classification_service.classify()` maps the breakdown to one of six classifications using
    thresholds stored in `SystemSetting` (editable from Settings, not hardcoded).
11. `policy_service.execute_policy()` looks up the configured action(s) for that
    classification (`SystemSetting` key `action.<classification>`) and executes them: update
    email status, create a `QuarantineItem`, create a `Notification`, and/or call the
    provider's `move_message`/`mark_as_spam`/`delete_message` where the provider supports it.
12. Everything is persisted (`Email`, `ThreatAnalysis`, `ThreatIndicator` rows) and an
    `AuditLog` entry records the scan outcome.
13. `mailbox.last_uid_scanned` and per-mailbox counters are updated so the next scan only
    looks at genuinely new mail.

## Why services are split the way they are

Each stage above is a separate, independently unit-testable module specifically so the
detection logic (which is the part examiners will scrutinize most closely) can be tested
without a database, an HTTP request, or a real mailbox:

- `email_parser` is pure functions over bytes -> `ParsedEmail`.
- `detection/*_rules.py` are pure functions over `EmailContext` -> `RuleResult`.
- `scoring_service` is a pure function over `list[RuleResult]` -> `ScoreBreakdown`.
- `classification_service` is a pure function (given thresholds) over `ScoreBreakdown` ->
  classification string.

Only `scanner_service` and `policy_service` touch the database and the network, and they do
so by composing the pure pieces above.

## Background scanning

`app/services/scheduler.py` starts an APScheduler `BackgroundScheduler` inside the Flask
process on app startup. A single dispatch job runs every minute and, for each mailbox with
`monitoring_enabled=True` whose `scan_interval_minutes` has elapsed since its last scan, calls
`scanner_service.run_scan(mailbox, trigger="scheduled")`. This avoids ever running a mailbox
scan inside an HTTP request/response cycle (Section 37) while keeping the deployment simple
(no Redis/Celery required for a typical final-year-project demo). The interface is narrow
enough that swapping in a Celery-based worker later only means replacing this one module.

## Multi-tenancy model

```
Organization
    +-- Users (role: admin | user)
    +-- Mailboxes
    |     +-- Emails
    |           +-- Attachments, URLRecords, ThreatAnalysis (+ ThreatIndicators), QuarantineItem
    +-- DetectionRule (custom rules) + RuleCondition
    +-- WhitelistEntry / BlacklistEntry
    +-- AuditLog
```

Every organization-scoped route checks `resource.organization_id == current_user.organization_id`
before allowing access - `role == admin` grants extra permissions *within* an organization
(user management, threshold/policy changes) but never bypasses the organization boundary. This
is covered by `tests/security/test_idor.py`.
