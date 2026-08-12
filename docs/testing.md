# Testing

```bash
pytest                  # everything
pytest -q               # quiet
pytest --cov=app        # with coverage (requires pytest-cov, already in requirements.txt)
```

No test in this suite requires a live mailbox, real credentials, or network access - provider
tests mock `imaplib`/HTTP, and everything else runs against an in-memory SQLite database
(`TestingConfig`, `SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"`).

## Layout

```
tests/
    conftest.py            Shared fixtures: app, client, db, organization, admin_user, regular_user
    unit/                  Pure-logic tests, no HTTP, no live DB writes beyond in-memory setup
        test_email_parser.py
        test_spam_rules.py / test_scam_rules.py / test_phishing_rules.py
        test_url_rules.py / test_attachment_rules.py
        test_scoring_and_classification.py
        test_custom_rules.py
    integration/            Full request/response + database integration
        test_auth.py
        test_pipeline.py    Demo mailbox -> scan -> classification -> policy, end to end
        test_quarantine.py
        test_api.py
    security/                Security-specific regression tests
        test_idor.py         Cross-organization access must always be 403
        test_csrf.py          POST without a CSRF token must be rejected
        test_xss_and_html_sanitization.py
        test_injection_and_auth_bypass.py
    providers/
        test_demo_provider.py
        test_imap_provider.py   Mocks imaplib.IMAP4_SSL - no live server required
```

## What each layer actually proves

- **Unit tests** prove individual rules fire (and don't false-positive) on realistic inputs
  built with `tests/unit/helpers.py`'s `make_context`/`make_url`/`make_attachment` builders,
  and that scoring/classification arithmetic and threshold logic is correct in isolation.
- **Integration tests** prove the full pipeline (`scanner_service.run_scan`) - deduplication,
  whitelist short-circuiting, and the specific demo fixtures - produces the expected
  classifications and persisted records, and that quarantine state transitions work.
- **Security tests** are regression tests for exactly the two real vulnerabilities this
  project's own test suite caught during development (see `docs/security.md`): an
  organization-scoping bypass in the `is_admin` IDOR check, and (as a defense-in-depth check,
  not a discovered bug) that CSRF and email-HTML sanitization behave as specified.
- **Provider tests** prove the IMAP command sequence (`SELECT`/`UID SEARCH`/`UID FETCH`/login)
  is correct without needing a real mailbox, by mocking `imaplib.IMAP4_SSL`.

## Manual verification checklist

For a supervisor demo, beyond the automated suite:

1. `python run.py`, register an account.
2. Add a Demo mailbox, click Scan Now, confirm the Dashboard populates with real counts and
   charts (not zeros/placeholders).
3. Open a PHISHING or SCAM email from the Emails list and confirm the score breakdown and
   triggered-rules list match what's described in `docs/detection-engine.md`.
4. Release one quarantined email and mark another as a false positive; confirm both actions
   are reflected immediately and recorded in the Audit Log.
5. Create a custom rule (e.g. matching a phrase specific to your demo), re-scan, and confirm
   it appears in the triggered-rules list alongside the built-in rules.
6. Visit `/health` and confirm the background worker shows RUNNING.
