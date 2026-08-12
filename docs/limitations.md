# Limitations

Stated honestly, as required for academic defensibility (Section 71).

1. **Rule-based, not machine learning.** The system will not catch a genuinely novel attack
   pattern that matches none of its rules. This is a deliberate trade-off (explainability,
   cost, maintainability) explained in `docs/detection-engine.md`, not an oversight.

2. **Post-delivery filtering is the guarantee; pre-delivery is provider-dependent.** IETDS
   always sees mail *after* it has already landed in the mailbox for generic IMAP
   connections. True pre-delivery blocking is only possible where the provider exposes it
   (Gmail/Microsoft Graph server-side rules), and this deployment does not request the
   additional OAuth scope (`gmail.settings.basic`) needed for Gmail filter creation
   specifically - see `docs/mailbox-integration.md`.

3. **No sandboxing or antivirus scanning of attachments.** Attachments are inspected
   (filename, extension, MIME type, size, hash) but never opened or executed. A cleverly
   disguised malicious file that doesn't match any of the extension/macro heuristics would not
   be caught by content analysis.

4. **Local-only reputation data.** Whitelist/blacklist and lookalike-domain detection are
   entirely local (no external threat-intelligence API), per Section 25's explicit
   requirement that basic operation not depend on a paid API. This means brand-new malicious
   domains that aren't lookalikes of a known brand and aren't yet blacklisted will not be
   flagged by domain reputation alone (though other signals - content, authentication
   failures, attachment analysis - may still catch the message).

5. **Push notifications are not implemented.** Both `GmailProvider` and
   `MicrosoftGraphProvider` declare `push_notifications: True` in their capability model to
   reflect that the *provider* supports it, but IETDS itself only polls (via the APScheduler
   dispatch tick) - it does not yet register for Gmail Pub/Sub or Graph change notifications.

6. **Single-process background scheduling.** The default APScheduler-in-Flask-process
   approach (Section 4's documented lightweight alternative to Celery+Redis) is appropriate
   for a single-instance deployment; horizontally scaling to multiple app instances requires
   either pinning the scheduler to one instance or swapping in a real task queue (see
   `docs/deployment.md`).

7. **Testing scope.** The case study/testing environment used during development was a
   personal Gmail account and the built-in synthetic demo fixtures (Section 3's stated scope);
   the system has not been validated at enterprise mailbox volumes or against every possible
   mail server's IMAP quirks.

8. **PDF report export is not implemented.** CSV and JSON export are implemented
   (`/reports/export/csv`, `/reports/export/json`); PDF is listed as a "future enhancement"
   rather than implemented, since it was explicitly optional in the brief and the underlying
   data (`report_service`) is already in place for whoever adds it.

9. **Single organization per user at registration.** Registering an account creates a new
   organization with that user as its admin; there is no invitation/join-existing-organization
   flow yet, so multi-user organizations currently require an admin to manually create
   additional user accounts (a natural next step, not implemented in this iteration).
