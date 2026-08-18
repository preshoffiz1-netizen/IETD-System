"""
Regression test for the scheduler's monitored-mailbox dispatch tick.

Reproduces a real bug found while testing on Windows: `mailbox.last_scan_at`
comes back from SQLite as a naive datetime, while `utcnow()` (what wrote it)
is timezone-aware, so a bare `now - mailbox.last_scan_at` raised
`TypeError: can't subtract offset-naive and offset-aware datetimes` as soon
as a mailbox had monitoring enabled and at least one prior scan.
"""

from __future__ import annotations

from datetime import timedelta, timezone

from app.models.base import utcnow
from app.services import mailbox_service
from app.services.scheduler import _run_all_monitored_mailboxes


def test_dispatch_tick_does_not_crash_on_naive_last_scan_at(app, db, organization, admin_user):
    mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
    mailbox.monitoring_enabled = True
    # Simulate what SQLite hands back after a round trip: a naive datetime,
    # even though it was written with utcnow() (timezone-aware).
    mailbox.last_scan_at = utcnow().replace(tzinfo=None) - timedelta(minutes=1)
    mailbox.scan_interval_minutes = 5
    db.session.commit()

    _run_all_monitored_mailboxes(app)  # must not raise TypeError

    # Within the interval (1 minute ago, 5 minute interval) -> should have been skipped,
    # so last_scan_at should be unchanged (still naive, still ~1 minute old).
    db.session.refresh(mailbox)
    assert mailbox.last_scan_at.tzinfo is None


def test_dispatch_tick_scans_when_interval_elapsed(app, db, organization, admin_user):
    mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
    mailbox.monitoring_enabled = True
    mailbox.last_scan_at = utcnow().replace(tzinfo=None) - timedelta(minutes=10)
    mailbox.scan_interval_minutes = 5
    db.session.commit()

    _run_all_monitored_mailboxes(app)  # must not raise TypeError

    db.session.refresh(mailbox)
    # A scan should have run and bumped last_scan_at to just now.
    refreshed = mailbox.last_scan_at
    if refreshed.tzinfo is None:
        refreshed = refreshed.replace(tzinfo=timezone.utc)
    assert (utcnow() - refreshed) < timedelta(minutes=1)
