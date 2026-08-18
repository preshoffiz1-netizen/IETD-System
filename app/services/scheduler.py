"""
Background scanning (Section 37).

Uses APScheduler's BackgroundScheduler running inside the Flask process --
no external broker required, which keeps a final-year-project deployment
simple. (Section 4 explicitly allows this as the lightweight alternative to
Celery + Redis; the interface below is narrow enough that swapping in a
Celery-based worker later would only mean replacing this module.)

Each mailbox with monitoring_enabled=True gets its own recurring job at its
configured scan_interval_minutes. Scans never run inside an HTTP request.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("ietds.scheduler")

_scheduler: BackgroundScheduler | None = None


def init_scheduler(app) -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=lambda: _run_all_monitored_mailboxes(app),
        trigger="interval",
        minutes=1,
        id="ietds_monitor_dispatch",
        replace_existing=True,
        # A slow IMAP round-trip (retries, timeouts) can make one tick run
        # longer than the 1-minute interval; without this, APScheduler skips
        # the next tick entirely and logs a "maximum number of running
        # instances reached" warning instead of just letting the two
        # overlap safely (each tick only touches mailboxes whose interval
        # has actually elapsed, so overlap is harmless).
        max_instances=2,
        coalesce=True,
    )
    scheduler.start()
    _scheduler = scheduler
    app.extensions["ietds_scheduler"] = scheduler
    logger.info("Background scheduler started (dispatch tick: every 1 minute).")
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def _run_all_monitored_mailboxes(app) -> None:
    """
    Dispatch tick: runs every minute, and for each monitored mailbox whose
    scan_interval has elapsed since its last scan, kicks off a scan. This
    single-job-fans-out-to-many-mailboxes design avoids registering/
    unregistering a job per mailbox as monitoring is toggled.
    """
    from datetime import timedelta, timezone

    from app.extensions import db
    from app.models import Mailbox
    from app.models.base import utcnow
    from app.services.scanner_service import run_scan

    with app.app_context():
        try:
            mailboxes = Mailbox.query.filter_by(monitoring_enabled=True).all()
        except Exception:
            logger.exception("Could not query mailboxes for scheduled scanning")
            return

        now = utcnow()
        for mailbox in mailboxes:
            interval = timedelta(minutes=mailbox.scan_interval_minutes or 5)
            last_scan_at = mailbox.last_scan_at
            if last_scan_at is not None and last_scan_at.tzinfo is None:
                # SQLite (and some other DBAPIs) always hand back naive datetimes,
                # even though utcnow() -- what wrote this column -- is UTC-aware.
                # Re-attach UTC so this subtraction doesn't raise TypeError.
                last_scan_at = last_scan_at.replace(tzinfo=timezone.utc)
            if last_scan_at and (now - last_scan_at) < interval:
                continue
            try:
                run_scan(mailbox, trigger="scheduled")
            except Exception:
                logger.exception("Scheduled scan failed for mailbox %s", mailbox.id)
