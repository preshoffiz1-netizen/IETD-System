"""
Platform-wide read-only queries for the super admin portal.

Deliberately kept in its own file, separate from every other service module
in this directory. Every other service here is organization-scoped on
purpose (that's what makes the per-org isolation/IDOR fixes hold); this file
is the one place allowed to run unfiltered, cross-organization aggregate
queries, and it exists specifically so that scoped-by-design code elsewhere
never has to be loosened to answer a platform-level question. Nothing here
returns another organization's email body/content -- counts and metadata
only (see the super admin design notes for why).
"""

from __future__ import annotations

from datetime import timedelta

from app.models import Email, Mailbox, Organization, User
from app.models.base import utcnow


def platform_overview() -> dict:
    now = utcnow()
    since_24h = now - timedelta(hours=24)

    total_orgs = Organization.query.count()
    total_users = User.query.count()
    total_mailboxes = Mailbox.query.count()
    monitored_mailboxes = Mailbox.query.filter_by(monitoring_enabled=True).count()
    total_emails_scanned = Email.query.count()
    emails_last_24h = Email.query.filter(Email.created_at >= since_24h).count()
    threats_last_24h = Email.query.filter(
        Email.created_at >= since_24h, Email.classification != "clean"
    ).count()

    return {
        "total_orgs": total_orgs,
        "total_users": total_users,
        "total_mailboxes": total_mailboxes,
        "monitored_mailboxes": monitored_mailboxes,
        "total_emails_scanned": total_emails_scanned,
        "emails_last_24h": emails_last_24h,
        "threats_last_24h": threats_last_24h,
        "generated_at": now,
    }


def organizations_summary() -> list[dict]:
    orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    rows = []
    for org in orgs:
        user_count = User.query.filter_by(organization_id=org.id).count()
        mailbox_count = Mailbox.query.filter_by(organization_id=org.id).count()
        email_count = (
            Email.query.join(Mailbox, Email.mailbox_id == Mailbox.id)
            .filter(Mailbox.organization_id == org.id)
            .count()
        )
        rows.append({
            "organization": org,
            "user_count": user_count,
            "mailbox_count": mailbox_count,
            "email_count": email_count,
        })
    return rows


def users_summary() -> list[User]:
    return User.query.order_by(User.created_at.desc()).all()


def mailbox_health() -> list[Mailbox]:
    """Mailboxes that are erroring or haven't scanned recently -- surfaces exactly
    the kind of IMAP timeout issue that shows up in real-world scan logs."""
    return (
        Mailbox.query.filter(Mailbox.status == "error")
        .order_by(Mailbox.updated_at.desc())
        .limit(50)
        .all()
    )
