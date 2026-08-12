"""Quarantine module (Section 29)."""

from __future__ import annotations

from app.extensions import db
from app.models import Email, EmailStatus, QuarantineItem, QuarantineStatus, WhitelistEntry, BlacklistEntry
from app.models.base import utcnow
from app.services import audit_service


def quarantine_email(email: Email, reason: str) -> QuarantineItem:
    item = QuarantineItem(email_id=email.id, mailbox_id=email.mailbox_id, reason=reason,
                           status=QuarantineStatus.QUARANTINED, quarantined_at=utcnow())
    email.status = EmailStatus.QUARANTINED
    db.session.add(item)
    db.session.add(email)
    db.session.commit()
    audit_service.log_event("email_quarantined", target_type="email", target_id=email.id,
                             metadata={"reason": reason})
    return item


def release_email(item: QuarantineItem, user_id: str) -> None:
    item.status = QuarantineStatus.RELEASED
    item.released_at = utcnow()
    item.released_by_id = user_id
    item.email.status = EmailStatus.RELEASED
    db.session.commit()
    audit_service.log_event("email_released", user_id=user_id, target_type="email", target_id=item.email_id)


def mark_safe(item: QuarantineItem, user_id: str) -> None:
    item.status = QuarantineStatus.MARKED_SAFE
    item.released_at = utcnow()
    item.released_by_id = user_id
    item.email.status = EmailStatus.RELEASED
    item.email.classification = "clean"
    db.session.commit()
    audit_service.log_event("email_marked_safe", user_id=user_id, target_type="email", target_id=item.email_id)


def delete_permanently(item: QuarantineItem, user_id: str) -> None:
    item.status = QuarantineStatus.DELETED
    item.email.status = EmailStatus.DELETED
    db.session.commit()
    audit_service.log_event("email_deleted", user_id=user_id, target_type="email", target_id=item.email_id)


def whitelist_sender(email: Email, organization_id: str, user_id: str, entry_type: str = "email") -> WhitelistEntry:
    value = email.sender if entry_type == "email" else email.sender_domain
    existing = WhitelistEntry.query.filter_by(organization_id=organization_id, value=value).first()
    if existing:
        existing.enabled = True
        db.session.commit()
        return existing
    entry = WhitelistEntry(organization_id=organization_id, user_id=user_id, entry_type=entry_type, value=value)
    db.session.add(entry)
    db.session.commit()
    audit_service.log_event("whitelist_changed", user_id=user_id, target_type="whitelist", target_id=entry.id,
                             metadata={"action": "add", "value": value})
    return entry


def blacklist_sender(email: Email, organization_id: str, user_id: str, entry_type: str = "email") -> BlacklistEntry:
    value = email.sender if entry_type == "email" else email.sender_domain
    existing = BlacklistEntry.query.filter_by(organization_id=organization_id, value=value).first()
    if existing:
        existing.enabled = True
        db.session.commit()
        return existing
    entry = BlacklistEntry(organization_id=organization_id, user_id=user_id, entry_type=entry_type, value=value)
    db.session.add(entry)
    db.session.commit()
    audit_service.log_event("blacklist_changed", user_id=user_id, target_type="blacklist", target_id=entry.id,
                             metadata={"action": "add", "value": value})
    return entry
