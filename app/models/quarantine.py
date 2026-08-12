from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class QuarantineStatus:
    QUARANTINED = "quarantined"
    RELEASED = "released"
    DELETED = "deleted"
    MARKED_SAFE = "marked_safe"


class QuarantineItem(db.Model, TimestampMixin):
    __tablename__ = "quarantine_items"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    email_id = db.Column(db.String(32), db.ForeignKey("emails.id"), nullable=False, unique=True)
    mailbox_id = db.Column(db.String(32), db.ForeignKey("mailboxes.id"), nullable=False)

    reason = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), default=QuarantineStatus.QUARANTINED, nullable=False)

    quarantined_at = db.Column(db.DateTime, nullable=True)
    released_at = db.Column(db.DateTime, nullable=True)
    released_by_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)

    email = db.relationship("Email", back_populates="quarantine_item")


class ScanJobStatus:
    QUEUED = "queued"
    CONNECTING = "connecting"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    QUARANTINING = "quarantining"
    COMPLETED = "completed"
    FAILED = "failed"

    ALL = (QUEUED, CONNECTING, SCANNING, ANALYZING, QUARANTINING, COMPLETED, FAILED)


class ScanJob(db.Model, TimestampMixin):
    __tablename__ = "scan_jobs"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    mailbox_id = db.Column(db.String(32), db.ForeignKey("mailboxes.id"), nullable=False)

    status = db.Column(db.String(20), default=ScanJobStatus.QUEUED, nullable=False)
    trigger = db.Column(db.String(20), default="manual")  # manual / scheduled / demo

    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    messages_processed = db.Column(db.Integer, default=0)
    clean_count = db.Column(db.Integer, default=0)
    suspicious_count = db.Column(db.Integer, default=0)
    spam_count = db.Column(db.Integer, default=0)
    scam_count = db.Column(db.Integer, default=0)
    phishing_count = db.Column(db.Integer, default=0)
    malicious_attachment_count = db.Column(db.Integer, default=0)
    quarantined_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)

    mailbox = db.relationship("Mailbox", back_populates="scan_jobs")
