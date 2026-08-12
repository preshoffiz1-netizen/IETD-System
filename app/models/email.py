from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class Classification:
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    SPAM = "spam"
    SCAM = "scam"
    PHISHING = "phishing"
    MALICIOUS_ATTACHMENT = "malicious_attachment"

    ALL = (CLEAN, SUSPICIOUS, SPAM, SCAM, PHISHING, MALICIOUS_ATTACHMENT)
    THREAT_LEVELS = (SUSPICIOUS, SPAM, SCAM, PHISHING, MALICIOUS_ATTACHMENT)


class EmailStatus:
    ACTIVE = "active"          # delivered / visible to user
    FLAGGED = "flagged"
    QUARANTINED = "quarantined"
    RELEASED = "released"
    DELETED = "deleted"


class Email(db.Model, TimestampMixin):
    __tablename__ = "emails"
    __table_args__ = (
        db.UniqueConstraint("mailbox_id", "dedup_key", name="uq_email_mailbox_dedup"),
        db.Index("ix_emails_mailbox_classification", "mailbox_id", "classification"),
    )

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    mailbox_id = db.Column(db.String(32), db.ForeignKey("mailboxes.id"), nullable=False)

    # --- Deduplication (Section 53): provider UID + Message-ID, whichever is stable
    provider_uid = db.Column(db.String(128), nullable=True)
    message_id = db.Column(db.String(512), nullable=True)
    dedup_key = db.Column(db.String(255), nullable=False, index=True)

    # --- Envelope -----------------------------------------------------------------
    sender = db.Column(db.String(320), nullable=True, index=True)
    sender_display_name = db.Column(db.String(255), nullable=True)
    sender_domain = db.Column(db.String(255), nullable=True, index=True)
    recipient = db.Column(db.String(320), nullable=True)
    reply_to = db.Column(db.String(320), nullable=True)
    return_path = db.Column(db.String(320), nullable=True)
    subject = db.Column(db.String(998), nullable=True)

    date_sent = db.Column(db.DateTime, nullable=True)
    date_received = db.Column(db.DateTime, nullable=True)

    # --- Content (Section 45: retention-managed; may be purged independently) -----
    body_text = db.Column(db.Text, nullable=True)
    body_html = db.Column(db.Text, nullable=True)
    raw_headers = db.Column(db.Text, nullable=True)  # JSON-encoded header dict

    # --- Authentication results (Section 24) ---------------------------------------
    spf_result = db.Column(db.String(20), nullable=True)     # pass/fail/neutral/none/not_available
    dkim_result = db.Column(db.String(20), nullable=True)
    dmarc_result = db.Column(db.String(20), nullable=True)

    # --- Detection outcome ------------------------------------------------------------
    classification = db.Column(db.String(30), default=Classification.CLEAN, nullable=False, index=True)
    threat_score = db.Column(db.Integer, default=0, nullable=False)
    action_taken = db.Column(db.String(30), nullable=True)
    status = db.Column(db.String(20), default=EmailStatus.ACTIVE, nullable=False, index=True)

    is_demo = db.Column(db.Boolean, default=False, nullable=False)

    mailbox = db.relationship("Mailbox", back_populates="emails")
    attachments = db.relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    urls = db.relationship("URLRecord", back_populates="email", cascade="all, delete-orphan")
    threat_analysis = db.relationship(
        "ThreatAnalysis", back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    quarantine_item = db.relationship(
        "QuarantineItem", back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    feedback_entries = db.relationship("Feedback", back_populates="email", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Email {self.subject!r} from {self.sender}>"


class Attachment(db.Model, TimestampMixin):
    __tablename__ = "attachments"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    email_id = db.Column(db.String(32), db.ForeignKey("emails.id"), nullable=False)

    filename = db.Column(db.String(500), nullable=False)
    extension = db.Column(db.String(30), nullable=True)
    mime_type = db.Column(db.String(255), nullable=True)
    size_bytes = db.Column(db.Integer, default=0)
    sha256_hash = db.Column(db.String(64), nullable=True)

    is_dangerous_extension = db.Column(db.Boolean, default=False)
    has_double_extension = db.Column(db.Boolean, default=False)
    is_macro_enabled = db.Column(db.Boolean, default=False)

    email = db.relationship("Email", back_populates="attachments")


class URLRecord(db.Model, TimestampMixin):
    __tablename__ = "urls"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    email_id = db.Column(db.String(32), db.ForeignKey("emails.id"), nullable=False)

    url = db.Column(db.Text, nullable=False)
    display_text = db.Column(db.Text, nullable=True)
    domain = db.Column(db.String(255), nullable=True)

    is_ip_address = db.Column(db.Boolean, default=False)
    is_shortened = db.Column(db.Boolean, default=False)
    is_punycode = db.Column(db.Boolean, default=False)
    has_display_mismatch = db.Column(db.Boolean, default=False)
    is_suspicious = db.Column(db.Boolean, default=False)

    email = db.relationship("Email", back_populates="urls")
