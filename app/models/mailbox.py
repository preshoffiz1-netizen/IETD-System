from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class ProviderType:
    IMAP = "imap"
    GMAIL = "gmail"
    DEMO = "demo"

    ALL = (IMAP, GMAIL, DEMO)


class MailboxStatus:
    PENDING = "pending"
    CONNECTED = "connected"
    ERROR = "error"
    DISCONNECTED = "disconnected"


class Mailbox(db.Model, TimestampMixin):
    """
    A single connected mailbox. Credentials are stored encrypted
    (see app.utils.security) -- never in plaintext.
    """

    __tablename__ = "mailboxes"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=False)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False)

    provider = db.Column(db.String(20), nullable=False, default=ProviderType.IMAP)
    email_address = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=True)

    status = db.Column(db.String(20), default=MailboxStatus.PENDING, nullable=False)
    status_message = db.Column(db.String(500), nullable=True)

    # --- Generic IMAP connection settings ---------------------------------------
    imap_host = db.Column(db.String(255), nullable=True)
    imap_port = db.Column(db.Integer, nullable=True, default=993)
    imap_use_ssl = db.Column(db.Boolean, default=True)
    imap_username = db.Column(db.String(255), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=True)  # Fernet-encrypted app password

    # --- OAuth (Gmail) --------------------------------------------------------------
    encrypted_oauth_token = db.Column(db.Text, nullable=True)  # Fernet-encrypted JSON token blob

    # --- Monitoring / scanning ------------------------------------------------------
    monitoring_enabled = db.Column(db.Boolean, default=False, nullable=False)
    scan_interval_minutes = db.Column(db.Integer, default=5, nullable=False)
    last_scan_at = db.Column(db.DateTime, nullable=True)
    last_uid_scanned = db.Column(db.String(64), nullable=True)  # dedup watermark

    messages_processed = db.Column(db.Integer, default=0, nullable=False)
    threats_detected = db.Column(db.Integer, default=0, nullable=False)

    organization = db.relationship("Organization", back_populates="mailboxes")
    owner = db.relationship("User", back_populates="mailboxes")
    emails = db.relationship("Email", back_populates="mailbox", cascade="all, delete-orphan")
    scan_jobs = db.relationship("ScanJob", back_populates="mailbox", cascade="all, delete-orphan")

    def capabilities(self) -> dict:
        """Delegate to the provider capability model (Section 66)."""
        from app.providers import get_provider_class

        provider_cls = get_provider_class(self.provider)
        return provider_cls.CAPABILITIES if provider_cls else {}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Mailbox {self.email_address} ({self.provider})>"
