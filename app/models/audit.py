from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid, utcnow


class AuditLog(db.Model):
    """
    Append-only audit trail (Section 41). Never records passwords, tokens, or
    encryption keys -- callers pass only non-sensitive metadata.
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=True)

    action = db.Column(db.String(100), nullable=False, index=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(20), default="success")  # success / failure
    audit_metadata = db.Column(db.Text, nullable=True)  # JSON, non-sensitive only
    ip_address = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class NotificationLevel:
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Notification(db.Model, TimestampMixin):
    __tablename__ = "notifications"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), default=NotificationLevel.INFO)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    link = db.Column(db.String(500), nullable=True)

    user = db.relationship("User", back_populates="notifications")


class UserSetting(db.Model, TimestampMixin):
    __tablename__ = "user_settings"
    __table_args__ = (db.UniqueConstraint("user_id", "key", name="uq_user_settings_key"),)

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False)
    key = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Text, nullable=True)

    user = db.relationship("User", back_populates="settings")


class SystemSetting(db.Model, TimestampMixin):
    """
    Central, editable configuration store (Section 26 / 33). The Settings UI
    reads/writes this table instead of scattering thresholds through code.
    """

    __tablename__ = "system_settings"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    value_type = db.Column(db.String(20), default="string")  # string/int/bool/json
    description = db.Column(db.String(500), nullable=True)


class FeedbackType:
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class Feedback(db.Model, TimestampMixin):
    __tablename__ = "feedback"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    email_id = db.Column(db.String(32), db.ForeignKey("emails.id"), nullable=False)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)

    feedback_type = db.Column(db.String(20), nullable=False)
    comment = db.Column(db.Text, nullable=True)

    email = db.relationship("Email", back_populates="feedback_entries")
