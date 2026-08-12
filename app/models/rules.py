from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class RuleAction:
    ALLOW = "allow"
    FLAG = "flag"
    QUARANTINE = "quarantine"
    MOVE_TO_SPAM = "move_to_spam"
    MOVE_TO_FOLDER = "move_to_folder"
    DELETE = "delete"
    NOTIFY = "notify"

    ALL = (ALLOW, FLAG, QUARANTINE, MOVE_TO_SPAM, MOVE_TO_FOLDER, DELETE, NOTIFY)


class DetectionRule(db.Model, TimestampMixin):
    """
    A weighted detection rule. Built-in rules (spam/scam/phishing/url/attachment/
    header/authentication/sender modules under app/detection) are represented in
    code for performance and testability; this table holds *custom* rules created
    through the Rule Builder UI (Section 32) plus editable metadata (enabled flag,
    score override) for built-in rules referenced by `code_ref`.
    """

    __tablename__ = "detection_rules"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=True)
    created_by_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default="custom")
    severity = db.Column(db.String(20), nullable=False, default="medium")
    score = db.Column(db.Integer, nullable=False, default=10)
    action = db.Column(db.String(30), nullable=False, default=RuleAction.FLAG)

    is_custom = db.Column(db.Boolean, default=True, nullable=False)
    code_ref = db.Column(db.String(100), nullable=True)  # e.g. "spam.urgent_subject_keywords"
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    condition_logic = db.Column(db.String(10), default="AND")  # AND / OR

    organization = db.relationship("Organization", back_populates="rules")
    conditions = db.relationship(
        "RuleCondition", back_populates="rule", cascade="all, delete-orphan", order_by="RuleCondition.position"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DetectionRule {self.name}>"


class RuleCondition(db.Model, TimestampMixin):
    """A single condition inside a custom rule (Section 32)."""

    __tablename__ = "rule_conditions"

    FIELDS = (
        "sender", "sender_domain", "subject", "body", "url", "url_domain",
        "attachment_extension", "attachment_mime_type", "threat_score",
        "spf_status", "dkim_status", "dmarc_status",
    )
    OPERATORS = ("contains", "equals", "not_equals", "starts_with", "ends_with", "greater_than", "less_than")
    JOINERS = ("AND", "OR", "NOT")

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    rule_id = db.Column(db.String(32), db.ForeignKey("detection_rules.id"), nullable=False)

    field = db.Column(db.String(50), nullable=False)
    operator = db.Column(db.String(20), nullable=False, default="contains")
    value = db.Column(db.String(500), nullable=False)
    joiner = db.Column(db.String(5), default="AND")  # how this condition joins with the previous one
    position = db.Column(db.Integer, default=0)

    rule = db.relationship("DetectionRule", back_populates="conditions")


class ListEntryType:
    EMAIL = "email"
    DOMAIN = "domain"


class WhitelistEntry(db.Model, TimestampMixin):
    __tablename__ = "whitelist_entries"
    __table_args__ = (db.UniqueConstraint("organization_id", "value", name="uq_whitelist_org_value"),)

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=False)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)

    entry_type = db.Column(db.String(10), nullable=False, default=ListEntryType.EMAIL)
    value = db.Column(db.String(320), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.String(500), nullable=True)


class BlacklistEntry(db.Model, TimestampMixin):
    __tablename__ = "blacklist_entries"
    __table_args__ = (db.UniqueConstraint("organization_id", "value", name="uq_blacklist_org_value"),)

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=False)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True)

    entry_type = db.Column(db.String(10), nullable=False, default=ListEntryType.EMAIL)
    value = db.Column(db.String(320), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.String(500), nullable=True)
