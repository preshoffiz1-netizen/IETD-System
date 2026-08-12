"""
Import every model so that Flask-SQLAlchemy / Flask-Migrate can discover them
via `db.metadata` and so `from app.models import X` works everywhere else.
"""

from app.models.organization import Organization
from app.models.user import User, Role
from app.models.mailbox import Mailbox, ProviderType, MailboxStatus
from app.models.email import Email, Attachment, URLRecord, Classification, EmailStatus
from app.models.threat import ThreatAnalysis, ThreatIndicator
from app.models.rules import (
    DetectionRule,
    RuleCondition,
    RuleAction,
    WhitelistEntry,
    BlacklistEntry,
    ListEntryType,
)
from app.models.quarantine import QuarantineItem, QuarantineStatus, ScanJob, ScanJobStatus
from app.models.audit import (
    AuditLog,
    Notification,
    NotificationLevel,
    UserSetting,
    SystemSetting,
    Feedback,
    FeedbackType,
)

__all__ = [
    "Organization",
    "User",
    "Role",
    "Mailbox",
    "ProviderType",
    "MailboxStatus",
    "Email",
    "Attachment",
    "URLRecord",
    "Classification",
    "EmailStatus",
    "ThreatAnalysis",
    "ThreatIndicator",
    "DetectionRule",
    "RuleCondition",
    "RuleAction",
    "WhitelistEntry",
    "BlacklistEntry",
    "ListEntryType",
    "QuarantineItem",
    "QuarantineStatus",
    "ScanJob",
    "ScanJobStatus",
    "AuditLog",
    "Notification",
    "NotificationLevel",
    "UserSetting",
    "SystemSetting",
    "Feedback",
    "FeedbackType",
]
