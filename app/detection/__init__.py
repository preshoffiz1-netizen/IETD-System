from app.detection.attachment_rules import ATTACHMENT_RULES
from app.detection.authentication_rules import AUTHENTICATION_RULES
from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity
from app.detection.header_rules import HEADER_RULES
from app.detection.phishing_rules import PHISHING_RULES
from app.detection.scam_rules import SCAM_RULES
from app.detection.sender_rules import SENDER_RULES
from app.detection.spam_rules import SPAM_RULES
from app.detection.url_rules import URL_RULES

ALL_BUILTIN_RULES: list[BaseRule] = [
    *SENDER_RULES,
    *SPAM_RULES,
    *SCAM_RULES,
    *PHISHING_RULES,
    *URL_RULES,
    *ATTACHMENT_RULES,
    *HEADER_RULES,
    *AUTHENTICATION_RULES,
]

RULES_BY_CATEGORY = {
    Category.SENDER: SENDER_RULES,
    Category.SPAM: SPAM_RULES,
    Category.SCAM: SCAM_RULES,
    Category.PHISHING: PHISHING_RULES,
    Category.URL: URL_RULES,
    Category.ATTACHMENT: ATTACHMENT_RULES,
    Category.HEADER: HEADER_RULES,
    Category.AUTHENTICATION: AUTHENTICATION_RULES,
}

__all__ = [
    "BaseRule",
    "Category",
    "EmailContext",
    "RuleResult",
    "Severity",
    "ALL_BUILTIN_RULES",
    "RULES_BY_CATEGORY",
]
