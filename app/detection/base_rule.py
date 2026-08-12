"""
Detection engine core (Sections 15-16).

The engine is intentionally RULE-BASED: every rule is a small, independently
testable, explainable unit that inspects an EmailContext and either fires or
doesn't. Nothing here is a trained model -- the "learning" in this system is
whatever a human encodes as a rule (see docs/detection-engine.md for the
academic framing of this design choice).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.services.email_parser import ParsedEmail


class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category:
    SENDER = "sender"
    SUBJECT = "subject"
    BODY = "body"
    URL = "url"
    ATTACHMENT = "attachment"
    HEADER = "header"
    AUTHENTICATION = "authentication"
    SPAM = "spam"
    SCAM = "scam"
    PHISHING = "phishing"


@dataclass
class EmailContext:
    """Everything a rule might need, gathered once and reused by every rule."""

    parsed: ParsedEmail
    whitelist_emails: set[str] = field(default_factory=set)
    whitelist_domains: set[str] = field(default_factory=set)
    blacklist_emails: set[str] = field(default_factory=set)
    blacklist_domains: set[str] = field(default_factory=set)

    @property
    def subject_lower(self) -> str:
        return (self.parsed.subject or "").lower()

    @property
    def body_lower(self) -> str:
        return f"{self.parsed.body_text or ''}\n{self.parsed.body_html or ''}".lower()

    @property
    def sender_is_whitelisted(self) -> bool:
        return (
            self.parsed.sender in self.whitelist_emails
            or self.parsed.sender_domain in self.whitelist_domains
        )

    @property
    def sender_is_blacklisted(self) -> bool:
        return (
            self.parsed.sender in self.blacklist_emails
            or self.parsed.sender_domain in self.blacklist_domains
        )


@dataclass
class RuleResult:
    matched: bool
    score: int = 0
    reason: str = ""
    category: str = Category.BODY
    severity: str = Severity.LOW
    rule_name: str = ""
    metadata: dict = field(default_factory=dict)

    @staticmethod
    def no_match(rule_name: str = "") -> "RuleResult":
        return RuleResult(matched=False, rule_name=rule_name)


class BaseRule:
    """
    Every concrete rule implements `evaluate(context) -> RuleResult`.

    name/category/default_score/severity are class attributes so the Settings
    UI and the custom-rule table can reference built-in rules by `code_ref`
    (e.g. "spam.urgent_subject_keywords") and override their score or enabled
    state without touching code.
    """

    name: str = "base_rule"
    category: str = Category.BODY
    default_score: int = 10
    severity: str = Severity.LOW
    enabled_by_default: bool = True

    def evaluate(self, context: EmailContext) -> RuleResult:  # pragma: no cover - interface
        raise NotImplementedError

    def _result(self, matched: bool, reason: str = "", score: Optional[int] = None,
                metadata: Optional[dict] = None) -> RuleResult:
        return RuleResult(
            matched=matched,
            score=self.default_score if score is None else score,
            reason=reason,
            category=self.category,
            severity=self.severity,
            rule_name=self.name,
            metadata=metadata or {},
        )
