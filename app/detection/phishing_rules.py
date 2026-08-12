"""Phishing detection rules (Section 19). Weak evidence -> SUSPICIOUS, not a hard claim."""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity
from app.utils.domain_utils import (
    domain_matches_brand,
    find_impersonated_brand,
    is_lookalike_domain,
)

CREDENTIAL_REQUEST_KEYWORDS = ["verify your account", "confirm your password", "verify your password",
                                "update your password", "re-enter your password", "confirm your identity",
                                "login to verify", "enter your credentials"]
SUSPENSION_THREAT_KEYWORDS = ["account will be suspended", "account has been limited", "account suspended",
                               "unusual activity", "your account will be closed", "permanently limited"]


class CredentialRequestRule(BaseRule):
    name = "phishing.credential_request"
    category = Category.PHISHING
    default_score = 20
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = [kw for kw in CREDENTIAL_REQUEST_KEYWORDS if kw in context.body_lower]
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message requests credentials/password verification: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class AccountSuspensionThreatRule(BaseRule):
    name = "phishing.suspension_threat"
    category = Category.PHISHING
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = [kw for kw in SUSPENSION_THREAT_KEYWORDS if kw in context.body_lower]
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message threatens account suspension to create urgency: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class BrandImpersonationRule(BaseRule):
    """
    Body/subject references a well-known brand, but the sending domain neither
    belongs to that brand nor is a recognized lookalike -- flagged at LOW
    confidence since brand mentions alone are common in legitimate mail too.
    """
    name = "phishing.brand_impersonation"
    category = Category.PHISHING
    default_score = 12
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        combined_text = f"{context.parsed.subject} {context.parsed.sender_display_name}"
        brand = find_impersonated_brand(combined_text)
        if not brand:
            return RuleResult.no_match(self.name)
        domain = context.parsed.sender_domain
        if domain_matches_brand(domain, brand):
            return RuleResult.no_match(self.name)  # legitimately from the brand
        score = self.default_score
        reason = f"References brand '{brand}' but sender domain '{domain}' does not belong to that brand"
        severity = self.severity
        if is_lookalike_domain(domain, brand):
            score += 15
            severity = Severity.CRITICAL
            reason += " (domain closely resembles the brand's real domain - likely impersonation)"
        return self._result(True, reason, score=score,
                             metadata={"brand": brand, "sender_domain": domain, "severity": severity})


class SenderReplyToMismatchRule(BaseRule):
    name = "phishing.sender_replyto_mismatch"
    category = Category.PHISHING
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        reply_to = context.parsed.reply_to
        sender = context.parsed.sender
        if not reply_to or not sender:
            return RuleResult.no_match(self.name)
        reply_domain = reply_to.rsplit("@", 1)[-1].lower() if "@" in reply_to else ""
        sender_domain = context.parsed.sender_domain
        if reply_domain and sender_domain and reply_domain != sender_domain:
            return self._result(
                True,
                f"Reply-To domain ('{reply_domain}') differs from From domain ('{sender_domain}')",
                metadata={"reply_to_domain": reply_domain, "sender_domain": sender_domain},
            )
        return RuleResult.no_match(self.name)


PHISHING_RULES = [
    CredentialRequestRule(),
    AccountSuspensionThreatRule(),
    BrandImpersonationRule(),
    SenderReplyToMismatchRule(),
]
