"""Sender reputation rules (Section 25). Local whitelist/blacklist intelligence only."""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity


class BlacklistedSenderRule(BaseRule):
    name = "sender.blacklisted"
    category = Category.SENDER
    default_score = 40
    severity = Severity.CRITICAL

    def evaluate(self, context: EmailContext) -> RuleResult:
        if context.sender_is_blacklisted:
            return self._result(True, f"Sender '{context.parsed.sender}' or domain '{context.parsed.sender_domain}' is on the blacklist")
        return RuleResult.no_match(self.name)


class FreemailBrandClaimRule(BaseRule):
    """A display name claims to be a company/department, but the sender uses a free consumer webmail domain."""
    name = "sender.freemail_brand_claim"
    category = Category.SENDER
    default_score = 10
    severity = Severity.LOW

    FREE_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "mail.com", "yandex.com"}
    CORPORATE_TERMS = ("support", "security", "billing", "accounts", "hr", "payroll", "admin", "helpdesk",
                        "notification", "service")

    def evaluate(self, context: EmailContext) -> RuleResult:
        domain = context.parsed.sender_domain
        display = (context.parsed.sender_display_name or "").lower()
        if domain in self.FREE_DOMAINS and any(term in display for term in self.CORPORATE_TERMS):
            return self._result(True, f"Display name ('{context.parsed.sender_display_name}') suggests an official department, but the message was sent from a free consumer email domain ('{domain}')")
        return RuleResult.no_match(self.name)


SENDER_RULES = [
    BlacklistedSenderRule(),
    FreemailBrandClaimRule(),
]
