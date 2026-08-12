"""
SPF / DKIM / DMARC rules (Section 24).

Authentication results are read directly from the email's
Authentication-Results header where present. We never invent a pass/fail
verdict -- if the header is absent, the status is reported as
"not_available" and contributes no score, per the project's honesty
requirement about provider/header limitations.
"""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity


class SPFFailRule(BaseRule):
    name = "authentication.spf_fail"
    category = Category.AUTHENTICATION
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        if context.parsed.spf_result == "fail":
            return self._result(True, "SPF authentication failed for this message's sending domain")
        return RuleResult.no_match(self.name)


class DKIMFailRule(BaseRule):
    name = "authentication.dkim_fail"
    category = Category.AUTHENTICATION
    default_score = 12
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        if context.parsed.dkim_result == "fail":
            return self._result(True, "DKIM signature verification failed")
        return RuleResult.no_match(self.name)


class DMARCFailRule(BaseRule):
    name = "authentication.dmarc_fail"
    category = Category.AUTHENTICATION
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        if context.parsed.dmarc_result == "fail":
            return self._result(True, "DMARC policy check failed -- sender is not authorized to send as this domain")
        return RuleResult.no_match(self.name)


class AllAuthenticationFailedRule(BaseRule):
    """Compounding indicator: when SPF, DKIM, and DMARC all fail together, that's a strong signal."""
    name = "authentication.all_failed"
    category = Category.AUTHENTICATION
    default_score = 15
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        p = context.parsed
        if p.spf_result == "fail" and p.dkim_result == "fail" and p.dmarc_result == "fail":
            return self._result(True, "SPF, DKIM, and DMARC all failed -- strong indicator of a spoofed sender")
        return RuleResult.no_match(self.name)


AUTHENTICATION_RULES = [
    SPFFailRule(),
    DKIMFailRule(),
    DMARCFailRule(),
    AllAuthenticationFailedRule(),
]
