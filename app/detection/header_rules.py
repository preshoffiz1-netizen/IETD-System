"""Header analysis rules (Section 23)."""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity


class ReturnPathMismatchRule(BaseRule):
    name = "header.return_path_mismatch"
    category = Category.HEADER
    default_score = 12
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        return_path = context.parsed.return_path
        sender_domain = context.parsed.sender_domain
        if not return_path or not sender_domain:
            return RuleResult.no_match(self.name)
        return_domain = return_path.rsplit("@", 1)[-1].lower() if "@" in return_path else ""
        if return_domain and return_domain != sender_domain:
            return self._result(True, f"Return-Path domain ('{return_domain}') differs from the From domain ('{sender_domain}')",
                                 metadata={"return_path_domain": return_domain, "sender_domain": sender_domain})
        return RuleResult.no_match(self.name)


class MissingMessageIdRule(BaseRule):
    name = "header.missing_message_id"
    category = Category.HEADER
    default_score = 5
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        if not context.parsed.message_id:
            return self._result(True, "Message is missing a Message-ID header, which is unusual for legitimate mail servers")
        return RuleResult.no_match(self.name)


class EmptySenderDisplayNameMismatchRule(BaseRule):
    """A display name that itself looks like an email address different from the real sender."""
    name = "header.display_name_spoofing"
    category = Category.HEADER
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        display = (context.parsed.sender_display_name or "").lower()
        sender = (context.parsed.sender or "").lower()
        if "@" in display and display != sender and display not in sender:
            return self._result(True, f"Sender display name ('{context.parsed.sender_display_name}') itself looks like a different email address than the actual sender ('{sender}')")
        return RuleResult.no_match(self.name)


HEADER_RULES = [
    ReturnPathMismatchRule(),
    MissingMessageIdRule(),
    EmptySenderDisplayNameMismatchRule(),
]
