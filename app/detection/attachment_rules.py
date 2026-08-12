"""
Attachment analysis rules (Section 22).

Inspection only -- filename, extension, MIME type, size. Attachments are
NEVER opened, executed, or run through any active-content interpreter.
"""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".msi", ".hta", ".wsf", ".vbs", ".js"}


class DangerousExtensionRule(BaseRule):
    name = "attachment.dangerous_extension"
    category = Category.ATTACHMENT
    default_score = 25
    severity = Severity.CRITICAL

    def evaluate(self, context: EmailContext) -> RuleResult:
        for att in context.parsed.attachments:
            if att.is_dangerous_extension:
                return self._result(True, f"Attachment '{att.filename}' has a high-risk file extension ({att.extension})",
                                     metadata={"filename": att.filename, "extension": att.extension})
        return RuleResult.no_match(self.name)


class ExecutableAttachmentRule(BaseRule):
    name = "attachment.executable"
    category = Category.ATTACHMENT
    default_score = 30
    severity = Severity.CRITICAL

    def evaluate(self, context: EmailContext) -> RuleResult:
        for att in context.parsed.attachments:
            if att.extension in EXECUTABLE_EXTENSIONS:
                return self._result(True, f"Attachment '{att.filename}' is an executable/script file ({att.extension})",
                                     metadata={"filename": att.filename})
        return RuleResult.no_match(self.name)


class MacroEnabledDocumentRule(BaseRule):
    name = "attachment.macro_enabled"
    category = Category.ATTACHMENT
    default_score = 20
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        for att in context.parsed.attachments:
            if att.is_macro_enabled:
                return self._result(True, f"Attachment '{att.filename}' is a macro-enabled document ({att.extension})",
                                     metadata={"filename": att.filename})
        return RuleResult.no_match(self.name)


class DoubleExtensionRule(BaseRule):
    name = "attachment.double_extension"
    category = Category.ATTACHMENT
    default_score = 22
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        for att in context.parsed.attachments:
            if att.has_double_extension:
                return self._result(True, f"Attachment '{att.filename}' uses a double file extension to disguise its true type",
                                     metadata={"filename": att.filename})
        return RuleResult.no_match(self.name)


class ArchiveAttachmentRule(BaseRule):
    name = "attachment.archive"
    category = Category.ATTACHMENT
    default_score = 8
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        for att in context.parsed.attachments:
            if att.extension in {".zip", ".rar", ".iso"}:
                return self._result(True, f"Attachment '{att.filename}' is a compressed archive; contents were not opened",
                                     metadata={"filename": att.filename})
        return RuleResult.no_match(self.name)


ATTACHMENT_RULES = [
    DangerousExtensionRule(),
    ExecutableAttachmentRule(),
    MacroEnabledDocumentRule(),
    DoubleExtensionRule(),
    ArchiveAttachmentRule(),
]
