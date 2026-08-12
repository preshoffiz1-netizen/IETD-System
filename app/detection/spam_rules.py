"""Spam detection rules (Section 17). Weighted, not purely keyword-only."""

from __future__ import annotations

import re

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity

SPAM_SUBJECT_KEYWORDS = [
    "free!!!", "win now", "urgent!!!", "act now", "special offer",
    "you have won", "claim now", "congratulations you",
]

PROMOTIONAL_KEYWORDS = [
    "buy now", "limited time", "offer expires", "subscribe now", "unbeatable price",
    "discount code", "exclusive deal", "act fast", "risk free", "no obligation",
]


class SubjectSpamKeywordsRule(BaseRule):
    name = "spam.subject_keywords"
    category = Category.SPAM
    default_score = 12
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        subject = context.subject_lower
        hits = [kw for kw in SPAM_SUBJECT_KEYWORDS if kw in subject]
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Subject contains spam-associated phrase(s): {', '.join(hits)}",
                             score=self.default_score, metadata={"matched_keywords": hits})


class ExcessiveCapitalizationRule(BaseRule):
    name = "spam.excessive_capitalization"
    category = Category.SPAM
    default_score = 8
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        subject = context.parsed.subject or ""
        letters = [c for c in subject if c.isalpha()]
        if len(letters) < 6:
            return RuleResult.no_match(self.name)
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if upper_ratio < 0.7:
            return RuleResult.no_match(self.name)
        return self._result(True, "Subject line is excessively capitalized",
                             metadata={"upper_ratio": round(upper_ratio, 2)})


class ExcessivePunctuationRule(BaseRule):
    name = "spam.excessive_punctuation"
    category = Category.SPAM
    default_score = 6
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        subject = context.parsed.subject or ""
        if re.search(r"[!?]{3,}", subject):
            return self._result(True, "Subject contains excessive punctuation (e.g. '!!!')")
        return RuleResult.no_match(self.name)


class UnsolicitedPromotionalLanguageRule(BaseRule):
    name = "spam.promotional_language"
    category = Category.SPAM
    default_score = 10
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        body = context.body_lower
        hits = [kw for kw in PROMOTIONAL_KEYWORDS if kw in body]
        if len(hits) < 2:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Body contains repeated promotional/marketing language: {', '.join(hits)}",
                             score=self.default_score + (len(hits) - 2) * 2,
                             metadata={"matched_keywords": hits})


SPAM_RULES = [
    SubjectSpamKeywordsRule(),
    ExcessiveCapitalizationRule(),
    ExcessivePunctuationRule(),
    UnsolicitedPromotionalLanguageRule(),
]
