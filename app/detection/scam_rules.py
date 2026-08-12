"""Scam detection rules (Section 18): lottery, investment, inheritance, BEC-style fraud."""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity

LOTTERY_PRIZE_KEYWORDS = ["lottery", "you have won", "winning notification", "prize award", "jackpot"]
INVESTMENT_CRYPTO_KEYWORDS = ["guaranteed profit", "bitcoin", "cryptocurrency", "double your", "forex trading",
                              "investment opportunity", "risk-free investment"]
INHERITANCE_KEYWORDS = ["inheritance", "unclaimed fund", "next of kin", "beneficiary", "deceased client",
                         "processing fee"]
FAKE_JOB_KEYWORDS = ["work from home", "earn $", "no experience required", "hiring immediately",
                      "job offer letter", "recruitment fee"]
FAKE_REFUND_KEYWORDS = ["tax refund", "refund pending", "eligible for a refund", "claim your refund"]
URGENT_TRANSFER_KEYWORDS = ["wire transfer", "send money", "western union", "money gram", "gift card",
                             "urgent transfer", "processing fee", "advance fee"]
FAKE_INVOICE_KEYWORDS = ["overdue invoice", "outstanding payment", "urgent payment required", "update your banking"]
EMOTIONAL_MANIPULATION_KEYWORDS = ["god bless", "please help me", "i am dying", "trust you", "keep this confidential",
                                    "do not tell anyone", "my only hope"]


def _keyword_rule(keywords: list[str], body: str) -> list[str]:
    return [kw for kw in keywords if kw in body]


class LotteryPrizeScamRule(BaseRule):
    name = "scam.lottery_prize"
    category = Category.SCAM
    default_score = 25
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(LOTTERY_PRIZE_KEYWORDS, context.body_lower + " " + context.subject_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches lottery/prize scam pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class InvestmentCryptoScamRule(BaseRule):
    name = "scam.investment_crypto"
    category = Category.SCAM
    default_score = 22
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(INVESTMENT_CRYPTO_KEYWORDS, context.body_lower)
        if len(hits) < 2:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches investment/crypto scam pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class InheritanceScamRule(BaseRule):
    name = "scam.inheritance"
    category = Category.SCAM
    default_score = 25
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(INHERITANCE_KEYWORDS, context.body_lower)
        if len(hits) < 2:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches inheritance/advance-fee scam pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class FakeJobScamRule(BaseRule):
    name = "scam.fake_job"
    category = Category.SCAM
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(FAKE_JOB_KEYWORDS, context.body_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches fake job offer pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class FakeRefundScamRule(BaseRule):
    name = "scam.fake_refund"
    category = Category.SCAM
    default_score = 18
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(FAKE_REFUND_KEYWORDS, context.body_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches fake refund scam pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class UrgentMoneyTransferRule(BaseRule):
    name = "scam.urgent_money_transfer"
    category = Category.SCAM
    default_score = 20
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(URGENT_TRANSFER_KEYWORDS, context.body_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message requests urgent money transfer: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class FakeInvoiceScamRule(BaseRule):
    name = "scam.fake_invoice"
    category = Category.SCAM
    default_score = 15
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(FAKE_INVOICE_KEYWORDS, context.body_lower + " " + context.subject_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message matches fake invoice/payment fraud pattern: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


class EmotionalManipulationRule(BaseRule):
    name = "scam.emotional_manipulation"
    category = Category.SCAM
    default_score = 10
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        hits = _keyword_rule(EMOTIONAL_MANIPULATION_KEYWORDS, context.body_lower)
        if not hits:
            return RuleResult.no_match(self.name)
        return self._result(True, f"Message uses emotional-manipulation / social-engineering language: {', '.join(hits)}",
                             metadata={"matched_keywords": hits})


SCAM_RULES = [
    LotteryPrizeScamRule(),
    InvestmentCryptoScamRule(),
    InheritanceScamRule(),
    FakeJobScamRule(),
    FakeRefundScamRule(),
    UrgentMoneyTransferRule(),
    FakeInvoiceScamRule(),
    EmotionalManipulationRule(),
]
