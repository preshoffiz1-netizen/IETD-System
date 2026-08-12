"""
Threat scoring (Section 26).

Aggregates the RuleResult list produced by threat_engine.analyze() into the
component scores stored on ThreatAnalysis, plus a total. Kept as pure
functions (no DB writes) so it is trivially unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detection import Category, RuleResult

CATEGORY_TO_COLUMN = {
    Category.SENDER: "sender_score",
    Category.SUBJECT: "subject_score",
    Category.BODY: "body_score",
    Category.URL: "url_score",
    Category.ATTACHMENT: "attachment_score",
    Category.HEADER: "header_score",
    Category.AUTHENTICATION: "authentication_score",
    Category.SPAM: "spam_score",
    Category.SCAM: "scam_score",
    Category.PHISHING: "phishing_score",
}


@dataclass
class ScoreBreakdown:
    sender_score: int = 0
    subject_score: int = 0
    body_score: int = 0
    url_score: int = 0
    attachment_score: int = 0
    header_score: int = 0
    authentication_score: int = 0
    spam_score: int = 0
    scam_score: int = 0
    phishing_score: int = 0
    total_score: int = 0
    indicators: list[RuleResult] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "sender_score": self.sender_score,
            "subject_score": self.subject_score,
            "body_score": self.body_score,
            "url_score": self.url_score,
            "attachment_score": self.attachment_score,
            "header_score": self.header_score,
            "authentication_score": self.authentication_score,
            "spam_score": self.spam_score,
            "scam_score": self.scam_score,
            "phishing_score": self.phishing_score,
            "total_score": self.total_score,
        }


def calculate_score(rule_results: list[RuleResult]) -> ScoreBreakdown:
    breakdown = ScoreBreakdown()
    for result in rule_results:
        column = CATEGORY_TO_COLUMN.get(result.category, "body_score")
        current = getattr(breakdown, column, 0)
        setattr(breakdown, column, current + result.score)
    breakdown.total_score = sum(r.score for r in rule_results)
    breakdown.indicators = list(rule_results)
    return breakdown
