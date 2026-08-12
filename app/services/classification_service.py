"""
Classification (Section 16 / 26).

Maps a ScoreBreakdown to one of the six Classification values using the
configurable thresholds from settings_service. When the total score lands in
the HIGH RISK band (>= high_risk_min), a secondary pass picks the most
specific category (PHISHING / SCAM / MALICIOUS_ATTACHMENT) based on which
sub-score contributed the most -- this is exactly the two-stage approach
described in Chapter 2 (Section 26) and the conceptual framework.
"""

from __future__ import annotations

from app.models import Classification
from app.services import settings_service
from app.services.scoring_service import ScoreBreakdown


def classify(breakdown: ScoreBreakdown) -> str:
    thresholds = settings_service.get_thresholds()
    total = breakdown.total_score

    if total <= thresholds["clean_max"]:
        return Classification.CLEAN
    if total <= thresholds["suspicious_max"]:
        return Classification.SUSPICIOUS
    if total <= thresholds["spam_max"]:
        return Classification.SPAM

    # HIGH RISK band (total >= high_risk_min): pick the most specific
    # sub-category, but ONLY escalate to PHISHING / SCAM / MALICIOUS_ATTACHMENT
    # when there is actual rule evidence in that specific category. A message
    # that crosses the high-risk threshold purely on spam/url/header/auth
    # signals -- with zero phishing-, scam-, or dangerous-attachment-specific
    # indicators -- is still just aggressive SPAM, not phishing; capping it at
    # SPAM here keeps the classification explainable and avoids mislabeling
    # loud marketing email as a credential-theft attempt.
    has_dangerous_attachment = any(
        r.category == "attachment" and r.rule_name in {
            "attachment.dangerous_extension", "attachment.executable", "attachment.macro_enabled",
        }
        for r in breakdown.indicators
    )
    if has_dangerous_attachment and breakdown.attachment_score >= max(breakdown.phishing_score, breakdown.scam_score):
        return Classification.MALICIOUS_ATTACHMENT

    if breakdown.phishing_score == 0 and breakdown.scam_score == 0 and breakdown.attachment_score == 0:
        return Classification.SPAM

    if breakdown.phishing_score >= breakdown.scam_score and breakdown.phishing_score >= breakdown.attachment_score:
        return Classification.PHISHING
    if breakdown.scam_score >= breakdown.attachment_score:
        return Classification.SCAM
    return Classification.MALICIOUS_ATTACHMENT


def risk_level(classification: str) -> str:
    """Human-friendly grouping used by the UI (e.g. badge colour)."""
    if classification == Classification.CLEAN:
        return "none"
    if classification == Classification.SUSPICIOUS:
        return "low"
    if classification == Classification.SPAM:
        return "medium"
    return "high"  # scam / phishing / malicious_attachment
