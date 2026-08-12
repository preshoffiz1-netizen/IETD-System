from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class ThreatAnalysis(db.Model, TimestampMixin):
    """
    One row per analyzed email holding the score breakdown (Section 26).
    Kept separate from Email so re-analysis / historical re-scoring is easy.
    """

    __tablename__ = "threat_analyses"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    email_id = db.Column(db.String(32), db.ForeignKey("emails.id"), nullable=False, unique=True)

    sender_score = db.Column(db.Integer, default=0)
    subject_score = db.Column(db.Integer, default=0)
    body_score = db.Column(db.Integer, default=0)
    url_score = db.Column(db.Integer, default=0)
    attachment_score = db.Column(db.Integer, default=0)
    header_score = db.Column(db.Integer, default=0)
    authentication_score = db.Column(db.Integer, default=0)
    spam_score = db.Column(db.Integer, default=0)
    scam_score = db.Column(db.Integer, default=0)
    phishing_score = db.Column(db.Integer, default=0)

    total_score = db.Column(db.Integer, default=0, nullable=False)
    classification = db.Column(db.String(30), nullable=False)

    engine_version = db.Column(db.String(20), default="1.0")
    analyzed_at = db.Column(db.DateTime, nullable=True)

    email = db.relationship("Email", back_populates="threat_analysis")
    indicators = db.relationship(
        "ThreatIndicator", back_populates="threat_analysis", cascade="all, delete-orphan",
        order_by="desc(ThreatIndicator.score_contribution)",
    )

    def score_breakdown(self) -> dict:
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
        }


class ThreatIndicator(db.Model, TimestampMixin):
    """
    A single triggered-rule explanation line (Section 27, "Explainable Detection").
    """

    __tablename__ = "threat_indicators"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    threat_analysis_id = db.Column(db.String(32), db.ForeignKey("threat_analyses.id"), nullable=False)

    rule_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # spam/scam/phishing/url/attachment/header/auth/sender
    severity = db.Column(db.String(20), nullable=False)  # low/medium/high/critical
    score_contribution = db.Column(db.Integer, default=0, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    indicator_metadata = db.Column(db.Text, nullable=True)  # JSON blob with extra detail

    threat_analysis = db.relationship("ThreatAnalysis", back_populates="indicators")
