from app.detection.base_rule import Category, RuleResult, Severity
from app.services.scoring_service import calculate_score


def test_calculate_score_aggregates_by_category():
    results = [
        RuleResult(matched=True, score=10, category=Category.SPAM, severity=Severity.LOW, rule_name="a"),
        RuleResult(matched=True, score=15, category=Category.PHISHING, severity=Severity.HIGH, rule_name="b"),
        RuleResult(matched=True, score=5, category=Category.SPAM, severity=Severity.LOW, rule_name="c"),
    ]
    breakdown = calculate_score(results)
    assert breakdown.spam_score == 15
    assert breakdown.phishing_score == 15
    assert breakdown.total_score == 30


def test_calculate_score_empty_is_zero():
    breakdown = calculate_score([])
    assert breakdown.total_score == 0
    assert breakdown.as_dict()["total_score"] == 0


def test_classify_within_app_context(app):
    """Classification reads thresholds from the DB, so it needs an app context."""
    with app.app_context():
        from app.extensions import db
        from app.services import settings_service
        from app.services.classification_service import classify
        from app.services.scoring_service import ScoreBreakdown
        from app.models import Classification

        db.create_all()
        settings_service.ensure_defaults()

        assert classify(ScoreBreakdown(total_score=0)) == Classification.CLEAN
        assert classify(ScoreBreakdown(total_score=19)) == Classification.CLEAN
        assert classify(ScoreBreakdown(total_score=20)) == Classification.SUSPICIOUS
        assert classify(ScoreBreakdown(total_score=39)) == Classification.SUSPICIOUS
        assert classify(ScoreBreakdown(total_score=59)) == Classification.SPAM

        # High risk, no category-specific evidence -> stays SPAM (see classification_service docstring).
        assert classify(ScoreBreakdown(total_score=70)) == Classification.SPAM

        # High risk with phishing evidence -> PHISHING.
        assert classify(ScoreBreakdown(total_score=70, phishing_score=40)) == Classification.PHISHING

        # High risk with scam evidence dominant -> SCAM.
        assert classify(ScoreBreakdown(total_score=70, scam_score=50, phishing_score=10)) == Classification.SCAM


def test_risk_percentage_clamps_to_0_100():
    """
    End-user-facing risk % (Section 26 usability follow-up): a raw score of 0
    is 0%, a raw score of 100+ (many stacked rule hits) caps at 100% instead
    of showing something confusing like "340% risk".
    """
    from app.services.classification_service import risk_percentage

    assert risk_percentage(0) == 0
    assert risk_percentage(19) == 19
    assert risk_percentage(60) == 60
    assert risk_percentage(100) == 100
    assert risk_percentage(340) == 100
    assert risk_percentage(-5) == 0  # defensive; scores shouldn't go negative but don't show "-5%" if they do


def test_email_and_threat_analysis_expose_risk_percentage(app, db, organization, admin_user):
    """The raw score->percentage conversion is reachable straight off the models
    templates already render (`email.risk_percentage`, `threat_analysis.risk_percentage`),
    not just as a standalone function."""
    from app.models import Email, ThreatAnalysis
    from app.services import mailbox_service

    mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
    email = Email(mailbox_id=mailbox.id, dedup_key="risk-pct-test", sender="a@example.com",
                  classification="spam", threat_score=45)
    db.session.add(email)
    db.session.flush()
    analysis = ThreatAnalysis(email_id=email.id, total_score=145, classification="phishing")
    db.session.add(analysis)
    db.session.commit()

    assert email.risk_percentage == 45
    assert analysis.risk_percentage == 100  # clamped
