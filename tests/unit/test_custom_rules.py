from tests.unit.helpers import make_context


def test_custom_rule_matches_and_scores(app, db, organization):
    from app.models import DetectionRule, RuleCondition
    from app.services.threat_engine import run_custom_rules

    rule = DetectionRule(organization_id=organization.id, name="Crypto Investment Scam", category="scam",
                          score=35, action="quarantine", is_custom=True, enabled=True)
    db.session.add(rule)
    db.session.flush()
    db.session.add(RuleCondition(rule_id=rule.id, field="body", operator="contains", value="bitcoin",
                                  joiner="AND", position=0))
    db.session.add(RuleCondition(rule_id=rule.id, field="body", operator="contains", value="guaranteed profit",
                                  joiner="AND", position=1))
    db.session.commit()

    ctx = make_context(body_text="Invest in bitcoin today for guaranteed profit!")
    results = run_custom_rules(ctx, organization.id, running_score=0)
    assert len(results) == 1
    assert results[0].score == 35
    assert results[0].matched


def test_custom_rule_does_not_match_when_one_condition_fails(app, db, organization):
    from app.models import DetectionRule, RuleCondition
    from app.services.threat_engine import run_custom_rules

    rule = DetectionRule(organization_id=organization.id, name="Needs Both", category="scam", score=20,
                          action="flag", is_custom=True, enabled=True)
    db.session.add(rule)
    db.session.flush()
    db.session.add(RuleCondition(rule_id=rule.id, field="body", operator="contains", value="bitcoin",
                                  joiner="AND", position=0))
    db.session.add(RuleCondition(rule_id=rule.id, field="body", operator="contains", value="guaranteed profit",
                                  joiner="AND", position=1))
    db.session.commit()

    ctx = make_context(body_text="I like bitcoin but nothing is guaranteed.")
    results = run_custom_rules(ctx, organization.id, running_score=0)
    assert results == []


def test_disabled_custom_rule_is_ignored(app, db, organization):
    from app.models import DetectionRule, RuleCondition
    from app.services.threat_engine import run_custom_rules

    rule = DetectionRule(organization_id=organization.id, name="Disabled Rule", category="scam", score=20,
                          action="flag", is_custom=True, enabled=False)
    db.session.add(rule)
    db.session.flush()
    db.session.add(RuleCondition(rule_id=rule.id, field="body", operator="contains", value="bitcoin",
                                  joiner="AND", position=0))
    db.session.commit()

    ctx = make_context(body_text="bitcoin bitcoin bitcoin")
    results = run_custom_rules(ctx, organization.id, running_score=0)
    assert results == []
