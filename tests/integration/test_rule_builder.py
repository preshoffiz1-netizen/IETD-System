"""
Regression tests for the simplified Create Custom Rule form (Section 32).

The rule builder was reworked so end users pick severity (which drives the
raw point score by default) instead of typing a raw score, and invalid/
tampered field or operator names are rejected server-side instead of being
silently saved as an unmatchable condition.
"""

from tests.conftest import login


def test_create_rule_page_renders(client, admin_user, organization):
    login(client, "admin@example.com")
    resp = client.get("/rules/create")
    assert resp.status_code == 200
    # Quick-preset buttons and the severity-driven flow should be present.
    assert b"preset-btn" in resp.data
    assert b"How serious is this" in resp.data


def test_create_rule_uses_severity_default_score_when_score_blank(client, admin_user, organization):
    from app.models import DetectionRule

    login(client, "admin@example.com")
    resp = client.post("/rules/create", data={
        "name": "Block scam sender",
        "severity": "high",
        "action": "quarantine",
        "category": "custom",
        "condition_field": "sender",
        "condition_operator": "equals",
        "condition_value": "scammer@example.com",
        "condition_joiner": "AND",
        # score intentionally omitted -- should fall back to the "high" default (45)
    }, follow_redirects=True)
    assert resp.status_code == 200

    rule = DetectionRule.query.filter_by(name="Block scam sender", organization_id=organization.id).first()
    assert rule is not None
    assert rule.score == 45
    assert len(rule.conditions) == 1
    assert rule.conditions[0].field == "sender"


def test_create_rule_rejects_missing_condition(client, admin_user, organization):
    from app.models import DetectionRule

    login(client, "admin@example.com")
    resp = client.post("/rules/create", data={
        "name": "Empty rule",
        "severity": "medium",
        "action": "flag",
        "category": "custom",
        # no condition_field/condition_value at all
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Add at least one condition" in resp.data
    assert DetectionRule.query.filter_by(name="Empty rule").first() is None


def test_create_rule_rejects_tampered_field_and_operator(client, admin_user, organization):
    from app.models import DetectionRule

    login(client, "admin@example.com")
    resp = client.post("/rules/create", data={
        "name": "Tampered rule",
        "severity": "medium",
        "action": "flag",
        "category": "custom",
        "condition_field": "'; DROP TABLE users; --",
        "condition_operator": "not_a_real_operator",
        "condition_value": "x",
        "condition_joiner": "AND",
    }, follow_redirects=True)
    assert resp.status_code == 200
    # The bogus condition is silently dropped -> no valid conditions -> rejected.
    assert DetectionRule.query.filter_by(name="Tampered rule").first() is None
