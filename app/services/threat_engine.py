"""
Threat analysis orchestration (Sections 15, 27, 32).

Runs every enabled built-in rule plus every enabled custom rule (from the
Rule Builder) against an EmailContext and returns the full list of
RuleResult objects. Scoring/classification/policy are deliberately kept in
separate modules (scoring_service, classification_service, policy_service)
so each stage is independently testable.
"""

from __future__ import annotations

import logging

from app.detection import ALL_BUILTIN_RULES, EmailContext, RuleResult
from app.models import DetectionRule, RuleCondition

logger = logging.getLogger("ietds.threat_engine")


def _field_value(context: EmailContext, field: str) -> str:
    p = context.parsed
    mapping = {
        "sender": p.sender,
        "sender_domain": p.sender_domain,
        "subject": p.subject,
        "body": f"{p.body_text}\n{p.body_html}",
        "url": " ".join(u.url for u in p.urls),
        "url_domain": " ".join(u.url for u in p.urls),  # domain comparisons handled via 'contains'
        "attachment_extension": " ".join(a.extension for a in p.attachments),
        "attachment_mime_type": " ".join(a.mime_type for a in p.attachments),
        "spf_status": p.spf_result,
        "dkim_status": p.dkim_result,
        "dmarc_status": p.dmarc_result,
    }
    return (mapping.get(field, "") or "").lower()


def _evaluate_condition(context: EmailContext, condition: RuleCondition, total_score_so_far: int) -> bool:
    if condition.field == "threat_score":
        actual = total_score_so_far
        try:
            target = float(condition.value)
        except ValueError:
            return False
        if condition.operator == "greater_than":
            return actual > target
        if condition.operator == "less_than":
            return actual < target
        if condition.operator == "equals":
            return actual == target
        return False

    actual = _field_value(context, condition.field)
    target = (condition.value or "").lower()

    if condition.operator == "contains":
        return target in actual
    if condition.operator == "equals":
        return actual.strip() == target.strip()
    if condition.operator == "not_equals":
        return actual.strip() != target.strip()
    if condition.operator == "starts_with":
        return actual.strip().startswith(target)
    if condition.operator == "ends_with":
        return actual.strip().endswith(target)
    return False


def _evaluate_custom_rule(context: EmailContext, rule: DetectionRule, running_score: int) -> RuleResult:
    if not rule.conditions:
        return RuleResult.no_match(rule.name)

    result = None
    for condition in rule.conditions:
        cond_value = _evaluate_condition(context, condition, running_score)
        if condition.joiner == "NOT":
            cond_value = not cond_value

        if result is None:
            result = cond_value
        elif condition.joiner == "OR":
            result = result or cond_value
        else:  # AND (default)
            result = result and cond_value

    if not result:
        return RuleResult.no_match(rule.name)

    return RuleResult(
        matched=True,
        score=rule.score,
        reason=f"Custom rule matched: {rule.name}" + (f" - {rule.description}" if rule.description else ""),
        category=rule.category,
        severity=rule.severity,
        rule_name=f"custom.{rule.name}",
        metadata={"rule_id": rule.id, "action": rule.action},
    )


def run_builtin_rules(context: EmailContext) -> list[RuleResult]:
    results = []
    for rule in ALL_BUILTIN_RULES:
        try:
            result = rule.evaluate(context)
        except Exception as exc:  # pragma: no cover - a single bad rule must not break the pipeline
            logger.exception("Rule %s raised an exception", getattr(rule, "name", rule))
            continue
        if result.matched:
            results.append(result)
    return results


def run_custom_rules(context: EmailContext, organization_id: str | None, running_score: int) -> list[RuleResult]:
    if organization_id is None:
        return []
    query = DetectionRule.query.filter_by(is_custom=True, enabled=True)
    query = query.filter((DetectionRule.organization_id == organization_id) | (DetectionRule.organization_id.is_(None)))
    results = []
    for rule in query.all():
        result = _evaluate_custom_rule(context, rule, running_score)
        if result.matched:
            results.append(result)
    return results


def analyze(context: EmailContext, organization_id: str | None = None) -> list[RuleResult]:
    """Full rule pass: built-ins first (to establish a running score), then custom rules."""
    builtin_results = run_builtin_rules(context)
    running_score = sum(r.score for r in builtin_results)
    custom_results = run_custom_rules(context, organization_id, running_score)
    return builtin_results + custom_results
