"""Custom rule builder (Section 32) + built-in rule overview."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.detection import ALL_BUILTIN_RULES
from app.extensions import db
from app.models import DetectionRule, RuleAction, RuleCondition
from app.services import audit_service

bp = Blueprint("rules", __name__, url_prefix="/rules")


@bp.route("/")
@login_required
def list_rules():
    custom_rules = DetectionRule.query.filter(
        DetectionRule.is_custom.is_(True),
        (DetectionRule.organization_id == current_user.organization_id) | (DetectionRule.organization_id.is_(None)),
    ).order_by(DetectionRule.created_at.desc()).all()

    builtin_summary = [
        {"name": r.name, "category": r.category, "score": r.default_score, "severity": r.severity}
        for r in ALL_BUILTIN_RULES
    ]
    return render_template("rules/list.html", custom_rules=custom_rules, builtin_rules=builtin_summary)


@bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        rule = DetectionRule(
            organization_id=current_user.organization_id,
            created_by_id=current_user.id,
            name=request.form.get("name", "").strip(),
            description=request.form.get("description", "").strip(),
            category=request.form.get("category", "custom"),
            severity=request.form.get("severity", "medium"),
            score=request.form.get("score", type=int) or 10,
            action=request.form.get("action", RuleAction.FLAG),
            is_custom=True,
            enabled=True,
        )
        if not rule.name:
            flash("Rule name is required.", "danger")
            return render_template("rules/create.html", fields=RuleCondition.FIELDS,
                                    operators=RuleCondition.OPERATORS, actions=RuleAction.ALL)

        db.session.add(rule)
        db.session.flush()

        fields = request.form.getlist("condition_field")
        operators = request.form.getlist("condition_operator")
        values = request.form.getlist("condition_value")
        joiners = request.form.getlist("condition_joiner")

        for i, (field, operator, value) in enumerate(zip(fields, operators, values)):
            if not value.strip():
                continue
            db.session.add(RuleCondition(
                rule_id=rule.id, field=field, operator=operator, value=value.strip(),
                joiner=joiners[i] if i < len(joiners) else "AND", position=i,
            ))

        db.session.commit()
        audit_service.log_event("rule_created", user_id=current_user.id, target_type="rule", target_id=rule.id,
                                 metadata={"name": rule.name})
        flash(f"Custom rule '{rule.name}' created.", "success")
        return redirect(url_for("rules.list_rules"))

    return render_template("rules/create.html", fields=RuleCondition.FIELDS,
                            operators=RuleCondition.OPERATORS, actions=RuleAction.ALL)


def _get_rule_or_404(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    if rule.organization_id != current_user.organization_id:
        abort(403)
    return rule


@bp.route("/<rule_id>/toggle", methods=["POST"])
@login_required
def toggle(rule_id):
    rule = _get_rule_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    audit_service.log_event("rule_updated", user_id=current_user.id, target_type="rule", target_id=rule.id,
                             metadata={"enabled": rule.enabled})
    return redirect(url_for("rules.list_rules"))


@bp.route("/<rule_id>/delete", methods=["POST"])
@login_required
def delete(rule_id):
    rule = _get_rule_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    audit_service.log_event("rule_deleted", user_id=current_user.id, target_type="rule", target_id=rule_id)
    flash("Custom rule deleted.", "info")
    return redirect(url_for("rules.list_rules"))
