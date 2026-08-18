"""Custom rule builder (Section 32) + built-in rule overview."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.detection import ALL_BUILTIN_RULES
from app.extensions import db
from app.models import DetectionRule, RuleAction, RuleCondition
from app.services import audit_service

bp = Blueprint("rules", __name__, url_prefix="/rules")

# Plain-language labels shown in the simplified rule builder, so end users
# never have to know the underlying field/operator names. Kept here (not in
# the model) since this is presentation, not data.
FIELD_LABELS = {
    "sender": "Sender's email address",
    "sender_domain": "Sender's domain (e.g. paypal-secure.com)",
    "subject": "Subject line",
    "body": "Email body / message text",
    "url": "A link inside the email",
    "url_domain": "A link's domain",
    "attachment_extension": "Attachment file type (e.g. .exe, .zip)",
    "attachment_mime_type": "Attachment file type (technical / MIME)",
    "threat_score": "IETDS's existing risk score for this email",
    "spf_status": "Sender authentication check: SPF",
    "dkim_status": "Sender authentication check: DKIM",
    "dmarc_status": "Sender authentication check: DMARC",
}
# Fields simple enough to show by default; the rest are grouped under
# "Advanced" in the builder since they need some email-security background.
BASIC_FIELDS = (
    "sender", "sender_domain", "subject", "body", "url", "url_domain", "attachment_extension",
)
OPERATOR_LABELS = {
    "contains": "contains",
    "equals": "is exactly",
    "not_equals": "is not",
    "starts_with": "starts with",
    "ends_with": "ends with",
    "greater_than": "is greater than",
    "less_than": "is less than",
}
# A rule builder that makes people type a raw "how many points" number is a
# usability dead end for non-technical end users, so severity now drives the
# score by default. Power users can still override it (see "Advanced" in the
# template) -- the number just isn't front-and-center anymore.
SEVERITY_SCORE_DEFAULTS = {"low": 10, "medium": 25, "high": 45, "critical": 70}

# One-click starting points for the most common rule shapes, so a
# non-technical user can go from "I want to block emails from this address"
# to a working rule without first learning what a "condition" is. Each entry
# just pre-fills the field/operator/severity in the browser (see create.html);
# nothing server-side changes, it's the same DetectionRule/RuleCondition data.
QUICK_RULE_PRESETS = [
    {"key": "sender", "label": "Block a specific sender", "icon": "fa-user-slash",
     "field": "sender", "operator": "equals", "severity": "high", "action": RuleAction.QUARANTINE,
     "placeholder": "scammer@example.com"},
    {"key": "keyword", "label": "Flag a word/phrase in the subject", "icon": "fa-font",
     "field": "subject", "operator": "contains", "severity": "medium", "action": RuleAction.FLAG,
     "placeholder": "e.g. urgent wire transfer"},
    {"key": "link", "label": "Flag a suspicious link domain", "icon": "fa-link",
     "field": "url_domain", "operator": "contains", "severity": "high", "action": RuleAction.QUARANTINE,
     "placeholder": "e.g. bit.ly"},
    {"key": "attachment", "label": "Flag a risky attachment type", "icon": "fa-paperclip",
     "field": "attachment_extension", "operator": "equals", "severity": "critical",
     "action": RuleAction.QUARANTINE, "placeholder": "e.g. .exe"},
]


def _rule_builder_context(**extra):
    return dict(
        fields=RuleCondition.FIELDS,
        basic_fields=BASIC_FIELDS,
        advanced_fields=[f for f in RuleCondition.FIELDS if f not in BASIC_FIELDS],
        field_labels=FIELD_LABELS,
        operators=RuleCondition.OPERATORS,
        operator_labels=OPERATOR_LABELS,
        actions=RuleAction.ALL,
        severity_defaults=SEVERITY_SCORE_DEFAULTS,
        presets=QUICK_RULE_PRESETS,
        **extra,
    )


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
        name = request.form.get("name", "").strip()
        severity = request.form.get("severity", "medium")
        if severity not in SEVERITY_SCORE_DEFAULTS:
            severity = "medium"
        category = request.form.get("category", "custom")
        action = request.form.get("action", RuleAction.FLAG)
        if action not in RuleAction.ALL:
            action = RuleAction.FLAG

        # "Advanced" score override: if the user never touched the advanced
        # score field, fall back to a sensible default for the severity they
        # picked instead of forcing everyone to think in raw points.
        raw_score = request.form.get("score", "").strip()
        if raw_score:
            score = max(1, min(150, request.form.get("score", type=int) or SEVERITY_SCORE_DEFAULTS[severity]))
        else:
            score = SEVERITY_SCORE_DEFAULTS[severity]

        errors = []
        if not name:
            errors.append("Rule name is required.")

        fields = request.form.getlist("condition_field")
        operators = request.form.getlist("condition_operator")
        values = request.form.getlist("condition_value")
        joiners = request.form.getlist("condition_joiner")

        valid_conditions = []
        for i, (field, operator, value) in enumerate(zip(fields, operators, values)):
            value = value.strip()
            if not value:
                continue
            if field not in RuleCondition.FIELDS or operator not in RuleCondition.OPERATORS:
                # Ignore silently-tampered/garbage input rather than crashing or
                # saving a condition that can never be evaluated.
                continue
            valid_conditions.append({
                "field": field, "operator": operator, "value": value,
                "joiner": joiners[i] if i < len(joiners) and joiners[i] in RuleCondition.JOINERS else "AND",
            })

        if not valid_conditions:
            errors.append("Add at least one condition (what should this rule look for?) with a value filled in.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("rules/create.html", **_rule_builder_context(form=request.form))

        rule = DetectionRule(
            organization_id=current_user.organization_id,
            created_by_id=current_user.id,
            name=name,
            description=request.form.get("description", "").strip(),
            category=category,
            severity=severity,
            score=score,
            action=action,
            is_custom=True,
            enabled=True,
        )
        db.session.add(rule)
        db.session.flush()

        for i, cond in enumerate(valid_conditions):
            db.session.add(RuleCondition(
                rule_id=rule.id, field=cond["field"], operator=cond["operator"], value=cond["value"],
                joiner=cond["joiner"], position=i,
            ))

        db.session.commit()
        audit_service.log_event("rule_created", user_id=current_user.id, target_type="rule", target_id=rule.id,
                                 metadata={"name": rule.name})
        flash(f"Custom rule '{rule.name}' created.", "success")
        return redirect(url_for("rules.list_rules"))

    return render_template("rules/create.html", **_rule_builder_context(form=None))


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
