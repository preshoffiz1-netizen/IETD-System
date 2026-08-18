"""
REST API (Section 55).

Session-cookie authenticated (reuses Flask-Login), which keeps things simple
for a final-year project while still being a genuine, protected JSON API --
every route below requires @login_required and enforces organization-scoped
access exactly like the HTML routes.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required, login_user

from app.extensions import csrf
from app.models import DetectionRule, Email, Mailbox, QuarantineItem, RuleAction, RuleCondition, User
from app.services import mailbox_service, quarantine_service, report_service, scanner_service

bp = Blueprint("api", __name__, url_prefix="/api")


def _mailbox_to_dict(m: Mailbox) -> dict:
    return {
        "id": m.id, "provider": m.provider, "email_address": m.email_address,
        "status": m.status, "monitoring_enabled": m.monitoring_enabled,
        "scan_interval_minutes": m.scan_interval_minutes,
        "last_scan_at": m.last_scan_at.isoformat() if m.last_scan_at else None,
        "messages_processed": m.messages_processed, "threats_detected": m.threats_detected,
        "capabilities": m.capabilities(),
    }


def _email_to_dict(e: Email) -> dict:
    return {
        "id": e.id, "sender": e.sender, "subject": e.subject, "classification": e.classification,
        "threat_score": e.threat_score, "risk_percentage": e.risk_percentage,
        "status": e.status, "action_taken": e.action_taken,
        "created_at": e.created_at.isoformat(),
    }


@bp.route("/auth/login", methods=["POST"])
@csrf.exempt
def api_login():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password) and user.is_active:
        login_user(user)
        return jsonify({"success": True, "user": {"id": user.id, "email": user.email, "role": user.role}})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@bp.route("/mailboxes", methods=["GET"])
@login_required
def api_list_mailboxes():
    mailboxes = Mailbox.query.filter_by(organization_id=current_user.organization_id).all()
    return jsonify([_mailbox_to_dict(m) for m in mailboxes])


def _get_mailbox_or_404(mailbox_id):
    mailbox = Mailbox.query.get_or_404(mailbox_id)
    if mailbox.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    return mailbox


@bp.route("/mailboxes/<mailbox_id>/test", methods=["POST"])
@login_required
def api_test_mailbox(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    result = mailbox_service.test_connection(mailbox)
    return jsonify({"success": result.success, "message": result.message})


@bp.route("/mailboxes/<mailbox_id>/scan", methods=["POST"])
@login_required
def api_scan_mailbox(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    job = scanner_service.run_scan(mailbox, trigger="manual")
    return jsonify({
        "status": job.status, "messages_processed": job.messages_processed,
        "quarantined_count": job.quarantined_count, "error_message": job.error_message,
    })


@bp.route("/emails", methods=["GET"])
@login_required
def api_list_emails():
    mailbox_ids = [m.id for m in Mailbox.query.filter_by(organization_id=current_user.organization_id).all()]
    query = Email.query.filter(Email.mailbox_id.in_(mailbox_ids)) if mailbox_ids else Email.query.filter(False)
    classification = request.args.get("classification")
    if classification:
        query = query.filter(Email.classification == classification)
    limit = min(request.args.get("limit", 50, type=int), 200)
    emails = query.order_by(Email.created_at.desc()).limit(limit).all()
    return jsonify([_email_to_dict(e) for e in emails])


@bp.route("/emails/<email_id>", methods=["GET"])
@login_required
def api_get_email(email_id):
    email = Email.query.get_or_404(email_id)
    if email.mailbox.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    data = _email_to_dict(email)
    if email.threat_analysis:
        data["score_breakdown"] = email.threat_analysis.score_breakdown()
        data["indicators"] = [
            {"rule": i.rule_name, "category": i.category, "severity": i.severity,
             "score": i.score_contribution, "reason": i.reason}
            for i in email.threat_analysis.indicators
        ]
    return jsonify(data)


@bp.route("/quarantine", methods=["GET"])
@login_required
def api_list_quarantine():
    mailbox_ids = [m.id for m in Mailbox.query.filter_by(organization_id=current_user.organization_id).all()]
    items = QuarantineItem.query.filter(QuarantineItem.mailbox_id.in_(mailbox_ids)).all() if mailbox_ids else []
    return jsonify([{"id": i.id, "email_id": i.email_id, "status": i.status, "reason": i.reason} for i in items])


@bp.route("/quarantine/<item_id>/release", methods=["POST"])
@login_required
def api_release_quarantine(item_id):
    item = QuarantineItem.query.get_or_404(item_id)
    if item.email.mailbox.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    quarantine_service.release_email(item, current_user.id)
    return jsonify({"success": True})


@bp.route("/quarantine/<item_id>/delete", methods=["POST"])
@login_required
def api_delete_quarantine(item_id):
    item = QuarantineItem.query.get_or_404(item_id)
    if item.email.mailbox.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    quarantine_service.delete_permanently(item, current_user.id)
    return jsonify({"success": True})


@bp.route("/rules", methods=["GET"])
@login_required
def api_list_rules():
    rules = DetectionRule.query.filter(
        (DetectionRule.organization_id == current_user.organization_id) | (DetectionRule.organization_id.is_(None))
    ).all()
    return jsonify([{"id": r.id, "name": r.name, "category": r.category, "score": r.score,
                      "action": r.action, "enabled": r.enabled} for r in rules])


@bp.route("/rules", methods=["POST"])
@login_required
def api_create_rule():
    from app.extensions import db

    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "flag")
    if action not in RuleAction.ALL:
        action = "flag"
    try:
        score = max(1, min(150, int(payload.get("score", 10))))
    except (TypeError, ValueError):
        score = 10

    rule = DetectionRule(
        organization_id=current_user.organization_id, created_by_id=current_user.id,
        name=payload.get("name", "Untitled Rule"), description=payload.get("description", ""),
        category=payload.get("category", "custom"), severity=payload.get("severity", "medium"),
        score=score, action=action, is_custom=True,
    )
    db.session.add(rule)
    db.session.flush()
    position = 0
    for condition in payload.get("conditions", []):
        field = condition.get("field")
        operator = condition.get("operator", "contains")
        value = (condition.get("value") or "").strip()
        # Skip anything that isn't a real, evaluable condition instead of
        # persisting garbage that the detection engine would never match.
        if not value or field not in RuleCondition.FIELDS or operator not in RuleCondition.OPERATORS:
            continue
        db.session.add(RuleCondition(
            rule_id=rule.id, field=field, operator=operator,
            value=value, joiner=condition.get("joiner", "AND"), position=position,
        ))
        position += 1
    db.session.commit()
    return jsonify({"id": rule.id, "name": rule.name}), 201


@bp.route("/rules/<rule_id>", methods=["PUT"])
@login_required
def api_update_rule(rule_id):
    from app.extensions import db

    rule = DetectionRule.query.get_or_404(rule_id)
    if rule.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    payload = request.get_json(silent=True) or {}
    for field in ("name", "description", "category", "severity", "action"):
        if field in payload:
            setattr(rule, field, payload[field])
    if "score" in payload:
        rule.score = int(payload["score"])
    if "enabled" in payload:
        rule.enabled = bool(payload["enabled"])
    db.session.commit()
    return jsonify({"success": True})


@bp.route("/rules/<rule_id>", methods=["DELETE"])
@login_required
def api_delete_rule(rule_id):
    from app.extensions import db

    rule = DetectionRule.query.get_or_404(rule_id)
    if rule.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"success": True})


@bp.route("/dashboard/stats", methods=["GET"])
@login_required
def api_dashboard_stats():
    return jsonify(report_service.dashboard_stats(current_user.organization_id))


@bp.route("/reports", methods=["GET"])
@login_required
def api_reports():
    org_id = current_user.organization_id
    return jsonify({
        "stats": report_service.dashboard_stats(org_id),
        "top_senders": report_service.top_suspicious_senders(org_id),
        "top_domains": report_service.top_suspicious_domains(org_id),
        "top_rules": report_service.most_triggered_rules(org_id),
    })
