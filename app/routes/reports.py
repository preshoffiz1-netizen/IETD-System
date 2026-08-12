"""Reporting (Section 40)."""

from __future__ import annotations

from flask import Blueprint, Response, render_template
from flask_login import current_user, login_required

from app.models import Feedback, FeedbackType, Mailbox
from app.services import report_service

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
@login_required
def index():
    org_id = current_user.organization_id
    mailbox_ids = [m.id for m in Mailbox.query.filter_by(organization_id=org_id).all()]

    fp_count = fn_count = 0
    if mailbox_ids:
        from app.models import Email
        email_ids = [e.id for e in Email.query.filter(Email.mailbox_id.in_(mailbox_ids)).all()]
        if email_ids:
            fp_count = Feedback.query.filter(Feedback.email_id.in_(email_ids),
                                              Feedback.feedback_type == FeedbackType.FALSE_POSITIVE).count()
            fn_count = Feedback.query.filter(Feedback.email_id.in_(email_ids),
                                              Feedback.feedback_type == FeedbackType.FALSE_NEGATIVE).count()

    return render_template(
        "reports/index.html",
        stats=report_service.dashboard_stats(org_id),
        top_senders=report_service.top_suspicious_senders(org_id),
        top_domains=report_service.top_suspicious_domains(org_id),
        top_rules=report_service.most_triggered_rules(org_id),
        false_positive_count=fp_count,
        false_negative_count=fn_count,
    )


@bp.route("/export/csv")
@login_required
def export_csv():
    csv_data = report_service.export_csv(current_user.organization_id)
    return Response(csv_data, mimetype="text/csv",
                     headers={"Content-Disposition": "attachment; filename=ietds_report.csv"})


@bp.route("/export/json")
@login_required
def export_json():
    json_data = report_service.export_json(current_user.organization_id)
    return Response(json_data, mimetype="application/json",
                     headers={"Content-Disposition": "attachment; filename=ietds_report.json"})
