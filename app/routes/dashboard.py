from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.services import report_service

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@bp.route("/dashboard")
@login_required
def index():
    org_id = current_user.organization_id
    stats = report_service.dashboard_stats(org_id)
    return render_template(
        "dashboard/index.html",
        stats=stats,
        classification_chart=report_service.classification_distribution(org_id),
        threats_over_time=report_service.threats_over_time(org_id),
        top_senders=report_service.top_suspicious_senders(org_id),
        top_domains=report_service.top_suspicious_domains(org_id),
        top_rules=report_service.most_triggered_rules(org_id),
        score_distribution=report_service.score_distribution(org_id),
        recent_threats=report_service.recent_threats(org_id),
    )
