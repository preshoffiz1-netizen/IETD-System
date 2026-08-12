"""System health (Section 42)."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template
from flask_login import current_user, login_required
from sqlalchemy import text

from app.extensions import db
from app.models import Mailbox, ScanJob, ScanJobStatus

bp = Blueprint("health", __name__)


def _compute_health(organization_id: str | None = None) -> dict:
    db_healthy = True
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        db_healthy = False

    scheduler = current_app.extensions.get("ietds_scheduler")
    scheduler_running = bool(scheduler and scheduler.running)

    mailbox_query = Mailbox.query
    if organization_id:
        mailbox_query = mailbox_query.filter_by(organization_id=organization_id)
    connected_mailboxes = mailbox_query.filter_by(status="connected").count()

    job_query = ScanJob.query
    if organization_id:
        job_query = job_query.join(Mailbox).filter(Mailbox.organization_id == organization_id)
    last_scan = job_query.order_by(ScanJob.completed_at.desc()).first()
    failed_jobs = job_query.filter(ScanJob.status == ScanJobStatus.FAILED).count()

    return {
        "application": "healthy",
        "database": "healthy" if db_healthy else "error",
        "background_worker": "running" if scheduler_running else "stopped",
        "queue": "healthy" if scheduler_running else "error",
        "last_successful_scan": last_scan.completed_at.isoformat() if last_scan and last_scan.completed_at else None,
        "connected_mailboxes": connected_mailboxes,
        "failed_jobs": failed_jobs,
    }


@bp.route("/health")
@login_required
def health_page():
    return render_template("health/index.html", health=_compute_health(current_user.organization_id))


@bp.route("/api/health")
def health_json():
    """Unauthenticated liveness endpoint for load balancers / uptime monitors."""
    return jsonify(_compute_health())
