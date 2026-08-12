"""Settings (Section 33, 45): thresholds, retention, branding, profile, scan defaults."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AuditLog, Mailbox
from app.models.base import utcnow
from app.services import audit_service, settings_service

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/")
@login_required
def index():
    return render_template("settings/index.html", settings=settings_service.get_all(),
                            thresholds=settings_service.get_thresholds())


@bp.route("/thresholds", methods=["POST"])
@login_required
def update_thresholds():
    if not current_user.is_admin:
        flash("Only administrators can change detection thresholds.", "danger")
        return redirect(url_for("settings.index"))

    for key in ("clean_max", "suspicious_max", "spam_max", "high_risk_min"):
        value = request.form.get(key, type=int)
        if value is not None:
            settings_service.set(f"threshold.{key}", value, value_type="int")

    audit_service.log_event("settings_changed", user_id=current_user.id, target_type="settings",
                             metadata={"section": "thresholds"})
    flash("Detection thresholds updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/actions", methods=["POST"])
@login_required
def update_actions():
    if not current_user.is_admin:
        flash("Only administrators can change action policies.", "danger")
        return redirect(url_for("settings.index"))

    for classification in ("clean", "suspicious", "spam", "scam", "phishing", "malicious_attachment"):
        value = request.form.get(f"action_{classification}")
        if value is not None:
            settings_service.set(f"action.{classification}", value)

    audit_service.log_event("settings_changed", user_id=current_user.id, target_type="settings",
                             metadata={"section": "actions"})
    flash("Action policies updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/branding", methods=["POST"])
@login_required
def update_branding():
    if not current_user.is_admin:
        flash("Only administrators can change branding.", "danger")
        return redirect(url_for("settings.index"))

    settings_service.set("branding.app_name", request.form.get("app_name", "IETDS"))
    settings_service.set("branding.tagline", request.form.get("tagline", ""))
    flash("Branding updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.full_name = request.form.get("full_name", current_user.full_name).strip()
        new_password = request.form.get("new_password", "")
        if new_password:
            if len(new_password) < 10:
                flash("New password must be at least 10 characters.", "danger")
                return redirect(url_for("settings.profile"))
            current_user.set_password(new_password)
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("settings.profile"))

    return render_template("settings/profile.html")
