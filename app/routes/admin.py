"""Admin routes (Section 11): user management, org settings, audit log viewer."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AuditLog, Role, User
from app.utils.decorators import admin_required

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users")
@login_required
@admin_required
def users():
    org_users = User.query.filter_by(organization_id=current_user.organization_id).order_by(User.created_at).all()
    return render_template("admin/users.html", users=org_users, roles=Role.ALL)


@bp.route("/users/<user_id>/role", methods=["POST"])
@login_required
@admin_required
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    if user.organization_id != current_user.organization_id:
        flash("You can only manage users in your own organization.", "danger")
        return redirect(url_for("admin.users"))
    new_role = request.form.get("role")
    if new_role in Role.ALL:
        user.role = new_role
        db.session.commit()
        flash(f"{user.email}'s role updated to {new_role}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<user_id>/toggle-active", methods=["POST"])
@login_required
@admin_required
def toggle_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.organization_id != current_user.organization_id:
        flash("You can only manage users in your own organization.", "danger")
        return redirect(url_for("admin.users"))
    user.is_active_flag = not user.is_active_flag
    db.session.commit()
    flash(f"{user.email} is now {'active' if user.is_active_flag else 'disabled'}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/audit-log")
@login_required
@admin_required
def audit_log():
    page = request.args.get("page", 1, type=int)
    query = AuditLog.query.filter_by(organization_id=current_user.organization_id).order_by(
        AuditLog.created_at.desc())
    pagination = query.paginate(page=page, per_page=50, error_out=False)
    return render_template("admin/audit_log.html", pagination=pagination, logs=pagination.items)
