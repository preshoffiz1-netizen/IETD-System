"""
Super admin portal (platform owner only). Read-only visibility across every
organization -- user counts, mailbox counts, scan activity, and app logs --
for the developer to track how the deployed app is doing and demo it, NOT to
view or act on any individual user's email/mailbox data. See
app/services/superadmin_service.py and app/utils/decorators.py for the
isolation rationale.

This is additive: a super admin account is a completely normal user account
(own organization, own mailboxes, own rules, everything else in the app
works for them exactly like anyone else) that additionally has this section
unlocked -- so the same login can be used to actually try IETDS as an end
user *and* see the platform-wide picture, without needing a separate account.
"""

from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from app.services import audit_service, superadmin_service
from app.utils.decorators import super_admin_required
from app.utils.log_buffer import recent as recent_logs

bp = Blueprint("superadmin", __name__, url_prefix="/superadmin")


@bp.route("/")
@login_required
@super_admin_required
def index():
    audit_service.log_event("superadmin.viewed_overview", user_id=current_user.id)
    return render_template(
        "superadmin/index.html",
        overview=superadmin_service.platform_overview(),
        organizations=superadmin_service.organizations_summary(),
        unhealthy_mailboxes=superadmin_service.mailbox_health(),
    )


@bp.route("/users")
@login_required
@super_admin_required
def users():
    audit_service.log_event("superadmin.viewed_users", user_id=current_user.id)
    return render_template("superadmin/users.html", users=superadmin_service.users_summary())


@bp.route("/logs")
@login_required
@super_admin_required
def logs():
    level = request.args.get("level") or None
    audit_service.log_event("superadmin.viewed_logs", user_id=current_user.id, metadata={"level": level})
    return render_template("superadmin/logs.html", logs=recent_logs(limit=200, level=level), level=level)
