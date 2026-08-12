"""Quarantine management routes (Section 29)."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import Mailbox, QuarantineItem, QuarantineStatus
from app.services import quarantine_service

bp = Blueprint("quarantine", __name__, url_prefix="/quarantine")


def _org_mailbox_ids():
    return [m.id for m in Mailbox.query.filter_by(organization_id=current_user.organization_id).all()]


@bp.route("/")
@login_required
def list_quarantine():
    mailbox_ids = _org_mailbox_ids()
    query = QuarantineItem.query.filter(QuarantineItem.mailbox_id.in_(mailbox_ids)) if mailbox_ids \
        else QuarantineItem.query.filter(False)

    status = request.args.get("status", QuarantineStatus.QUARANTINED)
    if status:
        query = query.filter(QuarantineItem.status == status)

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(QuarantineItem.quarantined_at.desc()).paginate(page=page, per_page=25,
                                                                                error_out=False)
    return render_template("quarantine/list.html", pagination=pagination, items=pagination.items, status=status)


def _get_item_or_404(item_id: str) -> QuarantineItem:
    item = QuarantineItem.query.get_or_404(item_id)
    if item.email.mailbox.organization_id != current_user.organization_id:
        abort(403)
    return item


@bp.route("/<item_id>/release", methods=["POST"])
@login_required
def release(item_id):
    item = _get_item_or_404(item_id)
    quarantine_service.release_email(item, current_user.id)
    flash("Email released from quarantine.", "success")
    return redirect(url_for("quarantine.list_quarantine"))


@bp.route("/<item_id>/mark-safe", methods=["POST"])
@login_required
def mark_safe(item_id):
    item = _get_item_or_404(item_id)
    quarantine_service.mark_safe(item, current_user.id)
    flash("Email marked as safe and released.", "success")
    return redirect(url_for("quarantine.list_quarantine"))


@bp.route("/<item_id>/delete", methods=["POST"])
@login_required
def delete(item_id):
    item = _get_item_or_404(item_id)
    quarantine_service.delete_permanently(item, current_user.id)
    flash("Email permanently deleted.", "info")
    return redirect(url_for("quarantine.list_quarantine"))


@bp.route("/<item_id>/whitelist", methods=["POST"])
@login_required
def whitelist(item_id):
    item = _get_item_or_404(item_id)
    quarantine_service.whitelist_sender(item.email, item.email.mailbox.organization_id, current_user.id)
    flash("Sender whitelisted.", "success")
    return redirect(url_for("quarantine.list_quarantine"))


@bp.route("/<item_id>/blacklist", methods=["POST"])
@login_required
def blacklist(item_id):
    item = _get_item_or_404(item_id)
    quarantine_service.blacklist_sender(item.email, item.email.mailbox.organization_id, current_user.id)
    flash("Sender blacklisted.", "success")
    return redirect(url_for("quarantine.list_quarantine"))
