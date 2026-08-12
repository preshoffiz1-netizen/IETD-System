"""Email listing, search, and inspection (Sections 35, 39)."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Classification, Email, Feedback, FeedbackType, Mailbox
from app.services import quarantine_service
from app.utils.security import sanitize_email_html

bp = Blueprint("emails", __name__, url_prefix="/emails")


def _org_mailbox_ids():
    return [m.id for m in Mailbox.query.filter_by(organization_id=current_user.organization_id).all()]


@bp.route("/")
@login_required
def list_emails():
    mailbox_ids = _org_mailbox_ids()
    query = Email.query.filter(Email.mailbox_id.in_(mailbox_ids)) if mailbox_ids else Email.query.filter(False)

    sender = request.args.get("sender", "").strip()
    subject = request.args.get("subject", "").strip()
    classification = request.args.get("classification", "").strip()
    mailbox_id = request.args.get("mailbox_id", "").strip()
    min_score = request.args.get("min_score", type=int)
    page = request.args.get("page", 1, type=int)

    if sender:
        query = query.filter(Email.sender.ilike(f"%{sender}%"))
    if subject:
        query = query.filter(Email.subject.ilike(f"%{subject}%"))
    if classification:
        query = query.filter(Email.classification == classification)
    if mailbox_id:
        query = query.filter(Email.mailbox_id == mailbox_id)
    if min_score is not None:
        query = query.filter(Email.threat_score >= min_score)

    pagination = query.order_by(Email.created_at.desc()).paginate(page=page, per_page=25, error_out=False)

    return render_template(
        "emails/list.html", pagination=pagination, emails=pagination.items,
        classifications=Classification.ALL,
        mailboxes=Mailbox.query.filter_by(organization_id=current_user.organization_id).all(),
        filters=request.args,
    )


def _get_email_or_404(email_id: str) -> Email:
    email = Email.query.get_or_404(email_id)
    if email.mailbox.organization_id != current_user.organization_id:
        abort(403)
    return email


@bp.route("/<email_id>")
@login_required
def detail(email_id):
    email = _get_email_or_404(email_id)
    safe_html = sanitize_email_html(email.body_html) if email.body_html else ""
    return render_template("emails/detail.html", email=email, safe_html=safe_html)


@bp.route("/<email_id>/release", methods=["POST"])
@login_required
def release(email_id):
    email = _get_email_or_404(email_id)
    if email.quarantine_item:
        quarantine_service.release_email(email.quarantine_item, current_user.id)
        flash("Email released from quarantine.", "success")
    return redirect(url_for("emails.detail", email_id=email_id))


@bp.route("/<email_id>/whitelist", methods=["POST"])
@login_required
def whitelist(email_id):
    email = _get_email_or_404(email_id)
    entry_type = request.form.get("entry_type", "email")
    quarantine_service.whitelist_sender(email, email.mailbox.organization_id, current_user.id, entry_type)
    flash("Sender added to whitelist.", "success")
    return redirect(url_for("emails.detail", email_id=email_id))


@bp.route("/<email_id>/blacklist", methods=["POST"])
@login_required
def blacklist(email_id):
    email = _get_email_or_404(email_id)
    entry_type = request.form.get("entry_type", "email")
    quarantine_service.blacklist_sender(email, email.mailbox.organization_id, current_user.id, entry_type)
    flash("Sender added to blacklist.", "success")
    return redirect(url_for("emails.detail", email_id=email_id))


@bp.route("/<email_id>/feedback", methods=["POST"])
@login_required
def feedback(email_id):
    email = _get_email_or_404(email_id)
    feedback_type = request.form.get("feedback_type")
    if feedback_type not in {FeedbackType.FALSE_POSITIVE, FeedbackType.FALSE_NEGATIVE}:
        abort(400)
    db.session.add(Feedback(email_id=email.id, user_id=current_user.id, feedback_type=feedback_type,
                             comment=request.form.get("comment", "")))
    db.session.commit()
    flash("Thank you - your feedback has been recorded for rule analysis.", "success")
    return redirect(url_for("emails.detail", email_id=email_id))


@bp.route("/<email_id>/delete", methods=["POST"])
@login_required
def delete(email_id):
    email = _get_email_or_404(email_id)
    if email.quarantine_item:
        quarantine_service.delete_permanently(email.quarantine_item, current_user.id)
    else:
        email.status = "deleted"
        db.session.commit()
    flash("Email deleted.", "info")
    return redirect(url_for("emails.list_emails"))
