"""Mailbox connection & management routes (Section 8)."""

from __future__ import annotations

import secrets

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Mailbox, ProviderType
from app.providers import available_providers
from app.providers.gmail_provider import build_authorization_url as gmail_auth_url
from app.providers.gmail_provider import exchange_code_for_token as gmail_exchange
from app.providers.microsoft_provider import build_authorization_url as ms_auth_url
from app.providers.microsoft_provider import exchange_code_for_token as ms_exchange
from app.services import audit_service, mailbox_service, scanner_service
from app.utils.decorators import owns_resource_or_admin

bp = Blueprint("mailbox", __name__, url_prefix="/mailboxes")


def _get_mailbox_or_404(mailbox_id: str) -> Mailbox:
    mailbox = Mailbox.query.get_or_404(mailbox_id)
    if mailbox.organization_id != current_user.organization_id:
        from flask import abort
        abort(403)
    return mailbox


@bp.route("/")
@login_required
def list_mailboxes():
    mailboxes = Mailbox.query.filter_by(organization_id=current_user.organization_id).all()
    return render_template("mailboxes/list.html", mailboxes=mailboxes, providers=available_providers())


@bp.route("/connect", methods=["GET", "POST"])
@login_required
def connect():
    provider = request.args.get("provider", "imap")

    if request.method == "POST":
        provider = request.form.get("provider", "imap")

        if provider == "imap":
            mailbox_service.create_imap_mailbox(
                organization_id=current_user.organization_id,
                user_id=current_user.id,
                email_address=request.form.get("email_address", "").strip(),
                imap_host=request.form.get("imap_host", "").strip(),
                imap_port=int(request.form.get("imap_port") or 993),
                imap_use_ssl=bool(request.form.get("imap_use_ssl")),
                imap_username=request.form.get("imap_username", "").strip(),
                password=request.form.get("password", ""),
                display_name=request.form.get("display_name", "").strip(),
            )
            flash("Mailbox added. Click 'Test Connection' to verify it, then 'Scan Now' or enable monitoring.",
                  "success")
            return redirect(url_for("mailbox.list_mailboxes"))

        if provider == "demo":
            mailbox_service.create_demo_mailbox(organization_id=current_user.organization_id, user_id=current_user.id)
            flash("Demo mailbox created with synthetic test emails.", "success")
            return redirect(url_for("mailbox.list_mailboxes"))

        if provider == "gmail":
            return redirect(url_for("mailbox.gmail_oauth_start"))

        if provider == "microsoft":
            return redirect(url_for("mailbox.microsoft_oauth_start"))

    return render_template("mailboxes/connect.html", provider=provider)


@bp.route("/<mailbox_id>/test", methods=["POST"])
@login_required
def test_connection(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    result = mailbox_service.test_connection(mailbox)
    flash(result.message, "success" if result.success else "danger")
    return redirect(url_for("mailbox.list_mailboxes"))


@bp.route("/<mailbox_id>/scan", methods=["POST"])
@login_required
def scan_now(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    job = scanner_service.run_scan(mailbox, trigger="manual")
    if job.status == "completed":
        flash(f"Scan complete: {job.messages_processed} message(s) processed, "
              f"{job.quarantined_count} quarantined.", "success")
    else:
        flash(f"Scan failed: {job.error_message}", "danger")
    return redirect(url_for("mailbox.list_mailboxes"))


@bp.route("/<mailbox_id>/monitoring", methods=["POST"])
@login_required
def toggle_monitoring(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    enabled = request.form.get("enabled") == "1"
    interval = request.form.get("interval_minutes", type=int)
    mailbox_service.set_monitoring(mailbox, enabled, interval)
    flash(f"Monitoring {'enabled' if enabled else 'disabled'} for {mailbox.email_address}.", "success")
    return redirect(url_for("mailbox.list_mailboxes"))


@bp.route("/<mailbox_id>/disconnect", methods=["POST"])
@login_required
def disconnect(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    mailbox_service.disconnect(mailbox, current_user.id)
    flash("Mailbox disconnected.", "info")
    return redirect(url_for("mailbox.list_mailboxes"))


@bp.route("/<mailbox_id>/delete", methods=["POST"])
@login_required
def delete(mailbox_id):
    mailbox = _get_mailbox_or_404(mailbox_id)
    mailbox_service.delete_mailbox(mailbox, current_user.id)
    flash("Mailbox deleted.", "info")
    return redirect(url_for("mailbox.list_mailboxes"))


# --- Gmail OAuth (Section 6) --------------------------------------------------------------

@bp.route("/oauth/gmail/start")
@login_required
def gmail_oauth_start():
    client_id = current_app.config.get("GMAIL_CLIENT_ID")
    redirect_uri = current_app.config.get("GMAIL_REDIRECT_URI")
    if not client_id or not redirect_uri:
        flash("Gmail OAuth is not configured on this server. Set GMAIL_CLIENT_ID / "
              "GMAIL_CLIENT_SECRET / GMAIL_REDIRECT_URI in .env.", "warning")
        return redirect(url_for("mailbox.connect", provider="gmail"))
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    return redirect(gmail_auth_url(client_id, redirect_uri, state))


@bp.route("/oauth/gmail/callback")
@login_required
def gmail_oauth_callback():
    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Please try connecting Gmail again.", "danger")
        return redirect(url_for("mailbox.connect", provider="gmail"))

    code = request.args.get("code")
    if not code:
        flash("Gmail authorization was cancelled or failed.", "warning")
        return redirect(url_for("mailbox.connect", provider="gmail"))

    token = gmail_exchange(
        current_app.config["GMAIL_CLIENT_ID"], current_app.config["GMAIL_CLIENT_SECRET"],
        current_app.config["GMAIL_REDIRECT_URI"], code,
    )
    # In a production build, decode the ID token / call userinfo to get the exact
    # address; for this project we ask the user to confirm it once.
    email_address = request.args.get("email") or current_user.email
    mailbox_service.create_oauth_mailbox(
        organization_id=current_user.organization_id, user_id=current_user.id,
        provider=ProviderType.GMAIL, email_address=email_address, token=token,
    )
    flash("Gmail mailbox connected via OAuth 2.0.", "success")
    return redirect(url_for("mailbox.list_mailboxes"))


# --- Microsoft OAuth (Section 6) ----------------------------------------------------------

@bp.route("/oauth/microsoft/start")
@login_required
def microsoft_oauth_start():
    client_id = current_app.config.get("MICROSOFT_CLIENT_ID")
    redirect_uri = current_app.config.get("MICROSOFT_REDIRECT_URI")
    if not client_id or not redirect_uri:
        flash("Microsoft OAuth is not configured on this server. Set MICROSOFT_CLIENT_ID / "
              "MICROSOFT_CLIENT_SECRET / MICROSOFT_REDIRECT_URI in .env.", "warning")
        return redirect(url_for("mailbox.connect", provider="microsoft"))
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    tenant = current_app.config.get("MICROSOFT_TENANT_ID", "common")
    return redirect(ms_auth_url(client_id, redirect_uri, tenant, state))


@bp.route("/oauth/microsoft/callback")
@login_required
def microsoft_oauth_callback():
    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Please try connecting Microsoft 365 again.", "danger")
        return redirect(url_for("mailbox.connect", provider="microsoft"))

    code = request.args.get("code")
    if not code:
        flash("Microsoft authorization was cancelled or failed.", "warning")
        return redirect(url_for("mailbox.connect", provider="microsoft"))

    token = ms_exchange(
        current_app.config["MICROSOFT_CLIENT_ID"], current_app.config["MICROSOFT_CLIENT_SECRET"],
        current_app.config["MICROSOFT_REDIRECT_URI"], current_app.config.get("MICROSOFT_TENANT_ID", "common"), code,
    )
    email_address = request.args.get("email") or current_user.email
    mailbox_service.create_oauth_mailbox(
        organization_id=current_user.organization_id, user_id=current_user.id,
        provider=ProviderType.MICROSOFT, email_address=email_address, token=token,
    )
    flash("Microsoft 365 mailbox connected via OAuth 2.0.", "success")
    return redirect(url_for("mailbox.list_mailboxes"))
