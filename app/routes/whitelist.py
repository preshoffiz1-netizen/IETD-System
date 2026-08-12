"""Whitelist management (Section 30)."""

from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import WhitelistEntry
from app.services import audit_service

bp = Blueprint("whitelist", __name__, url_prefix="/whitelist")


@bp.route("/")
@login_required
def list_entries():
    entries = WhitelistEntry.query.filter_by(organization_id=current_user.organization_id).order_by(
        WhitelistEntry.created_at.desc()).all()
    return render_template("lists/whitelist.html", entries=entries)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    entry_type = request.form.get("entry_type", "email")
    value = request.form.get("value", "").strip().lower()
    if not value:
        flash("Value is required.", "danger")
        return redirect(url_for("whitelist.list_entries"))
    entry = WhitelistEntry(organization_id=current_user.organization_id, user_id=current_user.id,
                            entry_type=entry_type, value=value, notes=request.form.get("notes", ""))
    db.session.add(entry)
    db.session.commit()
    audit_service.log_event("whitelist_changed", user_id=current_user.id, target_type="whitelist",
                             target_id=entry.id, metadata={"action": "add", "value": value})
    flash("Added to whitelist.", "success")
    return redirect(url_for("whitelist.list_entries"))


def _get_entry_or_404(entry_id):
    entry = WhitelistEntry.query.get_or_404(entry_id)
    if entry.organization_id != current_user.organization_id:
        abort(403)
    return entry


@bp.route("/<entry_id>/toggle", methods=["POST"])
@login_required
def toggle(entry_id):
    entry = _get_entry_or_404(entry_id)
    entry.enabled = not entry.enabled
    db.session.commit()
    return redirect(url_for("whitelist.list_entries"))


@bp.route("/<entry_id>/delete", methods=["POST"])
@login_required
def delete(entry_id):
    entry = _get_entry_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    audit_service.log_event("whitelist_changed", user_id=current_user.id, target_type="whitelist",
                             target_id=entry_id, metadata={"action": "delete"})
    flash("Removed from whitelist.", "info")
    return redirect(url_for("whitelist.list_entries"))


@bp.route("/export")
@login_required
def export():
    entries = WhitelistEntry.query.filter_by(organization_id=current_user.organization_id).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "enabled", "notes"])
    for e in entries:
        writer.writerow([e.entry_type, e.value, e.enabled, e.notes or ""])
    return Response(buffer.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": "attachment; filename=whitelist.csv"})


@bp.route("/import", methods=["POST"])
@login_required
def import_csv():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("No file uploaded.", "danger")
        return redirect(url_for("whitelist.list_entries"))
    if not file.filename.lower().endswith(".csv"):
        flash("Only .csv files are accepted.", "danger")
        return redirect(url_for("whitelist.list_entries"))
    raw = file.read(2 * 1024 * 1024 + 1)  # cap at 2MB
    if len(raw) > 2 * 1024 * 1024:
        flash("File is too large (max 2MB).", "danger")
        return redirect(url_for("whitelist.list_entries"))
    content = raw.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    count = 0
    for row in reader:
        value = (row.get("value") or "").strip().lower()
        if not value:
            continue
        if WhitelistEntry.query.filter_by(organization_id=current_user.organization_id, value=value).first():
            continue
        db.session.add(WhitelistEntry(
            organization_id=current_user.organization_id, user_id=current_user.id,
            entry_type=row.get("type", "email"), value=value, notes=row.get("notes", ""),
        ))
        count += 1
    db.session.commit()
    flash(f"Imported {count} whitelist entries.", "success")
    return redirect(url_for("whitelist.list_entries"))
