"""Authentication routes (Section 12)."""

from __future__ import annotations

import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import HAS_LIMITER, db, limiter
from app.models import Organization, Role, User
from app.models.base import gen_uuid, utcnow
from app.services import audit_service

bp = Blueprint("auth", __name__)


def _rate_limit(rule: str):
    """No-op decorator when Flask-Limiter isn't installed, so the routes still work."""
    if HAS_LIMITER and limiter is not None:
        return limiter.limit(rule)
    return lambda view: view

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or gen_uuid()[:8]


@bp.route("/register", methods=["GET", "POST"])
@_rate_limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        organization_name = request.form.get("organization_name", "").strip() or f"{full_name}'s Organization"
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if not EMAIL_RE.match(email):
            errors.append("A valid email address is required.")
        if len(password) < 10:
            errors.append("Password must be at least 10 characters long.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if User.query.filter_by(email=email).first():
            errors.append("An account with this email already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/register.html", form=request.form)

        base_slug = _slugify(organization_name)
        slug = base_slug
        suffix = 1
        while Organization.query.filter_by(slug=slug).first():
            suffix += 1
            slug = f"{base_slug}-{suffix}"

        organization = Organization(name=organization_name, slug=slug)
        db.session.add(organization)
        db.session.flush()

        # The first user in a newly created organization is its admin.
        user = User(organization_id=organization.id, email=email, full_name=full_name, role=Role.ADMIN)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        audit_service.log_event("user_created", user_id=user.id, organization_id=organization.id,
                                 target_type="user", target_id=user.id, metadata={"email": email})

        login_user(user)
        flash("Welcome to IETDS! Your account and organization have been created.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("auth/register.html", form={})


@bp.route("/login", methods=["GET", "POST"])
@_rate_limit("15 per 5 minutes")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=bool(request.form.get("remember")))
            user.last_login_at = utcnow()
            db.session.commit()
            audit_service.log_event("login", user_id=user.id, organization_id=user.organization_id)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))

        audit_service.log_event("login", result="failure", metadata={"email": email})
        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html")


@bp.route("/logout")
@login_required
def logout():
    audit_service.log_event("logout", user_id=current_user.id, organization_id=current_user.organization_id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
