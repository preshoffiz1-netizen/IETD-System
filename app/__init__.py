"""
Application factory.

`create_app()` wires together config, extensions, blueprints, security
headers, error handlers, and (outside of testing) the background scanning
scheduler. Kept deliberately thin -- almost everything interesting lives in
services/, detection/, providers/, and models/.
"""

from __future__ import annotations

import logging
import os

from flask import Flask, current_app, render_template, request
from flask_login import current_user

from app.config import get_config
from app.extensions import HAS_LIMITER, csrf, db, limiter, login_manager, migrate


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))

    os.makedirs(app.instance_path, exist_ok=True)

    _init_logging(app)
    _init_extensions(app)
    _register_error_handlers(app)
    _register_context_processors(app)

    from app.routes import register_blueprints
    register_blueprints(app)

    from app.cli import register_cli
    register_cli(app)

    with app.app_context():
        from app import models  # noqa: F401 ensure models are registered with SQLAlchemy
        db.create_all()
        _apply_schema_patches()
        _ensure_super_admin()
        from app.services import settings_service
        settings_service.ensure_defaults()

    if not app.config.get("TESTING") and os.environ.get("IETDS_DISABLE_SCHEDULER") != "1":
        from app.services.scheduler import init_scheduler
        # Avoid double-starting the scheduler under Flask's debug reloader.
        if os.environ.get("WERKZEUG_RUN_MAIN") != "false":
            init_scheduler(app)

    return app


def _init_logging(app: Flask) -> None:
    level = logging.DEBUG if app.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    # Never log secrets: the security/audit modules scrub sensitive keys before
    # anything reaches the logger, but we also keep werkzeug's default access
    # log at INFO (no header/body dumping) to avoid accidental credential leaks.
    logging.getLogger("werkzeug").setLevel(logging.WARNING if not app.debug else logging.INFO)

    if not app.config.get("TESTING"):
        from app.utils.log_buffer import install as install_log_buffer
        install_log_buffer()


def _apply_schema_patches() -> None:
    """
    This project uses `db.create_all()` instead of versioned Alembic
    migrations (see README section 9), which only creates *missing tables* --
    it silently does nothing for a new column added to an existing table on
    someone's already-created local database file. This patches those in by
    hand, one at a time, so upgrading doesn't require deleting your local
    database. Safe to run every startup: each patch checks first.
    """
    from sqlalchemy import inspect, text

    from app.extensions import db

    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return  # fresh DB, db.create_all() above already created the column
    existing_columns = {col["name"] for col in inspector.get_columns("users")}
    if "is_super_admin" not in existing_columns:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN NOT NULL DEFAULT 0"))

def _ensure_super_admin() -> None:
    email = current_app.config.get("SUPER_ADMIN_EMAIL")
    if not email:
        return

    from app.models import User

    user = User.query.filter_by(email=email).first()
    if user is None:
        current_app.logger.info(
            "SUPER_ADMIN_EMAIL=%s is set but no account with that email exists yet.", email
        )
        return
    if not user.is_super_admin:
        user.is_super_admin = True
        db.session.commit()
        current_app.logger.info("Granted super admin to %s via SUPER_ADMIN_EMAIL.", email)
def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    if HAS_LIMITER and limiter is not None:
        limiter.init_app(app)

    @app.after_request
    def set_security_headers(response):
        # Section 43: security headers.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/error.html", code=400, message="Bad request."), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("errors/error.html", code=401, message="Please log in to continue."), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/error.html", code=403, message="You do not have permission to access this resource."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/error.html", code=404, message="The page you're looking for doesn't exist."), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template("errors/error.html", code=429, message="Too many requests. Please slow down."), 429

    @app.errorhandler(500)
    def server_error(e):
        # Never leak raw exception details to the client (Section 43).
        current_app.logger.exception("Unhandled server error")
        return render_template("errors/error.html", code=500, message="Something went wrong on our end."), 500


def _register_context_processors(app: Flask) -> None:
    @app.context_processor
    def inject_globals():
        from app.services import settings_service

        app_name = app.config.get("APP_NAME", "IETDS")
        tagline = app.config.get("APP_TAGLINE", "")
        unread = 0
        try:
            app_name = settings_service.get("branding.app_name", app_name)
            tagline = settings_service.get("branding.tagline", tagline)
            if current_user.is_authenticated:
                from app.services import notification_service
                unread = notification_service.unread_count(current_user.id)
        except Exception:  # pragma: no cover - defensive, e.g. before first request/db ready
            pass
        return {"app_name": app_name, "app_tagline": tagline, "unread_notifications": unread}
