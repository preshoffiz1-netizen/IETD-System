"""Blueprint registration."""

from __future__ import annotations


def register_blueprints(app) -> None:
    from app.routes import admin, api, auth, blacklist, dashboard, emails, health, mailbox, quarantine, reports, rules, settings, superadmin, whitelist

    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(mailbox.bp)
    app.register_blueprint(emails.bp)
    app.register_blueprint(quarantine.bp)
    app.register_blueprint(rules.bp)
    app.register_blueprint(whitelist.bp)
    app.register_blueprint(blacklist.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(settings.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(superadmin.bp)
    app.register_blueprint(health.bp)
    app.register_blueprint(api.bp)
