"""
Custom Flask CLI commands.

`create-super-admin` is the *only* way to grant the platform-level
`is_super_admin` flag (see app/models/user.py and
app/utils/decorators.py:super_admin_required) -- there is intentionally no
web route or UI toggle for this, so a compromised org account can never
grant itself platform-wide visibility. Run it directly on the server /
your own machine:

    flask --app wsgi:app create-super-admin you@gmail.com
    flask --app run.py create-super-admin you@gmail.com   # local dev
"""

from __future__ import annotations

import click
from flask import Flask


def register_cli(app: Flask) -> None:
    @app.cli.command("create-super-admin")
    @click.argument("email")
    def create_super_admin(email: str) -> None:
        """Grant an existing user account super admin (platform owner) access."""
        from app.extensions import db
        from app.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email '{email}'. Register the account in the app first, then re-run this.")
            return
        user.is_super_admin = True
        db.session.commit()
        click.echo(f"'{user.email}' is now a super admin. They'll see a 'Super Admin' link in the app nav on next login.")

    @app.cli.command("revoke-super-admin")
    @click.argument("email")
    def revoke_super_admin(email: str) -> None:
        """Revoke super admin access from an account, without touching anything else about it."""
        from app.extensions import db
        from app.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email '{email}'.")
            return
        user.is_super_admin = False
        db.session.commit()
        click.echo(f"Super admin access revoked for '{user.email}'.")
