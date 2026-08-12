#!/usr/bin/env python3
"""
Seed a demo organization/user/mailbox and run an initial scan, for a quick
supervisor demo without clicking through the UI.

Usage:
    python scripts/seed_demo_data.py [--email you@example.com] [--password ...]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed IETDS with a demo organization and scan synthetic emails.")
    parser.add_argument("--email", default="demo@ietds.local")
    parser.add_argument("--password", default="demo-password-123")
    parser.add_argument("--org-name", default="Demo Organization")
    args = parser.parse_args()

    app = create_app(os.environ.get("FLASK_ENV", "development"))
    with app.app_context():
        from app.extensions import db
        from app.models import Organization, Role, User
        from app.services import mailbox_service, scanner_service

        user = User.query.filter_by(email=args.email).first()
        if user is None:
            org = Organization(name=args.org_name, slug="demo-organization")
            db.session.add(org)
            db.session.flush()
            user = User(organization_id=org.id, email=args.email, full_name="Demo User", role=Role.ADMIN)
            user.set_password(args.password)
            db.session.add(user)
            db.session.commit()
            print(f"Created user {args.email} / organization {org.name}")
        else:
            org = user.organization
            print(f"Using existing user {args.email} / organization {org.name}")

        from app.models import Mailbox
        mailbox = Mailbox.query.filter_by(organization_id=org.id, provider="demo").first()
        if mailbox is None:
            mailbox = mailbox_service.create_demo_mailbox(organization_id=org.id, user_id=user.id)
            print("Created demo mailbox.")

        job = scanner_service.run_scan(mailbox, trigger="manual")
        print(f"Scan {job.status}: {job.messages_processed} processed, "
              f"{job.quarantined_count} quarantined, {job.error_count} errors.")
        print("\nLog in at http://127.0.0.1:5000/login with:")
        print(f"  email:    {args.email}")
        print(f"  password: {args.password}")


if __name__ == "__main__":
    main()
