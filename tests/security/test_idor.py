"""
IDOR (insecure direct object reference) tests: a user from one organization
must never be able to read or act on another organization's mailboxes,
emails, or quarantine items just by guessing/incrementing an ID.
"""

from app.models import Organization, Role, User
from tests.conftest import login


def _make_org_and_admin(db, org_name, org_slug, email):
    org = Organization(name=org_name, slug=org_slug)
    db.session.add(org)
    db.session.flush()
    user = User(organization_id=org.id, email=email, full_name="Org Admin", role=Role.ADMIN)
    user.set_password("supersecret123")
    db.session.add(user)
    db.session.commit()
    return org, user


def test_user_cannot_view_another_orgs_email(app, db, client):
    from app.services import mailbox_service, scanner_service

    org_a, admin_a = _make_org_and_admin(db, "Org A", "org-a", "a@example.com")
    org_b, admin_b = _make_org_and_admin(db, "Org B", "org-b", "b@example.com")

    mailbox_a = mailbox_service.create_demo_mailbox(organization_id=org_a.id, user_id=admin_a.id)
    scanner_service.run_scan(mailbox_a, trigger="manual")

    from app.models import Email
    victim_email = Email.query.filter_by(mailbox_id=mailbox_a.id).first()

    # Log in as Org B's admin and attempt to view Org A's email.
    login(client, "b@example.com")
    resp = client.get(f"/emails/{victim_email.id}")
    assert resp.status_code == 403


def test_user_cannot_release_another_orgs_quarantine_item(app, db, client):
    from app.services import mailbox_service, scanner_service

    org_a, admin_a = _make_org_and_admin(db, "Org A", "org-a2", "a2@example.com")
    org_b, admin_b = _make_org_and_admin(db, "Org B", "org-b2", "b2@example.com")

    mailbox_a = mailbox_service.create_demo_mailbox(organization_id=org_a.id, user_id=admin_a.id)
    scanner_service.run_scan(mailbox_a, trigger="manual")

    from app.models import QuarantineItem
    item = QuarantineItem.query.join(QuarantineItem.email).filter(
        QuarantineItem.mailbox_id == mailbox_a.id
    ).first()
    assert item is not None

    login(client, "b2@example.com")
    resp = client.post(f"/quarantine/{item.id}/release")
    assert resp.status_code == 403

    # Confirm it truly was not released.
    assert item.status == "quarantined"


def test_user_cannot_view_another_orgs_mailbox_via_test_endpoint(app, db, client):
    org_a, admin_a = _make_org_and_admin(db, "Org A", "org-a3", "a3@example.com")
    org_b, admin_b = _make_org_and_admin(db, "Org B", "org-b3", "b3@example.com")

    from app.services import mailbox_service
    mailbox_a = mailbox_service.create_demo_mailbox(organization_id=org_a.id, user_id=admin_a.id)

    login(client, "b3@example.com")
    resp = client.post(f"/mailboxes/{mailbox_a.id}/scan")
    assert resp.status_code == 403
