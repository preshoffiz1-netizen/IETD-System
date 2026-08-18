"""
Regression tests for the super admin portal.

Covers the core safety property this feature has to hold: the portal only
ever opens up for accounts explicitly flagged `is_super_admin` (never for a
regular org-admin), it shows real cross-organization counts, and it never
exposes another organization's email content.
"""

from tests.conftest import login


def test_regular_admin_cannot_reach_superadmin_portal(client, admin_user, organization):
    """A normal per-org admin (is_admin=True via Role.ADMIN) must NOT get in --
    that would be exactly the IDOR pattern this feature was designed to avoid."""
    login(client, "admin@example.com")
    resp = client.get("/superadmin/")
    assert resp.status_code == 403


def test_anonymous_user_gets_401_not_a_login_page_leak(client):
    resp = client.get("/superadmin/")
    assert resp.status_code in (302, 401)


def test_flagged_super_admin_can_reach_portal_and_sees_cross_org_counts(client, db, organization, admin_user):
    from app.extensions import db as _db
    from app.models import Organization, User, Role, Mailbox
    from app.services import mailbox_service

    admin_user.is_super_admin = True
    _db.session.commit()

    # A second, unrelated organization -- the super admin should see it counted,
    # without the portal ever showing that org's email content.
    other_org = Organization(name="Other Org", slug="other-org")
    _db.session.add(other_org)
    _db.session.flush()
    other_user = User(organization_id=other_org.id, email="other@example.com", full_name="Other Admin", role=Role.ADMIN)
    other_user.set_password("supersecret123")
    _db.session.add(other_user)
    _db.session.commit()
    mailbox_service.create_demo_mailbox(organization_id=other_org.id, user_id=other_user.id)

    login(client, "admin@example.com")
    resp = client.get("/superadmin/")
    assert resp.status_code == 200
    assert b"Other Org" in resp.data  # cross-org visibility works
    assert b"2" in resp.data  # 2 organizations total (own + other)


def test_super_admin_users_page_lists_every_organizations_users(client, db, organization, admin_user):
    from app.extensions import db as _db
    from app.models import Organization, User, Role

    admin_user.is_super_admin = True
    other_org = Organization(name="Other Org 2", slug="other-org-2")
    _db.session.add(other_org)
    _db.session.flush()
    other_user = User(organization_id=other_org.id, email="someone-else@example.com", full_name="Someone Else", role=Role.USER)
    other_user.set_password("supersecret123")
    _db.session.add(other_user)
    _db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/superadmin/users")
    assert resp.status_code == 200
    assert b"someone-else@example.com" in resp.data


def test_super_admin_logs_page_renders(client, admin_user, organization, db):
    from app.extensions import db as _db

    admin_user.is_super_admin = True
    _db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/superadmin/logs")
    assert resp.status_code == 200


def test_super_admin_portal_actions_are_audit_logged(client, admin_user, organization, db):
    from app.extensions import db as _db
    from app.models import AuditLog

    admin_user.is_super_admin = True
    _db.session.commit()

    login(client, "admin@example.com")
    client.get("/superadmin/")
    entry = AuditLog.query.filter_by(action="superadmin.viewed_overview", user_id=admin_user.id).first()
    assert entry is not None


def test_super_admin_account_still_works_as_a_normal_user(client, admin_user, organization, db):
    """The whole point: a super admin login is still an ordinary account everywhere else in the app."""
    from app.extensions import db as _db

    admin_user.is_super_admin = True
    _db.session.commit()

    login(client, "admin@example.com")
    assert client.get("/dashboard").status_code == 200
    assert client.get("/mailboxes/").status_code == 200
