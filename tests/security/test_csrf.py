"""CSRF protection (Section 43). TestingConfig disables CSRF for convenience
elsewhere, so this file builds its own app with CSRF explicitly re-enabled."""

import pytest

from app import create_app


@pytest.fixture()
def csrf_app():
    application = create_app("testing")
    application.config["WTF_CSRF_ENABLED"] = True
    return application


@pytest.fixture()
def csrf_client(csrf_app):
    return csrf_app.test_client()


def test_login_post_without_csrf_token_is_rejected(csrf_client):
    resp = csrf_client.post("/login", data={"email": "admin@example.com", "password": "supersecret123"})
    assert resp.status_code == 400


def test_login_post_with_valid_csrf_token_is_accepted(csrf_app, csrf_client):
    with csrf_app.app_context():
        from app.extensions import db
        from app.models import Organization, Role, User

        org = Organization(name="Org", slug="org-csrf")
        db.session.add(org)
        db.session.flush()
        user = User(organization_id=org.id, email="admin@example.com", full_name="Admin", role=Role.ADMIN)
        user.set_password("supersecret123")
        db.session.add(user)
        db.session.commit()

    get_resp = csrf_client.get("/login")
    import re
    token = re.search(rb'name="csrf_token" value="([^"]+)"', get_resp.data).group(1).decode()

    resp = csrf_client.post("/login", data={
        "csrf_token": token, "email": "admin@example.com", "password": "supersecret123",
    }, follow_redirects=True)
    assert resp.status_code == 200
