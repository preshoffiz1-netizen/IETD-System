from __future__ import annotations

import os

os.environ.setdefault("IETDS_DISABLE_SCHEDULER", "1")

import pytest

from app import create_app
from app.extensions import db as _db
from app.models import Organization, Role, User


@pytest.fixture()
def app():
    application = create_app("testing")
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    with app.app_context():
        yield _db


@pytest.fixture()
def organization(db):
    org = Organization(name="Test Org", slug="test-org")
    db.session.add(org)
    db.session.commit()
    return org


@pytest.fixture()
def admin_user(db, organization):
    user = User(organization_id=organization.id, email="admin@example.com", full_name="Admin User", role=Role.ADMIN)
    user.set_password("supersecret123")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def regular_user(db, organization):
    user = User(organization_id=organization.id, email="user@example.com", full_name="Regular User", role=Role.USER)
    user.set_password("supersecret123")
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email: str, password: str = "supersecret123"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)
