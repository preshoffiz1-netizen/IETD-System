from tests.conftest import login


def test_register_creates_org_and_admin_user(client, app):
    resp = client.post("/register", data={
        "full_name": "New User", "email": "newuser@example.com", "organization_name": "New Org",
        "password": "supersecret123", "confirm_password": "supersecret123",
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        from app.models import Organization, Role, User
        user = User.query.filter_by(email="newuser@example.com").first()
        assert user is not None
        assert user.role == Role.ADMIN  # first user in a new org is admin
        org = Organization.query.get(user.organization_id)
        assert org is not None


def test_register_rejects_short_password(client):
    resp = client.post("/register", data={
        "full_name": "New User", "email": "shortpw@example.com", "organization_name": "Org",
        "password": "short", "confirm_password": "short",
    })
    assert resp.status_code == 200  # re-renders form with error
    assert b"Password must be at least 10 characters" in resp.data


def test_register_rejects_duplicate_email(client):
    client.post("/register", data={
        "full_name": "First", "email": "dupe@example.com", "organization_name": "Org1",
        "password": "supersecret123", "confirm_password": "supersecret123",
    })
    client.get("/logout")
    resp = client.post("/register", data={
        "full_name": "Second", "email": "dupe@example.com", "organization_name": "Org2",
        "password": "supersecret123", "confirm_password": "supersecret123",
    })
    assert b"already exists" in resp.data


def test_login_with_correct_credentials(client, admin_user):
    resp = login(client, "admin@example.com")
    assert resp.status_code == 200
    resp2 = client.get("/dashboard")
    assert resp2.status_code == 200


def test_login_with_wrong_password_fails(client, admin_user):
    resp = client.post("/login", data={"email": "admin@example.com", "password": "wrongpassword"},
                        follow_redirects=True)
    assert b"Invalid email or password" in resp.data


def test_logout_clears_session(client, admin_user):
    login(client, "admin@example.com")
    client.get("/logout")
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 401)  # redirected to login (or unauthorized)


def test_protected_route_requires_login(client):
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")
