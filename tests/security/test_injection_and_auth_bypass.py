"""
SQL injection resistance (all queries go through the SQLAlchemy ORM /
parameterized queries -- never raw string-formatted SQL) and basic
authentication-bypass attempts.
"""

from tests.conftest import login


def test_sql_injection_in_login_email_field_does_not_bypass_auth(client, admin_user):
    payload = "admin@example.com' OR '1'='1"
    resp = client.post("/login", data={"email": payload, "password": "anything"}, follow_redirects=True)
    assert b"Invalid email or password" in resp.data


def test_sql_injection_in_search_filters_does_not_error(client, admin_user):
    login(client, "admin@example.com")
    resp = client.get("/emails/?sender=" + "' OR '1'='1")
    assert resp.status_code == 200  # ORM parameterizes this; it's just treated as a literal string


def test_disabled_user_cannot_log_in(client, db, admin_user):
    admin_user.is_active_flag = False
    db.session.commit()
    resp = client.post("/login", data={"email": "admin@example.com", "password": "supersecret123"},
                        follow_redirects=True)
    assert b"Invalid email or password" in resp.data


def test_non_admin_cannot_access_admin_routes(client, regular_user):
    login(client, "user@example.com")
    resp = client.get("/admin/users")
    assert resp.status_code == 403


def test_non_admin_cannot_change_thresholds(client, regular_user):
    login(client, "user@example.com")
    resp = client.post("/settings/thresholds", data={"clean_max": "999"}, follow_redirects=True)
    assert b"Only administrators" in resp.data


def test_password_is_never_stored_in_plaintext(db, admin_user):
    assert admin_user.password_hash != "supersecret123"
    assert "supersecret123" not in admin_user.password_hash
    assert admin_user.password_hash.startswith("$argon2")
