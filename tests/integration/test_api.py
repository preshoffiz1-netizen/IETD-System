from tests.conftest import login


def test_api_requires_authentication(client):
    resp = client.get("/api/mailboxes")
    assert resp.status_code in (302, 401)


def test_api_dashboard_stats_returns_real_counts(client, admin_user, organization):
    login(client, "admin@example.com")
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_emails"] == 0  # no mailboxes scanned yet in this test


def test_api_create_and_delete_rule(client, admin_user, organization):
    login(client, "admin@example.com")
    resp = client.post("/api/rules", json={
        "name": "Test API Rule", "category": "scam", "score": 25, "action": "quarantine",
        "conditions": [{"field": "body", "operator": "contains", "value": "test-phrase", "joiner": "AND"}],
    })
    assert resp.status_code == 201
    rule_id = resp.get_json()["id"]

    resp2 = client.get("/api/rules")
    assert any(r["id"] == rule_id for r in resp2.get_json())

    resp3 = client.delete(f"/api/rules/{rule_id}")
    assert resp3.status_code == 200

    resp4 = client.get("/api/rules")
    assert not any(r["id"] == rule_id for r in resp4.get_json())


def test_api_login_endpoint(client, admin_user):
    resp = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "supersecret123"})
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_api_login_rejects_bad_credentials(client, admin_user):
    resp = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "wrong"})
    assert resp.status_code == 401
