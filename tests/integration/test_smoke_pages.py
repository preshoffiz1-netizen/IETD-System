from tests.conftest import login


def test_pages_render_with_a_scored_email(client, admin_user, organization, db):
    from app.services import mailbox_service
    from app.models import Email, ThreatAnalysis, QuarantineItem

    login(client, "admin@example.com")

    mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
    email = Email(mailbox_id=mailbox.id, dedup_key="smoke-1", sender="a@example.com", subject="hi",
                  classification="spam", threat_score=45, status="quarantined")
    db.session.add(email)
    db.session.flush()
    analysis = ThreatAnalysis(email_id=email.id, total_score=45, classification="spam", body_score=45)
    db.session.add(analysis)
    db.session.add(QuarantineItem(email_id=email.id, mailbox_id=mailbox.id, reason="test", status="quarantined"))
    db.session.commit()

    for path in ["/dashboard", "/emails/", "/quarantine/", "/rules/create"]:
        r = client.get(path)
        assert r.status_code == 200, (path, r.status_code, r.data[:500])
        assert b"45%" in r.data or path == "/rules/create"
