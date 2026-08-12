"""
Full ingestion pipeline integration test: demo mailbox -> scan -> parse ->
detect -> score -> classify -> policy action -> persisted records.
"""

from app.models import Classification


def test_full_scan_pipeline_classifies_demo_messages(app, db, organization, admin_user):
    from app.services import mailbox_service, scanner_service

    with app.app_context():
        mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
        job = scanner_service.run_scan(mailbox, trigger="manual")

        assert job.status == "completed"
        assert job.messages_processed == 10
        assert job.error_count == 0

        from app.models import Email
        emails = Email.query.filter_by(mailbox_id=mailbox.id).all()
        assert len(emails) == 10

        by_subject = {e.subject: e for e in emails}
        assert by_subject["[DEMO] Lunch this weekend?"].classification == Classification.CLEAN
        assert by_subject["[DEMO] Lunch this weekend?"].threat_score == 0

        phishing_email = by_subject["[DEMO] Your account will be suspended - verify your password now"]
        assert phishing_email.classification == Classification.PHISHING
        assert phishing_email.threat_score > 0
        assert phishing_email.action_taken and "quarantine" in phishing_email.action_taken

        malware_email = by_subject["[DEMO] Overdue invoice attached - open immediately"]
        assert malware_email.classification == Classification.MALICIOUS_ATTACHMENT

        # Explainability: every non-clean email must have at least one triggered indicator.
        for e in emails:
            if e.classification != Classification.CLEAN:
                assert e.threat_analysis is not None
                assert len(e.threat_analysis.indicators) > 0


def test_rescanning_does_not_duplicate_emails(app, db, organization, admin_user):
    from app.services import mailbox_service, scanner_service
    from app.models import Email

    with app.app_context():
        mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
        scanner_service.run_scan(mailbox, trigger="manual")
        first_count = Email.query.filter_by(mailbox_id=mailbox.id).count()

        scanner_service.run_scan(mailbox, trigger="manual")
        second_count = Email.query.filter_by(mailbox_id=mailbox.id).count()

        assert first_count == second_count == 10  # deduplicated by dedup_key


def test_whitelisted_sender_is_always_clean(app, db, organization, admin_user):
    from app.models import WhitelistEntry
    from app.services import mailbox_service, scanner_service

    with app.app_context():
        db.session.add(WhitelistEntry(organization_id=organization.id, entry_type="domain",
                                       value="banklogin-verify-example.com"))
        db.session.commit()

        mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
        scanner_service.run_scan(mailbox, trigger="manual")

        from app.models import Email
        phishing_email = Email.query.filter_by(
            subject="[DEMO] Your account will be suspended - verify your password now"
        ).first()
        assert phishing_email.classification == Classification.CLEAN
        assert phishing_email.threat_score == 0
