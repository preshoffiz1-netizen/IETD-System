from app.models import Classification, QuarantineStatus


def _scan_demo_mailbox(app, organization, admin_user):
    from app.services import mailbox_service, scanner_service

    mailbox = mailbox_service.create_demo_mailbox(organization_id=organization.id, user_id=admin_user.id)
    scanner_service.run_scan(mailbox, trigger="manual")
    return mailbox


def test_quarantined_email_can_be_released(app, db, organization, admin_user):
    with app.app_context():
        _scan_demo_mailbox(app, organization, admin_user)
        from app.models import Email, QuarantineItem
        from app.services import quarantine_service

        item = QuarantineItem.query.filter_by(status=QuarantineStatus.QUARANTINED).first()
        assert item is not None

        quarantine_service.release_email(item, admin_user.id)
        assert item.status == QuarantineStatus.RELEASED
        assert item.email.status == "released"


def test_mark_safe_resets_classification(app, db, organization, admin_user):
    with app.app_context():
        _scan_demo_mailbox(app, organization, admin_user)
        from app.models import QuarantineItem
        from app.services import quarantine_service

        item = QuarantineItem.query.filter_by(status=QuarantineStatus.QUARANTINED).first()
        quarantine_service.mark_safe(item, admin_user.id)
        assert item.status == QuarantineStatus.MARKED_SAFE
        assert item.email.classification == Classification.CLEAN


def test_whitelisting_sender_from_email_creates_entry(app, db, organization, admin_user):
    with app.app_context():
        _scan_demo_mailbox(app, organization, admin_user)
        from app.models import Email, WhitelistEntry
        from app.services import quarantine_service

        email = Email.query.filter_by(classification=Classification.PHISHING).first()
        quarantine_service.whitelist_sender(email, organization.id, admin_user.id, entry_type="email")

        entry = WhitelistEntry.query.filter_by(organization_id=organization.id, value=email.sender).first()
        assert entry is not None
        assert entry.enabled is True
