"""
Scanner service (Section 13: full ingestion pipeline, Section 37/38: scanning
and scan history).

Orchestrates: fetch -> dedup -> parse -> detect -> score -> classify ->
act -> persist -> audit -> update stats, for one mailbox at a time. Designed
to be called either from an HTTP-triggered "Scan Now" request (kept fast by
capping `max_messages_per_run`) or from the APScheduler background job --
never performs unbounded work inside a web request (Section 37).
"""

from __future__ import annotations

import json
import logging

from app.extensions import db
from app.models import (
    Attachment,
    BlacklistEntry,
    Email,
    ScanJob,
    ScanJobStatus,
    URLRecord,
    WhitelistEntry,
)
from app.models.base import utcnow
from app.models.threat import ThreatAnalysis, ThreatIndicator
from app.services import audit_service, mailbox_service, policy_service, settings_service
from app.services.classification_service import classify
from app.services.email_parser import parse_raw_message
from app.services.scoring_service import calculate_score
from app.detection.base_rule import EmailContext

logger = logging.getLogger("ietds.scanner")


def _load_lists(organization_id: str) -> tuple[set, set, set, set]:
    whitelist = WhitelistEntry.query.filter_by(organization_id=organization_id, enabled=True).all()
    blacklist = BlacklistEntry.query.filter_by(organization_id=organization_id, enabled=True).all()
    w_emails = {e.value for e in whitelist if e.entry_type == "email"}
    w_domains = {e.value for e in whitelist if e.entry_type == "domain"}
    b_emails = {e.value for e in blacklist if e.entry_type == "email"}
    b_domains = {e.value for e in blacklist if e.entry_type == "domain"}
    return w_emails, w_domains, b_emails, b_domains


def run_scan(mailbox, trigger: str = "manual") -> ScanJob:
    job = ScanJob(mailbox_id=mailbox.id, status=ScanJobStatus.CONNECTING, trigger=trigger, started_at=utcnow())
    db.session.add(job)
    db.session.commit()

    max_messages = settings_service.get("scan.max_messages_per_run", 100)
    w_emails, w_domains, b_emails, b_domains = _load_lists(mailbox.organization_id)

    try:
        provider = mailbox_service.build_provider(mailbox)
        provider.connect()
        job.status = ScanJobStatus.SCANNING
        db.session.commit()

        raw_messages = list(provider.fetch_new_messages(
            folder="INBOX", since_uid=mailbox.last_uid_scanned, limit=max_messages
        ))

        job.status = ScanJobStatus.ANALYZING
        db.session.commit()

        highest_uid = mailbox.last_uid_scanned
        for raw in raw_messages:
            try:
                _process_message(mailbox, raw, w_emails, w_domains, b_emails, b_domains, job)
                job.messages_processed += 1
                if raw.provider_uid and (highest_uid is None or _uid_gt(raw.provider_uid, highest_uid)):
                    highest_uid = raw.provider_uid
            except Exception:
                logger.exception("Failed to process message uid=%s", raw.provider_uid)
                job.error_count += 1

        provider.disconnect()
        mailbox.last_uid_scanned = highest_uid
        mailbox.last_scan_at = utcnow()
        job.status = ScanJobStatus.COMPLETED
        job.completed_at = utcnow()
        db.session.commit()

        audit_service.log_event("scan_completed", target_type="mailbox", target_id=mailbox.id,
                                 metadata={"messages_processed": job.messages_processed,
                                           "quarantined": job.quarantined_count})

    except Exception as exc:
        logger.exception("Scan failed for mailbox %s", mailbox.id)
        job.status = ScanJobStatus.FAILED
        job.error_message = str(exc)
        job.completed_at = utcnow()
        db.session.commit()
        audit_service.log_event("scan_started", target_type="mailbox", target_id=mailbox.id, result="failure",
                                 metadata={"error": str(exc)})

    return job


def _uid_gt(a: str, b: str) -> bool:
    try:
        return int(a) > int(b)
    except (TypeError, ValueError):
        return a > b


def _process_message(mailbox, raw, w_emails, w_domains, b_emails, b_domains, job: ScanJob) -> Email | None:
    parsed = parse_raw_message(raw)

    dedup_key = parsed.dedup_key
    existing = Email.query.filter_by(mailbox_id=mailbox.id, dedup_key=dedup_key).first()
    if existing:
        return None  # already processed (Section 53: deduplication)

    context = EmailContext(
        parsed=parsed,
        whitelist_emails=w_emails,
        whitelist_domains=w_domains,
        blacklist_emails=b_emails,
        blacklist_domains=b_domains,
    )

    email = Email(
        mailbox_id=mailbox.id,
        provider_uid=raw.provider_uid,
        message_id=parsed.message_id,
        dedup_key=dedup_key,
        sender=parsed.sender,
        sender_display_name=parsed.sender_display_name,
        sender_domain=parsed.sender_domain,
        recipient=parsed.recipient,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        subject=parsed.subject,
        date_sent=parsed.date_sent,
        date_received=utcnow(),
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        raw_headers=json.dumps(parsed.raw_headers)[:20000],
        spf_result=parsed.spf_result,
        dkim_result=parsed.dkim_result,
        dmarc_result=parsed.dmarc_result,
        is_demo=(mailbox.provider == "demo"),
    )
    db.session.add(email)
    db.session.flush()  # get email.id without committing yet

    for att in parsed.attachments:
        db.session.add(Attachment(
            email_id=email.id, filename=att.filename, extension=att.extension,
            mime_type=att.mime_type, size_bytes=att.size_bytes, sha256_hash=att.sha256_hash,
            is_dangerous_extension=att.is_dangerous_extension,
            has_double_extension=att.has_double_extension, is_macro_enabled=att.is_macro_enabled,
        ))
    for u in parsed.urls:
        from app.utils.domain_utils import extract_domain, is_ip_address, is_punycode, is_shortened_url
        domain = extract_domain(u.url)
        db.session.add(URLRecord(
            email_id=email.id, url=u.url, display_text=u.display_text, domain=domain,
            is_ip_address=is_ip_address(domain), is_shortened=is_shortened_url(domain),
            is_punycode=is_punycode(domain),
        ))

    # --- Whitelist short-circuit: whitelisted senders are always CLEAN/ALLOW ---
    if context.sender_is_whitelisted:
        email.classification = "clean"
        email.threat_score = 0
        email.status = "active"
        db.session.commit()
        job.clean_count += 1
        return email

    # --- Rule-based detection (Sections 15-27) ---
    from app.services.threat_engine import analyze
    results = analyze(context, organization_id=mailbox.organization_id)
    breakdown = calculate_score(results)
    classification = classify(breakdown)

    email.threat_score = breakdown.total_score
    email.classification = classification
    db.session.flush()

    analysis = ThreatAnalysis(
        email_id=email.id, analyzed_at=utcnow(), classification=classification,
        **breakdown.as_dict(),
    )
    db.session.add(analysis)
    db.session.flush()

    for result in results:
        db.session.add(ThreatIndicator(
            threat_analysis_id=analysis.id, rule_name=result.rule_name, category=result.category,
            severity=result.severity, score_contribution=result.score, reason=result.reason,
            indicator_metadata=json.dumps(result.metadata) if result.metadata else None,
        ))
    db.session.commit()

    # --- Action / policy engine (Section 28) ---
    applied = policy_service.execute_policy(email, classification, user_id_for_notify=mailbox.user_id)
    email.action_taken = ",".join(applied)
    db.session.commit()

    # --- Stats ---
    _bump_counts(job, classification, "quarantine" in applied)
    mailbox.messages_processed = (mailbox.messages_processed or 0) + 1
    if classification != "clean":
        mailbox.threats_detected = (mailbox.threats_detected or 0) + 1
    db.session.commit()

    return email


def _bump_counts(job: ScanJob, classification: str, quarantined: bool) -> None:
    field_map = {
        "clean": "clean_count", "suspicious": "suspicious_count", "spam": "spam_count",
        "scam": "scam_count", "phishing": "phishing_count", "malicious_attachment": "malicious_attachment_count",
    }
    field = field_map.get(classification)
    if field:
        setattr(job, field, getattr(job, field, 0) + 1)
    if quarantined:
        job.quarantined_count += 1
