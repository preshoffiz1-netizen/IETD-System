"""
Dashboard statistics and reporting (Sections 34, 40).

Every number here comes from a real database query -- never a hardcoded or
fabricated statistic, per Section 34's explicit requirement.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func

from app.extensions import db
from app.models import (
    Classification,
    Email,
    Mailbox,
    QuarantineItem,
    QuarantineStatus,
    ThreatIndicator,
    ThreatAnalysis,
)
from app.models.base import utcnow


def _mailbox_ids_for_org(organization_id: str) -> list[str]:
    return [m.id for m in Mailbox.query.filter_by(organization_id=organization_id).all()]


def dashboard_stats(organization_id: str) -> dict:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return {
            "total_emails": 0, "clean": 0, "spam": 0, "scam": 0, "phishing": 0,
            "suspicious": 0, "malicious_attachment": 0, "quarantined": 0,
        }

    base_query = Email.query.filter(Email.mailbox_id.in_(mailbox_ids))
    total = base_query.count()

    counts = {c: 0 for c in Classification.ALL}
    rows = (
        db.session.query(Email.classification, func.count(Email.id))
        .filter(Email.mailbox_id.in_(mailbox_ids))
        .group_by(Email.classification)
        .all()
    )
    for classification, count in rows:
        counts[classification] = count

    quarantined = QuarantineItem.query.filter(
        QuarantineItem.mailbox_id.in_(mailbox_ids),
        QuarantineItem.status == QuarantineStatus.QUARANTINED,
    ).count()

    return {
        "total_emails": total,
        "clean": counts.get(Classification.CLEAN, 0),
        "suspicious": counts.get(Classification.SUSPICIOUS, 0),
        "spam": counts.get(Classification.SPAM, 0),
        "scam": counts.get(Classification.SCAM, 0),
        "phishing": counts.get(Classification.PHISHING, 0),
        "malicious_attachment": counts.get(Classification.MALICIOUS_ATTACHMENT, 0),
        "quarantined": quarantined,
    }


def threats_over_time(organization_id: str, days: int = 14) -> dict:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    since = utcnow() - timedelta(days=days)
    labels = [(since + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days + 1)]
    series = {label: 0 for label in labels}

    if mailbox_ids:
        rows = (
            Email.query.filter(Email.mailbox_id.in_(mailbox_ids), Email.created_at >= since,
                                Email.classification != Classification.CLEAN)
            .all()
        )
        for email in rows:
            key = email.created_at.strftime("%Y-%m-%d")
            if key in series:
                series[key] += 1

    return {"labels": labels, "values": [series[l] for l in labels]}


def classification_distribution(organization_id: str) -> dict:
    stats = dashboard_stats(organization_id)
    return {
        "labels": ["Clean", "Suspicious", "Spam", "Scam", "Phishing", "Malicious Attachment"],
        "values": [stats["clean"], stats["suspicious"], stats["spam"], stats["scam"],
                   stats["phishing"], stats["malicious_attachment"]],
    }


def top_suspicious_senders(organization_id: str, limit: int = 10) -> list[dict]:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return []
    rows = (
        db.session.query(Email.sender, func.count(Email.id).label("count"))
        .filter(Email.mailbox_id.in_(mailbox_ids), Email.classification != Classification.CLEAN)
        .group_by(Email.sender)
        .order_by(func.count(Email.id).desc())
        .limit(limit)
        .all()
    )
    return [{"sender": r[0], "count": r[1]} for r in rows if r[0]]


def top_suspicious_domains(organization_id: str, limit: int = 10) -> list[dict]:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return []
    rows = (
        db.session.query(Email.sender_domain, func.count(Email.id).label("count"))
        .filter(Email.mailbox_id.in_(mailbox_ids), Email.classification != Classification.CLEAN)
        .group_by(Email.sender_domain)
        .order_by(func.count(Email.id).desc())
        .limit(limit)
        .all()
    )
    return [{"domain": r[0], "count": r[1]} for r in rows if r[0]]


def most_triggered_rules(organization_id: str, limit: int = 10) -> list[dict]:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return []
    rows = (
        db.session.query(ThreatIndicator.rule_name, func.count(ThreatIndicator.id).label("count"))
        .join(ThreatAnalysis, ThreatIndicator.threat_analysis_id == ThreatAnalysis.id)
        .join(Email, ThreatAnalysis.email_id == Email.id)
        .filter(Email.mailbox_id.in_(mailbox_ids))
        .group_by(ThreatIndicator.rule_name)
        .order_by(func.count(ThreatIndicator.id).desc())
        .limit(limit)
        .all()
    )
    return [{"rule_name": r[0], "count": r[1]} for r in rows]


def score_distribution(organization_id: str, bucket_size: int = 10) -> dict:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return {"labels": [], "values": []}
    scores = [e.threat_score for e in Email.query.filter(Email.mailbox_id.in_(mailbox_ids)).all()]
    if not scores:
        return {"labels": [], "values": []}
    max_score = max(scores)
    buckets = Counter()
    for score in scores:
        bucket = (score // bucket_size) * bucket_size
        buckets[bucket] += 1
    labels = [f"{b}-{b + bucket_size - 1}" for b in sorted(buckets)]
    values = [buckets[b] for b in sorted(buckets)]
    return {"labels": labels, "values": values}


def recent_threats(organization_id: str, limit: int = 25) -> list[Email]:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    if not mailbox_ids:
        return []
    return (
        Email.query.filter(Email.mailbox_id.in_(mailbox_ids), Email.classification != Classification.CLEAN)
        .order_by(Email.created_at.desc())
        .limit(limit)
        .all()
    )


def export_csv(organization_id: str) -> str:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    emails = Email.query.filter(Email.mailbox_id.in_(mailbox_ids)).order_by(Email.created_at.desc()).all() \
        if mailbox_ids else []
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Date", "Sender", "Subject", "Classification", "Threat Score", "Action", "Status"])
    for e in emails:
        writer.writerow([e.created_at.isoformat(), e.sender, e.subject, e.classification,
                          e.threat_score, e.action_taken, e.status])
    return buffer.getvalue()


def export_json(organization_id: str) -> str:
    mailbox_ids = _mailbox_ids_for_org(organization_id)
    emails = Email.query.filter(Email.mailbox_id.in_(mailbox_ids)).order_by(Email.created_at.desc()).all() \
        if mailbox_ids else []
    payload = [{
        "date": e.created_at.isoformat(), "sender": e.sender, "subject": e.subject,
        "classification": e.classification, "threat_score": e.threat_score,
        "action": e.action_taken, "status": e.status,
    } for e in emails]
    return json.dumps(payload, indent=2)
