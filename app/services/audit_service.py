"""Audit logging (Section 41). Never pass passwords/tokens/keys into `metadata`."""

from __future__ import annotations

import json
import logging

from flask import has_request_context, request

from app.extensions import db
from app.models import AuditLog
from app.models.base import utcnow

logger = logging.getLogger("ietds.audit")

_FORBIDDEN_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "encryption_key", "client_secret"}


def _scrub(metadata: dict | None) -> dict:
    if not metadata:
        return {}
    return {k: v for k, v in metadata.items() if k.lower() not in _FORBIDDEN_KEYS}


def log_event(action: str, user_id: str | None = None, organization_id: str | None = None,
               target_type: str | None = None, target_id: str | None = None,
               result: str = "success", metadata: dict | None = None) -> None:
    ip_address = None
    if has_request_context():
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)

    entry = AuditLog(
        user_id=user_id,
        organization_id=organization_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        result=result,
        audit_metadata=json.dumps(_scrub(metadata)) if metadata else None,
        ip_address=ip_address,
        created_at=utcnow(),
    )
    db.session.add(entry)
    db.session.commit()
