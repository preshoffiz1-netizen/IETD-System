"""
Central settings store (Section 26 / 33 / 65).

All tunable behaviour -- thresholds, default actions, scan interval,
branding, retention -- lives in the `system_settings` table instead of being
scattered through the codebase. This module is the single place that reads
and writes it, with sane defaults seeded on first run (see
scripts/seed_demo_data.py / app/__init__.py's `ensure_default_settings`).
"""

from __future__ import annotations

import json
from typing import Any

from app.extensions import db
from app.models import SystemSetting

DEFAULTS: dict[str, tuple[Any, str, str]] = {
    # key: (value, value_type, description)
    "threshold.clean_max": (19, "int", "Scores at or below this are classified CLEAN"),
    "threshold.suspicious_max": (39, "int", "Scores at or below this (and above clean_max) are SUSPICIOUS"),
    "threshold.spam_max": (59, "int", "Scores at or below this (and above suspicious_max) are SPAM"),
    "threshold.high_risk_min": (60, "int", "Scores at or above this are HIGH RISK (phishing/scam/malicious_attachment)"),

    "action.clean": ("allow", "string", "Default action for CLEAN emails"),
    "action.suspicious": ("flag,notify", "string", "Default action(s) for SUSPICIOUS emails"),
    "action.spam": ("quarantine", "string", "Default action for SPAM emails"),
    "action.scam": ("quarantine,notify", "string", "Default action(s) for SCAM emails"),
    "action.phishing": ("quarantine,notify", "string", "Default action(s) for PHISHING emails"),
    "action.malicious_attachment": ("quarantine,notify", "string", "Default action(s) for MALICIOUS_ATTACHMENT emails"),

    "scan.default_interval_minutes": (5, "int", "Default background scan interval for new mailboxes"),
    "scan.max_messages_per_run": (100, "int", "Maximum messages fetched per scan run (memory/performance guard)"),

    "retention.email_body_days": (0, "int", "Days to keep email bodies (0 = keep indefinitely)"),
    "retention.quarantine_days": (0, "int", "Days to keep quarantine records (0 = keep indefinitely)"),

    "branding.app_name": ("IETDS", "string", "Application display name"),
    "branding.tagline": ("Protecting every mailbox from spam, scams, and email-based threats.",
                          "string", "Application tagline"),
}


def _cast(value: str, value_type: str) -> Any:
    if value_type == "int":
        return int(value)
    if value_type == "bool":
        return str(value).lower() in {"1", "true", "yes"}
    if value_type == "json":
        return json.loads(value)
    return value


def ensure_defaults() -> None:
    existing = {s.key for s in SystemSetting.query.all()}
    changed = False
    for key, (value, value_type, description) in DEFAULTS.items():
        if key not in existing:
            db.session.add(SystemSetting(key=key, value=str(value), value_type=value_type,
                                          description=description))
            changed = True
    if changed:
        db.session.commit()


def get(key: str, default: Any = None) -> Any:
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting is None:
        if key in DEFAULTS:
            return DEFAULTS[key][0]
        return default
    return _cast(setting.value, setting.value_type)


def set(key: str, value: Any, value_type: str | None = None, description: str | None = None) -> None:
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting is None:
        value_type = value_type or (DEFAULTS.get(key, (None, "string", ""))[1])
        setting = SystemSetting(key=key, value_type=value_type, description=description or "")
        db.session.add(setting)
    setting.value = str(value)
    db.session.commit()


def get_thresholds() -> dict:
    return {
        "clean_max": get("threshold.clean_max", 19),
        "suspicious_max": get("threshold.suspicious_max", 39),
        "spam_max": get("threshold.spam_max", 59),
        "high_risk_min": get("threshold.high_risk_min", 60),
    }


def get_all() -> list[SystemSetting]:
    return SystemSetting.query.order_by(SystemSetting.key).all()
