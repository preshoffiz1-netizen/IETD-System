"""
Action / Policy engine (Section 28).

Translates a classification into one or more configured actions and executes
them. Provider-side actions (move/delete/mark-as-spam) are only attempted
when the connected provider actually supports them (Section 66); otherwise
the system falls back to post-delivery filtering purely within IETDS's own
database (quarantine table, status flag) and is honest about that limitation
in the UI (Section 7).

Dangerous emails are NEVER permanently deleted by default -- only QUARANTINE
+ NOTIFY-style actions are used out of the box; DELETE must be explicitly
configured by an admin.
"""

from __future__ import annotations

import logging

from app.extensions import db
from app.models import Email, EmailStatus, Mailbox, NotificationLevel, ProviderType
from app.providers import get_provider_class
from app.providers.base import ProviderCapabilityError
from app.services import audit_service, notification_service, quarantine_service, settings_service

logger = logging.getLogger("ietds.policy")

_ACTION_SETTING_KEY = {
    "clean": "action.clean",
    "suspicious": "action.suspicious",
    "spam": "action.spam",
    "scam": "action.scam",
    "phishing": "action.phishing",
    "malicious_attachment": "action.malicious_attachment",
}


def actions_for_classification(classification: str) -> list[str]:
    key = _ACTION_SETTING_KEY.get(classification, "action.suspicious")
    raw = settings_service.get(key, "flag")
    return [a.strip() for a in str(raw).split(",") if a.strip()]


def _get_credentials_and_provider(mailbox: Mailbox):
    """Best-effort provider instantiation for optional server-side actions."""
    from app.services.mailbox_service import build_provider  # local import avoids a cycle

    try:
        return build_provider(mailbox)
    except Exception as exc:  # pragma: no cover - provider actions are best-effort
        logger.info("Could not build provider for mailbox %s: %s", mailbox.id, exc)
        return None


def execute_policy(email: Email, classification: str, user_id_for_notify: str | None = None) -> list[str]:
    """
    Execute every action configured for `classification`. Returns the list of
    action names actually applied (for the audit trail / UI feedback).
    """
    actions = actions_for_classification(classification)
    applied = []

    provider = None
    if any(a in {"move_to_spam", "move_to_folder", "delete"} for a in actions):
        provider = _get_credentials_and_provider(email.mailbox)

    for action in actions:
        try:
            if action == "allow":
                email.status = EmailStatus.ACTIVE
                applied.append(action)

            elif action == "flag":
                email.status = EmailStatus.FLAGGED
                applied.append(action)

            elif action == "quarantine":
                quarantine_service.quarantine_email(email, reason=f"Classified as {classification}")
                applied.append(action)

            elif action == "notify" and user_id_for_notify:
                notification_service.notify(
                    user_id_for_notify,
                    title=f"{classification.replace('_', ' ').title()} email detected",
                    message=f"'{email.subject or '(no subject)'}' from {email.sender} was classified as "
                             f"{classification.upper()} (score: {email.threat_score}).",
                    level=NotificationLevel.CRITICAL if classification in {"phishing", "scam", "malicious_attachment"}
                    else NotificationLevel.WARNING,
                    link=f"/emails/{email.id}",
                )
                applied.append(action)

            elif action == "move_to_spam":
                if provider and provider.supports("mark_as_spam"):
                    provider.mark_as_spam(email.provider_uid or "", folder="INBOX")
                    applied.append(action)
                else:
                    logger.info("move_to_spam requested but provider does not support it; "
                                "falling back to in-app flag only.")
                    email.status = EmailStatus.FLAGGED
                    applied.append("flag (provider fallback)")

            elif action == "move_to_folder":
                if provider and provider.supports("move_messages"):
                    provider.move_message(email.provider_uid or "", "IETDS-Quarantine", folder="INBOX")
                    applied.append(action)
                else:
                    applied.append("flag (provider fallback)")
                    email.status = EmailStatus.FLAGGED

            elif action == "delete":
                # Only ever runs if an admin has explicitly overridden the default policy.
                if provider and provider.supports("delete_messages"):
                    provider.delete_message(email.provider_uid or "", folder="INBOX")
                email.status = EmailStatus.DELETED
                applied.append(action)

        except ProviderCapabilityError as exc:
            logger.info("Provider capability error executing '%s': %s", action, exc)
        except Exception:  # pragma: no cover - a single action failure must not abort the pipeline
            logger.exception("Failed to execute action '%s' for email %s", action, email.id)

    db.session.commit()
    audit_service.log_event("policy_actions_executed", target_type="email", target_id=email.id,
                             metadata={"classification": classification, "actions": applied})
    return applied
