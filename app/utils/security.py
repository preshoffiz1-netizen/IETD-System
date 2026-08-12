"""
Security primitives shared across the application:

- Password hashing (Argon2)
- Symmetric encryption for sensitive mailbox credentials / OAuth tokens at rest
- Safe HTML sanitization for untrusted email bodies (Section 44)

Nothing in this module ever logs a secret value.
"""

from __future__ import annotations

import base64
import hashlib
import logging

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

logger = logging.getLogger("ietds.security")

_hasher = PasswordHasher()

# Allow-list for rendering untrusted HTML email bodies. Everything else is stripped.
SAFE_HTML_TAGS = [
    "a", "b", "i", "u", "em", "strong", "p", "br", "ul", "ol", "li",
    "span", "div", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
    "table", "thead", "tbody", "tr", "td", "th", "hr", "pre", "code", "img",
]
SAFE_HTML_ATTRS = {
    "a": ["href", "title", "rel", "target"],
    "img": ["src", "alt", "title", "width", "height"],
    # NOTE: "style" is intentionally NOT allowed. Sanitizing inline CSS safely
    # requires bleach's optional css_sanitizer (tinycss2 dependency); without
    # it, allowing "style" would let attackers pass through unsanitized CSS
    # (e.g. background-image exfiltration). Safer to strip it entirely.
}


# --- Password hashing -----------------------------------------------------------------

def hash_password(raw_password: str) -> str:
    return _hasher.hash(raw_password)


def verify_password(stored_hash: str, raw_password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, raw_password)
    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception:  # pragma: no cover - defensive
        logger.warning("Unexpected error verifying password hash")
        return False


# --- Symmetric encryption for credentials at rest --------------------------------------

def _get_fernet() -> Fernet:
    key = current_app.config.get("ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not configured. Set it in your .env file before storing "
            "mailbox credentials. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    # Accept either a proper Fernet key or an arbitrary secret (derived via SHA-256).
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError):
        digest = hashlib.sha256(key.encode()).digest()
        derived = base64.urlsafe_b64encode(digest)
        return Fernet(derived)


def encrypt_secret(plaintext: str) -> str:
    if plaintext is None:
        return ""
    token = _get_fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt stored secret: invalid token / wrong key")
        raise


# --- HTML sanitization for untrusted email content --------------------------------------

def sanitize_email_html(raw_html: str) -> str:
    """
    Never render raw email HTML directly. Strip scripts, event handlers, iframes,
    forms, and any tag/attribute not on the allow-list.
    """
    if not raw_html:
        return ""
    import bleach

    cleaned = bleach.clean(
        raw_html,
        tags=SAFE_HTML_TAGS,
        attributes=SAFE_HTML_ATTRS,
        strip=True,
    )
    cleaned = bleach.linkify(cleaned, skip_tags=["pre", "code"])
    return cleaned
