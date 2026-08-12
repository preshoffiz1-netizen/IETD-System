"""
Email parsing (Sections 13-14).

Turns a provider-agnostic RawMessage into a structured, in-memory
ParsedEmail that the detection engine can reason about. Uses Python's
standard `email` package only (no third-party MIME parser needed) and is
defensive about malformed messages -- a broken email should degrade
gracefully to "fields unavailable", never crash the ingestion pipeline.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, utils as email_utils
from email.header import decode_header
from email.message import Message
from typing import Optional

from app.providers.base import RawMessage

logger = logging.getLogger("ietds.parser")

URL_REGEX = re.compile(r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
""")

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".iso",
    ".zip", ".rar", ".xlsm", ".docm", ".pif", ".msi", ".hta", ".wsf",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}


@dataclass
class ParsedAttachment:
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    sha256_hash: str
    is_dangerous_extension: bool
    has_double_extension: bool
    is_macro_enabled: bool


@dataclass
class ParsedURL:
    url: str
    display_text: str = ""


@dataclass
class ParsedEmail:
    provider_uid: str
    message_id: Optional[str]
    sender: str = ""
    sender_display_name: str = ""
    sender_domain: str = ""
    recipient: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    date_sent: Optional[datetime] = None
    body_text: str = ""
    body_html: str = ""
    raw_headers: dict = field(default_factory=dict)
    spf_result: str = "not_available"
    dkim_result: str = "not_available"
    dmarc_result: str = "not_available"
    urls: list[ParsedURL] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def dedup_key(self) -> str:
        if self.message_id:
            return f"mid:{self.message_id}"
        return f"uid:{self.provider_uid}"


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
        decoded = ""
        for text, enc in parts:
            if isinstance(text, bytes):
                decoded += text.decode(enc or "utf-8", errors="replace")
            else:
                decoded += text
        return decoded.strip()
    except Exception:  # pragma: no cover - defensive
        return value


def _extract_domain(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().strip(">")


def _get_body(msg: Message) -> tuple[str, str]:
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, TypeError):
                decoded = payload.decode("utf-8", errors="replace")
            if content_type == "text/plain":
                text_parts.append(decoded)
            elif content_type == "text/html":
                html_parts.append(decoded)
    else:
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is not None:
            charset = msg.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, TypeError):
                decoded = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(decoded)
            else:
                text_parts.append(decoded)
    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_urls(text: str, html: str) -> list[ParsedURL]:
    urls: list[ParsedURL] = []
    seen = set()
    for candidate in URL_REGEX.findall(text or ""):
        cleaned = candidate.rstrip(".,;:!?)")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(ParsedURL(url=cleaned))

    if html:
        href_pattern = re.compile(r'href=["\']([^"\']+)["\'][^>]*>([^<]*)', re.IGNORECASE)
        for href, anchor_text in href_pattern.findall(html):
            cleaned = href.strip()
            if cleaned.startswith(("http://", "https://")) and cleaned not in seen:
                seen.add(cleaned)
                urls.append(ParsedURL(url=cleaned, display_text=anchor_text.strip()))
            elif cleaned not in seen and cleaned.startswith("http"):
                seen.add(cleaned)
                urls.append(ParsedURL(url=cleaned, display_text=anchor_text.strip()))
    return urls


def _extract_attachments(msg: Message) -> list[ParsedAttachment]:
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if "attachment" not in disposition and not filename:
            continue
        if not filename:
            continue
        filename = _decode(filename)

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower()

        double_ext = bool(re.search(r"\.[a-z0-9]{2,5}\.[a-z0-9]{2,5}$", filename.lower()))

        attachments.append(ParsedAttachment(
            filename=filename,
            extension=ext,
            mime_type=part.get_content_type() or "application/octet-stream",
            size_bytes=len(payload),
            sha256_hash=hashlib.sha256(payload).hexdigest() if payload else "",
            is_dangerous_extension=ext in DANGEROUS_EXTENSIONS,
            has_double_extension=double_ext,
            is_macro_enabled=ext in MACRO_EXTENSIONS,
        ))
    return attachments


def _parse_auth_results(header_value: str) -> dict:
    """Extract spf/dkim/dmarc verdicts from an Authentication-Results header."""
    result = {"spf": "not_available", "dkim": "not_available", "dmarc": "not_available"}
    if not header_value:
        return result
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}\s*=\s*(\w+)", header_value, re.IGNORECASE)
        if match:
            result[mechanism] = match.group(1).lower()
    return result


def parse_raw_message(raw: RawMessage) -> ParsedEmail:
    parsed = ParsedEmail(provider_uid=raw.provider_uid, message_id=raw.message_id)

    try:
        msg = message_from_bytes(raw.raw_bytes)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to parse message uid=%s: %s", raw.provider_uid, exc)
        parsed.parse_errors.append(f"parse_failure: {exc}")
        return parsed

    from_hdr = _decode(msg.get("From", ""))
    name, addr = email_utils.parseaddr(from_hdr)
    parsed.sender = addr.lower()
    parsed.sender_display_name = _decode(name)
    parsed.sender_domain = _extract_domain(addr)

    parsed.recipient = _decode(msg.get("To", ""))
    parsed.reply_to = email_utils.parseaddr(_decode(msg.get("Reply-To", "")))[1]
    parsed.return_path = email_utils.parseaddr(_decode(msg.get("Return-Path", "")))[1]
    parsed.subject = _decode(msg.get("Subject", ""))

    if not parsed.message_id:
        parsed.message_id = (msg.get("Message-ID") or "").strip() or None

    date_hdr = msg.get("Date")
    if date_hdr:
        try:
            dt = email_utils.parsedate_to_datetime(date_hdr)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed.date_sent = dt
        except (TypeError, ValueError):
            parsed.date_sent = None

    parsed.body_text, parsed.body_html = _get_body(msg)
    parsed.urls = _extract_urls(parsed.body_text, parsed.body_html)
    parsed.attachments = _extract_attachments(msg)

    auth_results = _parse_auth_results(msg.get("Authentication-Results", ""))
    parsed.spf_result = auth_results["spf"]
    parsed.dkim_result = auth_results["dkim"]
    parsed.dmarc_result = auth_results["dmarc"]

    parsed.raw_headers = {k: _decode(v) for k, v in msg.items()}

    return parsed
