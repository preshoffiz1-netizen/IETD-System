from __future__ import annotations

from app.detection.base_rule import EmailContext
from app.services.email_parser import ParsedAttachment, ParsedEmail, ParsedURL


def make_parsed_email(**overrides) -> ParsedEmail:
    defaults = dict(
        provider_uid="1",
        message_id="<abc@example.com>",
        sender="sender@example.com",
        sender_display_name="Sender Name",
        sender_domain="example.com",
        recipient="user@example.com",
        reply_to="",
        return_path="",
        subject="Hello",
        body_text="Hello, this is a normal email.",
        body_html="",
        spf_result="not_available",
        dkim_result="not_available",
        dmarc_result="not_available",
        urls=[],
        attachments=[],
    )
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def make_context(parsed=None, **kwargs) -> EmailContext:
    return EmailContext(parsed=parsed or make_parsed_email(**kwargs))


def make_url(url: str, display_text: str = "") -> ParsedURL:
    return ParsedURL(url=url, display_text=display_text)


def make_attachment(filename: str, mime_type: str = "application/octet-stream", size_bytes: int = 100) -> ParsedAttachment:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    from app.services.email_parser import DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS
    import re
    return ParsedAttachment(
        filename=filename, extension=ext, mime_type=mime_type, size_bytes=size_bytes,
        sha256_hash="deadbeef",
        is_dangerous_extension=ext in DANGEROUS_EXTENSIONS,
        has_double_extension=bool(re.search(r"\.[a-z0-9]{2,5}\.[a-z0-9]{2,5}$", filename.lower())),
        is_macro_enabled=ext in MACRO_EXTENSIONS,
    )
