from app.providers.base import RawMessage
from app.services.email_parser import parse_raw_message


def _raw(headers: str, body: str) -> RawMessage:
    content = (headers + "\r\n" + body).encode("utf-8")
    return RawMessage(provider_uid="1", message_id=None, raw_bytes=content)


def test_parse_basic_headers_and_body():
    headers = (
        "From: Jane Doe <jane@example.com>\r\n"
        "To: user@example.com\r\n"
        "Subject: Test Subject\r\n"
        "Date: Mon, 01 Jan 2024 10:00:00 +0000\r\n"
        "Message-ID: <abc123@example.com>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
    )
    raw = _raw(headers, "Hello world")
    parsed = parse_raw_message(raw)

    assert parsed.sender == "jane@example.com"
    assert parsed.sender_display_name == "Jane Doe"
    assert parsed.sender_domain == "example.com"
    assert parsed.subject == "Test Subject"
    assert parsed.message_id == "<abc123@example.com>"
    assert "Hello world" in parsed.body_text


def test_parse_authentication_results():
    headers = (
        "From: sender@example.com\r\n"
        "Subject: Auth Test\r\n"
        "Authentication-Results: mx.example.com; spf=fail; dkim=pass; dmarc=fail\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
    )
    raw = _raw(headers, "body")
    parsed = parse_raw_message(raw)

    assert parsed.spf_result == "fail"
    assert parsed.dkim_result == "pass"
    assert parsed.dmarc_result == "fail"


def test_parse_missing_authentication_results_defaults_to_not_available():
    headers = "From: sender@example.com\r\nSubject: No auth\r\nContent-Type: text/plain\r\n"
    raw = _raw(headers, "body")
    parsed = parse_raw_message(raw)

    assert parsed.spf_result == "not_available"
    assert parsed.dkim_result == "not_available"
    assert parsed.dmarc_result == "not_available"


def test_parse_extracts_urls_from_plain_text():
    headers = "From: sender@example.com\r\nSubject: Links\r\nContent-Type: text/plain\r\n"
    raw = _raw(headers, "Visit https://example.com/path and http://192.168.1.1/login now.")
    parsed = parse_raw_message(raw)

    urls = [u.url for u in parsed.urls]
    assert any("example.com" in u for u in urls)
    assert any("192.168.1.1" in u for u in urls)


def test_malformed_message_does_not_crash():
    raw = RawMessage(provider_uid="1", message_id=None, raw_bytes=b"\xff\xfe\x00not valid mime at all")
    parsed = parse_raw_message(raw)
    # Should degrade gracefully rather than raising.
    assert parsed.provider_uid == "1"


def test_dedup_key_prefers_message_id():
    from app.services.email_parser import ParsedEmail

    p1 = ParsedEmail(provider_uid="1", message_id="<abc@example.com>")
    assert p1.dedup_key == "mid:<abc@example.com>"

    p2 = ParsedEmail(provider_uid="42", message_id=None)
    assert p2.dedup_key == "uid:42"
