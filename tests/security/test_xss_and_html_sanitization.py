"""
Email HTML is untrusted input (Section 44) -- these tests confirm scripts and
active content are stripped before rendering.
"""

from app.utils.security import sanitize_email_html


def test_script_tags_are_stripped():
    raw = '<p>Hello</p><script>alert("xss")</script>'
    cleaned = sanitize_email_html(raw)
    # The <script> tag markup itself must be gone -- bleach.clean(strip=True)
    # removes disallowed tags but leaves their inner text as inert plain text,
    # which is safe because it is no longer wrapped in an executable <script>
    # element (rendered inside a normal HTML context, it cannot execute).
    assert "<script" not in cleaned
    assert "</script>" not in cleaned


def test_event_handlers_are_stripped():
    raw = '<img src="x.png" onerror="alert(1)">'
    cleaned = sanitize_email_html(raw)
    assert "onerror" not in cleaned


def test_javascript_uri_is_stripped():
    raw = '<a href="javascript:alert(1)">Click me</a>'
    cleaned = sanitize_email_html(raw)
    assert "javascript:" not in cleaned


def test_iframe_is_stripped():
    raw = '<iframe src="http://evil.example.com"></iframe>'
    cleaned = sanitize_email_html(raw)
    assert "<iframe" not in cleaned


def test_safe_content_is_preserved():
    raw = "<p>Please <b>review</b> the attached invoice.</p>"
    cleaned = sanitize_email_html(raw)
    assert "review" in cleaned
    assert "<b>" in cleaned


def test_empty_html_returns_empty():
    assert sanitize_email_html("") == ""
    assert sanitize_email_html(None) == ""
