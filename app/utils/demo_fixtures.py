"""
Synthetic demo/test emails (Section 50).

Every message below is entirely invented for demonstration purposes -- no
real person's email content is used. Each fixture is a full RFC 822 message
so it flows through the exact same parser/detection pipeline as a real
mailbox. They are clearly labelled DEMO in Message-ID / subject.
"""

from __future__ import annotations

import base64

_EICAR_LIKE_PLACEHOLDER = base64.b64encode(
    b"THIS-IS-NOT-MALWARE-DEMO-ATTACHMENT-PLACEHOLDER-BYTES-FOR-IETDS-TESTING"
).decode()


def _eml(msg_id: str, from_hdr: str, to_hdr: str, subject: str, date: str,
         body_text: str, extra_headers: str = "", body_html: str | None = None,
         attachment: tuple[str, str, str] | None = None) -> str:
    """Build a minimal, syntactically valid raw email message."""
    boundary = "===IETDS_DEMO_BOUNDARY==="
    headers = (
        f"Message-ID: <{msg_id}@demo.ietds.local>\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"{extra_headers}"
    )

    if not body_html and not attachment:
        headers += "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        return headers + body_text

    parts = []
    parts.append(f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body_text}\r\n")
    if body_html:
        parts.append(f"--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body_html}\r\n")
    if attachment:
        filename, mime_type, b64content = attachment
        parts.append(
            f"--{boundary}\r\n"
            f"Content-Type: {mime_type}; name=\"{filename}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n"
            f"Content-Disposition: attachment; filename=\"{filename}\"\r\n\r\n"
            f"{b64content}\r\n"
        )
    parts.append(f"--{boundary}--")

    headers += f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
    return headers + "".join(parts)


DEMO_MESSAGES = [
    {
        "uid": "demo-1",
        "message_id": "demo-1",
        "label": "Clean personal email",
        "raw": _eml(
            "demo-1", "Amaka Obi <amaka.obi@example.com>", "user@example.com",
            "[DEMO] Lunch this weekend?",
            "Mon, 03 Aug 2026 09:12:00 +0100",
            "Hi! Are you still free for lunch on Saturday? Let me know what time works.\n\n- Amaka",
            extra_headers="Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n",
        ),
    },
    {
        "uid": "demo-2",
        "message_id": "demo-2",
        "label": "Clean business email",
        "raw": _eml(
            "demo-2", "Billing <billing@cloudsuite-example.com>", "user@example.com",
            "[DEMO] Your invoice #4471 is ready",
            "Tue, 04 Aug 2026 14:30:00 +0100",
            "Hello, your monthly invoice is attached to your account dashboard. "
            "No action is required if you are on auto-pay. Thank you for your business.",
            extra_headers="Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n",
        ),
    },
    {
        "uid": "demo-3",
        "message_id": "demo-3",
        "label": "Newsletter",
        "raw": _eml(
            "demo-3", "Tech Weekly <newsletter@techweekly-example.com>", "user@example.com",
            "[DEMO] This week in tech: 5 stories you should read",
            "Wed, 05 Aug 2026 08:00:00 +0100",
            "This week: new frameworks, hardware releases, and developer tools. Read more on our site.",
            extra_headers="Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
                          "List-Unsubscribe: <mailto:unsubscribe@techweekly-example.com>\r\n",
        ),
    },
    {
        "uid": "demo-4",
        "message_id": "demo-4",
        "label": "Spam",
        "raw": _eml(
            "demo-4", "Big Deals <deals@promo-blast-example.net>", "user@example.com",
            "[DEMO] FREE!!! CLAIM NOW - ACT NOW!!! SPECIAL OFFER",
            "Thu, 06 Aug 2026 11:45:00 +0100",
            "SPECIAL OFFER just for you!!! ACT NOW to CLAIM NOW your FREE gift with no obligation! "
            "Limited time - offer expires today! Buy now at an unbeatable price, exclusive deal, act fast!!!",
            extra_headers="Authentication-Results: mx.example.com; spf=neutral; dkim=none; dmarc=fail\r\n",
        ),
    },
    {
        "uid": "demo-5",
        "message_id": "demo-5",
        "label": "Scam (advance-fee / inheritance)",
        "raw": _eml(
            "demo-5", "Barrister J. Williams <barrister.williams@fastmail-consult-example.com>",
            "user@example.com",
            "[DEMO] URGENT: Unclaimed Inheritance Fund of $10,500,000 USD",
            "Fri, 07 Aug 2026 16:20:00 +0100",
            "Dear Beneficiary, I am contacting you regarding an unclaimed inheritance fund left by a "
            "deceased client bearing your surname. This is a confidential and urgent matter requiring "
            "immediate action. To proceed with the transfer, kindly send your full name, phone number, "
            "and a processing fee of $250 via wire transfer within 48 hours or the fund will be forfeited.",
            extra_headers="Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n",
        ),
    },
    {
        "uid": "demo-6",
        "message_id": "demo-6",
        "label": "Scam (crypto investment)",
        "raw": _eml(
            "demo-6", "Investment Desk <support@crypto-returns-example.biz>", "user@example.com",
            "[DEMO] Guaranteed profit: double your bitcoin in 7 days",
            "Sat, 08 Aug 2026 10:05:00 +0100",
            "We offer guaranteed profit on all bitcoin deposits. Invest today and double your bitcoin "
            "in 7 days with zero risk. Limited slots available, act urgently to secure your spot.",
            extra_headers="Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=none\r\n",
        ),
    },
    {
        "uid": "demo-7",
        "message_id": "demo-7",
        "label": "Phishing (credential theft, brand impersonation)",
        "raw": _eml(
            "demo-7", "Account Security <security@banklogin-verify-example.com>",
            "user@example.com",
            "[DEMO] Your account will be suspended - verify your password now",
            "Sun, 09 Aug 2026 07:15:00 +0100",
            "We detected unusual activity on your account. Verify your password immediately or your "
            "account will be suspended within 24 hours. Confirm your login at the link below.",
            body_html=(
                "<p>We detected unusual activity on your account. <b>Verify your password immediately</b> "
                "or your account will be suspended within 24 hours.</p>"
                '<p><a href="http://192.168.44.21/secure-login/verify">'
                "https://www.yourbank-example.com/secure-login</a></p>"
            ),
            extra_headers=(
                "Reply-To: attacker-drop@mail-relay-example.ru\r\n"
                "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
            ),
        ),
    },
    {
        "uid": "demo-8",
        "message_id": "demo-8",
        "label": "Suspicious URL (shortener + lookalike domain)",
        "raw": _eml(
            "demo-8", "HR Notifications <hr-notify@company-portal-example.co>", "user@example.com",
            "[DEMO] Action required: update your payroll details",
            "Mon, 10 Aug 2026 13:40:00 +0100",
            "Please update your payroll banking details using the secure portal link below before Friday.",
            body_html=(
                "<p>Please update your payroll banking details using the secure portal link below "
                'before Friday.</p><p><a href="http://bit.ly/3xUpdatePayroll">'
                "Update Payroll Details</a></p>"
            ),
            extra_headers="Authentication-Results: mx.example.com; spf=neutral; dkim=none; dmarc=none\r\n",
        ),
    },
    {
        "uid": "demo-9",
        "message_id": "demo-9",
        "label": "Malicious attachment (macro-enabled document)",
        "raw": _eml(
            "demo-9", "Accounts Payable <invoices@vendor-billing-example.info>", "user@example.com",
            "[DEMO] Overdue invoice attached - open immediately",
            "Tue, 11 Aug 2026 09:55:00 +0100",
            "Please find the overdue invoice attached. Open the document and enable macros/content "
            "to view the full invoice details.",
            extra_headers="Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n",
            attachment=("Invoice_Overdue_4471.docm",
                        "application/vnd.ms-word.document.macroEnabled.12",
                        _EICAR_LIKE_PLACEHOLDER),
        ),
    },
    {
        "uid": "demo-10",
        "message_id": "demo-10",
        "label": "Sender/domain mismatch (spoofing attempt)",
        "raw": _eml(
            "demo-10", '"PayPal Support" <support@paypa1-secure-example.com>', "user@example.com",
            "[DEMO] Your PayPal payment is on hold - confirm your identity",
            "Wed, 12 Aug 2026 12:00:00 +0100",
            "Your recent payment has been placed on hold. Confirm your identity and password to release "
            "your funds. Failure to respond within 24 hours will result in permanent account limitation.",
            extra_headers=(
                "Reply-To: no-reply@differentdomain-example.tk\r\n"
                "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
            ),
        ),
    },
]
