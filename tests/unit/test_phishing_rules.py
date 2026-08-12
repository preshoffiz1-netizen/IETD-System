from app.detection.phishing_rules import (
    AccountSuspensionThreatRule,
    BrandImpersonationRule,
    CredentialRequestRule,
    SenderReplyToMismatchRule,
)
from tests.unit.helpers import make_context


def test_credential_request_detected():
    ctx = make_context(body_text="Please verify your password immediately to avoid suspension.")
    result = CredentialRequestRule().evaluate(ctx)
    assert result.matched


def test_suspension_threat_detected():
    ctx = make_context(body_text="Your account will be suspended within 24 hours.")
    result = AccountSuspensionThreatRule().evaluate(ctx)
    assert result.matched


def test_brand_impersonation_flags_lookalike_domain():
    ctx = make_context(subject="PayPal Account Alert", sender_domain="paypa1-secure-example.com")
    result = BrandImpersonationRule().evaluate(ctx)
    assert result.matched
    assert result.metadata["brand"] == "paypal"


def test_brand_impersonation_does_not_flag_legitimate_sender():
    ctx = make_context(subject="Your PayPal receipt", sender_domain="paypal.com")
    result = BrandImpersonationRule().evaluate(ctx)
    assert not result.matched


def test_sender_replyto_mismatch():
    ctx = make_context(sender_domain="example.com", reply_to="attacker@evil-domain.com")
    result = SenderReplyToMismatchRule().evaluate(ctx)
    assert result.matched


def test_sender_replyto_match_not_flagged():
    ctx = make_context(sender_domain="example.com", reply_to="support@example.com")
    result = SenderReplyToMismatchRule().evaluate(ctx)
    assert not result.matched
