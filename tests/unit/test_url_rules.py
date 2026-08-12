from app.detection.url_rules import (
    IPAddressURLRule,
    LookalikeDomainURLRule,
    URLShortenerRule,
)
from tests.unit.helpers import make_context, make_url


def test_ip_address_url_detected():
    ctx = make_context(urls=[make_url("http://192.168.1.5/login")])
    result = IPAddressURLRule().evaluate(ctx)
    assert result.matched


def test_normal_url_not_flagged_as_ip():
    ctx = make_context(urls=[make_url("https://www.example.com/page")])
    result = IPAddressURLRule().evaluate(ctx)
    assert not result.matched


def test_url_shortener_detected():
    ctx = make_context(urls=[make_url("http://bit.ly/abc123")])
    result = URLShortenerRule().evaluate(ctx)
    assert result.matched


def test_lookalike_domain_requires_brand_mention():
    ctx = make_context(subject="Your PayPal account", body_text="verify now",
                        urls=[make_url("http://paypa1-login-example.com/verify")])
    result = LookalikeDomainURLRule().evaluate(ctx)
    assert result.matched


def test_legit_brand_domain_not_flagged():
    ctx = make_context(subject="Your PayPal receipt", body_text="thanks",
                        urls=[make_url("https://paypal.com/receipt")])
    result = LookalikeDomainURLRule().evaluate(ctx)
    assert not result.matched
