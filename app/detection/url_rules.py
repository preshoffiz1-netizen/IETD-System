"""URL / link analysis rules (Section 20). Unfamiliar != malicious on its own."""

from __future__ import annotations

from app.detection.base_rule import BaseRule, Category, EmailContext, RuleResult, Severity
from app.utils.domain_utils import (
    extract_domain,
    find_impersonated_brand,
    has_suspicious_login_keywords,
    is_ip_address,
    is_lookalike_domain,
    is_punycode,
    is_shortened_url,
    subdomain_count,
)


class IPAddressURLRule(BaseRule):
    name = "url.ip_address_url"
    category = Category.URL
    default_score = 18
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            domain = extract_domain(u.url)
            if is_ip_address(domain):
                return self._result(True, f"Email contains a raw IP-address URL: {u.url}",
                                     metadata={"url": u.url})
        return RuleResult.no_match(self.name)


class URLShortenerRule(BaseRule):
    name = "url.shortener"
    category = Category.URL
    default_score = 10
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            domain = extract_domain(u.url)
            if is_shortened_url(domain):
                return self._result(True, f"Email uses a URL-shortening service ({domain}) that hides the real destination",
                                     metadata={"url": u.url})
        return RuleResult.no_match(self.name)


class PunycodeURLRule(BaseRule):
    name = "url.punycode_domain"
    category = Category.URL
    default_score = 15
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            domain = extract_domain(u.url)
            if is_punycode(domain):
                return self._result(True, f"URL domain uses punycode/IDN encoding ({domain}), often used to spoof lookalike characters",
                                     metadata={"url": u.url})
        return RuleResult.no_match(self.name)


class ExcessiveSubdomainsRule(BaseRule):
    name = "url.excessive_subdomains"
    category = Category.URL
    default_score = 8
    severity = Severity.LOW

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            domain = extract_domain(u.url)
            if subdomain_count(domain) >= 3:
                return self._result(True, f"URL has an unusually deep subdomain structure ({domain})",
                                     metadata={"url": u.url})
        return RuleResult.no_match(self.name)


class DisplayURLMismatchRule(BaseRule):
    name = "url.display_mismatch"
    category = Category.URL
    default_score = 20
    severity = Severity.HIGH

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            if not u.display_text or "http" not in u.display_text.lower():
                continue
            shown_domain = extract_domain(u.display_text)
            actual_domain = extract_domain(u.url)
            if shown_domain and actual_domain and shown_domain != actual_domain:
                return self._result(
                    True,
                    f"Displayed link text ('{shown_domain}') does not match the actual destination ('{actual_domain}')",
                    metadata={"displayed": shown_domain, "actual": actual_domain},
                )
        return RuleResult.no_match(self.name)


class LookalikeDomainURLRule(BaseRule):
    name = "url.lookalike_domain"
    category = Category.URL
    default_score = 22
    severity = Severity.CRITICAL

    def evaluate(self, context: EmailContext) -> RuleResult:
        combined_text = f"{context.parsed.subject} {context.parsed.body_text}"
        brand = find_impersonated_brand(combined_text)
        if not brand:
            return RuleResult.no_match(self.name)
        for u in context.parsed.urls:
            domain = extract_domain(u.url)
            if is_lookalike_domain(domain, brand):
                return self._result(True, f"URL domain '{domain}' closely resembles the legitimate '{brand}' domain",
                                     metadata={"url": u.url, "brand": brand})
        return RuleResult.no_match(self.name)


class SuspiciousLoginURLRule(BaseRule):
    name = "url.suspicious_login_keywords"
    category = Category.URL
    default_score = 10
    severity = Severity.MEDIUM

    def evaluate(self, context: EmailContext) -> RuleResult:
        for u in context.parsed.urls:
            if has_suspicious_login_keywords(u.url) and extract_domain(u.url) not in context.whitelist_domains:
                return self._result(True, f"URL path/domain contains login/verification keywords: {u.url}",
                                     metadata={"url": u.url})
        return RuleResult.no_match(self.name)


URL_RULES = [
    IPAddressURLRule(),
    URLShortenerRule(),
    PunycodeURLRule(),
    ExcessiveSubdomainsRule(),
    DisplayURLMismatchRule(),
    LookalikeDomainURLRule(),
    SuspiciousLoginURLRule(),
]
