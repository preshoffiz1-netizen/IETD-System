"""
Shared helpers for URL / domain analysis (Sections 20-21).

Kept dependency-light (no external reputation API calls) per Section 25:
"Do not require paid threat-intelligence APIs for basic operation." All
reputation/heuristic checks here are local and deterministic.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy",
}

# Well-known brands frequently impersonated in phishing/scam emails, mapped to
# their legitimate top-level domain(s). Used only for *local* lookalike
# comparison -- never treated as a live reputation feed.
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "bank": [],  # generic term; brand-specific bank domains are added via whitelist
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
}

LOGIN_KEYWORDS = ("login", "signin", "sign-in", "verify", "secure", "update",
                   "confirm", "account", "password", "credential", "reset")


def extract_domain(url_or_email: str) -> str:
    if not url_or_email:
        return ""
    if "@" in url_or_email and "://" not in url_or_email:
        return url_or_email.rsplit("@", 1)[-1].lower().strip()
    parsed = urlparse(url_or_email if "://" in url_or_email else f"http://{url_or_email}")
    host = (parsed.netloc or parsed.path).lower()
    host = host.split("@")[-1]  # strip userinfo@ if present
    host = host.split(":")[0]   # strip port
    return host.strip("/")


def is_ip_address(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_shortened_url(domain: str) -> bool:
    return domain.lower() in URL_SHORTENERS


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def subdomain_count(domain: str) -> int:
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def find_impersonated_brand(text: str) -> str | None:
    """Return the brand keyword mentioned in `text`, if any known brand name appears."""
    lowered = text.lower()
    for brand in KNOWN_BRANDS:
        if brand in lowered:
            return brand
    return None


def domain_matches_brand(domain: str, brand: str) -> bool:
    legit_domains = KNOWN_BRANDS.get(brand, [])
    return any(domain == d or domain.endswith("." + d) for d in legit_domains)


_LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def _normalize_leetspeak(value: str) -> str:
    """Undo common leetspeak/homoglyph digit substitutions used in lookalike domains."""
    return value.translate(_LEETSPEAK_MAP)


def is_lookalike_domain(domain: str, brand: str, max_distance: int = 2) -> bool:
    """
    True if `domain` is suspiciously close to one of the brand's legitimate
    domains but not an exact/subdomain match -- e.g. "paypa1-secure-example.com"
    or "paypal-login-example.com" vs "paypal.com".

    Checks (in order): an exact brand-name segment appearing after undoing
    leetspeak substitutions (e.g. "paypa1" -> "paypal"), the brand name as a
    substring of the normalized registrable name, and small edit-distance
    matches on any hyphen/dot-separated segment.
    """
    legit_domains = KNOWN_BRANDS.get(brand, [])
    if not legit_domains:
        return False
    if domain_matches_brand(domain, brand):
        return False
    if not domain:
        return False

    labels = domain.split(".")
    # Registrable "name" portion, e.g. "paypa1-login-example" out of
    # "paypa1-login-example.com" -- everything except the final TLD label.
    name_part = ".".join(labels[:-1]) if len(labels) > 1 else domain
    normalized = _normalize_leetspeak(name_part)
    segments = re.split(r"[-.]", normalized)

    for legit in legit_domains:
        legit_root = legit.split(".")[0]
        if legit_root in segments:
            return True
        if legit_root in normalized:
            return True
        for segment in segments:
            if segment and 0 < levenshtein(segment, legit_root) <= max_distance:
                return True
    return False


def has_suspicious_login_keywords(url: str) -> bool:
    lowered = url.lower()
    return any(kw in lowered for kw in LOGIN_KEYWORDS)


def looks_like_double_extension(filename: str) -> bool:
    return bool(re.search(r"\.[a-z0-9]{2,5}\.[a-z0-9]{2,5}$", filename.lower()))
