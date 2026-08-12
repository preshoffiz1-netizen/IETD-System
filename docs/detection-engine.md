# Detection Engine

## Why rule-based, not machine learning

The core detection mechanism in IETDS is **rule-based**, not machine learning, and this is a
deliberate design decision rather than a limitation of convenience (Sections 15, 64 of the
project brief). The literature reviewed in Chapter 2 identifies the same trade-off: ML/deep
learning approaches can achieve strong accuracy but require large labeled datasets,
significant computational resources, ongoing retraining as attacker behaviour shifts, and
produce comparatively opaque ("black-box") decisions. For the target users of this project -
individuals and small-scale organizations with no dedicated security team or training data -
those requirements are impractical. A rule-based engine is:

- **Explainable** - every classification comes with a list of exactly which rules fired, what
  they matched, and how many points each contributed (see "Explainable detection" below).
- **Cheap to run** - no GPU, no model file, no inference latency budget.
- **Immediately maintainable** - a new threat pattern is a new rule (or a new custom rule
  created through the Rule Builder UI), not a retraining cycle.
- **Auditable** - a supervisor/examiner can read `app/detection/*_rules.py` top to bottom and
  understand exactly what the system does.

The trade-off, stated honestly: rule-based detection is weaker against genuinely novel attack
patterns that don't match any existing rule, and rule bases need periodic maintenance as new
threats emerge. Future work (see README) could add an ML-assisted *second opinion* alongside
the rule engine without replacing it.

## Rule interface

Every rule (`app/detection/base_rule.py`) implements:

```python
def evaluate(self, context: EmailContext) -> RuleResult: ...
```

`EmailContext` wraps the parsed email plus the organization's whitelist/blacklist sets.
`RuleResult` carries `matched`, `score`, `reason` (a human-readable explanation), `category`,
`severity`, and optional `metadata`. Rules never raise on malformed input by design - a single
misbehaving rule is caught and skipped by `threat_engine.run_builtin_rules()` so one bad rule
can never take down a scan.

## Rule categories and files

| File | Category | Examples |
|---|---|---|
| `sender_rules.py` | sender | blacklisted sender, corporate-sounding display name on a free webmail domain |
| `spam_rules.py` | spam | subject spam keywords, excessive caps/punctuation, promotional language |
| `scam_rules.py` | scam | lottery/prize, inheritance/advance-fee, crypto investment, urgent money transfer, fake invoice, emotional manipulation |
| `phishing_rules.py` | phishing | credential requests, suspension threats, brand impersonation, Reply-To mismatch |
| `url_rules.py` | url | raw IP URLs, shorteners, punycode, excessive subdomains, display-text/href mismatch, lookalike brand domains |
| `attachment_rules.py` | attachment | dangerous extensions, executables, macro-enabled documents, double extensions |
| `header_rules.py` | header | Return-Path mismatch, missing Message-ID, spoofed display-name-as-address |
| `authentication_rules.py` | authentication | SPF/DKIM/DMARC failure (individually and combined) |

Rules are intentionally **weighted, not purely keyword-based** (Section 17's explicit
requirement) - e.g. `UnsolicitedPromotionalLanguageRule` requires *two or more* promotional
phrases before it fires, and its score scales with how many appear.

## Lookalike domain detection

`app/utils/domain_utils.is_lookalike_domain()` compares a sending/URL domain against a small
local table of commonly-impersonated brands (`KNOWN_BRANDS`) without calling any external
reputation API (Section 25: no paid threat-intelligence dependency for basic operation). It:

1. Undoes common leetspeak/homoglyph digit substitutions (`0`->`o`, `1`->`l`, `3`->`e`, etc.),
   since attackers frequently register domains like `paypa1-secure-example.com`.
2. Checks whether the brand name appears as its own hyphen/dot-separated segment, or as a
   substring, of the normalized registrable name.
3. Falls back to a small edit-distance (Levenshtein) check per segment for close typos.

An unfamiliar domain is *never* treated as malicious on its own (Section 20's explicit
requirement) - only a domain that resembles a *specific known brand* while not actually
belonging to that brand is flagged, and only as a contributing score, not an automatic
"malicious" verdict.

## Custom rules (Rule Builder)

Organizations can add their own weighted rules through **Rules -> Create Custom Rule**. A
custom rule is a `DetectionRule` row with one or more `RuleCondition` rows (`field`,
`operator`, `value`, and a `joiner` of `AND`/`OR`/`NOT` relative to the previous condition).
`threat_engine.run_custom_rules()` evaluates these against the same `EmailContext` used by the
built-in rules, and a matched custom rule contributes its configured score exactly like a
built-in one - they are combined transparently.

## Explainable detection

Every non-clean email's inspection page (`/emails/<id>`) shows:

- The total threat score and its full per-category breakdown (sender/subject/body/url/
  attachment/header/authentication/spam/scam/phishing).
- Every triggered rule, with its score contribution, severity, and a plain-language reason
  (e.g. "Reply-To domain ('evil.tk') differs from the From domain ('example.com')").

This is generated directly from the `ThreatIndicator` rows created during scoring - there is
no separate "explanation generator"; the explanation *is* the record of what the scoring
engine actually did, which guarantees it can never drift from the real decision.

## Threat scoring and classification thresholds

Default thresholds (all editable from **Settings**, stored in `SystemSetting`, never
hardcoded through the codebase - Section 26):

| Total score | Classification |
|---|---|
| 0-19 | CLEAN |
| 20-39 | SUSPICIOUS |
| 40-59 | SPAM |
| 60+ | HIGH RISK -> subdivided into PHISHING / SCAM / MALICIOUS_ATTACHMENT |

**Subdivision logic** (`classification_service.classify`): within the HIGH RISK band, the
system looks at which category-specific score (phishing_score, scam_score, or a confirmed
dangerous-attachment match) is dominant. If the score crossed 60 purely on generic
spam/URL/header/authentication signals - with *no* phishing-specific, scam-specific, or
attachment-specific evidence at all - the classification is capped at **SPAM** rather than
being force-labelled as phishing or scam. This avoids a defensible failure mode: a very loud
marketing email should not be reported to a user as "phishing" just because it crossed a
numeric threshold; it should only earn that label when there is actual credential-theft,
fraud-pattern, or dangerous-attachment evidence behind it. This design choice is covered by
`tests/unit/test_scoring_and_classification.py`.
