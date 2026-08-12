from app.detection.spam_rules import (
    ExcessiveCapitalizationRule,
    ExcessivePunctuationRule,
    SubjectSpamKeywordsRule,
    UnsolicitedPromotionalLanguageRule,
)
from tests.unit.helpers import make_context


def test_subject_spam_keywords_matches():
    ctx = make_context(subject="FREE!!! CLAIM NOW")
    result = SubjectSpamKeywordsRule().evaluate(ctx)
    assert result.matched
    assert result.score > 0


def test_subject_spam_keywords_no_match_on_clean_subject():
    ctx = make_context(subject="Team meeting notes")
    result = SubjectSpamKeywordsRule().evaluate(ctx)
    assert not result.matched


def test_excessive_capitalization():
    ctx = make_context(subject="URGENT ACCOUNT NOTICE PLEASE READ")
    result = ExcessiveCapitalizationRule().evaluate(ctx)
    assert result.matched


def test_normal_subject_not_flagged_for_caps():
    ctx = make_context(subject="Meeting notes for Tuesday")
    result = ExcessiveCapitalizationRule().evaluate(ctx)
    assert not result.matched


def test_excessive_punctuation():
    ctx = make_context(subject="Buy now!!!")
    result = ExcessivePunctuationRule().evaluate(ctx)
    assert result.matched


def test_promotional_language_requires_multiple_hits():
    ctx = make_context(body_text="This has one limited time offer.")
    result = UnsolicitedPromotionalLanguageRule().evaluate(ctx)
    assert not result.matched  # only one keyword hit

    ctx2 = make_context(body_text="Limited time offer! Buy now! Exclusive deal! Act fast!")
    result2 = UnsolicitedPromotionalLanguageRule().evaluate(ctx2)
    assert result2.matched
