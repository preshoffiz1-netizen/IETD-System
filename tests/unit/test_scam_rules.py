from app.detection.scam_rules import InheritanceScamRule, LotteryPrizeScamRule, UrgentMoneyTransferRule
from tests.unit.helpers import make_context


def test_inheritance_scam_detected():
    ctx = make_context(body_text="This concerns an unclaimed inheritance fund. You are the beneficiary "
                                  "of a deceased client. A processing fee applies.")
    result = InheritanceScamRule().evaluate(ctx)
    assert result.matched


def test_lottery_scam_detected():
    ctx = make_context(body_text="Congratulations, you have won our international lottery jackpot!")
    result = LotteryPrizeScamRule().evaluate(ctx)
    assert result.matched


def test_clean_email_not_flagged_as_scam():
    ctx = make_context(body_text="Attached is the quarterly report for your review.")
    assert not InheritanceScamRule().evaluate(ctx).matched
    assert not LotteryPrizeScamRule().evaluate(ctx).matched


def test_urgent_money_transfer_detected():
    ctx = make_context(body_text="Please send a gift card immediately via wire transfer, this is urgent.")
    result = UrgentMoneyTransferRule().evaluate(ctx)
    assert result.matched
