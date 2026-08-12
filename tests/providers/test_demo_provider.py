from app.providers.demo_provider import DemoProvider


class _FakeMailbox:
    id = "mb-1"


def test_demo_provider_lists_and_fetches_messages():
    provider = DemoProvider(_FakeMailbox())
    result = provider.test_connection()
    assert result.success

    uids = provider.list_messages(limit=100)
    assert len(uids) == 10

    msg = provider.fetch_message(uids[0])
    assert msg.provider_uid == uids[0]
    assert b"Message-ID" in msg.raw_bytes


def test_demo_provider_capabilities_declared():
    assert DemoProvider.CAPABILITIES["fetch_messages"] is True
    assert DemoProvider.CAPABILITIES["oauth"] is False
