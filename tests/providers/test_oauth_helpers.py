"""
Tests for the OAuth "who did we actually authorize" helper added to the
Gmail provider, and the automatic access-token refresh logic in
mailbox_service. No live credentials or network calls involved -
requests.get/post are monkeypatched.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.providers import gmail_provider


class _FakeResponse:
    def __init__(self, json_data=None, status_code=200):
        self._json = json_data or {}
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


class TestGmailGetAuthenticatedEmail:
    def test_returns_email_on_success(self):
        with patch("requests.get", return_value=_FakeResponse({"email": "real.user@gmail.com"})):
            assert gmail_provider.get_authenticated_email("token-abc") == "real.user@gmail.com"

    def test_returns_none_on_failure(self):
        import requests

        with patch("requests.get", side_effect=requests.RequestException("boom")):
            assert gmail_provider.get_authenticated_email("token-abc") is None


@pytest.fixture()
def gmail_mailbox(db, organization, admin_user):
    from app.services import mailbox_service

    mailbox = mailbox_service.create_oauth_mailbox(
        organization_id=organization.id, user_id=admin_user.id, provider="gmail",
        email_address="user@gmail.com",
        # obtained_at=1 (1970) -> unambiguously expired, without being falsy like 0
        token={"access_token": "old-access", "refresh_token": "refresh-xyz",
               "expires_in": 3600, "obtained_at": 1},
    )
    return mailbox


class TestTokenRefresh:
    def test_expired_token_is_refreshed_and_persisted(self, app, gmail_mailbox):
        from app.services import mailbox_service

        with app.app_context():
            app.config["GMAIL_CLIENT_ID"] = "test-client-id"
            app.config["GMAIL_CLIENT_SECRET"] = "test-client-secret"
            with patch(
                "app.providers.gmail_provider.refresh_access_token",
                return_value={"access_token": "new-access", "expires_in": 3600},
            ) as mock_refresh:
                provider = mailbox_service.build_provider(gmail_mailbox)

            mock_refresh.assert_called_once()
            assert provider._oauth_token["access_token"] == "new-access"
            # refresh_token isn't rotated by Google, so the old one must survive.
            assert provider._oauth_token["refresh_token"] == "refresh-xyz"

            # And the refreshed token must actually be persisted, not just returned.
            stored = mailbox_service.get_decrypted_oauth_token(gmail_mailbox)
            assert stored["access_token"] == "new-access"

    def test_fresh_token_is_not_refreshed(self, app, db, organization, admin_user):
        from app.services import mailbox_service
        import time

        mailbox = mailbox_service.create_oauth_mailbox(
            organization_id=organization.id, user_id=admin_user.id, provider="gmail",
            email_address="user@gmail.com",
            token={"access_token": "still-good", "refresh_token": "refresh-xyz",
                   "expires_in": 3600, "obtained_at": time.time()},
        )
        with app.app_context():
            with patch("app.providers.gmail_provider.refresh_access_token") as mock_refresh:
                provider = mailbox_service.build_provider(mailbox)
            mock_refresh.assert_not_called()
            assert provider._oauth_token["access_token"] == "still-good"

    def test_refresh_failure_falls_back_to_old_token_without_raising(self, app, gmail_mailbox):
        from app.services import mailbox_service

        with app.app_context():
            app.config["GMAIL_CLIENT_ID"] = "test-client-id"
            app.config["GMAIL_CLIENT_SECRET"] = "test-client-secret"
            with patch(
                "app.providers.gmail_provider.refresh_access_token",
                side_effect=Exception("refresh token revoked"),
            ):
                provider = mailbox_service.build_provider(gmail_mailbox)  # must not raise

            assert provider._oauth_token["access_token"] == "old-access"
