"""
Central application configuration.

Every tunable value referenced elsewhere in the codebase (thresholds, scan
intervals, branding, cookie flags, etc.) is defined here or loaded from the
SystemSetting table at runtime -- nothing important should be hardcoded deep
inside a route or service module.
"""

from __future__ import annotations

import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration shared by all environments."""

    # --- Branding / customization (Section 33) --------------------------------
    APP_NAME = os.environ.get("APP_NAME", "IETDS")
    APP_FULL_NAME = os.environ.get(
        "APP_FULL_NAME", "Integrated Email Threat Detection System"
    )
    APP_TAGLINE = os.environ.get(
        "APP_TAGLINE", "Protecting every mailbox from spam, scams, and email-based threats."
    )

    # --- Core Flask ------------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # --- Database ----------------------------------------------------------------
    # NOTE: Flask-SQLAlchemy resolves a *relative* sqlite:/// path against the
    # app's instance/ folder automatically (Flask-SQLAlchemy >= 3.0). The
    # absolute fallback below is used only if DATABASE_URL is unset.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'ietds.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # --- Sessions / cookies (Section 43) ----------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", "0")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", "0")

    # --- Credential encryption (Section 9) ----------------------------------------
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")

    # --- OAuth providers (Section 6) ------------------------------------------
    GMAIL_CLIENT_ID = os.environ.get("GMAIL_CLIENT_ID", "")
    GMAIL_CLIENT_SECRET = os.environ.get("GMAIL_CLIENT_SECRET", "")
    GMAIL_REDIRECT_URI = os.environ.get("GMAIL_REDIRECT_URI", "")

    MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
    MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
    MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common")
    MICROSOFT_REDIRECT_URI = os.environ.get("MICROSOFT_REDIRECT_URI", "")

    # --- Background worker (Section 4 / 37) -------------------------------------
    SCHEDULER_BACKEND = os.environ.get("SCHEDULER_BACKEND", "apscheduler")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    DEFAULT_SCAN_INTERVAL_MINUTES = int(os.environ.get("DEFAULT_SCAN_INTERVAL_MINUTES", "5"))
    SCHEDULER_API_ENABLED = False

    # --- Demo mode (Section 50) ---------------------------------------------------
    DEMO_MODE = _bool("DEMO_MODE", "1")

    # --- Misc --------------------------------------------------------------------
    TIMEZONE = os.environ.get("TIMEZONE", "Africa/Lagos")
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB upper bound on any single request

    # --- Rule-based threat scoring defaults (Section 26) --------------------------
    # These are seeded into SystemSetting on first run and can be edited from the
    # Settings UI afterwards; nothing downstream should read these constants
    # directly once the app has booted once (see services/settings_service.py).
    DEFAULT_THRESHOLDS = {
        "clean_max": 19,
        "suspicious_max": 39,
        "spam_max": 59,
        # 60+ => HIGH RISK, further split into PHISHING / SCAM / MALICIOUS_ATTACHMENT
        # by whichever detection category contributed the most score.
    }


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "testing-secret-key"
    ENCRYPTION_KEY = "6mFhg8y1p8qBqzM4z1V6z1V6z1V6z1V6z1V6z1V6z1U="  # test-only fixed key


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(name: str | None = None):
    name = name or os.environ.get("FLASK_ENV", "default")
    return CONFIG_MAP.get(name, DevelopmentConfig)
