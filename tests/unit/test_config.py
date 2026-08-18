"""
Regression test for the `postgres://` -> `postgresql://` DATABASE_URL fixup
in app/config.py, needed because some hosts (Render, Heroku, others) still
hand out the old `postgres://` scheme, which SQLAlchemy 1.4+/2.x rejects.
"""

from __future__ import annotations

import importlib
import os


def test_postgres_scheme_is_normalized_to_postgresql(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@host:5432/dbname")
    import app.config as config_module
    importlib.reload(config_module)
    try:
        assert config_module.Config.SQLALCHEMY_DATABASE_URI == "postgresql://user:pass@host:5432/dbname"
    finally:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        importlib.reload(config_module)  # restore module state for any tests that run after this one


def test_already_postgresql_scheme_is_left_alone(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@host:5432/dbname")
    import app.config as config_module
    importlib.reload(config_module)
    try:
        assert config_module.Config.SQLALCHEMY_DATABASE_URI == "postgresql://user:pass@host:5432/dbname"
    finally:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        importlib.reload(config_module)
