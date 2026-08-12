"""
Flask extension instances.

Kept in a dedicated module (rather than inside __init__.py) so that models,
services, and routes can import ``db``, ``login_manager`` etc. without
triggering circular imports with the application factory.
"""

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address)
    HAS_LIMITER = True
except ImportError:  # pragma: no cover - optional dependency
    limiter = None
    HAS_LIMITER = False

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
