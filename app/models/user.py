from __future__ import annotations

from flask_login import UserMixin

from app.extensions import db, login_manager
from app.models.base import TimestampMixin, gen_uuid
from app.utils.security import hash_password, verify_password


class Role:
    ADMIN = "admin"
    USER = "user"

    ALL = (ADMIN, USER)


class User(db.Model, UserMixin, TimestampMixin):
    __tablename__ = "users"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=False)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=Role.USER, nullable=False)

    is_active_flag = db.Column("is_active", db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    organization = db.relationship("Organization", back_populates="users")
    mailboxes = db.relationship("Mailbox", back_populates="owner", cascade="all, delete-orphan")
    settings = db.relationship("UserSetting", back_populates="user", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="user", cascade="all, delete-orphan")

    # --- Flask-Login required property ---------------------------------------
    @property
    def is_active(self) -> bool:  # type: ignore[override]
        return self.is_active_flag

    # --- Password helpers -------------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        self.password_hash = hash_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return verify_password(self.password_hash, raw_password)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email}>"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, user_id)
