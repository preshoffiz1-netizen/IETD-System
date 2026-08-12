from __future__ import annotations

from app.extensions import db
from app.models.base import TimestampMixin, gen_uuid


class Organization(db.Model, TimestampMixin):
    """
    A tenant boundary. Every user, mailbox, rule, and email ultimately belongs
    to exactly one organization, which makes the platform multi-organization
    ready (Section 11) even though the default single-user deployment simply
    creates one organization per registrant.
    """

    __tablename__ = "organizations"

    id = db.Column(db.String(32), primary_key=True, default=gen_uuid)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    users = db.relationship("User", back_populates="organization", cascade="all, delete-orphan")
    mailboxes = db.relationship("Mailbox", back_populates="organization", cascade="all, delete-orphan")
    rules = db.relationship("DetectionRule", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Organization {self.slug}>"
