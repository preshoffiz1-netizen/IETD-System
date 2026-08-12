"""In-app notifications (Sections 28/34). Email/SMS delivery is documented as future work."""

from __future__ import annotations

from app.extensions import db
from app.models import Notification, NotificationLevel


def notify(user_id: str, title: str, message: str, level: str = NotificationLevel.INFO,
           link: str | None = None) -> Notification:
    notification = Notification(user_id=user_id, title=title, message=message, level=level, link=link)
    db.session.add(notification)
    db.session.commit()
    return notification


def unread_count(user_id: str) -> int:
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def mark_read(notification_id: str, user_id: str) -> bool:
    notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
    if not notification:
        return False
    notification.is_read = True
    db.session.commit()
    return True
