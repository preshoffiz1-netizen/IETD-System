"""Authorization decorators (Section 11: role-based access control)."""

from __future__ import annotations

from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def owns_resource_or_admin(get_owner_org_id):
    """
    Decorator factory for IDOR protection (Section 43): `get_owner_org_id` is a
    callable that receives the same args/kwargs as the view and returns the
    organization_id of the resource being accessed. Non-admin users may only
    access resources in their own organization.
    """

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            owner_org_id = get_owner_org_id(*args, **kwargs)
            if owner_org_id is None:
                abort(404)
            if not current_user.is_admin and owner_org_id != current_user.organization_id:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
