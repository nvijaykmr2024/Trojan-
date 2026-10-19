"""Role-Based Access Control (RBAC) and User Authentication Context for Response and Incident Management.

Enforces clear role boundaries across:
- READ_SECURITY_DATA: View alerts, telemetry, incidents, actions, and audit trail.
- MANAGE_ALERT: Update alert statuses (TRIAGED, RESOLVED, DISMISSED, etc.).
- MANAGE_INCIDENT: Create and update incidents, add investigation notes, change incident status.
- REQUEST_RESPONSE: Create/request defensive response actions.
- AUTHORIZE_RESPONSE: Explicit senior authorization of requested defensive response actions.
- EXECUTE_RESPONSE: Trigger execution and rollback of authorized defensive response actions.
"""

from __future__ import annotations

from dataclasses import dataclass
import enum
from typing import Any

from trojan_defense.core.exceptions import TrojanDefenseError


class AuthorizationError(TrojanDefenseError):
    """Raised when an operation is rejected due to insufficient privileges or invalid role."""
    pass


class Role(str, enum.Enum):
    """Supported analyst and operator roles."""
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    RESPONDER = "RESPONDER"
    ADMIN = "ADMIN"


class Permission(str, enum.Enum):
    """Atomic permissions governed by the defensive framework."""
    READ_SECURITY_DATA = "READ_SECURITY_DATA"
    MANAGE_ALERT = "MANAGE_ALERT"
    MANAGE_INCIDENT = "MANAGE_INCIDENT"
    REQUEST_RESPONSE = "REQUEST_RESPONSE"
    AUTHORIZE_RESPONSE = "AUTHORIZE_RESPONSE"
    EXECUTE_RESPONSE = "EXECUTE_RESPONSE"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.READ_SECURITY_DATA,
    },
    Role.ANALYST: {
        Permission.READ_SECURITY_DATA,
        Permission.MANAGE_ALERT,
        Permission.MANAGE_INCIDENT,
        Permission.REQUEST_RESPONSE,
    },
    Role.RESPONDER: {
        Permission.READ_SECURITY_DATA,
        Permission.MANAGE_ALERT,
        Permission.MANAGE_INCIDENT,
        Permission.REQUEST_RESPONSE,
        Permission.AUTHORIZE_RESPONSE,
        Permission.EXECUTE_RESPONSE,
    },
    Role.ADMIN: {
        Permission.READ_SECURITY_DATA,
        Permission.MANAGE_ALERT,
        Permission.MANAGE_INCIDENT,
        Permission.REQUEST_RESPONSE,
        Permission.AUTHORIZE_RESPONSE,
        Permission.EXECUTE_RESPONSE,
    },
}


@dataclass
class UserContext:
    """Security context representing the calling operator or API client."""
    username: str
    role: Role
    token: str | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if user's role grants the requested permission."""
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return permission in perms

    def require_permission(self, permission: Permission) -> None:
        """Verify permission or raise AuthorizationError."""
        if not self.has_permission(permission):
            raise AuthorizationError(
                f"User '{self.username}' with role '{self.role.value}' lacks required permission '{permission.value}'"
            )


def resolve_user_context(
    token: str | None = None,
    role_header: str | None = None,
    actor_header: str | None = None,
    configured_tokens: dict[str, str] | None = None,
    default_role: Role = Role.ADMIN,
) -> UserContext:
    """Resolve caller's UserContext from auth tokens, role headers, or defaults.
    
    Order of evaluation:
    1. Exact token match in configured_tokens.
    2. Explicit role header (if provided and valid).
    3. Default role (fallback for development/standalone mode).
    """
    configured_tokens = configured_tokens or {}

    # 1. Bearer / API token lookup
    if token:
        # Strip "Bearer " prefix if provided
        clean_token = token.replace("Bearer ", "").strip()
        if clean_token in configured_tokens:
            role_str = configured_tokens[clean_token].upper()
            try:
                role = Role(role_str)
                actor = actor_header or f"user-{clean_token[:8]}"
                return UserContext(username=actor, role=role, token=clean_token)
            except ValueError:
                pass

    # 2. Explicit role header check
    if role_header:
        role_str = role_header.strip().upper()
        try:
            role = Role(role_str)
            actor = actor_header or f"analyst-{role_str.lower()}"
            return UserContext(username=actor, role=role, token=token)
        except ValueError:
            raise AuthorizationError(f"Invalid role header '{role_header}'")

    # 3. Default fallback context
    actor = actor_header or "local-analyst"
    return UserContext(username=actor, role=default_role, token=token)
