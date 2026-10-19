"""Defensive response and incident management package.

Provides safe, auditable, and human-authorized remediation capabilities:
- Incident lifecycle management and analyst collaboration
- Human-in-the-loop authorization gates
- Safe OS remediation (process termination, file quarantine, network blocking)
- Reversibility and rollback controls
- Role-based access control (RBAC)
- Append-only immutable audit trail
"""

from trojan_defense.response.auth import (
    AuthorizationError,
    Permission,
    Role,
    UserContext,
    resolve_user_context,
)
from trojan_defense.response.executor import ResponseExecutionError, ResponseExecutor
from trojan_defense.response.models import (
    ActionStatus,
    AuditActionType,
    AuditLogEntry,
    Incident,
    IncidentNote,
    IncidentStatus,
    ResponseAction,
    ResponseActionType,
    VALID_ACTION_TRANSITIONS,
    VALID_INCIDENT_TRANSITIONS,
)
from trojan_defense.response.recommender import ActionRecommendation, ResponseRecommender
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)
from trojan_defense.response.safety import (
    NetworkSafetyValidator,
    PathSafetyValidator,
    ProcessSafetyValidator,
    ResponseSafetyError,
)

__all__ = [
    "ActionRecommendation",
    "ActionStatus",
    "AuditActionType",
    "AuditLogEntry",
    "AuthorizationError",
    "Incident",
    "IncidentNote",
    "IncidentStatus",
    "NetworkSafetyValidator",
    "PathSafetyValidator",
    "Permission",
    "ProcessSafetyValidator",
    "ResponseAction",
    "ResponseActionType",
    "ResponseExecutionError",
    "ResponseExecutor",
    "ResponseRecommender",
    "ResponseSafetyError",
    "Role",
    "SQLiteAuditRepository",
    "SQLiteIncidentRepository",
    "SQLiteResponseActionRepository",
    "UserContext",
    "VALID_ACTION_TRANSITIONS",
    "VALID_INCIDENT_TRANSITIONS",
    "resolve_user_context",
]
