"""Domain models and state machines for Controlled Defensive Response and Incident Management.

Provides persistent entities:
- Incident: Multi-alert grouping, investigation tracking, notes, lifecycle state machine.
- ResponseAction: Structured, human-authorized remediation action and execution lifecycle.
- AuditLogEntry: Immutable, append-only security and remediation action audit records.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import enum
import uuid
from typing import Any


class IncidentStatus(str, enum.Enum):
    """Lifecycle statuses for an Incident."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


VALID_INCIDENT_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,
    },
    IncidentStatus.CLOSED: {
        IncidentStatus.INVESTIGATING,  # Reopening an incident
    },
}


class ResponseActionType(str, enum.Enum):
    """Supported controlled defensive response action types."""
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    FILE_QUARANTINE = "FILE_QUARANTINE"
    RESTORE_FILE = "RESTORE_FILE"
    NETWORK_BLOCK = "NETWORK_BLOCK"
    UNBLOCK_NETWORK = "UNBLOCK_NETWORK"
    HOST_ISOLATION = "HOST_ISOLATION"
    RESTORE_HOST = "RESTORE_HOST"


RESPONSE_ACTION_ALIASES: dict[str, ResponseActionType] = {
    "ISOLATE_ENDPOINT": ResponseActionType.HOST_ISOLATION,
    "PROCESS_TERMINATION": ResponseActionType.PROCESS_TERMINATION,
    "FILE_QUARANTINE": ResponseActionType.FILE_QUARANTINE,
    "HOST_ISOLATION": ResponseActionType.HOST_ISOLATION,
    "QUARANTINE_FILE": ResponseActionType.FILE_QUARANTINE,
    "TERMINATE_PROCESS": ResponseActionType.PROCESS_TERMINATION,
    "BLOCK_NETWORK": ResponseActionType.NETWORK_BLOCK,
    "UNBLOCK_NETWORK": ResponseActionType.UNBLOCK_NETWORK,
    "RESTORE_FILE": ResponseActionType.RESTORE_FILE,
    "RESTORE_HOST": ResponseActionType.RESTORE_HOST,
    "NETWORK_BLOCK": ResponseActionType.NETWORK_BLOCK,
}


def normalize_response_action_type(value: ResponseActionType | str) -> ResponseActionType:
    """Normalize UI/API aliases to the canonical response action enum."""
    if isinstance(value, ResponseActionType):
        return value
    key = str(value).strip().upper()
    try:
        return RESPONSE_ACTION_ALIASES[key]
    except KeyError as exc:
        valid = ", ".join(sorted(RESPONSE_ACTION_ALIASES))
        raise ValueError(f"Invalid ResponseActionType '{value}'. Supported values: {valid}") from exc


class ActionStatus(str, enum.Enum):
    """Lifecycle statuses for a ResponseAction."""
    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    REJECTED = "REJECTED"


VALID_ACTION_TRANSITIONS: dict[ActionStatus, set[ActionStatus]] = {
    ActionStatus.REQUESTED: {
        ActionStatus.AUTHORIZED,
        ActionStatus.REJECTED,
    },
    ActionStatus.AUTHORIZED: {
        ActionStatus.EXECUTING,
        ActionStatus.REJECTED,
    },
    ActionStatus.EXECUTING: {
        ActionStatus.SUCCEEDED,
        ActionStatus.FAILED,
        ActionStatus.ROLLED_BACK,
        ActionStatus.ROLLBACK_FAILED,
    },
    ActionStatus.SUCCEEDED: {
        ActionStatus.EXECUTING,  # During rollback execution
        ActionStatus.ROLLED_BACK,
        ActionStatus.ROLLBACK_FAILED,
    },
    ActionStatus.FAILED: set(),
    ActionStatus.ROLLED_BACK: set(),
    ActionStatus.ROLLBACK_FAILED: set(),
    ActionStatus.REJECTED: set(),
}


class AuditActionType(str, enum.Enum):
    """Types of actions recorded in the immutable audit log."""
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    RESPONSE_REQUESTED = "RESPONSE_REQUESTED"
    RESPONSE_AUTHORIZED = "RESPONSE_AUTHORIZED"
    RESPONSE_REJECTED = "RESPONSE_REJECTED"
    RESPONSE_EXECUTING = "RESPONSE_EXECUTING"
    RESPONSE_SUCCEEDED = "RESPONSE_SUCCEEDED"
    RESPONSE_FAILED = "RESPONSE_FAILED"
    RESPONSE_ROLLED_BACK = "RESPONSE_ROLLED_BACK"
    RESPONSE_SAFETY_BLOCKED = "RESPONSE_SAFETY_BLOCKED"


@dataclass
class IncidentNote:
    """An analyst note attached to an incident."""
    note_id: str = field(default_factory=lambda: f"note-{uuid.uuid4().hex[:12]}")
    incident_id: str = ""
    author: str = "analyst"
    content: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentNote:
        return cls(
            note_id=data.get("note_id") or f"note-{uuid.uuid4().hex[:12]}",
            incident_id=data.get("incident_id", ""),
            author=data.get("author", "analyst"),
            content=data.get("content", ""),
            created_at=data.get("created_at") or datetime.now(timezone.utc).isoformat(),
        )


@dataclass
class Incident:
    """An incident grouping alerts, investigation notes, and response actions."""
    incident_id: str = field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    title: str = "Security Incident"
    description: str = ""
    status: IncidentStatus = IncidentStatus.OPEN
    severity: str = "HIGH"
    assigned_to: str | None = None
    alert_ids: list[str] = field(default_factory=list)
    response_action_ids: list[str] = field(default_factory=list)
    notes: list[IncidentNote] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    closed_at: str | None = None

    def can_transition_to(self, new_status: IncidentStatus | str) -> bool:
        """Check if transition to new status is valid."""
        if isinstance(new_status, str):
            try:
                new_status = IncidentStatus(new_status.upper())
            except ValueError:
                return False
        valid = VALID_INCIDENT_TRANSITIONS.get(self.status, set())
        return new_status in valid

    def transition_to(self, new_status: IncidentStatus | str) -> None:
        """Transition incident to new status with validation."""
        if isinstance(new_status, str):
            new_status = IncidentStatus(new_status.upper())
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Invalid incident transition from {self.status.value} to {new_status.value}"
            )
        self.status = new_status
        now = datetime.now(timezone.utc).isoformat()
        self.updated_at = now
        if new_status == IncidentStatus.CLOSED:
            self.closed_at = now
        elif self.closed_at and new_status != IncidentStatus.CLOSED:
            self.closed_at = None

    def add_note(self, author: str, content: str) -> IncidentNote:
        """Add an analyst investigation note to the incident."""
        note = IncidentNote(
            incident_id=self.incident_id,
            author=author,
            content=content,
        )
        self.notes.append(note)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return note

    def to_dict(self) -> dict[str, Any]:
        """Convert incident to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity,
            "assigned_to": self.assigned_to,
            "alert_ids": list(self.alert_ids),
            "response_action_ids": list(self.response_action_ids),
            "notes": [n.to_dict() for n in self.notes],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Construct incident from dictionary."""
        notes_raw = data.get("notes", [])
        notes = [IncidentNote.from_dict(n) if isinstance(n, dict) else n for n in notes_raw]
        raw_status = data.get("status", IncidentStatus.OPEN.value)
        status = IncidentStatus(raw_status.upper()) if isinstance(raw_status, str) else raw_status
        return cls(
            incident_id=data.get("incident_id") or f"inc-{uuid.uuid4().hex[:12]}",
            title=data.get("title", "Security Incident"),
            description=data.get("description", ""),
            status=status,
            severity=data.get("severity", "HIGH"),
            assigned_to=data.get("assigned_to"),
            alert_ids=list(data.get("alert_ids", [])),
            response_action_ids=list(data.get("response_action_ids", [])),
            notes=notes,
            created_at=data.get("created_at") or datetime.now(timezone.utc).isoformat(),
            updated_at=data.get("updated_at") or datetime.now(timezone.utc).isoformat(),
            closed_at=data.get("closed_at"),
        )


@dataclass
class ResponseAction:
    """A controlled defensive response action requiring explicit authorization."""
    action_id: str = field(default_factory=lambda: f"act-{uuid.uuid4().hex[:12]}")
    action_type: ResponseActionType = ResponseActionType.PROCESS_TERMINATION
    status: ActionStatus = ActionStatus.REQUESTED
    incident_id: str | None = None
    alert_id: str | None = None
    target_params: dict[str, Any] = field(default_factory=dict)
    requested_by: str = "analyst"
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    authorized_by: str | None = None
    authorized_at: str | None = None
    executed_at: str | None = None
    execution_result: dict[str, Any] | None = None
    error_message: str | None = None
    rollback_action_id: str | None = None
    rolled_back_at: str | None = None

    def can_transition_to(self, new_status: ActionStatus | str) -> bool:
        """Check if transition to new status is valid."""
        if isinstance(new_status, str):
            try:
                new_status = ActionStatus(new_status.upper())
            except ValueError:
                return False
        valid = VALID_ACTION_TRANSITIONS.get(self.status, set())
        return new_status in valid

    def transition_to(self, new_status: ActionStatus | str) -> None:
        """Transition action to new status with validation."""
        if isinstance(new_status, str):
            new_status = ActionStatus(new_status.upper())
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Invalid response action transition from {self.status.value} to {new_status.value}"
            )
        self.status = new_status

    def to_dict(self) -> dict[str, Any]:
        """Convert response action to dictionary."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "status": self.status.value,
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "target_params": dict(self.target_params),
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at,
            "executed_at": self.executed_at,
            "execution_result": dict(self.execution_result) if self.execution_result else None,
            "error_message": self.error_message,
            "rollback_action_id": self.rollback_action_id,
            "rolled_back_at": self.rolled_back_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseAction:
        """Construct response action from dictionary."""
        raw_type = data.get("action_type", ResponseActionType.PROCESS_TERMINATION.value)
        action_type = normalize_response_action_type(raw_type)
        raw_status = data.get("status", ActionStatus.REQUESTED.value)
        status = ActionStatus(raw_status) if isinstance(raw_status, str) else raw_status
        return cls(
            action_id=data.get("action_id") or f"act-{uuid.uuid4().hex[:12]}",
            action_type=action_type,
            status=status,
            incident_id=data.get("incident_id"),
            alert_id=data.get("alert_id"),
            target_params=dict(data.get("target_params", {})),
            requested_by=data.get("requested_by", "analyst"),
            requested_at=data.get("requested_at") or datetime.now(timezone.utc).isoformat(),
            authorized_by=data.get("authorized_by"),
            authorized_at=data.get("authorized_at"),
            executed_at=data.get("executed_at"),
            execution_result=data.get("execution_result"),
            error_message=data.get("error_message"),
            rollback_action_id=data.get("rollback_action_id"),
            rolled_back_at=data.get("rolled_back_at"),
        )


@dataclass
class AuditLogEntry:
    """An immutable audit log record capturing an analyst or response event."""
    audit_id: str = field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actor: str = "analyst"
    role: str = "ANALYST"
    action: AuditActionType = AuditActionType.RESPONSE_REQUESTED
    target_type: str = "response_action"
    target_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    ip_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert audit log entry to dictionary."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "role": self.role,
            "action": self.action.value if hasattr(self.action, "value") else str(self.action),
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": dict(self.details),
            "ip_address": self.ip_address,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditLogEntry:
        """Construct audit log entry from dictionary."""
        raw_action = data.get("action", AuditActionType.RESPONSE_REQUESTED.value)
        action = AuditActionType(raw_action) if isinstance(raw_action, str) else raw_action
        return cls(
            audit_id=data.get("audit_id") or f"aud-{uuid.uuid4().hex[:12]}",
            timestamp=data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            actor=data.get("actor", "analyst"),
            role=data.get("role", "ANALYST"),
            action=action,
            target_type=data.get("target_type", "response_action"),
            target_id=data.get("target_id", ""),
            details=dict(data.get("details", {})),
            ip_address=data.get("ip_address"),
        )
