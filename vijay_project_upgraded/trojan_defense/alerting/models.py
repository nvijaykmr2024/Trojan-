"""Domain models and lifecycle definitions for Phase 10 Alerting and Risk Scoring.

Defines the first-class Alert entity, state lifecycle transitions,
structured scoring reasons, and serialization helpers.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.core.exceptions import ValidationError
from trojan_defense.core.models.severity import Severity


class AlertStatus(str, Enum):
    """Lifecycle states for security alerts."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"

    @classmethod
    def from_string(cls, val: str) -> "AlertStatus":
        """Convert string to canonical AlertStatus enum."""
        v = val.strip().upper()
        try:
            return cls(v)
        except ValueError as exc:
            valid = [s.value for s in cls]
            raise ValidationError(
                f"Invalid alert status '{val}'. Must be one of: {valid}"
            ) from exc


# Permitted lifecycle state transitions
VALID_STATUS_TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.OPEN: {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED, AlertStatus.OPEN},
    AlertStatus.RESOLVED: {AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED},
}


@dataclass(frozen=True)
class ScoringReason:
    """Individual factor contributing to a calculated risk score."""
    factor: str
    contribution: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class RiskScore:
    """Calculated bounded risk score with assigned severity and explanation breakdown."""
    score: int
    severity: Severity
    reasons: list[ScoringReason] = field(default_factory=list)
    raw_calculated_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "score": self.score,
            "severity": self.severity.to_name(),
            "raw_calculated_score": self.raw_calculated_score,
            "reasons": [r.to_dict() for r in self.reasons],
        }


@dataclass
class Alert:
    """First-class persistent security alert entity.

    Represents an actionable alert generated from scored behavioral findings,
    maintaining full evidence lineage back to raw telemetry.
    """
    alert_id: str = field(default_factory=lambda: f"alt_{uuid.uuid4().hex[:16]}")
    title: str = "High-priority behavioral detection"
    severity: Severity = Severity.HIGH
    risk_score: int = 0
    status: AlertStatus = AlertStatus.OPEN
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    first_seen: str = ""
    last_seen: str = ""
    occurrence_count: int = 1
    endpoint_id: str = ""
    finding_id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    pid: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    username: str | None = None
    deception_id: str | None = None
    description: str = ""
    scoring_reasons: list[dict[str, Any]] = field(default_factory=list)
    related_event_ids: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = self.created_at
        if not self.last_seen:
            self.last_seen = self.created_at
        if isinstance(self.status, str):
            self.status = AlertStatus.from_string(self.status)
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)

    def to_dict(self) -> dict[str, Any]:
        """Serialize alert to a JSON-compatible dictionary."""
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity.to_name(),
            "risk_score": self.risk_score,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrence_count": self.occurrence_count,
            "endpoint_id": self.endpoint_id,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "pid": self.pid,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "username": self.username,
            "deception_id": self.deception_id,
            "description": self.description,
            "scoring_reasons": self.scoring_reasons,
            "related_event_ids": list(self.related_event_ids),
            "evidence": list(self.evidence),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """Construct an Alert from dictionary representation."""
        d = dict(data)
        if "status" in d and isinstance(d["status"], str):
            d["status"] = AlertStatus.from_string(d["status"])
        if "severity" in d and isinstance(d["severity"], str):
            d["severity"] = Severity.from_string(d["severity"])
        return cls(**d)

    def update_status(
        self,
        new_status: AlertStatus | str,
        comment: str | None = None,
    ) -> None:
        """Execute a validated lifecycle state transition."""
        target = AlertStatus.from_string(new_status) if isinstance(new_status, str) else new_status

        if target == self.status:
            return  # No-op

        permitted = VALID_STATUS_TRANSITIONS.get(self.status, set())
        if target not in permitted:
            raise ValidationError(
                f"Invalid lifecycle transition from '{self.status.value}' to '{target.value}'. "
                f"Permitted targets: {[s.value for s in permitted]}"
            )

        now_utc = datetime.now(timezone.utc).isoformat()
        self.status = target
        self.updated_at = now_utc

        if comment:
            history = self.extra.setdefault("status_history", [])
            history.append({
                "from_status": self.status.value,
                "to_status": target.value,
                "timestamp": now_utc,
                "comment": comment,
            })

    def acknowledge(self, comment: str | None = None) -> None:
        """Transition alert status to ACKNOWLEDGED."""
        self.update_status(AlertStatus.ACKNOWLEDGED, comment=comment)

    def resolve(self, comment: str | None = None) -> None:
        """Transition alert status to RESOLVED."""
        self.update_status(AlertStatus.RESOLVED, comment=comment)

    def reopen(self, comment: str | None = None) -> None:
        """Reopen an alert back to OPEN state."""
        self.update_status(AlertStatus.OPEN, comment=comment)

    def record_occurrence(
        self,
        finding: BehaviorFinding,
        event_timestamp: str | None = None,
    ) -> None:
        """Safely record a repeated occurrence without runaway score inflation."""
        self.occurrence_count += 1
        now_utc = datetime.now(timezone.utc).isoformat()
        self.last_seen = event_timestamp or finding.end_time or now_utc
        self.updated_at = now_utc

        # Append newly observed related event IDs without duplicates
        for eid in finding.related_event_ids:
            if eid not in self.related_event_ids:
                self.related_event_ids.append(eid)
