"""Behavioral correlation finding domain models.

Defines the structure for correlated behavioral findings, evidence lineages,
and conversion to canonical SecurityEvent instances for pipeline ingestion.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import uuid
from typing import Any

from trojan_defense.core.models.context import BehaviorContext, EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity


@dataclass
class BehaviorFinding:
    """Represents a higher-order correlated security detection.

    Synthesizes multiple correlated telemetry events into an auditable behavioral finding.
    """
    finding_id: str = field(default_factory=lambda: f"beh_{uuid.uuid4().hex[:16]}")
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.HIGH
    category: str = "BEHAVIOR"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    start_time: str = ""
    end_time: str = ""
    pid: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    related_event_ids: list[str] = field(default_factory=list)
    matched_conditions: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    description: str = ""
    status: str = "DETECTED"

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehaviorFinding":
        """Construct finding from dictionary."""
        d = dict(data)
        if "severity" in d and isinstance(d["severity"], str):
            try:
                d["severity"] = Severity(d["severity"].upper())
            except ValueError:
                d["severity"] = Severity.HIGH
        return cls(**d)

    def to_security_event(
        self,
        endpoint: EndpointIdentity | str | None = None,
    ) -> SecurityEvent:
        """Convert this finding into a canonical SecurityEvent.

        Enables seamless routing through the EventPipeline and persistence
        in standard event storage repositories.
        """
        if isinstance(endpoint, EndpointIdentity):
            ep = endpoint
        elif isinstance(endpoint, str):
            ep = EndpointIdentity.resolve(
                endpoint_id_override=endpoint,
                hostname_override=endpoint,
            )
        else:
            ep = EndpointIdentity.resolve()


        behavior_ctx = BehaviorContext(
            finding_id=self.finding_id,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            category=self.category,
            start_time=self.start_time or self.timestamp,
            end_time=self.end_time or self.timestamp,
            pid=self.pid,
            process_name=self.process_name,
            executable_path=self.executable_path,
            related_event_ids=list(self.related_event_ids),
            matched_conditions=list(self.matched_conditions),
            evidence=list(self.evidence),
            confidence=self.confidence,
            description=self.description,
            status=self.status,
        )

        process_ctx = None
        if self.pid is not None or self.process_name is not None or self.executable_path is not None:
            process_ctx = ProcessContext(
                pid=self.pid,
                name=self.process_name,
                executable_path=self.executable_path,
            )

        context = EventContext(
            behavior=behavior_ctx,
            process=process_ctx,
            extra={
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "description": self.description,
                "confidence": self.confidence,
                "evidence_count": len(self.evidence),
                "related_event_count": len(self.related_event_ids),
            },
        )

        return SecurityEvent(
            event_id=self.finding_id,
            timestamp=self.timestamp,
            event_type=EventType("BEHAVIOR", "FINDING"),
            severity=self.severity if isinstance(self.severity, Severity) else Severity(str(self.severity).upper()),
            source="behavior_engine",
            endpoint=ep,
            context=context,
        )

