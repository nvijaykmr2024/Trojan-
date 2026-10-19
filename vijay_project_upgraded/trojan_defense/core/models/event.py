"""Canonical SecurityEvent model for the Trojan Defense monitoring framework.

Serves as the single authoritative data structure produced by telemetry collectors,
processed by the pipeline, and persisted or transmitted across boundaries.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any
import uuid

from trojan_defense.core.models.context import EventContext
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity

SCHEMA_VERSION: str = "1.0.0"


def current_utc_timestamp() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityEvent:
    """Canonical security event model."""
    event_type: EventType
    severity: Severity
    source: str
    endpoint: EndpointIdentity
    context: EventContext = field(default_factory=EventContext)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=current_utc_timestamp)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Convert security event to dictionary format."""
        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "severity": self.severity.to_name(),
            "source": self.source,
            "endpoint": self.endpoint.to_dict(),
            "context": self.context.to_dict(),
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialize event to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Reconstruct a SecurityEvent from a dictionary.

        Raises:
            KeyError: If a required field is missing.
            ValueError: If a field value cannot be parsed or validated.
        """
        required_fields = ["event_type", "severity", "source", "endpoint"]
        for field_name in required_fields:
            if field_name not in data:
                raise KeyError(f"Missing required field in security event: '{field_name}'")

        # Parse event type
        raw_type = data["event_type"]
        event_type = EventType.from_string(raw_type) if isinstance(raw_type, str) else raw_type

        # Parse severity
        raw_sev = data["severity"]
        severity = Severity.from_string(raw_sev) if isinstance(raw_sev, str) else Severity(raw_sev)

        # Parse endpoint
        endpoint_data = data["endpoint"]
        endpoint = (
            EndpointIdentity.from_dict(endpoint_data)
            if isinstance(endpoint_data, dict)
            else endpoint_data
        )

        # Parse context
        context_data = data.get("context")
        context = (
            EventContext.from_dict(context_data)
            if isinstance(context_data, dict)
            else (context_data or EventContext())
        )

        return cls(
            event_id=data.get("event_id") or str(uuid.uuid4()),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            timestamp=data.get("timestamp") or current_utc_timestamp(),
            event_type=event_type,
            severity=severity,
            source=str(data["source"]),
            endpoint=endpoint,
            context=context,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SecurityEvent":
        """Deserialize a SecurityEvent from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
