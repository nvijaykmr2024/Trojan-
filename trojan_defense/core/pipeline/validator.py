"""Event validation rules for security telemetry.

Ensures every SecurityEvent adheres to mandatory schema constraints,
valid categories, non-empty identifiers, and parseable timestamps.
"""

from datetime import datetime
import re

from trojan_defense.core.exceptions import ValidationError
from trojan_defense.core.models.event import SCHEMA_VERSION, SecurityEvent
from trojan_defense.core.models.event_type import EventCategory


class EventValidator:
    """Validates structural integrity and correctness of SecurityEvents."""

    def __init__(self, allowed_versions: set[str] | None = None) -> None:
        self.allowed_versions = allowed_versions or {SCHEMA_VERSION}

    def validate(self, event: SecurityEvent) -> None:
        """Validate a SecurityEvent instance.

        Raises:
            ValidationError: If any field fails schema, format, or semantic constraints.
        """
        if not isinstance(event, SecurityEvent):
            raise ValidationError(f"Expected SecurityEvent instance, got '{type(event).__name__}'")

        # Event ID validation
        if not event.event_id or not isinstance(event.event_id, str) or not event.event_id.strip():
            raise ValidationError("SecurityEvent 'event_id' must be a non-empty string")

        # Schema version validation
        if event.schema_version not in self.allowed_versions:
            raise ValidationError(
                f"Unsupported schema version '{event.schema_version}'. Allowed: {sorted(self.allowed_versions)}"
            )

        # Timestamp validation
        if not event.timestamp or not isinstance(event.timestamp, str):
            raise ValidationError("SecurityEvent 'timestamp' must be a non-empty ISO 8601 string")
        try:
            # Parse ISO 8601 string
            datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"Invalid timestamp format '{event.timestamp}': {exc}") from exc

        # Event Type validation
        if not event.event_type:
            raise ValidationError("SecurityEvent 'event_type' cannot be None")
        if event.event_type.category not in EventCategory:
            raise ValidationError(f"Invalid event category '{event.event_type.category}'")

        # Severity validation
        if event.severity is None:
            raise ValidationError("SecurityEvent 'severity' cannot be None")

        # Source validation
        if not event.source or not isinstance(event.source, str) or not event.source.strip():
            raise ValidationError("SecurityEvent 'source' must be a non-empty string")

        # Endpoint identity validation
        if not event.endpoint:
            raise ValidationError("SecurityEvent 'endpoint' cannot be None")
        if not event.endpoint.endpoint_id or not event.endpoint.endpoint_id.strip():
            raise ValidationError("Endpoint identity must have a non-empty 'endpoint_id'")
        if not event.endpoint.hostname or not event.endpoint.hostname.strip():
            raise ValidationError("Endpoint identity must have a non-empty 'hostname'")
        if not event.endpoint.platform or not event.endpoint.platform.strip():
            raise ValidationError("Endpoint identity must have a non-empty 'platform'")
