"""Event normalization component for security telemetry.

Standardizes timestamp representation, trims string whitespace, and fills
missing default endpoint details if an endpoint context is supplied.
"""

from datetime import datetime, timezone

from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.identity import EndpointIdentity


class EventNormalizer:
    """Normalizes event fields into a canonical standard representation."""

    def __init__(self, default_endpoint: EndpointIdentity | None = None) -> None:
        self.default_endpoint = default_endpoint

    def normalize(self, event: SecurityEvent) -> SecurityEvent:
        """Normalize event fields.

        Modifies the event in place (or returns updated event) ensuring:
        - Timestamps conform to standard UTC ISO 8601
        - Leading/trailing whitespace in strings is stripped
        - Endpoint identity is populated if absent
        """
        # Trim source
        if event.source:
            event.source = event.source.strip()

        # Fill default endpoint if missing
        if not event.endpoint and self.default_endpoint:
            event.endpoint = self.default_endpoint

        # Ensure normalized ISO timestamp
        if event.timestamp:
            try:
                # Standardize to ISO format with UTC timezone
                clean_ts = event.timestamp.replace("Z", "+00:00")
                parsed_dt = datetime.fromisoformat(clean_ts)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                event.timestamp = parsed_dt.astimezone(timezone.utc).isoformat()
            except (ValueError, TypeError):
                # Let validator report format errors
                pass

        return event
