"""Abstract transport boundary for dispatching security events.

Decouples the event pipeline and collectors from specific networking,
HTTP API, or remote telemetry ingestion implementations.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from trojan_defense.core.models.event import SecurityEvent


class BaseEventTransport(ABC):
    """Abstract interface for event transport."""

    @abstractmethod
    def send(self, event: SecurityEvent) -> bool:
        """Transmit a single security event across the transport boundary.

        Returns:
            bool: True if transmitted successfully, False otherwise.

        Raises:
            TransportError: If a fatal transport failure occurs.
        """
        pass

    @abstractmethod
    def send_batch(self, events: Sequence[SecurityEvent]) -> int:
        """Transmit a batch of security events across the transport boundary.

        Returns:
            int: The count of events successfully transmitted.

        Raises:
            TransportError: If a fatal transport failure occurs.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close transport handles and flush remaining buffers."""
        pass
