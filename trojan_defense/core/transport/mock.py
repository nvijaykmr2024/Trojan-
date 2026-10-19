"""Mock event transport for unit testing and local verification."""

from collections.abc import Sequence
import threading

from trojan_defense.core.exceptions import TransportError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.transport.base import BaseEventTransport


class MockEventTransport(BaseEventTransport):
    """In-memory recording transport for tests and dry-run verification."""

    def __init__(self, fail_next: bool = False) -> None:
        self._lock = threading.Lock()
        self.dispatched_events: list[SecurityEvent] = []
        self.fail_next = fail_next
        self.is_closed = False

    def send(self, event: SecurityEvent) -> bool:
        with self._lock:
            if self.fail_next:
                raise TransportError("Simulated transport transmission failure")
            self.dispatched_events.append(event)
            return True

    def send_batch(self, events: Sequence[SecurityEvent]) -> int:
        with self._lock:
            if self.fail_next:
                raise TransportError("Simulated transport transmission failure")
            self.dispatched_events.extend(events)
            return len(events)

    def clear(self) -> None:
        """Clear recorded events."""
        with self._lock:
            self.dispatched_events.clear()

    def close(self) -> None:
        with self._lock:
            self.is_closed = True
