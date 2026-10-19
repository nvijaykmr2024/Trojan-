"""In-memory event repository implementation.

Ideal for unit testing, development sandboxes, and ephemeral executions.
Includes query filtering, pagination, and deterministic deduplication.
"""

from collections.abc import Sequence
import threading

from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.persistence.base import BaseEventRepository, EventQueryFilter


class InMemoryEventRepository(BaseEventRepository):
    """Stores security events in memory with thread-safe access and querying."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, SecurityEvent] = {}
        self._is_closed = False

    def save(self, event: SecurityEvent) -> bool:
        """Persist a single event.

        Returns True if newly added, False if duplicate.
        """
        with self._lock:
            if event.event_id in self._events:
                return False
            self._events[event.event_id] = event
            return True

    def save_batch(self, events: Sequence[SecurityEvent]) -> int:
        """Persist multiple events.

        Returns count of newly saved events.
        """
        with self._lock:
            count = 0
            for event in events:
                if event.event_id not in self._events:
                    self._events[event.event_id] = event
                    count += 1
            return count

    def get_by_id(self, event_id: str) -> SecurityEvent | None:
        with self._lock:
            return self._events.get(event_id)

    def exists(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._events

    def query(self, filter_params: EventQueryFilter | None = None) -> tuple[list[SecurityEvent], int]:
        params = filter_params or EventQueryFilter()
        with self._lock:
            matched: list[SecurityEvent] = []
            for ev in self._events.values():
                if params.endpoint_id and ev.endpoint.endpoint_id != params.endpoint_id:
                    continue
                if params.event_type:
                    query_type = params.event_type.strip().upper()
                    if ev.event_type.value != query_type and ev.event_type.category.value != query_type:
                        continue
                if params.severity:
                    query_sev = params.severity.strip().upper()
                    if ev.severity.to_name() != query_sev:
                        continue
                if params.start_time and ev.timestamp < params.start_time:
                    continue
                if params.end_time and ev.timestamp > params.end_time:
                    continue
                matched.append(ev)

            # Deterministic sorting: timestamp descending, event_id ascending
            matched.sort(key=lambda e: e.event_id)
            matched.sort(key=lambda e: e.timestamp, reverse=True)

            total = len(matched)
            start = max(0, params.offset)
            end = start + max(1, params.limit)
            return matched[start:end], total

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        """Clear all stored events (testing helper)."""
        with self._lock:
            self._events.clear()

    def close(self) -> None:
        with self._lock:
            self._is_closed = True
