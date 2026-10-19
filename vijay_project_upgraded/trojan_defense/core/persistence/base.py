"""Abstract persistence boundary for security events.

Decouples event generation from storage technologies and facilitates
swapping between durable storage (e.g. SQLite) and testing repositories.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from trojan_defense.core.models.event import SecurityEvent


@dataclass(frozen=True)
class EventQueryFilter:
    """Parameters for querying persisted security events."""
    endpoint_id: str | None = None
    event_type: str | None = None
    severity: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    limit: int = 50
    offset: int = 0


class BaseEventRepository(ABC):
    """Abstract interface for event storage, deduplication, and retrieval."""

    @abstractmethod
    def save(self, event: SecurityEvent) -> bool:
        """Persist a single security event.

        Returns:
            bool: True if newly inserted, False if event_id already exists (duplicate).

        Raises:
            PersistenceError: If the event cannot be stored due to database failure.
        """
        pass

    @abstractmethod
    def save_batch(self, events: Sequence[SecurityEvent]) -> int:
        """Persist multiple security events atomically or in batch.

        Returns:
            int: The number of new events successfully saved.

        Raises:
            PersistenceError: If batch persistence fails.
        """
        pass

    @abstractmethod
    def get_by_id(self, event_id: str) -> SecurityEvent | None:
        """Retrieve an event by its unique ID.

        Returns:
            SecurityEvent or None if not found.

        Raises:
            PersistenceError: If query execution fails.
        """
        pass

    @abstractmethod
    def exists(self, event_id: str) -> bool:
        """Check whether an event with the given ID already exists."""
        pass

    @abstractmethod
    def query(self, filter_params: EventQueryFilter | None = None) -> tuple[list[SecurityEvent], int]:
        """Query events based on filter criteria with pagination and deterministic ordering.

        Returns:
            tuple[list[SecurityEvent], int]: (matched_events_page, total_matching_count).

        Raises:
            PersistenceError: If query execution fails.
        """
        pass

    @abstractmethod
    def count(self) -> int:
        """Return the total number of stored events."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release underlying connections and resources."""
        pass
