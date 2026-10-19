"""Tests for the Persistence layer (InMemory and SQLite)."""

from pathlib import Path
import pytest

from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository


class TestInMemoryRepository:
    def test_save_and_retrieve(self, sample_event: SecurityEvent):
        repo = InMemoryEventRepository()
        assert repo.count() == 0

        repo.save(sample_event)
        assert repo.count() == 1

        retrieved = repo.get_by_id(sample_event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == sample_event.event_id

    def test_save_batch(self, sample_endpoint: EndpointIdentity):
        repo = InMemoryEventRepository()
        events = [
            SecurityEvent(
                event_type=EventType.from_category(EventCategory.NETWORK),
                severity=Severity.LOW,
                source="net",
                endpoint=sample_endpoint,
            )
            for _ in range(4)
        ]
        saved_count = repo.save_batch(events)
        assert saved_count == 4
        assert repo.count() == 4


class TestSQLiteRepository:
    def test_sqlite_in_memory_mode(self, sample_event: SecurityEvent):
        repo = SQLiteEventRepository(db_path=":memory:")
        assert repo.count() == 0

        repo.save(sample_event)
        assert repo.count() == 1

        retrieved = repo.get_by_id(sample_event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == sample_event.event_id
        assert retrieved.severity == sample_event.severity
        assert retrieved.source == sample_event.source
        repo.close()

    def test_sqlite_file_storage(self, tmp_path: Path, sample_event: SecurityEvent):
        db_file = tmp_path / "test_sec.db"
        repo = SQLiteEventRepository(db_path=db_file)

        repo.save(sample_event)
        assert repo.count() == 1
        repo.close()

        # Reopen same database file and verify persistence
        repo2 = SQLiteEventRepository(db_path=db_file)
        retrieved = repo2.get_by_id(sample_event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == sample_event.event_id
        assert repo2.count() == 1
        repo2.close()

    def test_sqlite_batch_insert(self, tmp_path: Path, sample_endpoint: EndpointIdentity):
        db_file = tmp_path / "test_batch.db"
        repo = SQLiteEventRepository(db_path=db_file)

        events = [
            SecurityEvent(
                event_type=EventType.from_category(EventCategory.FILE),
                severity=Severity.HIGH,
                source=f"source_{i}",
                endpoint=sample_endpoint,
            )
            for i in range(10)
        ]

        inserted = repo.save_batch(events)
        assert inserted == 10
        assert repo.count() == 10
        repo.close()

    def test_get_non_existent_event_returns_none(self):
        repo = SQLiteEventRepository(db_path=":memory:")
        assert repo.get_by_id("non-existent-id") is None
        repo.close()

    def test_sqlite_deduplication(self, sample_event: SecurityEvent):
        repo = SQLiteEventRepository(db_path=":memory:")
        # First save succeeds
        assert repo.save(sample_event) is True
        assert repo.count() == 1
        assert repo.exists(sample_event.event_id) is True

        # Second save returns False (duplicate) without creating new entry
        assert repo.save(sample_event) is False
        assert repo.count() == 1
        repo.close()

    def test_sqlite_query_filtering_and_pagination(
        self, sample_endpoint: EndpointIdentity
    ):
        from trojan_defense.core.persistence.base import EventQueryFilter

        repo = SQLiteEventRepository(db_path=":memory:")
        for i in range(12):
            sev = Severity.HIGH if i % 2 == 0 else Severity.LOW
            ev = SecurityEvent(
                event_id=f"sql-filter-{i:02d}",
                event_type=EventType(EventCategory.PROCESS, "SPAWN"),
                severity=sev,
                source="test_src",
                endpoint=sample_endpoint,
                timestamp=f"2026-10-01T12:{i:02d}:00+00:00",
            )
            repo.save(ev)

        # Total count
        assert repo.count() == 12

        # Filter by severity HIGH (should be 6) with pagination limit=4
        events, total = repo.query(EventQueryFilter(severity="HIGH", limit=4, offset=0))
        assert total == 6
        assert len(events) == 4
        assert all(e.severity == Severity.HIGH for e in events)

        # Pagination next page: offset=4
        next_page, total2 = repo.query(EventQueryFilter(severity="HIGH", limit=4, offset=4))
        assert total2 == 6
        assert len(next_page) == 2

        # Check deterministic ordering: timestamp descending
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

        repo.close()
