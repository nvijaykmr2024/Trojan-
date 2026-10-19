"""Unit tests for the backend EventService."""

import pytest

from trojan_defense.backend.service import EventService
from trojan_defense.core.exceptions import ValidationError
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository


@pytest.fixture
def event_service(memory_repo: InMemoryEventRepository) -> EventService:
    return EventService(repository=memory_repo)


class TestEventService:
    def test_ingest_valid_security_event_object(
        self, event_service: EventService, sample_event: SecurityEvent
    ):
        event, is_new = event_service.ingest_event(sample_event)
        assert is_new is True
        assert event.event_id == sample_event.event_id
        assert event_service.count() == 1

    def test_ingest_valid_dictionary_payload(
        self, event_service: EventService, sample_event: SecurityEvent
    ):
        data = sample_event.to_dict()
        data["event_id"] = "dict-event-001"
        event, is_new = event_service.ingest_event(data)
        assert is_new is True
        assert event.event_id == "dict-event-001"
        assert event_service.count() == 1

    def test_ingest_duplicate_event_is_preserved_and_flagged(
        self, event_service: EventService, sample_event: SecurityEvent
    ):
        # First ingestion
        _, is_new_1 = event_service.ingest_event(sample_event)
        assert is_new_1 is True

        # Second ingestion with identical event_id
        _, is_new_2 = event_service.ingest_event(sample_event)
        assert is_new_2 is False
        assert event_service.count() == 1  # No duplicate record created

    def test_ingest_missing_required_fields_raises_validation_error(
        self, event_service: EventService
    ):
        bad_payload = {"event_type": "PROCESS"}  # Missing severity, endpoint, source
        with pytest.raises(ValidationError, match="Invalid event structure"):
            event_service.ingest_event(bad_payload)

    def test_ingest_invalid_event_type_raises_validation_error(
        self, event_service: EventService, sample_endpoint: EndpointIdentity
    ):
        bad_payload = {
            "event_id": "test-id",
            "schema_version": "1.0.0",
            "timestamp": "2026-10-01T12:00:00Z",
            "event_type": "NON_EXISTENT_CATEGORY.ACTION",
            "severity": "LOW",
            "source": "test",
            "endpoint": sample_endpoint.to_dict(),
        }
        with pytest.raises(ValidationError, match="Invalid event category"):
            event_service.ingest_event(bad_payload)

    def test_ingest_invalid_severity_raises_validation_error(
        self, event_service: EventService, sample_endpoint: EndpointIdentity
    ):
        bad_payload = {
            "event_id": "test-id-2",
            "schema_version": "1.0.0",
            "timestamp": "2026-10-01T12:00:00Z",
            "event_type": "PROCESS",
            "severity": "SUPER_CRITICAL",  # Invalid severity
            "source": "test",
            "endpoint": sample_endpoint.to_dict(),
        }
        with pytest.raises(ValidationError, match="Invalid severity"):
            event_service.ingest_event(bad_payload)

    def test_ingest_batch_of_events(
        self, event_service: EventService, sample_endpoint: EndpointIdentity
    ):
        events = [
            SecurityEvent(
                event_id=f"batch-ev-{i}",
                event_type=EventType(EventCategory.FILE, "MODIFY"),
                severity=Severity.MEDIUM,
                source="file_mon",
                endpoint=sample_endpoint,
            )
            for i in range(3)
        ]
        # Include one duplicate
        events.append(events[0])

        processed, new_count = event_service.ingest_batch(events)
        assert len(processed) == 4
        assert new_count == 3
        assert event_service.count() == 3

    def test_get_event_by_id(
        self, event_service: EventService, sample_event: SecurityEvent
    ):
        event_service.ingest_event(sample_event)
        retrieved = event_service.get_event(sample_event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == sample_event.event_id

        assert event_service.get_event("non_existent_id") is None
        assert event_service.get_event("   ") is None

    def test_query_events_with_filters(
        self, event_service: EventService, sample_endpoint: EndpointIdentity
    ):
        # Create events with varied categories and severities
        e1 = SecurityEvent(
            event_id="e1",
            event_type=EventType(EventCategory.PROCESS, "CREATE"),
            severity=Severity.LOW,
            source="proc",
            endpoint=sample_endpoint,
            timestamp="2026-10-01T10:00:00+00:00",
        )
        e2 = SecurityEvent(
            event_id="e2",
            event_type=EventType(EventCategory.FILE, "WRITE"),
            severity=Severity.HIGH,
            source="file",
            endpoint=sample_endpoint,
            timestamp="2026-10-01T11:00:00+00:00",
        )
        e3 = SecurityEvent(
            event_id="e3",
            event_type=EventType(EventCategory.NETWORK, "CONNECT"),
            severity=Severity.HIGH,
            source="net",
            endpoint=sample_endpoint,
            timestamp="2026-10-01T12:00:00+00:00",
        )

        event_service.ingest_batch([e1, e2, e3])

        # Filter by severity HIGH
        high_events, count = event_service.query_events(EventQueryFilter(severity="HIGH"))
        assert count == 2
        assert len(high_events) == 2
        assert {e.event_id for e in high_events} == {"e2", "e3"}

        # Filter by category FILE
        file_events, count = event_service.query_events(EventQueryFilter(event_type="FILE"))
        assert count == 1
        assert file_events[0].event_id == "e2"

        # Filter by time range
        time_events, count = event_service.query_events(
            EventQueryFilter(
                start_time="2026-10-01T10:30:00+00:00",
                end_time="2026-10-01T11:30:00+00:00",
            )
        )
        assert count == 1
        assert time_events[0].event_id == "e2"
