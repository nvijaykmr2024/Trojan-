"""Tests for the Event Pipeline, Validator, and Normalizer."""

import pytest

from trojan_defense.core.config.schema import PipelineConfig
from trojan_defense.core.exceptions import PipelineError, ValidationError
from trojan_defense.core.models.context import EventContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.core.pipeline.normalizer import EventNormalizer
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.core.pipeline.validator import EventValidator
from trojan_defense.core.transport.mock import MockEventTransport


class TestEventValidator:
    def test_valid_event_passes(self, sample_event: SecurityEvent):
        validator = EventValidator()
        validator.validate(sample_event)  # Should not raise

    def test_invalid_event_id_raises(self, sample_event: SecurityEvent):
        sample_event.event_id = "   "
        with pytest.raises(ValidationError, match="event_id' must be a non-empty string"):
            EventValidator().validate(sample_event)

    def test_unsupported_schema_version_raises(self, sample_event: SecurityEvent):
        sample_event.schema_version = "99.0.0"
        with pytest.raises(ValidationError, match="Unsupported schema version"):
            EventValidator().validate(sample_event)

    def test_invalid_timestamp_raises(self, sample_event: SecurityEvent):
        sample_event.timestamp = "invalid-date-format"
        with pytest.raises(ValidationError, match="Invalid timestamp format"):
            EventValidator().validate(sample_event)

    def test_empty_source_raises(self, sample_event: SecurityEvent):
        sample_event.source = ""
        with pytest.raises(ValidationError, match="source' must be a non-empty string"):
            EventValidator().validate(sample_event)

    def test_invalid_endpoint_raises(self, sample_event: SecurityEvent):
        bad_endpoint = EndpointIdentity(
            endpoint_id="",
            hostname="test",
            platform="Windows",
            os_version="",
            architecture="",
        )
        sample_event.endpoint = bad_endpoint
        with pytest.raises(ValidationError, match="must have a non-empty 'endpoint_id'"):
            EventValidator().validate(sample_event)


class TestEventNormalizer:
    def test_normalizer_trims_source(self, sample_endpoint: EndpointIdentity):
        event = SecurityEvent(
            event_type=EventType.from_category(EventCategory.PROCESS),
            severity=Severity.INFO,
            source="   padded_collector_source   ",
            endpoint=sample_endpoint,
        )
        normalizer = EventNormalizer()
        normalized = normalizer.normalize(event)
        assert normalized.source == "padded_collector_source"

    def test_normalizer_injects_default_endpoint_if_missing(self, sample_endpoint: EndpointIdentity):
        event = SecurityEvent(
            event_type=EventType.from_category(EventCategory.PROCESS),
            severity=Severity.INFO,
            source="test",
            endpoint=None,  # type: ignore
        )
        normalizer = EventNormalizer(default_endpoint=sample_endpoint)
        normalized = normalizer.normalize(event)
        assert normalized.endpoint == sample_endpoint


class TestEventPipeline:
    def test_pipeline_end_to_end_flow(
        self,
        test_pipeline: EventPipeline,
        sample_event: SecurityEvent,
        memory_repo: InMemoryEventRepository,
        mock_transport: MockEventTransport,
    ):
        processed = test_pipeline.process(sample_event)

        assert processed.event_id == sample_event.event_id
        assert test_pipeline.stats["events_processed"] == 1
        assert test_pipeline.stats["events_failed"] == 0

        # Verify persistence
        stored = memory_repo.get_by_id(sample_event.event_id)
        assert stored is not None
        assert stored.event_id == sample_event.event_id

        # Verify transport
        assert len(mock_transport.dispatched_events) == 1
        assert mock_transport.dispatched_events[0].event_id == sample_event.event_id

    def test_pipeline_batch_processing(
        self,
        test_pipeline: EventPipeline,
        sample_endpoint: EndpointIdentity,
        memory_repo: InMemoryEventRepository,
    ):
        events = [
            SecurityEvent(
                event_type=EventType.from_category(EventCategory.FILE),
                severity=Severity.LOW,
                source=f"batch_source_{i}",
                endpoint=sample_endpoint,
            )
            for i in range(5)
        ]

        processed = test_pipeline.process_batch(events)
        assert len(processed) == 5
        assert memory_repo.count() == 5
        assert test_pipeline.stats["events_processed"] == 5

    def test_pipeline_rejects_invalid_event(self, test_pipeline: EventPipeline, sample_endpoint: EndpointIdentity):
        bad_event = SecurityEvent(
            event_type=EventType.from_category(EventCategory.PROCESS),
            severity=Severity.INFO,
            source="",  # Empty source violates validation
            endpoint=sample_endpoint,
        )

        with pytest.raises(ValidationError):
            test_pipeline.process(bad_event)

        assert test_pipeline.stats["events_failed"] == 1

    def test_pipeline_handles_transport_failure(
        self,
        memory_repo: InMemoryEventRepository,
        sample_event: SecurityEvent,
    ):
        failing_transport = MockEventTransport(fail_next=True)
        pipeline = EventPipeline(
            repository=memory_repo,
            transport=failing_transport,
        )

        with pytest.raises(PipelineError, match="Transport failed"):
            pipeline.process(sample_event)

        assert pipeline.stats["events_failed"] == 1
