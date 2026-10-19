"""Tests for the Collector abstraction and Registry."""

import pytest

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.collectors.registry import CollectorRegistry
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline


class DummyCollector(BaseCollector):
    """Test implementation of BaseCollector."""

    def __init__(
        self,
        name: str = "dummy",
        category: EventCategory = EventCategory.PROCESS,
        should_fail: bool = False,
    ) -> None:
        super().__init__(name=name, category=category)
        self.should_fail = should_fail

    def start(self) -> None:
        if self.should_fail:
            self._status = CollectorStatus.ERROR
            raise RuntimeError("Dummy collector startup failure")
        self._status = CollectorStatus.RUNNING

    def stop(self) -> None:
        self._status = CollectorStatus.STOPPED


class TestCollectorAbstraction:
    def test_collector_lifecycle_transitions(self):
        collector = DummyCollector(name="test_col")
        assert collector.status == CollectorStatus.UNINITIALIZED
        assert not collector.health_check()

        collector.start()
        assert collector.status == CollectorStatus.RUNNING
        assert collector.health_check()

        collector.stop()
        assert collector.status == CollectorStatus.STOPPED
        assert not collector.health_check()

    def test_collector_emit_event(self, test_pipeline: EventPipeline, sample_endpoint: EndpointIdentity):
        collector = DummyCollector(name="emitting_col")
        collector.set_pipeline(test_pipeline)
        collector.set_endpoint(sample_endpoint)

        event = SecurityEvent(
            event_type=EventType.from_category(EventCategory.PROCESS),
            severity=Severity.INFO,
            source=collector.name,
            endpoint=sample_endpoint,
        )

        emitted = collector.emit(event)
        assert emitted.event_id == event.event_id
        assert test_pipeline.stats["events_processed"] == 1

    def test_emit_without_pipeline_raises(self, sample_event: SecurityEvent):
        collector = DummyCollector(name="orphan_col")
        with pytest.raises(CollectorError, match="has no active event pipeline"):
            collector.emit(sample_event)


class TestCollectorRegistry:
    def test_register_and_lookup(self):
        registry = CollectorRegistry()
        col1 = DummyCollector(name="col1")
        registry.register(col1)

        assert registry.get("col1") is col1
        assert len(registry.list_collectors()) == 1

    def test_duplicate_registration_raises(self):
        registry = CollectorRegistry()
        col1 = DummyCollector(name="col_dup")
        col2 = DummyCollector(name="col_dup")

        registry.register(col1)
        with pytest.raises(CollectorError, match="already registered"):
            registry.register(col2)

    def test_start_and_stop_all(self):
        registry = CollectorRegistry()
        col1 = DummyCollector(name="col_1")
        col2 = DummyCollector(name="col_2")
        registry.register(col1)
        registry.register(col2)

        start_results = registry.start_all()
        assert start_results == {"col_1": True, "col_2": True}
        assert col1.status == CollectorStatus.RUNNING
        assert col2.status == CollectorStatus.RUNNING

        stop_results = registry.stop_all()
        assert stop_results == {"col_1": True, "col_2": True}
        assert col1.status == CollectorStatus.STOPPED
        assert col2.status == CollectorStatus.STOPPED

    def test_fault_isolation_during_startup(self):
        registry = CollectorRegistry()
        healthy = DummyCollector(name="healthy", should_fail=False)
        failing = DummyCollector(name="failing", should_fail=True)

        registry.register(healthy)
        registry.register(failing)

        # Without fail_fast, one failure should not stop the other
        results = registry.start_all(fail_fast=False)
        assert results["healthy"] is True
        assert results["failing"] is False
        assert healthy.status == CollectorStatus.RUNNING
        assert failing.status == CollectorStatus.ERROR
