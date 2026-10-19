"""Integration tests for Phase 9 Behavioral Correlation with Pipeline, Storage, and Lifecycle."""

from pathlib import Path
import tempfile
import pytest

from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.core.config.schema import BehaviorConfig, RootConfig
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    NetworkContext,
    ProcessContext,
)
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline


# Test 16: Pipeline and SQLite Persistence Integration
def test_pipeline_and_sqlite_persistence_integration(tmp_path: Path) -> None:
    db_file = tmp_path / "behavior_test.db"
    repository = SQLiteEventRepository(db_path=db_file)
    endpoint = EndpointIdentity.resolve(endpoint_id_override="ep-integ-01", hostname_override="host-integ")


    pipeline = EventPipeline(repository=repository)
    engine = BehaviorCorrelationEngine(
        config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0),
        pipeline=pipeline,
    )
    pipeline.set_correlation_engine(engine)

    # Ingest Process Create Event
    proc_evt = SecurityEvent(
        event_type=EventType("PROCESS", "CREATE"),
        severity=Severity.INFO,
        source="process_monitor",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(pid=9999, name="infiltrator.exe", executable_path="C:\\infiltrator.exe")
        ),
    )
    pipeline.process(proc_evt)

    # Ingest File Create Event on startup directory (triggers RULE-BEH-001)
    file_evt = SecurityEvent(
        event_type=EventType("FILE", "CREATE"),
        severity=Severity.INFO,
        source="file_monitor",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(pid=9999, name="infiltrator.exe"),
            file=FileContext(path="C:\\startup\\persist.exe", operation="create"),
        ),
    )
    pipeline.process(file_evt)

    # Verify that SQLite repository contains the raw events AND the correlated BEHAVIOR.FINDING event
    assert repository.count() >= 3

    # Query behavior finding events
    filter_behavior = EventQueryFilter(event_type="BEHAVIOR.FINDING")
    findings, total = repository.query(filter_behavior)
    assert total >= 1
    assert len(findings) >= 1

    finding_event = findings[0]
    assert finding_event.event_type.category == EventCategory.BEHAVIOR
    assert finding_event.event_type.action == "FINDING"
    assert finding_event.source == "behavior_engine"
    assert finding_event.context.behavior is not None
    assert finding_event.context.behavior.rule_id == "RULE-BEH-001"
    assert proc_evt.event_id in finding_event.context.behavior.related_event_ids
    assert file_evt.event_id in finding_event.context.behavior.related_event_ids

    repository.close()



def test_application_manager_behavior_lifecycle(tmp_path: Path) -> None:
    """Verify that ApplicationManager initializes, wires, and stops behavior engine."""
    db_file = tmp_path / "app_behavior.db"
    cfg = RootConfig()
    cfg.persistence.enabled = True
    cfg.persistence.driver = "sqlite"
    cfg.persistence.db_path = str(db_file)
    cfg.behavior.enabled = True
    cfg.behavior.correlation_window_seconds = 45.0

    manager = ApplicationManager()
    manager.initialize(config=cfg)

    assert manager.behavior_engine is not None
    assert manager.behavior_engine.is_enabled is True
    assert manager.behavior_engine.config.correlation_window_seconds == 45.0
    assert manager.pipeline.correlation_engine is manager.behavior_engine

    manager.stop()
    assert manager.behavior_engine.stats["tracked_processes"] == 0
