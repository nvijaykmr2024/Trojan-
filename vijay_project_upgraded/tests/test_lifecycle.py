"""Tests for the Application Lifecycle Manager and end-to-end integration."""

from pathlib import Path
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    LoggingConfig,
    PersistenceConfig,
    PipelineConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.exceptions import LifecycleError
from trojan_defense.core.lifecycle.manager import ApplicationManager, LifecycleState
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.severity import Severity


@pytest.fixture
def test_config(tmp_path: Path) -> RootConfig:
    """Fixture providing test configuration using temporary storage."""
    return RootConfig(
        app=AppConfig(environment="test", debug=True),
        logging=LoggingConfig(level="DEBUG", log_to_file=False),
        persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=str(tmp_path / "test.db")),
        transport=TransportConfig(enabled=True, driver="mock"),
        pipeline=PipelineConfig(batch_size=10, validate_events=True),
    )


class TestApplicationLifecycle:
    def test_lifecycle_clean_flow(self, test_config: RootConfig):
        manager = ApplicationManager()
        assert manager.state == LifecycleState.UNINITIALIZED
        assert not manager.is_healthy()

        # Initialize
        manager.initialize(config=test_config)
        assert manager.state == LifecycleState.INITIALIZED
        assert manager.endpoint is not None
        assert manager.pipeline is not None

        # Start
        manager.start()
        assert manager.state == LifecycleState.RUNNING
        assert manager.is_healthy()

        # Stop
        manager.stop()
        assert manager.state == LifecycleState.STOPPED
        assert not manager.is_healthy()

    def test_invalid_start_before_init_raises(self):
        manager = ApplicationManager()
        with pytest.raises(LifecycleError, match="Cannot start application from state 'UNINITIALIZED'"):
            manager.start()

    def test_double_initialize_raises(self, test_config: RootConfig):
        manager = ApplicationManager()
        manager.initialize(config=test_config)
        with pytest.raises(LifecycleError, match="Cannot initialize from state 'INITIALIZED'"):
            manager.initialize(config=test_config)

    def test_end_to_end_event_processing(self, test_config: RootConfig):
        manager = ApplicationManager()
        manager.initialize(config=test_config)
        manager.start()

        try:
            assert manager.pipeline is not None
            assert manager.endpoint is not None
            assert manager.repository is not None
            assert manager.transport is not None

            # Create and emit event
            event = SecurityEvent(
                event_type=EventType(EventCategory.PROCESS, "SPAWN"),
                severity=Severity.HIGH,
                source="e2e_test",
                endpoint=manager.endpoint,
                context=EventContext(
                    process=ProcessContext(name="svchost.exe", pid=2048)
                ),
            )

            processed = manager.pipeline.process(event)
            assert processed.event_id == event.event_id

            # Verify saved in SQLite repository
            stored = manager.repository.get_by_id(event.event_id)
            assert stored is not None
            assert stored.event_id == event.event_id
            assert stored.severity == Severity.HIGH

            # Verify pipeline stats
            assert manager.pipeline.stats["events_processed"] == 1
        finally:
            manager.stop()

        assert manager.state == LifecycleState.STOPPED
