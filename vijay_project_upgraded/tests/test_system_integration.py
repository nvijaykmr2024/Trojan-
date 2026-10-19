"""Integration tests for Windows System and Privilege Telemetry.

Tests the full pipeline from live Windows system monitoring (boot/startup,
session state, and process privilege contexts) through WindowsSystemMonitor,
EventPipeline, and persistence in the SQLite repository.
"""

from pathlib import Path
import time
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    CollectorToggleConfig,
    PersistenceConfig,
    RootConfig,
    SystemCollectorConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import EventCategory, Severity
from trojan_defense.core.persistence.base import EventQueryFilter


class TestSystemMonitoringIntegration:
    """Integration test suite for system & privilege telemetry collection and persistence."""

    def test_live_system_lifecycle_to_sqlite(self, tmp_path: Path) -> None:
        """Verify real Windows system telemetry flows through pipeline into SQLite."""
        db_path = str(tmp_path / "test_system_integration.db")

        config = RootConfig(
            app=AppConfig(environment="test", debug=True),
            persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=db_path),
            transport=TransportConfig(enabled=False),
            collectors=CollectorToggleConfig(system=True),
            system_collector=SystemCollectorConfig(
                enabled=True,
                polling_interval=0.1,  # Fast polling for integration test
                monitor_sessions=True,
                monitor_event_log=False,
                monitor_privileges=True,
            ),
        )

        manager = ApplicationManager()
        manager.initialize(config=config)
        assert manager.repository is not None

        manager.start()

        try:
            # Poll SQLite repository for SYSTEM.STARTUP event
            startup_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="SYSTEM.STARTUP", limit=10)
                )
                if events:
                    startup_event = events[0]
                    break
                time.sleep(0.1)

            assert startup_event is not None, "SYSTEM.STARTUP event not found in SQLite repository"
            assert startup_event.event_type.value == "SYSTEM.STARTUP"
            assert startup_event.event_type.category == EventCategory.SYSTEM
            assert startup_event.severity == Severity.INFO
            assert startup_event.source == "windows_system_monitor"
            assert startup_event.context.system is not None
            assert startup_event.context.system.boot_time is not None
            assert startup_event.endpoint.hostname != ""

            # Check that collector stats and pipeline processed count incremented
            stats = manager.pipeline.stats
            assert stats["events_processed"] >= 1
            assert stats["events_failed"] == 0

        finally:
            manager.stop()

        # Verify collector is stopped after manager stop
        collectors = manager.registry.list_collectors()
        assert len(collectors) >= 1
        assert not collectors[0].is_running
