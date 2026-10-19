"""Integration tests for Windows Process Monitoring.

Tests the full pipeline from real subprocess execution on Windows through
WindowsProcessMonitor, EventPipeline, and persistence in SQLite.
"""

import subprocess
import sys
import time
from pathlib import Path
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    CollectorToggleConfig,
    PersistenceConfig,
    ProcessCollectorConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import EventCategory, Severity
from trojan_defense.core.persistence.base import EventQueryFilter


class TestProcessMonitoringIntegration:
    """Integration test suite for process telemetry collection."""

    def test_live_process_creation_and_termination_capture(self, tmp_path: Path) -> None:
        """Spawn a benign subprocess, observe PROCESS.CREATE and PROCESS.TERMINATE events in SQLite."""
        db_path = str(tmp_path / "test_process_integration.db")

        config = RootConfig(
            app=AppConfig(environment="test", debug=True),
            persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=db_path),
            transport=TransportConfig(enabled=False),
            collectors=CollectorToggleConfig(process=True),
            process_collector=ProcessCollectorConfig(
                enabled=True,
                polling_interval=0.1,  # fast polling for test
                collect_command_line=True,
            ),
        )

        manager = ApplicationManager()
        manager.initialize(config=config)
        assert manager.repository is not None

        manager.start()
        try:
            # Baseline is seeded now.
            # Spawn a benign child python process that sleeps briefly.
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(1.0)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            target_pid = proc.pid

            # Wait for creation event to be polled and persisted
            created_event = None
            max_wait_time = 8.0
            start_time = time.time()

            while (time.time() - start_time) < max_wait_time:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="PROCESS.CREATE", limit=50)
                )
                matching = [e for e in events if e.context.process and e.context.process.pid == target_pid]
                if matching:
                    created_event = matching[0]
                    break
                time.sleep(0.1)

            assert created_event is not None, f"PROCESS.CREATE event not captured for PID {target_pid}"
            assert created_event.context.process.pid == target_pid
            assert "python" in created_event.context.process.name.lower()
            assert created_event.severity == Severity.LOW

            # Now wait for process to finish
            proc.wait(timeout=5.0)

            # Wait for termination event to be polled and persisted
            terminated_event = None
            start_time = time.time()

            while (time.time() - start_time) < max_wait_time:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="PROCESS.TERMINATE", limit=50)
                )
                matching = [e for e in events if e.context.process and e.context.process.pid == target_pid]
                if matching:
                    terminated_event = matching[0]
                    break
                time.sleep(0.1)

            assert terminated_event is not None, f"PROCESS.TERMINATE event not captured for PID {target_pid}"
            assert terminated_event.context.process.pid == target_pid
            assert "python" in terminated_event.context.process.name.lower()
            assert terminated_event.severity == Severity.INFO

        finally:
            manager.stop()
