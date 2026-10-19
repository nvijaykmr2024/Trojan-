"""Integration tests for Windows Filesystem Monitoring.

Tests the full pipeline from real Windows filesystem activity through
watchdog WindowsApiObserver, WindowsFileMonitor, EventPipeline,
and persistence in the SQLite repository.
"""

from pathlib import Path
import time
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    CollectorToggleConfig,
    FileCollectorConfig,
    PersistenceConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import Severity
from trojan_defense.core.persistence.base import EventQueryFilter


class TestFileMonitoringIntegration:
    """Integration test suite for filesystem telemetry collection."""

    def test_live_filesystem_lifecycle_capture(self, tmp_path: Path) -> None:
        """Perform real Windows filesystem operations, verify all events in SQLite."""
        db_path = str(tmp_path / "test_file_integration.db")
        monitored_root = tmp_path / "monitored_root"
        monitored_root.mkdir(parents=True, exist_ok=True)

        config = RootConfig(
            app=AppConfig(environment="test", debug=True),
            persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=db_path),
            transport=TransportConfig(enabled=False),
            collectors=CollectorToggleConfig(file=True),
            file_collector=FileCollectorConfig(
                enabled=True,
                monitored_paths=[str(monitored_root)],
                recursive=True,
                debounce_ms=50,
                collect_hashes=False,
            ),
        )

        manager = ApplicationManager()
        manager.initialize(config=config)
        assert manager.repository is not None

        manager.start()
        try:
            # Allow observer thread to bind
            time.sleep(0.3)

            # 1. Create file
            target_file = monitored_root / "sample_doc.txt"
            target_file.write_text("Hello from Phase 4", encoding="utf-8")

            # Poll repository for FILE.CREATE
            create_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="FILE.CREATE", limit=50)
                )
                matching = [
                    e for e in events
                    if e.context.file and e.context.file.file_name == "sample_doc.txt"
                ]
                if matching:
                    create_event = matching[0]
                    break
                time.sleep(0.1)

            assert create_event is not None, "FILE.CREATE event was not captured"
            assert create_event.context.file.file_name == "sample_doc.txt"
            assert create_event.context.file.extension == ".txt"
            assert create_event.severity == Severity.LOW

            # 2. Modify file
            time.sleep(0.1)
            target_file.write_text("Modified content with more bytes", encoding="utf-8")

            modify_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="FILE.MODIFY", limit=50)
                )
                matching = [
                    e for e in events
                    if e.context.file and e.context.file.file_name == "sample_doc.txt"
                ]
                if matching:
                    modify_event = matching[0]
                    break
                time.sleep(0.1)

            assert modify_event is not None, "FILE.MODIFY event was not captured"
            assert modify_event.context.file.file_name == "sample_doc.txt"
            assert modify_event.severity == Severity.LOW

            # 3. Rename file
            time.sleep(0.1)
            renamed_file = monitored_root / "renamed_doc.txt"
            target_file.rename(renamed_file)

            rename_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="FILE.RENAME", limit=50)
                )
                matching = [
                    e for e in events
                    if e.context.file and e.context.file.file_name == "renamed_doc.txt"
                ]
                if matching:
                    rename_event = matching[0]
                    break
                time.sleep(0.1)

            assert rename_event is not None, "FILE.RENAME event was not captured"
            assert rename_event.context.file.file_name == "renamed_doc.txt"
            assert rename_event.context.file.previous_path is not None
            assert "sample_doc.txt" in rename_event.context.file.previous_path

            # 4. Delete file
            time.sleep(0.1)
            renamed_file.unlink()

            delete_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="FILE.DELETE", limit=50)
                )
                matching = [
                    e for e in events
                    if e.context.file and e.context.file.file_name == "renamed_doc.txt"
                ]
                if matching:
                    delete_event = matching[0]
                    break
                time.sleep(0.1)

            assert delete_event is not None, "FILE.DELETE event was not captured"
            assert delete_event.context.file.file_name == "renamed_doc.txt"
            assert delete_event.severity == Severity.MEDIUM

            # 5. Nested directory recursive monitoring
            time.sleep(0.1)
            sub_dir = monitored_root / "deep" / "sub"
            sub_dir.mkdir(parents=True, exist_ok=True)
            nested_file = sub_dir / "nested.dat"
            nested_file.write_text("nested data", encoding="utf-8")

            nested_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="FILE.CREATE", limit=50)
                )
                matching = [
                    e for e in events
                    if e.context.file and e.context.file.file_name == "nested.dat"
                ]
                if matching:
                    nested_event = matching[0]
                    break
                time.sleep(0.1)

            assert nested_event is not None, "Nested FILE.CREATE event was not captured"
            assert nested_event.context.file.file_name == "nested.dat"

        finally:
            manager.stop()
