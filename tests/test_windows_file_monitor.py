"""Unit tests for WindowsFileMonitor.

Tests configuration, disabled mode, root initialization, file creation, modification,
deletion, rename/move, directory creation/deletion, recursive events, debouncing,
permission handling, missing file races, event schema, and collector lifecycle.
"""

from pathlib import Path
import time
from unittest.mock import MagicMock, patch
import pytest

from trojan_defense.core.config.loader import load_config
from trojan_defense.core.config.schema import FileCollectorConfig
from trojan_defense.core.models import (
    EndpointIdentity,
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
)
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.platform.windows.file_monitor import (
    FileTelemetryEventHandler,
    WindowsFileMonitor,
    is_path_contained,
    normalize_path,
)


@pytest.fixture
def mock_pipeline() -> MagicMock:
    """Fixture providing a mock EventPipeline."""
    pipeline = MagicMock(spec=EventPipeline)
    pipeline.process.side_effect = lambda event: event
    return pipeline


@pytest.fixture
def test_endpoint() -> EndpointIdentity:
    """Fixture providing a resolved EndpointIdentity."""
    return EndpointIdentity(
        endpoint_id="test-endpoint-id",
        hostname="test-host",
        platform="Windows",
        os_version="10.0.19045",
        architecture="AMD64",
        agent_version="0.1.0",
    )


@pytest.fixture
def file_monitor(
    tmp_path: Path, mock_pipeline: MagicMock, test_endpoint: EndpointIdentity
) -> WindowsFileMonitor:
    """Fixture providing a configured WindowsFileMonitor."""
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir(parents=True, exist_ok=True)

    config = FileCollectorConfig(
        enabled=True,
        monitored_paths=[str(monitored_dir)],
        recursive=True,
        debounce_ms=100,
        collect_hashes=False,
    )
    monitor = WindowsFileMonitor(
        config=config,
        pipeline=mock_pipeline,
        endpoint=test_endpoint,
    )
    return monitor


class TestWindowsFileMonitor:
    """Test suite for WindowsFileMonitor unit behavior."""

    def test_01_configuration_loading(self) -> None:
        """Verify file monitor configuration loads with valid defaults."""
        cfg = load_config()
        assert cfg.file_collector is not None
        assert cfg.file_collector.debounce_ms == 200
        assert cfg.file_collector.recursive is True
        assert len(cfg.file_collector.monitored_paths) >= 1

    def test_02_disabled_mode(
        self, tmp_path: Path, mock_pipeline: MagicMock, test_endpoint: EndpointIdentity
    ) -> None:
        """Verify that when disabled, the collector does not run."""
        config = FileCollectorConfig(enabled=False, monitored_paths=[str(tmp_path)])
        monitor = WindowsFileMonitor(config=config, pipeline=mock_pipeline, endpoint=test_endpoint)
        assert not monitor.is_running
        assert monitor.health_check() is False
        assert mock_pipeline.process.call_count == 0

    def test_03_monitor_initialization_and_path_containment(
        self, file_monitor: WindowsFileMonitor, tmp_path: Path
    ) -> None:
        """Verify initialization and path containment helper."""
        monitored = tmp_path / "monitored"
        inside_file = monitored / "sub" / "file.txt"
        outside_file = tmp_path / "other" / "file.txt"

        assert is_path_contained(inside_file, monitored) is True
        assert is_path_contained(outside_file, monitored) is False
        assert normalize_path(inside_file) == str(inside_file.resolve())

    def test_04_file_creation_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify file creation produces canonical FILE.CREATE event."""
        test_file = tmp_path / "monitored" / "sample.txt"
        test_file.write_text("hello world", encoding="utf-8")

        event = file_monitor._process_event(
            action="CREATE",
            path=str(test_file),
            is_directory=False,
            severity=Severity.LOW,
        )

        assert event is not None
        assert event.event_type.category == EventCategory.FILE
        assert event.event_type.action in ("CREATE", "create")
        assert event.severity == Severity.LOW
        assert event.source == "windows_file_monitor"
        assert event.context.file is not None
        assert event.context.file.path == str(test_file.resolve())
        assert event.context.file.file_name == "sample.txt"
        assert event.context.file.extension == ".txt"
        assert event.context.file.is_directory is False
        assert event.context.file.size_bytes == 11
        assert mock_pipeline.process.call_count == 1

    def test_05_file_modification_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify file modification produces canonical FILE.MODIFY event."""
        test_file = tmp_path / "monitored" / "data.log"
        test_file.write_text("initial", encoding="utf-8")

        event = file_monitor._process_event(
            action="MODIFY",
            path=str(test_file),
            is_directory=False,
            severity=Severity.LOW,
        )

        assert event is not None
        assert event.event_type.action in ("MODIFY", "modify")
        assert event.severity == Severity.LOW
        assert event.context.file.file_name == "data.log"
        assert event.context.file.operation == "modify"

    def test_06_file_deletion_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify file deletion produces canonical FILE.DELETE event."""
        test_file = tmp_path / "monitored" / "deleted.txt"

        event = file_monitor._process_event(
            action="DELETE",
            path=str(test_file),
            is_directory=False,
            severity=Severity.MEDIUM,
        )

        assert event is not None
        assert event.event_type.action in ("DELETE", "delete")
        assert event.severity == Severity.MEDIUM
        assert event.context.file.file_name == "deleted.txt"
        assert event.context.file.operation == "delete"

    def test_07_directory_creation_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify directory creation produces canonical FILE.DIR_CREATE event."""
        test_dir = tmp_path / "monitored" / "new_folder"
        test_dir.mkdir()

        event = file_monitor._process_event(
            action="DIR_CREATE",
            path=str(test_dir),
            is_directory=True,
            severity=Severity.LOW,
        )

        assert event is not None
        assert event.event_type.action in ("DIR_CREATE", "dir_create")
        assert event.context.file.is_directory is True
        assert event.context.file.file_name == "new_folder"
        assert event.context.file.extension is None

    def test_08_directory_deletion_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify directory deletion produces canonical FILE.DIR_DELETE event."""
        test_dir = tmp_path / "monitored" / "removed_folder"

        event = file_monitor._process_event(
            action="DIR_DELETE",
            path=str(test_dir),
            is_directory=True,
            severity=Severity.INFO,
        )

        assert event is not None
        assert event.event_type.action in ("DIR_DELETE", "dir_delete")
        assert event.context.file.is_directory is True
        assert event.severity == Severity.INFO

    def test_09_file_rename_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify file rename produces canonical FILE.RENAME event with both paths."""
        old_file = tmp_path / "monitored" / "old_name.txt"
        new_file = tmp_path / "monitored" / "new_name.txt"
        new_file.write_text("content", encoding="utf-8")

        event = file_monitor._process_event(
            action="RENAME",
            path=str(new_file),
            previous_path=str(old_file),
            is_directory=False,
            severity=Severity.LOW,
        )

        assert event is not None
        assert event.event_type.action in ("RENAME", "rename")
        assert event.context.file.path == str(new_file.resolve())
        assert event.context.file.previous_path == str(old_file.resolve())
        assert event.context.file.file_name == "new_name.txt"

    def test_10_recursive_monitoring_event(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify events in nested subdirectories are normalized and captured."""
        nested_dir = tmp_path / "monitored" / "deeply" / "nested"
        nested_dir.mkdir(parents=True)
        nested_file = nested_dir / "nested.dat"
        nested_file.write_text("nested data", encoding="utf-8")

        event = file_monitor._process_event(
            action="CREATE",
            path=str(nested_file),
            is_directory=False,
            severity=Severity.LOW,
        )

        assert event is not None
        assert event.context.file.path == str(nested_file.resolve())
        assert event.context.file.file_name == "nested.dat"
        assert event.context.file.directory == str(nested_dir.resolve())

    def test_11_debouncing_rapid_modifications(
        self, file_monitor: WindowsFileMonitor, mock_pipeline: MagicMock, tmp_path: Path
    ) -> None:
        """Verify rapid repeated modification events are coalesced within debounce window."""
        file_monitor.config.debounce_ms = 300
        test_file = tmp_path / "monitored" / "burst.txt"
        test_file.write_text("burst", encoding="utf-8")

        # First modification event passes
        event1 = file_monitor._process_event("MODIFY", str(test_file), False, Severity.LOW)
        assert event1 is not None

        # Immediate second modification event is debounced / coalesced
        event2 = file_monitor._process_event("MODIFY", str(test_file), False, Severity.LOW)
        assert event2 is None

        # Immediate third modification event is also debounced
        event3 = file_monitor._process_event("MODIFY", str(test_file), False, Severity.LOW)
        assert event3 is None

        # Wait for debounce window to expire
        time.sleep(0.35)

        # Subsequent modification passes
        event4 = file_monitor._process_event("MODIFY", str(test_file), False, Severity.LOW)
        assert event4 is not None

    def test_12_permission_error_and_lock_resilience(
        self, file_monitor: WindowsFileMonitor, tmp_path: Path
    ) -> None:
        """Verify collector gracefully extracts metadata when file is locked or access is denied."""
        test_file = tmp_path / "monitored" / "locked.bin"

        with patch("os.path.getsize", side_effect=PermissionError("Sharing violation")):
            size, h = file_monitor._extract_file_metadata(str(test_file), False, "MODIFY")
            assert size is None
            assert h is None

        # Monitor should still successfully create an event despite the lock
        event = file_monitor._create_security_event("MODIFY", str(test_file), False, Severity.LOW)
        assert event.context.file.size_bytes is None
        assert event.context.file.file_name == "locked.bin"

    def test_13_missing_file_race_condition(
        self, file_monitor: WindowsFileMonitor, tmp_path: Path
    ) -> None:
        """Verify race condition where file is removed before inspection is handled safely."""
        vanished_path = str(tmp_path / "monitored" / "vanished.tmp")

        # File does not exist on disk
        size, h = file_monitor._extract_file_metadata(vanished_path, False, "CREATE")
        assert size is None
        assert h is None

        event = file_monitor._create_security_event("CREATE", vanished_path, False, Severity.LOW)
        assert event.context.file.file_name == "vanished.tmp"
        assert event.context.file.size_bytes is None

    def test_14_event_schema_compliance(
        self, file_monitor: WindowsFileMonitor, tmp_path: Path
    ) -> None:
        """Verify emitted events roundtrip through dict and JSON serialization."""
        test_file = tmp_path / "monitored" / "schema_test.json"
        test_file.write_text("{}", encoding="utf-8")

        event = file_monitor._create_security_event("CREATE", str(test_file), False, Severity.LOW)
        event_dict = event.to_dict()
        restored = SecurityEvent.from_dict(event_dict)

        assert restored.event_id == event.event_id
        assert restored.event_type.value == "FILE.CREATE"
        assert restored.context.file.path == str(test_file.resolve())
        assert restored.context.file.extension == ".json"

    def test_16_collector_lifecycle_and_shutdown(
        self, file_monitor: WindowsFileMonitor
    ) -> None:
        """Verify start launches watchdog observer and stop cleanly shuts down resources."""
        file_monitor.start()
        try:
            assert file_monitor.is_running
            assert file_monitor.health_check() is True
        finally:
            file_monitor.stop()

        assert not file_monitor.is_running
        assert file_monitor.health_check() is False
