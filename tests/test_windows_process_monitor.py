"""Unit tests for WindowsProcessMonitor.

Tests process snapshotting, creation detection, termination detection, PID recycling,
command-line truncation, error resiliency (AccessDenied / NoSuchProcess), and collector lifecycle.
"""

from unittest.mock import MagicMock, patch
import pytest

from trojan_defense.core.config.schema import ProcessCollectorConfig
from trojan_defense.core.models import (
    EndpointIdentity,
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
)
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.platform.windows.process_monitor import (
    ProcessSnapshot,
    WindowsProcessMonitor,
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
def process_monitor(mock_pipeline: MagicMock, test_endpoint: EndpointIdentity) -> WindowsProcessMonitor:
    """Fixture providing a configured WindowsProcessMonitor."""
    config = ProcessCollectorConfig(
        enabled=True,
        polling_interval=0.1,
        collect_command_line=True,
        max_command_line_length=100,
    )
    monitor = WindowsProcessMonitor(
        config=config,
        pipeline=mock_pipeline,
        endpoint=test_endpoint,
    )
    return monitor


class TestWindowsProcessMonitor:
    """Test suite for WindowsProcessMonitor."""

    def test_initialization_defaults(self, test_endpoint: EndpointIdentity) -> None:
        """Verify initial collector state and identity attributes."""
        monitor = WindowsProcessMonitor(endpoint=test_endpoint)
        assert monitor.name == "windows_process_monitor"
        assert monitor.category == EventCategory.PROCESS
        assert monitor.endpoint == test_endpoint
        assert not monitor.is_running
        assert monitor.health_check() is False

    def test_baseline_seeding_does_not_emit_events(
        self, process_monitor: WindowsProcessMonitor, mock_pipeline: MagicMock
    ) -> None:
        """Verify baseline scan populates active process map without firing creation events."""
        fake_snapshot = {
            (1001, 1000.0): ProcessSnapshot(
                pid=1001,
                name="svchost.exe",
                create_time=1000.0,
                exe="C:\\Windows\\System32\\svchost.exe",
                cmdline="svchost.exe -k netsvcs",
                ppid=4,
                username="NT AUTHORITY\\SYSTEM",
            ),
            (1002, 1001.0): ProcessSnapshot(
                pid=1002,
                name="explorer.exe",
                create_time=1001.0,
                exe="C:\\Windows\\explorer.exe",
                cmdline="explorer.exe",
                ppid=1001,
                username="DOMAIN\\User",
            ),
        }

        with patch.object(process_monitor, "_scan_current_processes", return_value=fake_snapshot):
            process_monitor.start()
            try:
                assert process_monitor.is_running
                assert len(process_monitor.active_processes) == 2
                assert mock_pipeline.process.call_count == 0
            finally:
                process_monitor.stop()

    def test_process_creation_detection(
        self, process_monitor: WindowsProcessMonitor, mock_pipeline: MagicMock
    ) -> None:
        """Verify new process appears in scan results in a PROCESS.CREATE SecurityEvent."""
        initial_snap = {
            (1001, 1000.0): ProcessSnapshot(
                pid=1001, name="initial.exe", create_time=1000.0
            )
        }
        process_monitor._active_processes = initial_snap.copy()
        process_monitor._is_running = True

        new_snap = initial_snap.copy()
        new_snap[(2001, 1050.0)] = ProcessSnapshot(
            pid=2001,
            name="cmd.exe",
            create_time=1050.0,
            exe="C:\\Windows\\System32\\cmd.exe",
            cmdline="cmd.exe /c whoami",
            ppid=1001,
            parent_name="initial.exe",
            username="DOMAIN\\User",
        )

        with patch.object(process_monitor, "_scan_current_processes", return_value=new_snap):
            created, terminated = process_monitor.poll_once()

        assert created == 1
        assert terminated == 0
        assert mock_pipeline.process.call_count == 1

        emitted_event: SecurityEvent = mock_pipeline.process.call_args[0][0]
        assert emitted_event.event_type == EventType.with_action(EventCategory.PROCESS, "create")
        assert emitted_event.severity == Severity.LOW
        assert emitted_event.source == "windows_process_monitor"
        assert emitted_event.context.process is not None
        assert emitted_event.context.process.pid == 2001
        assert emitted_event.context.process.name == "cmd.exe"
        assert emitted_event.context.process.exe == "C:\\Windows\\System32\\cmd.exe"
        assert emitted_event.context.process.cmdline == "cmd.exe /c whoami"
        assert emitted_event.context.process.ppid == 1001
        assert emitted_event.context.process.parent_name == "initial.exe"
        assert emitted_event.context.process.username == "DOMAIN\\User"

    def test_process_termination_detection(
        self, process_monitor: WindowsProcessMonitor, mock_pipeline: MagicMock
    ) -> None:
        """Verify process missing from subsequent scan results in a PROCESS.TERMINATE SecurityEvent."""
        process_monitor._active_processes = {
            (1001, 1000.0): ProcessSnapshot(
                pid=1001,
                name="target_proc.exe",
                create_time=1000.0,
                exe="C:\\Tools\\target_proc.exe",
                cmdline="target_proc.exe --run",
                ppid=500,
                username="DOMAIN\\User",
            )
        }
        process_monitor._is_running = True

        # Process disappears from subsequent scan
        empty_snap: dict[tuple[int, float], ProcessSnapshot] = {}

        with patch.object(process_monitor, "_scan_current_processes", return_value=empty_snap):
            created, terminated = process_monitor.poll_once()

        assert created == 0
        assert terminated == 1
        assert mock_pipeline.process.call_count == 1

        emitted_event: SecurityEvent = mock_pipeline.process.call_args[0][0]
        assert emitted_event.event_type == EventType.with_action(EventCategory.PROCESS, "terminate")
        assert emitted_event.severity == Severity.INFO
        assert emitted_event.source == "windows_process_monitor"
        assert emitted_event.context.process is not None
        assert emitted_event.context.process.pid == 1001
        assert emitted_event.context.process.name == "target_proc.exe"
        assert emitted_event.context.process.exe == "C:\\Tools\\target_proc.exe"
        assert emitted_event.context.process.terminated_at is not None

    def test_pid_reuse_handling(
        self, process_monitor: WindowsProcessMonitor, mock_pipeline: MagicMock
    ) -> None:
        """Verify PID reuse with different create_time yields termination of old and creation of new."""
        # Initial PID 5000 created at 100.0
        process_monitor._active_processes = {
            (5000, 100.0): ProcessSnapshot(pid=5000, name="old_app.exe", create_time=100.0)
        }
        process_monitor._is_running = True

        # Same PID 5000, but new create_time 200.0
        reused_snap = {
            (5000, 200.0): ProcessSnapshot(pid=5000, name="new_app.exe", create_time=200.0)
        }

        with patch.object(process_monitor, "_scan_current_processes", return_value=reused_snap):
            created, terminated = process_monitor.poll_once()

        assert created == 1
        assert terminated == 1
        assert mock_pipeline.process.call_count == 2

        events = [call[0][0] for call in mock_pipeline.process.call_args_list]
        term_event = next(e for e in events if e.event_type.action in ("terminate", "TERMINATE"))
        create_event = next(e for e in events if e.event_type.action in ("create", "CREATE"))

        assert term_event.context.process.name == "old_app.exe"
        assert create_event.context.process.name == "new_app.exe"

    def test_command_line_truncation(
        self, process_monitor: WindowsProcessMonitor, mock_pipeline: MagicMock
    ) -> None:
        """Verify excessively long command lines are safely truncated with truncation marker."""
        process_monitor.config.max_command_line_length = 50
        long_arg = "A" * 100
        cmdline = f"python.exe -c {long_arg}"
        process_monitor._active_processes = {}
        process_monitor._is_running = True

        snap = {
            (3001, 100.0): ProcessSnapshot(
                pid=3001,
                name="python.exe",
                create_time=100.0,
                cmdline=cmdline,
            )
        }

        with patch.object(process_monitor, "_scan_current_processes", return_value=snap):
            process_monitor.poll_once()

        emitted: SecurityEvent = mock_pipeline.process.call_args[0][0]
        assert emitted.context.process.cmdline.endswith("... [TRUNCATED]")
        assert len(emitted.context.process.cmdline) <= 50 + len("... [TRUNCATED]")

    def test_error_resiliency_psutil_exceptions(
        self, process_monitor: WindowsProcessMonitor
    ) -> None:
        """Verify collector safely handles psutil exceptions without crashing."""
        import psutil

        class MockProc:
            def __init__(self, pid: int, raise_type: str = "none") -> None:
                self.pid = pid
                self._raise_type = raise_type

            def create_time(self) -> float:
                if self._raise_type == "no_such_process":
                    raise psutil.NoSuchProcess(self.pid)
                if self._raise_type == "access_denied":
                    raise psutil.AccessDenied(self.pid)
                if self._raise_type == "zombie":
                    raise psutil.ZombieProcess(self.pid)
                return 1000.0 + self.pid

            def name(self) -> str:
                return f"proc_{self.pid}.exe"

            def ppid(self) -> int:
                return 1

            def exe(self) -> str:
                return f"C:\\proc_{self.pid}.exe"

            def cmdline(self) -> list[str]:
                return [f"proc_{self.pid}.exe"]

            def username(self) -> str:
                return "SYSTEM"

        mock_procs = [
            MockProc(1, raise_type="none"),
            MockProc(2, raise_type="no_such_process"),
            MockProc(3, raise_type="access_denied"),
            MockProc(4, raise_type="zombie"),
        ]

        with patch("psutil.process_iter", return_value=mock_procs):
            result = process_monitor._scan_current_processes()

        # Should successfully extract proc 1, gracefully handle 2 (skipped),
        # 3 (captured with fallback attributes despite AccessDenied), and 4 (skipped)
        assert (1, 1001.0) in result
        assert (3, 0.0) in result
        assert result[(3, 0.0)].name == "unknown"

    def test_background_thread_start_and_stop(
        self, process_monitor: WindowsProcessMonitor
    ) -> None:
        """Verify start creates running background polling thread and stop cleanly shuts it down."""
        with patch.object(process_monitor, "_scan_current_processes", return_value={}):
            process_monitor.start()
            assert process_monitor.is_running
            assert process_monitor.health_check() is True

            process_monitor.stop()
            assert not process_monitor.is_running
            assert process_monitor.health_check() is False
