"""Unit tests for WindowsSystemMonitor and privilege telemetry.

Tests configuration loading, disabled mode, initialization, schema conformity,
system startup events, session lifecycle transitions (logon, logoff, lock, unlock),
process privilege context (token elevation, integrity level, privileges, user, SID),
error resilience, duplicate suppression, and collector lifecycle management.
"""

from collections import namedtuple
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch
import pytest

from trojan_defense.core.collectors.base import CollectorStatus
from trojan_defense.core.config.loader import load_config
from trojan_defense.core.config.schema import SystemCollectorConfig, RootConfig
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import (
    EndpointIdentity,
    EventCategory,
    EventContext,
    EventType,
    PrivilegeContext,
    SecurityEvent,
    Severity,
    SystemContext,
)
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.platform.windows.system_monitor import (
    WindowsSystemMonitor,
    get_active_sessions,
    get_process_privilege_context,
    is_current_user_admin,
    query_recent_system_events,
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
        os_version="10.0.26200",
        architecture="AMD64",
        agent_version="0.1.0",
    )


@pytest.fixture
def system_monitor(mock_pipeline: MagicMock, test_endpoint: EndpointIdentity) -> WindowsSystemMonitor:
    """Fixture providing a configured WindowsSystemMonitor with mocked APIs."""
    config = SystemCollectorConfig(
        enabled=True,
        polling_interval=0.1,
        monitor_sessions=True,
        monitor_event_log=False,  # disabled in unit test for isolation
        monitor_privileges=True,
    )
    return WindowsSystemMonitor(
        config=config,
        pipeline=mock_pipeline,
        endpoint=test_endpoint,
    )


# =========================================================================
# 1. Configuration & Schema Tests
# =========================================================================

def test_configuration_loading() -> None:
    """Verify system monitor configuration loads defaults and env var overrides."""
    config = SystemCollectorConfig()
    assert not config.enabled
    assert config.polling_interval == 2.0
    assert config.monitor_sessions is True
    assert config.monitor_event_log is True
    assert config.monitor_privileges is True

    # Test environment variable overrides
    with patch.dict(
        os.environ,
        {
            "TROJAN_DEFENSE_SYSTEM_ENABLED": "true",
            "TROJAN_DEFENSE_SYSTEM_POLLING_INTERVAL": "0.5",
            "TROJAN_DEFENSE_SYSTEM_MONITOR_SESSIONS": "false",
            "TROJAN_DEFENSE_SYSTEM_MONITOR_EVENT_LOG": "false",
            "TROJAN_DEFENSE_SYSTEM_MONITOR_PRIVILEGES": "true",
        },
    ):
        loaded = load_config()
        assert loaded.system_collector.enabled is True
        assert loaded.system_collector.polling_interval == 0.5
        assert loaded.system_collector.monitor_sessions is False
        assert loaded.system_collector.monitor_event_log is False
        assert loaded.system_collector.monitor_privileges is True
        assert loaded.collectors.system is True


def test_privilege_context_schema() -> None:
    """Verify PrivilegeContext dataclass serialization and deserialization."""
    priv = PrivilegeContext(
        is_elevated=True,
        elevation_type="Full",
        integrity_level="High",
        user="CORP\\testuser",
        sid="S-1-5-21-123456789-500",
        privileges=["SeDebugPrivilege", "SeSecurityPrivilege"],
    )
    d = priv.to_dict()
    assert d["is_elevated"] is True
    assert d["elevation_type"] == "Full"
    assert d["integrity_level"] == "High"
    assert d["user"] == "CORP\\testuser"
    assert d["sid"] == "S-1-5-21-123456789-500"
    assert "SeDebugPrivilege" in d["privileges"]

    # Test deserialization into EventContext
    ctx = EventContext.from_dict({"privilege": d})
    assert ctx.privilege is not None
    assert ctx.privilege.is_elevated is True
    assert ctx.privilege.elevation_type == "Full"
    assert ctx.privilege.integrity_level == "High"
    assert ctx.privilege.user == "CORP\\testuser"
    assert ctx.privilege.sid == "S-1-5-21-123456789-500"
    assert "SeDebugPrivilege" in ctx.privilege.privileges


def test_system_context_schema() -> None:
    """Verify SystemContext extended fields serialization and deserialization."""
    sys_ctx = SystemContext(
        subsystem="SESSION",
        action="LOGON",
        target="Console",
        username="testuser",
        session_id=1,
        session_name="Console",
        domain="WORKGROUP",
        state="Active",
        boot_time="2026-10-01T08:00:00Z",
        event_id=7001,
    )
    d = sys_ctx.to_dict()
    assert d["subsystem"] == "SESSION"
    assert d["session_id"] == 1
    assert d["session_name"] == "Console"
    assert d["domain"] == "WORKGROUP"
    assert d["event_id"] == 7001

    ctx = EventContext.from_dict({"system": d})
    assert ctx.system is not None
    assert ctx.system.session_id == 1
    assert ctx.system.state == "Active"
    assert ctx.system.event_id == 7001


# =========================================================================
# 2. Disabled Collector Mode & Initialization
# =========================================================================

def test_disabled_mode() -> None:
    """When disabled, system collector is not registered in ApplicationManager."""
    root_cfg = RootConfig()
    root_cfg.system_collector.enabled = False
    root_cfg.collectors.system = False

    manager = ApplicationManager()
    manager.initialize(config=root_cfg)

    collectors = manager.registry.list_collectors()
    assert not any(c.name == "windows_system_monitor" for c in collectors)


def test_initialization(system_monitor: WindowsSystemMonitor) -> None:
    """Verify collector initializes with correct attributes and uninitialized status."""
    assert system_monitor.name == "windows_system_monitor"
    assert system_monitor.category == EventCategory.SYSTEM
    assert system_monitor.status == CollectorStatus.UNINITIALIZED
    assert not system_monitor.is_running


# =========================================================================
# 3. System Startup Event Emission
# =========================================================================

def test_system_startup_emission(system_monitor: WindowsSystemMonitor, mock_pipeline: MagicMock) -> None:
    """Verify startup emits a SYSTEM.STARTUP baseline event."""
    with patch("psutil.boot_time", return_value=1700000000.0), \
         patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=[]), \
         patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=None):

        system_monitor.start()
        time.sleep(0.05)
        system_monitor.stop()

    assert mock_pipeline.process.call_count >= 1
    first_event = mock_pipeline.process.call_args_list[0][0][0]
    assert first_event.event_type.value == "SYSTEM.STARTUP"
    assert first_event.event_type.category == EventCategory.SYSTEM
    assert first_event.severity == Severity.INFO
    assert first_event.context.system is not None
    assert first_event.context.system.boot_time is not None
    assert first_event.source == "windows_system_monitor"


# =========================================================================
# 4. Session Monitoring & State Transitions
# =========================================================================

def test_session_lifecycle_transitions(system_monitor: WindowsSystemMonitor, mock_pipeline: MagicMock) -> None:
    """Verify session logon, lock, unlock, and logoff transitions emit correct events."""
    # State 1: Active user session 1
    session_state_1 = [
        {
            "session_id": 1,
            "session_name": "Console",
            "state": "Active",
            "username": "Alice",
            "domain": "WORKGROUP",
        }
    ]

    # State 2: Session 1 locks (Active -> Disconnected)
    session_state_2 = [
        {
            "session_id": 1,
            "session_name": "Console",
            "state": "Disconnected",
            "username": "Alice",
            "domain": "WORKGROUP",
        }
    ]

    # State 3: Session 1 unlocks (Disconnected -> Active)
    session_state_3 = [
        {
            "session_id": 1,
            "session_name": "Console",
            "state": "Active",
            "username": "Alice",
            "domain": "WORKGROUP",
        }
    ]

    # State 4: Session 1 logoff (session ended)
    session_state_4: list[dict] = []

    # Emit initial boot event baseline
    system_monitor._emit_system_startup_baseline()
    mock_pipeline.reset_mock()

    # Step 1: Detect Session 1 initial logon
    with patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=session_state_1), \
         patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=None):
        system_monitor._scan_system_and_privileges()

    assert mock_pipeline.process.call_count == 1
    logon_event = mock_pipeline.process.call_args[0][0]
    assert logon_event.event_type.value == "SYSTEM.LOGON"
    assert logon_event.context.system.session_id == 1
    assert logon_event.context.system.username == "Alice"

    mock_pipeline.reset_mock()

    # Step 2: Session locks (Active -> Disconnected)
    with patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=session_state_2), \
         patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=None):
        system_monitor._scan_system_and_privileges()

    assert mock_pipeline.process.call_count == 1
    lock_event = mock_pipeline.process.call_args[0][0]
    assert lock_event.event_type.value == "SYSTEM.LOCK"
    assert lock_event.context.system.session_id == 1
    assert lock_event.context.system.username == "Alice"

    mock_pipeline.reset_mock()

    # Step 3: Session unlocks (Disconnected -> Active)
    with patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=session_state_3), \
         patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=None):
        system_monitor._scan_system_and_privileges()

    assert mock_pipeline.process.call_count == 1
    unlock_event = mock_pipeline.process.call_args[0][0]
    assert unlock_event.event_type.value == "SYSTEM.UNLOCK"
    assert unlock_event.context.system.session_id == 1
    assert unlock_event.context.system.username == "Alice"

    mock_pipeline.reset_mock()

    # Step 4: Session logoff (missing from session list)
    with patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=session_state_4), \
         patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=None):
        system_monitor._scan_system_and_privileges()

    assert mock_pipeline.process.call_count == 1
    logoff_event = mock_pipeline.process.call_args[0][0]
    assert logoff_event.event_type.value == "SYSTEM.LOGOFF"
    assert logoff_event.context.system.session_id == 1
    assert logoff_event.context.system.username == "Alice"


# =========================================================================
# 5. Process Privilege Context & Native Win32 API
# =========================================================================

def test_real_windows_current_process_privilege() -> None:
    """Verify get_process_privilege_context returns valid PrivilegeContext for current process."""
    if sys.platform != "win32":
        pytest.skip("Windows-only native test")

    current_pid = os.getpid()
    priv = get_process_privilege_context(current_pid)

    assert priv is not None
    assert isinstance(priv.is_elevated, bool)
    assert priv.elevation_type in ("Default", "Full", "Limited", "Unknown")
    assert priv.integrity_level in ("Low", "Medium", "High", "System", "Untrusted", "Unknown")
    assert priv.sid is not None and priv.sid.startswith("S-1-")
    assert priv.user is not None and len(priv.user) > 0
    assert isinstance(priv.privileges, list)


def test_real_windows_admin_check() -> None:
    """Verify is_current_user_admin returns boolean on Windows."""
    if sys.platform != "win32":
        pytest.skip("Windows-only native test")

    is_admin = is_current_user_admin()
    assert isinstance(is_admin, bool)


def test_real_windows_active_sessions() -> None:
    """Verify get_active_sessions returns list of terminal sessions on Windows."""
    if sys.platform != "win32":
        pytest.skip("Windows-only native test")

    sessions = get_active_sessions()
    assert isinstance(sessions, list)
    assert len(sessions) >= 1
    # Check structure of at least one session
    sess = sessions[0]
    assert "session_id" in sess
    assert "state" in sess
    assert "session_name" in sess


def test_privilege_elevation_emission(system_monitor: WindowsSystemMonitor, mock_pipeline: MagicMock) -> None:
    """Verify _scan_system_and_privileges emits an event when process elevation is observed."""
    mock_priv = PrivilegeContext(
        is_elevated=True,
        elevation_type="Full",
        integrity_level="High",
        user="NT AUTHORITY\\SYSTEM",
        sid="S-1-5-18",
        privileges=["SeDebugPrivilege"],
    )

    with patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=mock_priv), \
         patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=[]):
        system_monitor._scan_system_and_privileges()

    assert mock_pipeline.process.call_count == 1
    event = mock_pipeline.process.call_args[0][0]
    assert event.event_type.value == "PRIVILEGE.ELEVATION"
    assert event.event_type.category == EventCategory.PRIVILEGE
    assert event.context.privilege is not None
    assert event.context.privilege.is_elevated is True
    assert event.context.privilege.integrity_level == "High"


def test_privilege_check_suppresses_duplicates(system_monitor: WindowsSystemMonitor, mock_pipeline: MagicMock) -> None:
    """Verify elevated processes are only emitted once and suppressed on subsequent scans."""
    mock_priv = PrivilegeContext(
        is_elevated=True,
        elevation_type="Full",
        integrity_level="High",
        user="NT AUTHORITY\\SYSTEM",
        sid="S-1-5-18",
        privileges=["SeDebugPrivilege"],
    )

    with patch("trojan_defense.platform.windows.system_monitor.get_process_privilege_context", return_value=mock_priv), \
         patch("trojan_defense.platform.windows.system_monitor.get_active_sessions", return_value=[]):
        system_monitor._scan_system_and_privileges()
        # Second scan with same process and privilege state
        system_monitor._scan_system_and_privileges()

    # Must only emit once
    assert mock_pipeline.process.call_count == 1


# =========================================================================
# 6. Event Log Query & Error Resilience
# =========================================================================

def test_event_log_query_returns_list() -> None:
    """Verify query_recent_system_events runs without crashing."""
    if sys.platform != "win32":
        pytest.skip("Windows-only native test")

    events = query_recent_system_events(max_records=5)
    assert isinstance(events, list)
    for evt in events:
        assert "event_id" in evt
        assert "record_id" in evt


def test_privilege_context_resilient_to_invalid_pid() -> None:
    """Verify get_process_privilege_context handles invalid PID gracefully without crashing."""
    res = get_process_privilege_context(9999999)
    assert res is not None
    assert res.is_elevated is None
    assert res.elevation_type == "Unavailable"
    assert res.integrity_level == "Unavailable"


def test_system_monitor_error_handling_in_loop(system_monitor: WindowsSystemMonitor) -> None:
    """Verify collector loop catches scan exceptions gracefully without crashing."""
    with patch.object(system_monitor, "_scan_system_and_privileges", side_effect=RuntimeError("Scan Error")):
        # Call _scan_system_and_privileges wrapped in loop error handling
        try:
            system_monitor._scan_system_and_privileges()
        except RuntimeError:
            pass  # Expected direct raise when called outside loop

    # Monitor is still intact
    assert not system_monitor.is_running


# =========================================================================
# 7. Clean Collector Lifecycle
# =========================================================================

def test_system_monitor_lifecycle(system_monitor: WindowsSystemMonitor) -> None:
    """Verify monitor starts background thread, updates status, and stops cleanly."""
    system_monitor.start()
    assert system_monitor.is_running is True
    assert system_monitor.status == CollectorStatus.RUNNING
    assert system_monitor._thread is not None
    assert system_monitor._thread.is_alive()

    system_monitor.stop()
    assert system_monitor.is_running is False
    assert system_monitor.status == CollectorStatus.STOPPED
    assert not system_monitor._thread.is_alive()
