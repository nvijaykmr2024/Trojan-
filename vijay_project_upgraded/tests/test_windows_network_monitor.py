"""Unit tests for WindowsNetworkMonitor.

Tests configuration, disabled mode, initialization, event schema, IPv4, IPv6,
TCP, UDP, process correlation, loopback classification, listening sockets,
duplicate control, connection lifecycle (connect, maintain, close), error handling,
and clean lifecycle shutdown.
"""

from collections import namedtuple
import os
import socket
import threading
import time
from unittest.mock import MagicMock, patch
import pytest

from trojan_defense.core.collectors.base import CollectorStatus
from trojan_defense.core.config.loader import load_config
from trojan_defense.core.config.schema import NetworkCollectorConfig, RootConfig
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import (
    EndpointIdentity,
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
)
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.platform.windows.network_monitor import (
    ConnectionKey,
    WindowsNetworkMonitor,
    is_loopback_address,
    normalize_ip_address,
)

# Mock structure matching psutil.net_connections return tuple
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


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
def network_monitor(mock_pipeline: MagicMock, test_endpoint: EndpointIdentity) -> WindowsNetworkMonitor:
    """Fixture providing a configured WindowsNetworkMonitor."""
    config = NetworkCollectorConfig(
        enabled=True,
        polling_interval=0.1,
        include_loopback=True,
        include_listening=True,
        include_udp=True,
        resolve_process_names=True,
    )
    return WindowsNetworkMonitor(
        config=config,
        pipeline=mock_pipeline,
        endpoint=test_endpoint,
    )


def test_configuration_loading() -> None:
    """Test 1: Verify network monitor configuration loads defaults and overrides."""
    config = NetworkCollectorConfig()
    assert not config.enabled
    assert config.polling_interval == 1.0
    assert config.include_loopback is True
    assert config.include_listening is True
    assert config.include_udp is True
    assert config.resolve_process_names is True

    # Test env var override
    with patch.dict(
        os.environ,
        {
            "TROJAN_DEFENSE_NETWORK_ENABLED": "true",
            "TROJAN_DEFENSE_NETWORK_POLLING_INTERVAL": "0.25",
            "TROJAN_DEFENSE_NETWORK_INCLUDE_LOOPBACK": "false",
        },
    ):
        loaded = load_config()
        assert loaded.network_collector.enabled is True
        assert loaded.collectors.network is True
        assert loaded.network_collector.polling_interval == 0.25
        assert loaded.network_collector.include_loopback is False


def test_disabled_mode(mock_pipeline: MagicMock, test_endpoint: EndpointIdentity) -> None:
    """Test 2: When disabled, network monitor collector is not registered or started."""
    root_cfg = RootConfig()
    root_cfg.network_collector.enabled = False
    root_cfg.collectors.network = False

    manager = ApplicationManager()
    manager.initialize(config=root_cfg)

    # WindowsNetworkMonitor must not be present in collector registry
    collectors = manager.registry.list_collectors()
    assert not any(c.name == "windows_network_monitor" for c in collectors)


def test_initialization(network_monitor: WindowsNetworkMonitor) -> None:
    """Test 3: Verify collector initializes with correct attributes."""
    assert network_monitor.name == "windows_network_monitor"
    assert network_monitor.category == EventCategory.NETWORK
    assert network_monitor.status == CollectorStatus.UNINITIALIZED
    assert not network_monitor.is_running


def test_network_event_schema(network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock) -> None:
    """Test 4: Verify generated network events conform to canonical SecurityEvent schema."""
    key = ConnectionKey(
        protocol="TCP",
        local_ip="192.168.1.50",
        local_port=49152,
        remote_ip="93.184.216.34",
        remote_port=443,
        pid=1234,
    )

    network_monitor._emit_connection_event(
        action="CONNECT",
        key=key,
        state="ESTABLISHED",
        process_name="test_proc.exe",
        process_exe="C:\\Windows\\System32\\test_proc.exe",
    )

    assert mock_pipeline.process.called
    event: SecurityEvent = mock_pipeline.process.call_args[0][0]

    assert isinstance(event, SecurityEvent)
    assert event.event_type.value == "NETWORK.CONNECT"
    assert event.severity == Severity.LOW
    assert event.source == "windows_network_monitor"
    assert event.endpoint.endpoint_id == "test-endpoint-id"

    # Context verification
    assert event.context.network is not None
    assert event.context.network.protocol == "TCP"
    assert event.context.network.local_ip == "192.168.1.50"
    assert event.context.network.local_port == 49152
    assert event.context.network.remote_ip == "93.184.216.34"
    assert event.context.network.remote_port == 443
    assert event.context.network.state == "ESTABLISHED"
    assert event.context.network.pid == 1234
    # Backward compatibility aliases
    assert event.context.network.source_ip == "192.168.1.50"
    assert event.context.network.destination_ip == "93.184.216.34"

    # Process correlation context
    assert event.context.process is not None
    assert event.context.process.pid == 1234
    assert event.context.process.name == "test_proc.exe"
    assert event.context.process.executable_path == "C:\\Windows\\System32\\test_proc.exe"


def test_ipv4_endpoint_representation() -> None:
    """Test 5: Verify valid IPv4 endpoints are normalized correctly."""
    assert normalize_ip_address("127.0.0.1") == "127.0.0.1"
    assert normalize_ip_address("  192.168.1.1  ") == "192.168.1.1"
    assert normalize_ip_address("0.0.0.0") == "0.0.0.0"
    assert normalize_ip_address("10.0.0.5") == "10.0.0.5"


def test_ipv6_endpoint_representation() -> None:
    """Test 6: Verify valid IPv6 endpoints are normalized without corruption."""
    assert normalize_ip_address("::1") == "::1"
    assert normalize_ip_address("::") == "::"
    # Strips scope identifier cleanly
    assert normalize_ip_address("fe80::1%12") == "fe80::1"
    assert normalize_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"


def test_tcp_metadata_representation(network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock) -> None:
    """Test 7: Verify TCP socket state and metadata representation."""
    mock_tcp = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="10.0.0.2", port=50000),
        raddr=MockAddr(ip="10.0.0.1", port=80),
        status="ESTABLISHED",
        pid=5555,
    )

    with patch("psutil.net_connections", return_value=[mock_tcp]):
        network_monitor._scan_connections(is_initial_baseline=False)

    assert mock_pipeline.process.called
    event: SecurityEvent = mock_pipeline.process.call_args[0][0]
    assert event.event_type.value == "NETWORK.CONNECT"
    assert event.context.network.protocol == "TCP"
    assert event.context.network.state == "ESTABLISHED"
    assert event.context.network.local_port == 50000
    assert event.context.network.remote_port == 80


def test_udp_metadata_representation(network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock) -> None:
    """Test 8: Verify UDP socket metadata is represented correctly."""
    mock_udp = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        laddr=MockAddr(ip="0.0.0.0", port=5353),
        raddr=(),
        status="NONE",
        pid=6666,
    )

    with patch("psutil.net_connections", return_value=[mock_udp]):
        network_monitor._scan_connections(is_initial_baseline=False)

    assert mock_pipeline.process.called
    event: SecurityEvent = mock_pipeline.process.call_args[0][0]
    assert event.context.network.protocol == "UDP"
    assert event.context.network.local_port == 5353
    assert event.context.network.remote_ip is None


def test_process_correlation_controlled_socket(
    network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock
) -> None:
    """Test 9: Verify PID and process identity correlation with controlled local socket."""
    current_pid = os.getpid()

    # Create a real listening socket on localhost ephemeral port
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        bound_port = server_sock.getsockname()[1]

        # Scan connections with real psutil call
        network_monitor._scan_connections(is_initial_baseline=False)

        # Verify an event was emitted for this bound socket
        emitted_events = [
            call[0][0]
            for call in mock_pipeline.process.call_args_list
            if call[0][0].context.network.local_port == bound_port
        ]

        assert len(emitted_events) >= 1
        event = emitted_events[0]
        assert event.context.network.pid == current_pid
        assert event.context.process is not None
        assert event.context.process.pid == current_pid
        assert "python" in str(event.context.process.name).lower()
    finally:
        server_sock.close()


def test_loopback_traffic_classification(
    network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock
) -> None:
    """Test 10: Verify loopback traffic is observed with neutral severity without being marked malicious."""
    assert is_loopback_address("127.0.0.1") is True
    assert is_loopback_address("::1") is True
    assert is_loopback_address("192.168.1.1") is False

    mock_conn = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="127.0.0.1", port=45000),
        raddr=MockAddr(ip="127.0.0.1", port=8080),
        status="ESTABLISHED",
        pid=1111,
    )

    with patch("psutil.net_connections", return_value=[mock_conn]):
        network_monitor._scan_connections(is_initial_baseline=False)

    assert mock_pipeline.process.called
    event: SecurityEvent = mock_pipeline.process.call_args[0][0]
    # Severity must be neutral / default LOW or INFO, never HIGH or CRITICAL
    assert event.severity in (Severity.LOW, Severity.INFO)
    assert event.context.network.local_ip == "127.0.0.1"


def test_listening_endpoint_representation(
    network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock
) -> None:
    """Test 11: Verify listening sockets are represented with NETWORK.LISTEN."""
    mock_listen = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="0.0.0.0", port=8080),
        raddr=(),
        status="LISTEN",
        pid=8888,
    )

    with patch("psutil.net_connections", return_value=[mock_listen]):
        network_monitor._scan_connections(is_initial_baseline=False)

    assert mock_pipeline.process.called
    event: SecurityEvent = mock_pipeline.process.call_args[0][0]
    assert event.event_type.value == "NETWORK.LISTEN"
    assert event.severity == Severity.INFO
    assert event.context.network.state == "LISTEN"
    assert event.context.network.local_port == 8080
    assert event.context.network.remote_ip is None


def test_duplicate_control(network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock) -> None:
    """Test 12: Verify repeated scans of unchanged connections do not emit duplicate events."""
    mock_conn = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="192.168.1.10", port=54321),
        raddr=MockAddr(ip="192.168.1.1", port=80),
        status="ESTABLISHED",
        pid=9999,
    )

    with patch("psutil.net_connections", return_value=[mock_conn]):
        # First scan
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.call_count == 1

        # Second scan: same active connection with same state
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.call_count == 1  # No duplicate emitted!

        # Third scan: still unchanged
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.call_count == 1  # Still no duplicate!


def test_connection_lifecycle(network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock) -> None:
    """Test 13: Verify connection establishment, maintenance, and closure transitions."""
    conn_a = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="192.168.1.10", port=40001),
        raddr=MockAddr(ip="1.1.1.1", port=443),
        status="ESTABLISHED",
        pid=4000,
    )

    with patch("psutil.net_connections", return_value=[conn_a]):
        # 1. Connection opens
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.call_count == 1
        first_event = mock_pipeline.process.call_args[0][0]
        assert first_event.event_type.value == "NETWORK.CONNECT"

    # 2. Connection closes (absent from next scan)
    with patch("psutil.net_connections", return_value=[]):
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.call_count == 2
        close_event = mock_pipeline.process.call_args[0][0]
        assert close_event.event_type.value == "NETWORK.CLOSE"
        assert close_event.severity == Severity.INFO
        assert close_event.context.network.local_port == 40001


def test_error_handling_access_denied_or_missing(
    network_monitor: WindowsNetworkMonitor, mock_pipeline: MagicMock
) -> None:
    """Test 14: Verify inaccessible processes or API errors do not crash the collector."""
    mock_conn = MockConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr(ip="192.168.1.10", port=40002),
        raddr=MockAddr(ip="8.8.8.8", port=53),
        status="ESTABLISHED",
        pid=99999,
    )

    # psutil.Process raises AccessDenied
    with (
        patch("psutil.net_connections", return_value=[mock_conn]),
        patch("psutil.Process", side_effect=PermissionError("Access denied")),
    ):
        # Must not throw
        network_monitor._scan_connections(is_initial_baseline=False)
        assert mock_pipeline.process.called
        event = mock_pipeline.process.call_args[0][0]
        assert event.context.network.pid == 99999
        # Process name should fallback to None without error
        assert event.context.process.name is None

    # psutil.net_connections itself raises AccessDenied
    with patch("psutil.net_connections", side_effect=PermissionError("OS Access Denied")):
        # Must not crash
        network_monitor._scan_connections(is_initial_baseline=False)


def test_collector_lifecycle_start_stop(network_monitor: WindowsNetworkMonitor) -> None:
    """Test 16: Verify clean start, monitoring thread execution, and graceful stop."""
    with patch("psutil.net_connections", return_value=[]):
        network_monitor.start()
        assert network_monitor.is_running
        assert network_monitor.status == CollectorStatus.RUNNING

        # Calling start again while running should be a no-op
        network_monitor.start()

        time.sleep(0.2)
        network_monitor.stop(timeout=2.0)
        assert not network_monitor.is_running
        assert network_monitor.status == CollectorStatus.STOPPED


def test_health_check(network_monitor: WindowsNetworkMonitor) -> None:
    """Verify health check reporting schema and values."""
    health = network_monitor.health_check()
    assert health["collector"] == "windows_network_monitor"
    assert health["status"] == CollectorStatus.UNINITIALIZED.value
    assert health["running"] is False
    assert health["polling_interval"] == 0.1
    assert health["tracked_connections"] == 0
    assert health["events_emitted"] == 0
    assert health["include_loopback"] is True
    assert health["include_listening"] is True
    assert health["include_udp"] is True
