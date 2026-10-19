"""Integration tests for Windows Network Telemetry.

Tests the full pipeline from real Windows TCP socket activity through
psutil net_connections, WindowsNetworkMonitor, EventPipeline,
and persistence in the SQLite repository.
"""

from pathlib import Path
import socket
import time
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    CollectorToggleConfig,
    NetworkCollectorConfig,
    PersistenceConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models import Severity
from trojan_defense.core.persistence.base import EventQueryFilter


class TestNetworkMonitoringIntegration:
    """Integration test suite for network telemetry collection and persistence."""

    def test_live_network_lifecycle_to_sqlite(self, tmp_path: Path) -> None:
        """Perform real localhost network socket activity and verify all events in SQLite."""
        db_path = str(tmp_path / "test_network_integration.db")

        config = RootConfig(
            app=AppConfig(environment="test", debug=True),
            persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=db_path),
            transport=TransportConfig(enabled=False),
            collectors=CollectorToggleConfig(network=True),
            network_collector=NetworkCollectorConfig(
                enabled=True,
                polling_interval=0.1,  # Fast polling for integration test
                include_loopback=True,
                include_listening=True,
                include_udp=True,
                resolve_process_names=True,
            ),
        )

        manager = ApplicationManager()
        manager.initialize(config=config)
        assert manager.repository is not None

        manager.start()
        server_sock = None
        client_sock = None
        accepted_conn = None

        try:
            # 1. Open a real listening TCP server socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            server_port = server_sock.getsockname()[1]

            # Poll repository for NETWORK.LISTEN on server_port
            listen_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="NETWORK.LISTEN", limit=100)
                )
                matching = [
                    e for e in events
                    if e.context.network and e.context.network.local_port == server_port
                ]
                if matching:
                    listen_event = matching[0]
                    break
                time.sleep(0.1)

            assert listen_event is not None, f"NETWORK.LISTEN event for port {server_port} not found in SQLite"
            assert listen_event.context.network.protocol == "TCP"
            assert listen_event.context.network.state == "LISTEN"
            assert listen_event.severity == Severity.INFO
            assert listen_event.source == "windows_network_monitor"

            # 2. Open a real client socket and connect to server
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect(("127.0.0.1", server_port))
            client_port = client_sock.getsockname()[1]
            accepted_conn, _ = server_sock.accept()

            # Poll repository for NETWORK.CONNECT on client_port or server_port
            connect_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="NETWORK.CONNECT", limit=100)
                )
                matching = [
                    e for e in events
                    if e.context.network and (
                        e.context.network.local_port == client_port or
                        e.context.network.remote_port == client_port
                    )
                ]
                if matching:
                    connect_event = matching[0]
                    break
                time.sleep(0.1)

            assert connect_event is not None, f"NETWORK.CONNECT event for port {client_port} not found in SQLite"
            assert connect_event.context.network.protocol == "TCP"
            assert connect_event.severity == Severity.LOW
            assert connect_event.context.network.state in ("ESTABLISHED", "SYN_SENT")

            # 3. Verify duplicate suppression: keep connection open for several intervals
            time.sleep(0.4)  # 4 intervals
            # Active stable connection must not generate continuous runaway duplicates
            events_now, _ = manager.repository.query(
                EventQueryFilter(event_type="NETWORK.CONNECT", limit=100)
            )
            client_events = [
                e for e in events_now
                if e.context.network and e.context.network.local_port == client_port
            ]
            assert len(client_events) <= 2, f"Expected duplicate suppression, got {len(client_events)} events"

            # 4. Close client socket and accepted connection
            client_sock.close()
            client_sock = None
            accepted_conn.close()
            accepted_conn = None

            # Poll repository for NETWORK.CLOSE
            close_event = None
            start_time = time.time()
            while (time.time() - start_time) < 5.0:
                events, _ = manager.repository.query(
                    EventQueryFilter(event_type="NETWORK.CLOSE", limit=100)
                )
                matching = [
                    e for e in events
                    if e.context.network and (
                        e.context.network.local_port == client_port or
                        e.context.network.remote_port == client_port
                    )
                ]
                if matching:
                    close_event = matching[0]
                    break
                time.sleep(0.1)

            assert close_event is not None, f"NETWORK.CLOSE event for port {client_port} not found in SQLite"
            assert close_event.context.network.protocol == "TCP"
            assert close_event.severity == Severity.INFO

        finally:
            if client_sock:
                try:
                    client_sock.close()
                except Exception:
                    pass
            if accepted_conn:
                try:
                    accepted_conn.close()
                except Exception:
                    pass
            if server_sock:
                try:
                    server_sock.close()
                except Exception:
                    pass
            manager.stop()
