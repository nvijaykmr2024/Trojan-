"""Windows Network Telemetry Collector for observing local socket activity.

Uses native Windows connection table APIs via psutil (GetExtendedTcpTable and
GetExtendedUdpTable from iphlpapi.dll) to observe local endpoint network connections
(TCP/UDP, IPv4/IPv6), correlates connections to local processes, tracks state
transitions, prevents duplicate event storms, and emits canonical SecurityEvents
into the event pipeline.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import socket
import threading
import time
from typing import Any

import psutil

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.config.schema import NetworkCollectorConfig
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import EventContext, NetworkContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent, current_utc_timestamp
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline

logger = get_logger("platform.windows.network_monitor")


def normalize_ip_address(ip_str: str | None) -> str:
    """Normalize and format IPv4 and IPv6 address strings."""
    if not ip_str:
        return ""
    cleaned = ip_str.strip()
    # Strip IPv6 scope identifier if present (e.g. fe80::1%12 -> fe80::1)
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        return cleaned


def is_loopback_address(ip_str: str | None) -> bool:
    """Determine whether an address string is loopback (127.0.0.0/8, ::1)."""
    if not ip_str:
        return False
    normalized = normalize_ip_address(ip_str)
    try:
        addr = ipaddress.ip_address(normalized)
        return addr.is_loopback
    except ValueError:
        return normalized in ("127.0.0.1", "::1", "localhost")


@dataclass(frozen=True)
class ConnectionKey:
    """Unique key identifying an endpoint network connection."""
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str | None
    remote_port: int | None
    pid: int | None


@dataclass
class TrackedConnection:
    """Internal state tracking an observed network connection."""
    key: ConnectionKey
    state: str
    first_seen_iso: str
    last_seen_iso: str
    process_name: str | None = None
    process_exe: str | None = None


class WindowsNetworkMonitor(BaseCollector):
    """Collector for monitoring Windows network connection activity."""

    def __init__(
        self,
        config: NetworkCollectorConfig,
        pipeline: EventPipeline,
        endpoint: EndpointIdentity | None = None,
    ) -> None:
        super().__init__(
            name="windows_network_monitor",
            category=EventCategory.NETWORK,
            pipeline=pipeline,
            endpoint=endpoint or EndpointIdentity.resolve(),
        )
        self.config = config
        self.endpoint = endpoint or EndpointIdentity.resolve()

        self._active_connections: dict[ConnectionKey, TrackedConnection] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._event_count: int = 0
        self._scan_count: int = 0
        self._process_cache: dict[int, tuple[str | None, str | None]] = {}

    @property
    def is_running(self) -> bool:
        """Indicate whether the monitor is running."""
        return self._status == CollectorStatus.RUNNING

    def start(self) -> None:
        """Start the Windows network monitor background thread."""
        with self._lock:
            if self._status in (CollectorStatus.STARTING, CollectorStatus.RUNNING):
                logger.warning("WindowsNetworkMonitor is already running or starting")
                return

            self._status = CollectorStatus.STARTING
            self._stop_event.clear()

        try:
            logger.info("Initializing WindowsNetworkMonitor baseline snapshot...")
            # Perform initial baseline scan without emitting burst alerts if desired,
            # or record current connections so subsequent scans detect real transitions.
            self._scan_connections(is_initial_baseline=True)

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="WindowsNetworkMonitorThread",
                daemon=True,
            )
            self._thread.start()
            self._status = CollectorStatus.RUNNING
            logger.info(
                f"WindowsNetworkMonitor started successfully (interval={self.config.polling_interval}s, "
                f"loopback={self.config.include_loopback}, listening={self.config.include_listening})"
            )
        except Exception as exc:
            self._status = CollectorStatus.ERROR
            logger.error(f"Failed to start WindowsNetworkMonitor: {exc}", exc_info=True)
            raise CollectorError(f"WindowsNetworkMonitor failed to start: {exc}") from exc

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the network monitor and wait for the background thread to exit."""
        with self._lock:
            if self._status in (CollectorStatus.STOPPED, CollectorStatus.STOPPING):
                return
            self._status = CollectorStatus.STOPPING

        logger.info("Stopping WindowsNetworkMonitor...")
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("WindowsNetworkMonitor thread did not exit cleanly within timeout")

        self._status = CollectorStatus.STOPPED
        logger.info(
            f"WindowsNetworkMonitor stopped (total_scans={self._scan_count}, "
            f"total_events_emitted={self._event_count})"
        )

    def health_check(self) -> dict[str, Any]:
        """Return operational health status and telemetry counters."""
        with self._lock:
            return {
                "collector": self.name,
                "status": self.status.value,
                "running": self.is_running,
                "polling_interval": self.config.polling_interval,
                "tracked_connections": len(self._active_connections),
                "events_emitted": self._event_count,
                "scan_count": self._scan_count,
                "include_loopback": self.config.include_loopback,
                "include_listening": self.config.include_listening,
                "include_udp": self.config.include_udp,
            }

    def _monitor_loop(self) -> None:
        """Periodic background reconciliation loop."""
        interval = max(0.1, self.config.polling_interval)
        while not self._stop_event.is_set():
            try:
                self._scan_connections(is_initial_baseline=False)
            except Exception as exc:
                logger.error(f"Error during network connection scan: {exc}", exc_info=True)

            # Sleep in short slices for responsive cancellation
            elapsed = 0.0
            slice_duration = 0.1
            while elapsed < interval and not self._stop_event.is_set():
                time.sleep(slice_duration)
                elapsed += slice_duration

    def _resolve_process_metadata(self, pid: int | None) -> tuple[str | None, str | None]:
        """Safely resolve process name and executable path without throwing exceptions."""
        if not pid or pid <= 0 or not self.config.resolve_process_names:
            return None, None

        if pid in self._process_cache:
            return self._process_cache[pid]

        name: str | None = None
        exe: str | None = None
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                exe = None
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass

        self._process_cache[pid] = (name, exe)
        return name, exe

    def _scan_connections(self, is_initial_baseline: bool = False) -> None:
        """Scan current network connections and reconcile with tracked state."""
        self._scan_count += 1

        # Clear transient process cache periodically to reflect PID changes
        if self._scan_count % 10 == 0:
            self._process_cache.clear()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            logger.debug(f"Unable to query system network connections: {exc}")
            return

        current_observed: dict[ConnectionKey, tuple[str, str | None, str | None]] = {}
        now_iso = current_utc_timestamp()

        for conn in raw_conns:
            # 1. Distinguish Protocol
            if conn.type == socket.SOCK_STREAM:
                proto = "TCP"
            elif conn.type == socket.SOCK_DGRAM:
                proto = "UDP"
            else:
                continue

            if proto == "UDP" and not self.config.include_udp:
                continue

            # 2. Extract and Normalize Addresses
            if not conn.laddr:
                continue

            l_ip = normalize_ip_address(conn.laddr.ip)
            l_port = conn.laddr.port

            # Filter loopback if configured
            if not self.config.include_loopback and is_loopback_address(l_ip):
                continue

            r_ip: str | None = None
            r_port: int | None = None
            if conn.raddr:
                r_ip = normalize_ip_address(conn.raddr.ip)
                r_port = conn.raddr.port
                if not self.config.include_loopback and is_loopback_address(r_ip):
                    continue

            # 3. Connection State
            state = str(conn.status).upper() if conn.status else "NONE"
            if proto == "UDP" and state == "NONE":
                state = "OPEN"

            # Filter listening sockets if configured
            if state == "LISTEN" and not self.config.include_listening:
                continue

            # 4. Process Correlation
            raw_pid = conn.pid
            clean_pid = raw_pid if (raw_pid is not None and raw_pid > 0) else None
            p_name, p_exe = self._resolve_process_metadata(clean_pid)

            key = ConnectionKey(
                protocol=proto,
                local_ip=l_ip,
                local_port=l_port,
                remote_ip=r_ip,
                remote_port=r_port,
                pid=clean_pid,
            )
            current_observed[key] = (state, p_name, p_exe)

        with self._lock:
            # A. Detect New or Changed Connections
            for key, (state, p_name, p_exe) in current_observed.items():
                if key not in self._active_connections:
                    # New connection observed
                    tracked = TrackedConnection(
                        key=key,
                        state=state,
                        first_seen_iso=now_iso,
                        last_seen_iso=now_iso,
                        process_name=p_name,
                        process_exe=p_exe,
                    )
                    self._active_connections[key] = tracked

                    # Emit event (for baseline, we emit initial listening or established sockets)
                    self._emit_connection_event(
                        action="LISTEN" if state == "LISTEN" else "CONNECT",
                        key=key,
                        state=state,
                        process_name=p_name,
                        process_exe=p_exe,
                    )
                else:
                    # Existing connection: check for state transitions
                    existing = self._active_connections[key]
                    existing.last_seen_iso = now_iso
                    if p_name and not existing.process_name:
                        existing.process_name = p_name
                        existing.process_exe = p_exe

                    if existing.state != state:
                        old_state = existing.state
                        existing.state = state
                        # State changed (e.g. SYN_SENT -> ESTABLISHED)
                        action = "LISTEN" if state == "LISTEN" else "CONNECT"
                        self._emit_connection_event(
                            action=action,
                            key=key,
                            state=state,
                            process_name=existing.process_name,
                            process_exe=existing.process_exe,
                            extra={"previous_state": old_state},
                        )

            # B. Detect Closed / Disappeared Connections
            missing_keys = [k for k in self._active_connections if k not in current_observed]
            for key in missing_keys:
                closed_conn = self._active_connections.pop(key)
                # Emit close event for active TCP connections or tracked endpoints
                if closed_conn.state != "LISTEN" or key.protocol == "TCP":
                    self._emit_connection_event(
                        action="CLOSE",
                        key=key,
                        state="CLOSED",
                        process_name=closed_conn.process_name,
                        process_exe=closed_conn.process_exe,
                        extra={"last_state": closed_conn.state},
                    )

    def _emit_connection_event(
        self,
        action: str,
        key: ConnectionKey,
        state: str,
        process_name: str | None = None,
        process_exe: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Construct canonical SecurityEvent and submit to the event pipeline."""
        event_type = EventType.with_action(EventCategory.NETWORK, action)

        severity = Severity.LOW if action == "CONNECT" else Severity.INFO

        net_context = NetworkContext(
            protocol=key.protocol,
            local_ip=key.local_ip,
            local_port=key.local_port,
            remote_ip=key.remote_ip,
            remote_port=key.remote_port,
            state=state,
            pid=key.pid,
        )

        proc_context: ProcessContext | None = None
        if key.pid is not None or process_name is not None:
            proc_context = ProcessContext(
                pid=key.pid,
                name=process_name,
                executable_path=process_exe,
            )

        event_context = EventContext(
            network=net_context,
            process=proc_context,
            extra=extra or {},
        )

        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=self.name,
            endpoint=self.endpoint,
            context=event_context,
        )

        try:
            self.pipeline.process(event)
            self._event_count += 1
            logger.debug(
                f"Emitted {event_type.value} event: {key.protocol} {key.local_ip}:{key.local_port} "
                f"-> {key.remote_ip}:{key.remote_port} (state={state}, pid={key.pid})"
            )
        except Exception as exc:
            logger.error(f"Failed to submit network event {event.event_id} to pipeline: {exc}")
