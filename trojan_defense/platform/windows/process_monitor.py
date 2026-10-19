"""Windows Process Monitoring Collector for detecting process creation and termination.

Uses psutil to observe real Windows process lifecycle activity, captures rich
process telemetry context, handles PID recycling and access-denied boundaries,
and emits canonical SecurityEvents into the event pipeline.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import threading
import time
from typing import Any

import psutil

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.config.schema import ProcessCollectorConfig
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent, current_utc_timestamp
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline

logger = get_logger("platform.windows.process_monitor")


def _format_epoch_to_iso(epoch_seconds: float) -> str:
    """Convert epoch timestamp to ISO 8601 UTC string."""
    try:
        dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, OSError):
        return current_utc_timestamp()


@dataclass(frozen=True, init=False)
class ProcessSnapshot:
    """Immutable snapshot of an observed process state."""
    pid: int
    name: str
    create_time: float
    ppid: int | None
    executable_path: str | None
    command_line: str | None
    username: str | None
    created_at_iso: str
    hash_sha256: str | None
    parent_name: str | None

    def __init__(
        self,
        pid: int,
        name: str = "unknown",
        create_time: float = 0.0,
        ppid: int | None = None,
        executable_path: str | None = None,
        command_line: str | None = None,
        username: str | None = None,
        created_at_iso: str = "",
        hash_sha256: str | None = None,
        parent_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        object.__setattr__(self, "pid", pid)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "create_time", create_time)
        object.__setattr__(self, "ppid", ppid)
        exe = executable_path if executable_path is not None else kwargs.get("exe")
        object.__setattr__(self, "executable_path", exe)
        cmd = command_line if command_line is not None else kwargs.get("cmdline")
        object.__setattr__(self, "command_line", cmd)
        object.__setattr__(self, "username", username)
        iso = created_at_iso or _format_epoch_to_iso(create_time)
        object.__setattr__(self, "created_at_iso", iso)
        object.__setattr__(self, "hash_sha256", hash_sha256)
        object.__setattr__(self, "parent_name", parent_name)

    @property
    def exe(self) -> str | None:
        """Alias for executable_path."""
        return self.executable_path

    @property
    def cmdline(self) -> str | None:
        """Alias for command_line."""
        return self.command_line


class WindowsProcessMonitor(BaseCollector):
    """Monitors Windows process creation and termination events."""

    def __init__(
        self,
        name: str = "windows_process_monitor",
        pipeline: EventPipeline | None = None,
        endpoint: EndpointIdentity | None = None,
        config: ProcessCollectorConfig | None = None,
    ) -> None:
        super().__init__(
            name=name,
            category=EventCategory.PROCESS,
            pipeline=pipeline,
            endpoint=endpoint,
        )
        self.config = config or ProcessCollectorConfig()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Keyed by (pid, create_time) to eliminate PID reuse collisions
        self._active_processes: dict[tuple[int, float], ProcessSnapshot] = {}
        self._events_emitted_count: int = 0

    @property
    def is_running(self) -> bool:
        """Indicate whether the monitor is running."""
        return self._status == CollectorStatus.RUNNING

    @property
    def events_emitted(self) -> int:
        """Total process security events emitted by this collector."""
        with self._lock:
            return self._events_emitted_count

    @property
    def active_process_count(self) -> int:
        """Count of currently tracked active processes."""
        with self._lock:
            return len(self._active_processes)

    @property
    def active_processes(self) -> dict[tuple[int, float], ProcessSnapshot]:
        """Copy of currently tracked active processes."""
        with self._lock:
            return dict(self._active_processes)

    def _calculate_file_hash(self, file_path: str | None) -> str | None:
        """Compute SHA256 of the executable file if accessible and configured."""
        if not self.config.collect_hashes or not file_path:
            return None
        try:
            target = Path(file_path)
            if not target.is_file() or target.stat().st_size > 10 * 1024 * 1024:
                return None
            hasher = hashlib.sha256()
            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, OSError, FileNotFoundError):
            return None

    def _inspect_process(self, pid: int, proc: Any | None = None) -> ProcessSnapshot | None:
        """Inspect a single process and safely capture available metadata."""
        try:
            if proc is None:
                proc = psutil.Process(pid)
            create_time = proc.create_time()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except psutil.AccessDenied:
            # Fallback for protected processes where access is restricted
            return ProcessSnapshot(
                pid=pid,
                name="unknown",
                create_time=0.0,
            )

        try:
            name = proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            name = f"pid_{pid}"

        try:
            ppid = proc.ppid()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            ppid = None

        parent_name = None
        if ppid:
            try:
                parent_proc = psutil.Process(ppid)
                parent_name = parent_proc.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                parent_name = None

        try:
            exe_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            exe_path = None

        cmd_line: str | None = None
        if self.config.collect_command_line:
            try:
                cmd_parts = proc.cmdline()
                if cmd_parts:
                    raw_cmd = " ".join(cmd_parts)
                    max_len = self.config.max_command_line_length
                    if len(raw_cmd) > max_len:
                        cmd_line = raw_cmd[:max_len] + "... [TRUNCATED]"
                    else:
                        cmd_line = raw_cmd
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                cmd_line = None

        try:
            username = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            username = None

        file_hash = self._calculate_file_hash(exe_path)

        return ProcessSnapshot(
            pid=pid,
            name=name,
            create_time=create_time,
            ppid=ppid,
            executable_path=exe_path,
            command_line=cmd_line,
            username=username,
            created_at_iso=_format_epoch_to_iso(create_time),
            hash_sha256=file_hash,
            parent_name=parent_name,
        )

    def _scan_current_processes(self) -> dict[tuple[int, float], ProcessSnapshot]:
        """Scan all currently running processes and return snapshots keyed by (pid, create_time)."""
        snapshots: dict[tuple[int, float], ProcessSnapshot] = {}
        for proc in psutil.process_iter():
            try:
                snapshot = self._inspect_process(proc.pid, proc=proc)
                if snapshot:
                    snapshots[(snapshot.pid, snapshot.create_time)] = snapshot
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug(f"Error reading process during scan: {exc}")
                continue
        return snapshots

    def _seed_initial_processes(self) -> None:
        """Take an initial snapshot of running processes without emitting creation events."""
        initial = self._scan_current_processes()
        with self._lock:
            self._active_processes = initial
            logger.info(
                f"WindowsProcessMonitor seeded with {len(self._active_processes)} baseline processes"
            )

    def _create_security_event(
        self,
        action: str,
        snapshot: ProcessSnapshot,
        severity: Severity,
        terminated_at: str | None = None,
    ) -> SecurityEvent:
        """Construct canonical SecurityEvent for process lifecycle events."""
        assert self.endpoint is not None, "Endpoint identity must be attached before emitting"

        cmd = snapshot.command_line
        if cmd and len(cmd) > self.config.max_command_line_length:
            cmd = cmd[: self.config.max_command_line_length] + "... [TRUNCATED]"

        process_ctx = ProcessContext(
            pid=snapshot.pid,
            ppid=snapshot.ppid,
            name=snapshot.name,
            executable_path=snapshot.executable_path,
            command_line=cmd,
            username=snapshot.username,
            hash_sha256=snapshot.hash_sha256,
            created_at=snapshot.created_at_iso,
            terminated_at=terminated_at,
            parent_name=snapshot.parent_name,
        )

        return SecurityEvent(
            event_type=EventType(EventCategory.PROCESS, action),
            severity=severity,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(process=process_ctx),
            timestamp=terminated_at if terminated_at else snapshot.created_at_iso,
        )

    def poll_once(self) -> tuple[int, int]:
        """Perform a single reconciliation scan of system processes.

        Returns:
            tuple[int, int]: (new_processes_detected, terminated_processes_detected)
        """
        current_snapshots = self._scan_current_processes()
        current_keys = set(current_snapshots.keys())

        with self._lock:
            previous_keys = set(self._active_processes.keys())

            # 1. New processes = current_keys - previous_keys
            new_keys = current_keys - previous_keys
            new_snapshots = [current_snapshots[k] for k in new_keys]

            # 2. Terminated processes = previous_keys - current_keys
            terminated_keys = previous_keys - current_keys
            terminated_snapshots = [self._active_processes[k] for k in terminated_keys]

            # Reconcile active processes
            for k in terminated_keys:
                self._active_processes.pop(k, None)
            for k in new_keys:
                self._active_processes[k] = current_snapshots[k]

        now_iso = current_utc_timestamp()

        # 3. Emit creation events
        created_count = 0
        for snap in new_snapshots:
            event = self._create_security_event(
                action="CREATE",
                snapshot=snap,
                severity=Severity.LOW,
            )
            try:
                self.emit(event)
                created_count += 1
                with self._lock:
                    self._events_emitted_count += 1
                logger.debug(
                    f"Emitted PROCESS.CREATE: PID {snap.pid} ({snap.name})"
                )
            except Exception as exc:
                logger.warning(
                    f"Failed emitting PROCESS.CREATE for PID {snap.pid}: {exc}"
                )

        # 4. Emit termination events
        terminated_count = 0
        for snap in terminated_snapshots:
            event = self._create_security_event(
                action="TERMINATE",
                snapshot=snap,
                severity=Severity.INFO,
                terminated_at=now_iso,
            )
            try:
                self.emit(event)
                terminated_count += 1
                with self._lock:
                    self._events_emitted_count += 1
                logger.debug(
                    f"Emitted PROCESS.TERMINATE: PID {snap.pid} ({snap.name})"
                )
            except Exception as exc:
                logger.warning(
                    f"Failed emitting PROCESS.TERMINATE for PID {snap.pid}: {exc}"
                )

        return created_count, terminated_count

    def _monitor_loop(self) -> None:
        """Background thread executing periodic reconciliation."""
        interval = self.config.polling_interval
        logger.info(f"WindowsProcessMonitor worker started (polling_interval={interval}s)")

        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                logger.error(f"Unexpected error in process monitor loop: {exc}", exc_info=True)

            self._stop_event.wait(interval)

        logger.info("WindowsProcessMonitor worker loop terminated.")

    def start(self) -> None:
        """Start the Windows process telemetry collector."""
        with self._lock:
            if self._status == CollectorStatus.RUNNING:
                logger.warning("WindowsProcessMonitor is already running")
                return
            if not self.pipeline:
                raise CollectorError("Cannot start WindowsProcessMonitor without active pipeline")
            if not self.endpoint:
                raise CollectorError("Cannot start WindowsProcessMonitor without endpoint identity")

            self._status = CollectorStatus.STARTING
            self._stop_event.clear()

        try:
            # Seed baseline processes
            self._seed_initial_processes()

            with self._lock:
                # Start background monitoring thread
                self._thread = threading.Thread(
                    target=self._monitor_loop,
                    name="TrojanDefense-ProcessMonitor",
                    daemon=True,
                )
                self._thread.start()
                self._status = CollectorStatus.RUNNING
                logger.info("WindowsProcessMonitor successfully STARTED")
        except Exception as exc:
            with self._lock:
                self._status = CollectorStatus.ERROR
                self._error_message = str(exc)
            logger.error(f"Failed to start WindowsProcessMonitor: {exc}", exc_info=True)
            raise CollectorError(f"WindowsProcessMonitor failed to start: {exc}") from exc

    def stop(self) -> None:
        """Stop the Windows process telemetry collector and release resources."""
        with self._lock:
            if self._status not in (CollectorStatus.RUNNING, CollectorStatus.STARTING):
                return
            self._status = CollectorStatus.STOPPING

        logger.info("Stopping WindowsProcessMonitor...")
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
            self._thread = None

        with self._lock:
            self._active_processes.clear()
            self._status = CollectorStatus.STOPPED

        logger.info("WindowsProcessMonitor STOPPED successfully")
