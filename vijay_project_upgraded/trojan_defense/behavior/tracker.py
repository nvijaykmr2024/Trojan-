"""State tracking for process identity and multi-event correlation.

Maintains bounded in-memory state of active processes, events within
sliding correlation windows, and provides protection against PID reuse on Windows.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import time
from typing import Any

from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory

logger = get_logger("behavior.tracker")


def parse_event_time(ts: str | None) -> float:
    """Parse ISO 8601 timestamp string into epoch seconds."""
    if not ts:
        return time.time()
    try:
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        return time.time()


@dataclass(frozen=True)
class ProcessIdentityKey:
    """Composite key identifying a distinct process instance to prevent PID reuse collisions."""
    pid: int
    created_at: str | None = None
    executable_path: str | None = None

    def __str__(self) -> str:
        return f"{self.pid}::{self.created_at or 'none'}::{self.executable_path or 'unknown'}"


@dataclass
class TrackedProcess:
    """Represents an active or recently terminated process with its event history."""
    key: ProcessIdentityKey
    pid: int
    name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    created_at: str | None = None
    terminated_at: str | None = None
    is_terminated: bool = False
    is_elevated: bool = False
    events: list[SecurityEvent] = field(default_factory=list)
    last_seen_epoch: float = field(default_factory=time.time)

    def add_event(self, event: SecurityEvent) -> None:
        """Append an event to the chronological history of this process."""
        self.events.append(event)
        event_epoch = parse_event_time(event.timestamp)
        if event_epoch > self.last_seen_epoch:
            self.last_seen_epoch = event_epoch

    def get_events_in_window(
        self,
        window_seconds: float,
        reference_time_epoch: float | None = None,
    ) -> list[SecurityEvent]:
        """Return events occurring within window_seconds prior to reference_time."""
        if not self.events:
            return []
        ref = reference_time_epoch or self.last_seen_epoch
        cutoff = ref - window_seconds
        return [
            evt for evt in self.events
            if parse_event_time(evt.timestamp) >= cutoff
        ]

    def prune_events(self, cutoff_epoch: float) -> int:
        """Remove events older than cutoff_epoch. Returns count of removed events."""
        initial_count = len(self.events)
        self.events = [
            evt for evt in self.events
            if parse_event_time(evt.timestamp) >= cutoff_epoch
        ]
        return initial_count - len(self.events)


class ProcessCorrelationTracker:
    """Thread-safe bounded tracker for correlating telemetry across processes."""

    def __init__(
        self,
        correlation_window_seconds: float = 60.0,
        max_tracked_processes: int = 1000,
    ) -> None:
        self.correlation_window_seconds = correlation_window_seconds
        self.max_tracked_processes = max_tracked_processes
        self._lock = threading.Lock()

        # Map of ProcessIdentityKey -> TrackedProcess (LRU order)
        self._processes: OrderedDict[ProcessIdentityKey, TrackedProcess] = OrderedDict()
        # Map of active PID -> current ProcessIdentityKey
        self._active_pids: dict[int, ProcessIdentityKey] = {}

    @property
    def tracked_count(self) -> int:
        """Total number of tracked processes currently in memory."""
        with self._lock:
            return len(self._processes)

    @property
    def active_pid_count(self) -> int:
        """Number of active non-terminated PIDs."""
        with self._lock:
            return len(self._active_pids)

    def track_event(self, event: SecurityEvent) -> TrackedProcess | None:
        """Ingest an event, updating or creating process tracking state.

        Applies PID reuse detection on PROCESS.CREATE/TERMINATE.
        """
        pid = self._extract_pid(event)
        if pid is None:
            # Events without any associated PID cannot be tracked by process
            return None

        event_epoch = parse_event_time(event.timestamp)

        with self._lock:
            # Check if this is a process lifecycle event
            is_process_event = (
                event.event_type.category == EventCategory.PROCESS
                and event.event_type.action in ("CREATE", "TERMINATE")
            )

            # Detect PID reuse on CREATE:
            # If a process create event arrives for a PID that was already active,
            # close/retire the old process record and start a new identity.
            if is_process_event and event.event_type.action == "CREATE":
                if pid in self._active_pids:
                    old_key = self._active_pids[pid]
                    if old_key in self._processes:
                        self._processes[old_key].is_terminated = True
                        self._processes[old_key].terminated_at = event.timestamp
                    del self._active_pids[pid]

            # Resolve or create the TrackedProcess
            tracked = self._get_or_create_process(event, pid, event_epoch)

            # If this is a TERMINATE event, mark terminated
            if is_process_event and event.event_type.action == "TERMINATE":
                tracked.is_terminated = True
                tracked.terminated_at = event.timestamp
                if pid in self._active_pids and self._active_pids[pid] == tracked.key:
                    del self._active_pids[pid]

            # Update elevation metadata if privilege information is present
            if event.context:
                if event.context.privilege and event.context.privilege.is_elevated:
                    tracked.is_elevated = True
                elif (
                    event.context.process
                    and getattr(event.context.process, "is_elevated", False)
                ):
                    tracked.is_elevated = True

            # Append event
            tracked.add_event(event)

            # Move key to end for LRU tracking
            if tracked.key in self._processes:
                self._processes.move_to_end(tracked.key)

            # Housekeeping: prune old events and enforce max size
            self._prune_expired_locked(event_epoch)
            self._enforce_capacity_locked()

            return tracked

    def get_process(self, pid: int) -> TrackedProcess | None:
        """Retrieve the currently active TrackedProcess for a PID."""
        with self._lock:
            key = self._active_pids.get(pid)
            if key and key in self._processes:
                return self._processes[key]
            return None

    def get_process_by_key(self, key: ProcessIdentityKey) -> TrackedProcess | None:
        """Retrieve a TrackedProcess by its exact composite key."""
        with self._lock:
            return self._processes.get(key)

    def get_all_tracked(self) -> list[TrackedProcess]:
        """Return a snapshot of all tracked processes."""
        with self._lock:
            return list(self._processes.values())

    def clear(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._processes.clear()
            self._active_pids.clear()


    def _extract_pid(self, event: SecurityEvent) -> int | None:
        """Extract PID from any available context section of the event."""
        if not event.context:
            return None
        if event.context.process and event.context.process.pid is not None:
            return event.context.process.pid
        if event.context.network and event.context.network.pid is not None:
            return event.context.network.pid
        return None

    def _get_or_create_process(
        self,
        event: SecurityEvent,
        pid: int,
        event_epoch: float,
    ) -> TrackedProcess:
        """Resolve existing TrackedProcess or instantiate a new one."""
        proc_ctx = event.context.process if event.context else None

        # If PID is currently active, reuse that process record
        if pid in self._active_pids:
            key = self._active_pids[pid]
            tracked = self._processes[key]
            # Update metadata if newly available
            if proc_ctx:
                if proc_ctx.name and not tracked.name:
                    tracked.name = proc_ctx.name
                if proc_ctx.executable_path and not tracked.executable_path:
                    tracked.executable_path = proc_ctx.executable_path
                if proc_ctx.command_line and not tracked.command_line:
                    tracked.command_line = proc_ctx.command_line
            return tracked

        # Create new process key
        created_at = proc_ctx.created_at if proc_ctx else None
        exe_path = proc_ctx.executable_path if proc_ctx else None
        proc_name = proc_ctx.name if proc_ctx else None

        key = ProcessIdentityKey(
            pid=pid,
            created_at=created_at or event.timestamp,
            executable_path=exe_path,
        )

        tracked = TrackedProcess(
            key=key,
            pid=pid,
            name=proc_name,
            executable_path=exe_path,
            command_line=proc_ctx.command_line if proc_ctx else None,
            created_at=created_at or event.timestamp,
            last_seen_epoch=event_epoch,
        )

        self._processes[key] = tracked
        self._active_pids[pid] = key
        return tracked

    def _prune_expired_locked(self, current_epoch: float) -> None:
        """Prune events and processes exceeding the correlation window."""
        cutoff = current_epoch - (self.correlation_window_seconds * 2)
        expired_keys = []

        for key, proc in self._processes.items():
            proc.prune_events(current_epoch - self.correlation_window_seconds)
            # If the process is terminated and has no recent events, it can be retired
            if proc.is_terminated and proc.last_seen_epoch < cutoff:
                expired_keys.append(key)

        for key in expired_keys:
            if key.pid in self._active_pids and self._active_pids[key.pid] == key:
                del self._active_pids[key.pid]
            del self._processes[key]

    def _enforce_capacity_locked(self) -> None:
        """Ensure total tracked processes does not exceed max_tracked_processes."""
        while len(self._processes) > self.max_tracked_processes:
            oldest_key, oldest_proc = self._processes.popitem(last=False)
            if oldest_key.pid in self._active_pids and self._active_pids[oldest_key.pid] == oldest_key:
                del self._active_pids[oldest_key.pid]
