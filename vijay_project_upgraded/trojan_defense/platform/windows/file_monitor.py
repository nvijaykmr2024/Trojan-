"""Windows Filesystem Monitoring Collector for detecting file and directory activity.

Uses watchdog (WindowsApiObserver / ReadDirectoryChangesW) to observe real Windows
filesystem events, captures rich file telemetry, normalizes paths, debounces rapid
modification bursts, handles file locks and permission boundaries gracefully, and emits
canonical SecurityEvents into the event pipeline.
"""

from collections.abc import Sequence
from fnmatch import fnmatch
import hashlib
import os
from pathlib import Path
import threading
import time
from typing import Any

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
    FileModifiedEvent,
    FileMovedEvent,
)
from watchdog.observers import Observer

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.config.schema import FileCollectorConfig
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import EventContext, FileContext
from trojan_defense.core.models.event import SecurityEvent, current_utc_timestamp
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline

logger = get_logger("platform.windows.file_monitor")


def normalize_path(path: str | Path) -> str:
    """Normalize filesystem path to a canonical, absolute representation."""
    try:
        resolved = Path(path).resolve()
        return str(resolved)
    except Exception:
        return os.path.normpath(os.path.abspath(str(path)))


def is_path_contained(target_path: str | Path, root_path: str | Path) -> bool:
    """Verify whether target_path resides inside root_path using canonical comparison."""
    try:
        target_res = Path(target_path).resolve()
        root_res = Path(root_path).resolve()
        target_res.relative_to(root_res)
        return True
    except (ValueError, RuntimeError):
        return False


class FileTelemetryEventHandler(FileSystemEventHandler):
    """Event handler that transforms watchdog events into canonical SecurityEvents."""

    def __init__(self, monitor: "WindowsFileMonitor") -> None:
        super().__init__()
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            self.monitor._process_event(
                action="DIR_CREATE",
                path=event.src_path,
                is_directory=True,
                severity=Severity.LOW,
            )
        else:
            self.monitor._process_event(
                action="CREATE",
                path=event.src_path,
                is_directory=False,
                severity=Severity.LOW,
            )

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            # Directory modification events (timestamp/mtime updates) are low value
            return

        self.monitor._process_event(
            action="MODIFY",
            path=event.src_path,
            is_directory=False,
            severity=Severity.LOW,
        )

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            self.monitor._process_event(
                action="DIR_DELETE",
                path=event.src_path,
                is_directory=True,
                severity=Severity.INFO,
            )
        else:
            self.monitor._process_event(
                action="DELETE",
                path=event.src_path,
                is_directory=False,
                severity=Severity.MEDIUM,
            )

    def on_moved(self, event: FileSystemMovedEvent) -> None:
        if event.is_directory:
            self.monitor._process_event(
                action="DIR_RENAME",
                path=event.dest_path,
                previous_path=event.src_path,
                is_directory=True,
                severity=Severity.LOW,
            )
        else:
            self.monitor._process_event(
                action="RENAME",
                path=event.dest_path,
                previous_path=event.src_path,
                is_directory=False,
                severity=Severity.LOW,
            )


class WindowsFileMonitor(BaseCollector):
    """Monitors Windows filesystem activity using event-driven notifications."""

    def __init__(
        self,
        name: str = "windows_file_monitor",
        pipeline: EventPipeline | None = None,
        endpoint: EndpointIdentity | None = None,
        config: FileCollectorConfig | None = None,
        deception_detector: Any = None,
    ) -> None:
        super().__init__(
            name=name,
            category=EventCategory.FILE,
            pipeline=pipeline,
            endpoint=endpoint,
        )
        self.config = config or FileCollectorConfig()
        self._lock = threading.RLock()
        self._observer: Observer | None = None
        self._watches: list[Any] = []
        self._events_emitted_count: int = 0
        self._deception_detector: Any = deception_detector

        # Debounce tracking for rapid modification bursts: path -> epoch seconds
        self._recent_modifications: dict[str, float] = {}

    @property
    def deception_detector(self) -> Any:
        """Attached deception interaction detector, if configured."""
        with self._lock:
            return self._deception_detector

    def set_deception_detector(self, detector: Any) -> None:
        """Attach or update the deception interaction detector."""
        with self._lock:
            self._deception_detector = detector

    @property
    def is_running(self) -> bool:
        """Indicate whether the monitor is running."""
        return self._status == CollectorStatus.RUNNING

    @property
    def events_emitted(self) -> int:
        """Total file security events emitted by this collector."""
        with self._lock:
            return self._events_emitted_count

    @property
    def monitored_paths(self) -> list[str]:
        """List of configured paths monitored by this collector."""
        return list(self.config.monitored_paths)

    def _should_ignore(self, file_name: str) -> bool:
        """Check if filename matches any configured ignore pattern."""
        for pattern in self.config.ignore_patterns:
            if fnmatch(file_name, pattern):
                return True
        return False

    def _is_debounced(self, normalized_path: str, action: str) -> bool:
        """Check and update debouncing for modification events."""
        if action != "MODIFY" or self.config.debounce_ms <= 0:
            return False

        now = time.time()
        debounce_window_sec = self.config.debounce_ms / 1000.0

        with self._lock:
            last_time = self._recent_modifications.get(normalized_path)
            if last_time is not None and (now - last_time) < debounce_window_sec:
                # Event is part of an ongoing rapid burst — coalesce it
                return True
            self._recent_modifications[normalized_path] = now

            # Housekeep debounce cache if it grows large
            if len(self._recent_modifications) > 2000:
                cutoff = now - (debounce_window_sec * 2)
                self._recent_modifications = {
                    p: t for p, t in self._recent_modifications.items() if t >= cutoff
                }

        return False

    def _calculate_file_hash(self, file_path: str) -> str | None:
        """Compute SHA256 of the target file if accessible, within size limit, and configured."""
        if not self.config.collect_hashes:
            return None
        try:
            target = Path(file_path)
            if not target.is_file() or target.stat().st_size > self.config.max_hash_file_size_bytes:
                return None
            hasher = hashlib.sha256()
            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, OSError, FileNotFoundError):
            return None

    def _extract_file_metadata(
        self, path: str, is_directory: bool, action: str
    ) -> tuple[int | None, str | None]:
        """Safely extract file size and optional hash without blocking or failing on locks."""
        if is_directory or action in ("DELETE", "DIR_DELETE"):
            return None, None

        size_bytes: int | None = None
        try:
            size_bytes = os.path.getsize(path)
        except (OSError, FileNotFoundError, PermissionError):
            size_bytes = None

        file_hash = self._calculate_file_hash(path)
        return size_bytes, file_hash

    def _create_security_event(
        self,
        action: str,
        path: str,
        is_directory: bool,
        severity: Severity,
        previous_path: str | None = None,
    ) -> SecurityEvent:
        """Construct canonical SecurityEvent for filesystem telemetry."""
        assert self.endpoint is not None, "Endpoint identity must be attached before emitting"

        norm_path = normalize_path(path)
        norm_prev_path = normalize_path(previous_path) if previous_path else None
        p_obj = Path(norm_path)

        file_name = p_obj.name
        directory = str(p_obj.parent)
        extension = p_obj.suffix.lower() if (not is_directory and p_obj.suffix) else None

        size_bytes, file_hash = self._extract_file_metadata(norm_path, is_directory, action)

        file_ctx = FileContext(
            path=norm_path,
            operation=action.lower(),
            size_bytes=size_bytes,
            hash_sha256=file_hash,
            is_directory=is_directory,
            file_name=file_name,
            directory=directory,
            extension=extension,
            previous_path=norm_prev_path,
        )

        return SecurityEvent(
            event_type=EventType(EventCategory.FILE, action),
            severity=severity,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(file=file_ctx),
            timestamp=current_utc_timestamp(),
        )

    def _process_event(
        self,
        action: str,
        path: str,
        is_directory: bool,
        severity: Severity,
        previous_path: str | None = None,
    ) -> SecurityEvent | None:
        """Internal worker called upon receiving a filesystem event."""
        norm_path = normalize_path(path)
        p_obj = Path(norm_path)

        # Ignore temporary files matching configured ignore patterns
        if self._should_ignore(p_obj.name):
            logger.debug(f"Ignoring file matching pattern: {norm_path}")
            return None

        # Coalesce burst modification events
        if self._is_debounced(norm_path, action):
            logger.debug(f"Coalesced burst modification event for {norm_path}")
            return None

        try:
            event = self._create_security_event(
                action=action,
                path=norm_path,
                is_directory=is_directory,
                severity=severity,
                previous_path=previous_path,
            )
            self.emit(event)
            with self._lock:
                self._events_emitted_count += 1
            logger.debug(
                f"Emitted FILE.{action}: {norm_path}"
                + (f" (from {previous_path})" if previous_path else "")
            )

            # Analyze for interactions with registered cyber deception decoys
            detector = self._deception_detector
            if detector is not None:
                try:
                    detector.analyze_event(event)
                except Exception as exc:
                    logger.warning(f"Error during deception interaction detection: {exc}")

            return event
        except Exception as exc:
            logger.warning(f"Failed emitting FILE.{action} for '{norm_path}': {exc}")
            return None

    def start(self) -> None:
        """Start the Windows filesystem telemetry collector."""
        with self._lock:
            if self._status == CollectorStatus.RUNNING:
                logger.warning("WindowsFileMonitor is already running")
                return
            if not self.pipeline:
                raise CollectorError("Cannot start WindowsFileMonitor without active pipeline")
            if not self.endpoint:
                raise CollectorError("Cannot start WindowsFileMonitor without endpoint identity")

            self._status = CollectorStatus.STARTING

        try:
            handler = FileTelemetryEventHandler(self)
            observer = Observer()
            scheduled_count = 0

            for root in self.config.monitored_paths:
                resolved_root = Path(root).resolve()
                if not resolved_root.exists():
                    # Create default project runtime directory safely if configured
                    try:
                        resolved_root.mkdir(parents=True, exist_ok=True)
                        logger.info(f"Created configured monitored root: {resolved_root}")
                    except OSError as exc:
                        logger.warning(
                            f"Could not create monitored root '{resolved_root}': {exc}"
                        )
                        continue

                try:
                    watch = observer.schedule(
                        handler,
                        str(resolved_root),
                        recursive=self.config.recursive,
                    )
                    self._watches.append(watch)
                    scheduled_count += 1
                    logger.info(
                        f"Watching root '{resolved_root}' (recursive={self.config.recursive})"
                    )
                except Exception as exc:
                    logger.warning(f"Failed to watch root '{resolved_root}': {exc}")

            if scheduled_count == 0:
                raise CollectorError(
                    f"No monitored roots could be watched out of: {self.config.monitored_paths}"
                )

            observer.start()

            with self._lock:
                self._observer = observer
                self._status = CollectorStatus.RUNNING
                logger.info(
                    f"WindowsFileMonitor successfully STARTED ({scheduled_count} roots watched)"
                )

        except Exception as exc:
            with self._lock:
                self._status = CollectorStatus.ERROR
                self._error_message = str(exc)
            logger.error(f"Failed to start WindowsFileMonitor: {exc}", exc_info=True)
            raise CollectorError(f"WindowsFileMonitor failed to start: {exc}") from exc

    def stop(self) -> None:
        """Stop the Windows filesystem telemetry collector and release resources."""
        with self._lock:
            if self._status not in (CollectorStatus.RUNNING, CollectorStatus.STARTING):
                return
            self._status = CollectorStatus.STOPPING
            observer = self._observer
            self._observer = None

        logger.info("Stopping WindowsFileMonitor...")

        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=3.0)
            except Exception as exc:
                logger.error(f"Error stopping filesystem observer: {exc}")

        with self._lock:
            self._watches.clear()
            self._recent_modifications.clear()
            self._status = CollectorStatus.STOPPED

        logger.info("WindowsFileMonitor STOPPED successfully")

    def health_check(self) -> bool:
        """Return True if the collector is healthy and observer thread is running."""
        with self._lock:
            if self._status != CollectorStatus.RUNNING:
                return False
            if self._observer is None or not self._observer.is_alive():
                return False
            return True
