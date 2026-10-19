"""Deception Interaction Detector for identifying interactions with registered decoys.

Consumes filesystem telemetry from Phase 4 WindowsFileMonitor, performs canonical
registry queries against Phase 7 DecoyRegistry, and emits authoritative
DECEPTION.INTERACTION telemetry without altering the filesystem or scoring threat.
"""

from pathlib import Path
import threading
import time
from typing import Any
import uuid

from trojan_defense.core.config.schema import DeceptionConfig
from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import DeceptionContext, EventContext
from trojan_defense.core.models.event import (
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
    current_utc_timestamp,
)
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.deception.models import DecoyRecord
from trojan_defense.deception.registry import DecoyRegistry

logger = get_logger("deception.detector")


class DeceptionDetectionError(TrojanDefenseError):
    """Raised on deception interaction detection failure."""
    pass


class DeceptionInteractionDetector:
    """Detects and generates telemetry for interactions with registered Phase 7 decoys.

    Architectural Boundary:
    - Observes existing Phase 4 filesystem telemetry; does NOT create a separate watcher.
    - Queries Phase 7 DecoyRegistry; does NOT maintain a separate list of decoys.
    - Emits factual DECEPTION.INTERACTION events; does NOT score risk or trigger remediation.
    """

    # Mapping from Phase 4 file action to canonical interaction type
    ACTION_TO_INTERACTION: dict[str, str] = {
        "CREATE": "created",
        "create": "created",
        "MODIFY": "modified",
        "modify": "modified",
        "DELETE": "deleted",
        "delete": "deleted",
        "RENAME": "renamed",
        "rename": "renamed",
        "DIR_CREATE": "dir_created",
        "dir_create": "dir_created",
        "DIR_DELETE": "dir_deleted",
        "dir_delete": "dir_deleted",
        "DIR_RENAME": "dir_renamed",
        "dir_rename": "dir_renamed",
    }

    def __init__(
        self,
        registry: DecoyRegistry,
        pipeline: EventPipeline | None = None,
        config: DeceptionConfig | None = None,
        endpoint: EndpointIdentity | None = None,
    ) -> None:
        self.registry = registry
        self.pipeline = pipeline
        self.config = config or DeceptionConfig()
        self.endpoint = endpoint

        self._lock = threading.RLock()
        self._events_evaluated_count: int = 0
        self._interactions_detected_count: int = 0
        self._interactions_emitted_count: int = 0

        # Debounce tracking: (decoy_id, interaction_type) -> epoch timestamp
        self._recent_interactions: dict[tuple[str, str], float] = {}

    @property
    def is_enabled(self) -> bool:
        """Check if deception interaction detection is operationally enabled."""
        return bool(self.config.interaction_detection_enabled)

    def is_decoy(self, path: str | Path) -> bool:
        """Check if a path corresponds to a registered Phase 7 decoy."""
        if not path:
            return False
        try:
            return self.registry.is_owned(path)
        except Exception as exc:
            logger.debug(f"Path query check failed for '{path}': {exc}")
            return False

    def get_decoy(self, path: str | Path) -> DecoyRecord | None:
        """Retrieve the decoy record for a path if it is a registered decoy."""
        if not path:
            return None
        try:
            return self.registry.get_by_path(path)
        except Exception as exc:
            logger.debug(f"Decoy lookup failed for '{path}': {exc}")
            return None

    def get_decoy_by_id(self, decoy_id: str) -> DecoyRecord | None:
        """Retrieve a registered decoy record by its ID."""
        if not decoy_id:
            return None
        return self.registry.get_by_id(decoy_id)

    def _is_debounced(self, decoy_id: str, interaction_type: str) -> bool:
        """Debounce rapid repeated events on the same decoy to prevent alert storms."""
        now = time.time()
        debounce_sec = max(0.01, self.config.interaction_debounce_ms / 1000.0)
        key = (decoy_id, interaction_type)

        with self._lock:
            last_time = self._recent_interactions.get(key)
            if last_time is not None and (now - last_time) < debounce_sec:
                return True
            self._recent_interactions[key] = now

            # Clean cache if it grows large
            if len(self._recent_interactions) > 1000:
                cutoff = now - (debounce_sec * 2)
                self._recent_interactions = {
                    k: t for k, t in self._recent_interactions.items() if t >= cutoff
                }

        return False

    def analyze_event(self, event: SecurityEvent) -> SecurityEvent | None:
        """Inspect a SecurityEvent to determine whether it affected a registered decoy.

        If a registered decoy was affected:
        - Constructs a DECEPTION.INTERACTION event preserving decoy, file, and process context.
        - Emits to the event pipeline if configured.
        - Returns the generated DECEPTION.INTERACTION event.

        If no registered decoy was affected or detector is disabled:
        - Returns None, leaving the original event as ordinary filesystem telemetry.
        """
        if not self.is_enabled:
            return None

        # Only evaluate filesystem events
        if event.event_type.category != EventCategory.FILE:
            return None

        file_ctx = event.context.file if event.context else None
        if not file_ctx or not file_ctx.path:
            return None

        with self._lock:
            self._events_evaluated_count += 1

        target_path = file_ctx.path
        prev_path = file_ctx.previous_path

        # 1. Lookup decoy in Phase 7 DecoyRegistry
        decoy: DecoyRecord | None = None
        try:
            decoy = self.registry.get_by_path(target_path)
            # For rename/move events, check if previous_path was the registered decoy
            if not decoy and prev_path:
                decoy = self.registry.get_by_path(prev_path)
        except Exception as exc:
            logger.warning(f"Error querying registry for path '{target_path}': {exc}")
            return None

        # If not a registered decoy, return None (ordinary file)
        if not decoy:
            return None

        # 2. Determine Interaction Type
        op = file_ctx.operation or event.event_type.action or "UNKNOWN"
        interaction_type = self.ACTION_TO_INTERACTION.get(op, op.lower())

        # 3. Check Debounce Cache
        if self._is_debounced(decoy.decoy_id, interaction_type):
            logger.debug(
                f"Suppressed duplicate interaction burst for decoy '{decoy.decoy_id}' ({interaction_type})"
            )
            return None

        # 4. Construct DECEPTION.INTERACTION Event
        with self._lock:
            self._interactions_detected_count += 1

        interaction_event = self._build_interaction_event(
            original_event=event,
            decoy=decoy,
            interaction_type=interaction_type,
        )

        # 5. Emit to Pipeline if configured
        if self.pipeline:
            try:
                self.pipeline.process(interaction_event)
                with self._lock:
                    self._interactions_emitted_count += 1
                logger.info(
                    f"Emitted DECEPTION.INTERACTION for decoy '{decoy.decoy_id}' "
                    f"({interaction_type}) at '{decoy.normalized_path}'"
                )
            except Exception as exc:
                logger.error(
                    f"Failed emitting DECEPTION.INTERACTION event to pipeline: {exc}",
                    exc_info=True,
                )

        return interaction_event

    def _build_interaction_event(
        self,
        original_event: SecurityEvent,
        decoy: DecoyRecord,
        interaction_type: str,
    ) -> SecurityEvent:
        """Build canonical SecurityEvent for deception interaction."""
        endpoint = original_event.endpoint or self.endpoint
        assert endpoint is not None, "Endpoint identity must be present"

        # Determine severity based strictly on interaction type
        if interaction_type in ("deleted", "dir_deleted", "modified"):
            severity = Severity.HIGH
        elif interaction_type in ("renamed", "dir_renamed"):
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        deception_ctx = DeceptionContext(
            is_decoy=True,
            decoy_id=decoy.decoy_id,
            decoy_type=decoy.artifact_type,
            interaction_type=interaction_type,
            path=decoy.normalized_path,
            relative_path=decoy.relative_path,
            action=original_event.context.file.operation if original_event.context.file else None,
            status=decoy.status,
            original_event_id=original_event.event_id,
        )

        composite_context = EventContext(
            file=original_event.context.file if original_event.context else None,
            process=original_event.context.process if original_event.context else None,
            system=original_event.context.system if original_event.context else None,
            deception=deception_ctx,
            extra={
                "original_event_id": original_event.event_id,
                "original_source": original_event.source,
                "decoy_purpose": decoy.purpose,
            },
        )

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType(EventCategory.DECEPTION, "INTERACTION"),
            severity=severity,
            source="deception_interaction_detector",
            endpoint=endpoint,
            context=composite_context,
            timestamp=current_utc_timestamp(),
        )

    def status(self) -> dict[str, Any]:
        """Return operational telemetry metrics of the detector."""
        with self._lock:
            return {
                "enabled": self.is_enabled,
                "events_evaluated": self._events_evaluated_count,
                "interactions_detected": self._interactions_detected_count,
                "interactions_emitted": self._interactions_emitted_count,
                "registered_decoys_count": len(self.registry.list_decoys(active_only=True)),
            }
