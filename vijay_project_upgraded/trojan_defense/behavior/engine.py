"""Behavioral Correlation and Detection Engine.

Coordinates state tracking, rule evaluation, finding deduplication,
and event pipeline emission for correlated behavioral telemetry.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import threading
import time
from typing import Any

from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.behavior.rules import (
    BehaviorRule,
    DecoyInteractionSequenceRule,
    PrivilegedProcessActivityRule,
    ProcessFileActivityRule,
    ProcessFileNetworkSequenceRule,
    ProcessNetworkActivityRule,
)
from trojan_defense.behavior.tracker import ProcessCorrelationTracker, parse_event_time
from trojan_defense.core.config.schema import BehaviorConfig
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory

logger = get_logger("behavior.engine")


class BehaviorCorrelationEngine:
    """Deterministic behavioral correlation and detection engine."""

    def __init__(
        self,
        config: BehaviorConfig | None = None,
        tracker: ProcessCorrelationTracker | None = None,
        pipeline: Any | None = None,
    ) -> None:
        self.config = config or BehaviorConfig()
        self.tracker = tracker or ProcessCorrelationTracker(
            correlation_window_seconds=self.config.correlation_window_seconds,
            max_tracked_processes=self.config.max_tracked_processes,
        )
        self.pipeline = pipeline
        self._rules: dict[str, BehaviorRule] = {}
        self._dedup_cache: dict[str, float] = {}
        self._lock = threading.Lock()
        self._total_findings: int = 0
        self._total_events_analyzed: int = 0

        # Register default 5 deterministic rules
        self.register_rule(ProcessFileActivityRule())
        self.register_rule(ProcessNetworkActivityRule())
        self.register_rule(PrivilegedProcessActivityRule())
        self.register_rule(ProcessFileNetworkSequenceRule())
        self.register_rule(DecoyInteractionSequenceRule())

    @property
    def is_enabled(self) -> bool:
        """Whether behavioral correlation is enabled."""
        return self.config.enabled

    @property
    def stats(self) -> dict[str, Any]:
        """Telemetry and metrics for the correlation engine."""
        with self._lock:
            return {
                "enabled": self.config.enabled,
                "events_analyzed": self._total_events_analyzed,
                "findings_generated": self._total_findings,
                "active_rules_count": len(self._rules),
                "tracked_processes": self.tracker.tracked_count,
                "active_pids": self.tracker.active_pid_count,
                "dedup_cache_size": len(self._dedup_cache),
            }

    def register_rule(self, rule: BehaviorRule) -> None:
        """Register a behavioral correlation rule."""
        with self._lock:
            self._rules[rule.rule_id] = rule
            logger.debug(f"Registered behavior rule: {rule.rule_id} ({rule.name})")

    def get_rule(self, rule_id: str) -> BehaviorRule | None:
        """Retrieve a registered rule by its identifier."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> list[BehaviorRule]:
        """List all currently registered rules."""
        with self._lock:
            return list(self._rules.values())

    def analyze_event(self, event: SecurityEvent) -> list[BehaviorFinding]:
        """Analyze an incoming event against stateful behavioral rules.

        Returns list of new non-deduplicated findings.
        If pipeline is attached, also submits generated finding events into the pipeline.
        """
        # 1. Check if engine is enabled
        if not self.config.enabled:
            return []

        # 2. Strict recursion guard: never re-analyze behavioral findings
        if event.event_type.category == EventCategory.BEHAVIOR:
            return []

        with self._lock:
            self._total_events_analyzed += 1

        # 3. Update state tracking
        self.tracker.track_event(event)

        event_epoch = parse_event_time(event.timestamp)
        new_findings: list[BehaviorFinding] = []

        # 4. Evaluate registered rules
        active_rules = self.list_rules()
        for rule in active_rules:
            # Check if this rule is enabled in configuration
            if self.config.rules and not self.config.rules.get(rule.rule_id, True):
                continue

            try:
                candidate_findings = rule.evaluate(
                    event=event,
                    tracker=self.tracker,
                    window_seconds=self.config.correlation_window_seconds,
                )
                for finding in candidate_findings:
                    if self._is_duplicate(finding, event_epoch):
                        logger.debug(
                            f"Suppressed duplicate finding for rule {finding.rule_id} on PID {finding.pid}"
                        )
                        continue

                    new_findings.append(finding)
                    with self._lock:
                        self._total_findings += 1

            except Exception as exc:
                logger.error(
                    f"Error evaluating rule {rule.rule_id} on event {event.event_id}: {exc}",
                    exc_info=True,
                )

        # 5. Clean up expired deduplication entries
        self._prune_dedup_cache(event_epoch)

        # 6. Route findings through pipeline if configured
        if self.pipeline and new_findings:
            for finding in new_findings:
                try:
                    finding_event = finding.to_security_event(endpoint=event.endpoint)
                    self.pipeline.process(finding_event)
                except Exception as exc:
                    logger.error(
                        f"Error routing behavioral finding {finding.finding_id} into pipeline: {exc}",
                        exc_info=True,
                    )


        return new_findings

    def clear(self) -> None:
        """Clear tracker state and deduplication cache."""
        with self._lock:
            self.tracker.clear()
            self._dedup_cache.clear()
            self._total_findings = 0
            self._total_events_analyzed = 0

    def _is_duplicate(self, finding: BehaviorFinding, current_epoch: float) -> bool:
        """Determine if a finding is a duplicate within dedup_window_seconds."""
        dedup_key = f"{finding.rule_id}::{finding.pid}::{finding.description}"
        with self._lock:
            last_epoch = self._dedup_cache.get(dedup_key)
            if last_epoch is not None and (current_epoch - last_epoch) < self.config.dedup_window_seconds:
                return True
            self._dedup_cache[dedup_key] = current_epoch
            return False

    def _prune_dedup_cache(self, current_epoch: float) -> None:
        """Prune entries from deduplication cache older than 2x dedup window."""
        cutoff = current_epoch - (self.config.dedup_window_seconds * 2)
        with self._lock:
            expired_keys = [
                k for k, last_ts in self._dedup_cache.items()
                if last_ts < cutoff
            ]
            for k in expired_keys:
                del self._dedup_cache[k]
