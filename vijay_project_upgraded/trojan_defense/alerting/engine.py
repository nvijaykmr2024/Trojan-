"""Core Alert Engine coordinating risk scoring, deduplication, and persistence.

Consumes behavioral findings, computes bounded explainable risk scores,
suppresses duplicate alert storms, and maintains durable alert lifecycles.
"""

from datetime import datetime, timezone
import threading
import time
from typing import Any

from trojan_defense.alerting.models import Alert, AlertStatus, RiskScore
from trojan_defense.alerting.repository import AlertQueryFilter, SQLiteAlertRepository
from trojan_defense.alerting.scorer import RiskScoringEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.behavior.tracker import parse_event_time
from trojan_defense.core.config.schema import AlertingConfig, RiskConfig
from trojan_defense.core.exceptions import ValidationError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory
from trojan_defense.core.models.identity import EndpointIdentity

logger = get_logger("alerting.engine")


class AlertEngine:
    """Central engine for Phase 10 Risk Scoring and Alert Generation.

    Transforms correlated behavioral findings into prioritized, deduplicated,
    and persistently managed security alerts.
    """

    def __init__(
        self,
        alert_config: AlertingConfig | None = None,
        risk_config: RiskConfig | None = None,
        repository: SQLiteAlertRepository | None = None,
        scorer: RiskScoringEngine | None = None,
    ) -> None:
        self.alert_config = alert_config or AlertingConfig()
        self.risk_config = risk_config or RiskConfig()
        self.repository = repository or SQLiteAlertRepository()
        self.scorer = scorer or RiskScoringEngine(config=self.risk_config)

        # In-memory tracking of active alerts for deduplication and cooldown:
        # dedup_key -> {"alert_id": str, "first_seen_epoch": float, "last_seen_epoch": float}
        self._dedup_cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

        # Telemetry metrics
        self._alerts_generated: int = 0
        self._alerts_suppressed: int = 0
        self._occurrences_recorded: int = 0

    @property
    def is_enabled(self) -> bool:
        """Whether alerting generation is enabled."""
        return self.alert_config.enabled

    @property
    def stats(self) -> dict[str, Any]:
        """Current operational statistics of the alert engine."""
        with self._lock:
            return {
                "enabled": self.alert_config.enabled,
                "alerts_generated": self._alerts_generated,
                "alerts_suppressed": self._alerts_suppressed,
                "occurrences_recorded": self._occurrences_recorded,
                "active_dedup_entries": len(self._dedup_cache),
                "min_alert_score": self.alert_config.min_alert_score,
                "dedup_window_seconds": self.alert_config.dedup_window_seconds,
                "cooldown_seconds": self.alert_config.cooldown_seconds,
            }

    def process_finding(
        self,
        finding: BehaviorFinding,
        endpoint_id: str | None = None,
    ) -> Alert | None:
        """Process a BehaviorFinding into an Alert if criteria and thresholds are met.

        Args:
            finding: Correlated behavioral finding to evaluate.
            endpoint_id: Optional target endpoint identifier.

        Returns:
            Alert if created or updated, or None if disabled or suppressed below threshold.
        """
        if not self.alert_config.enabled:
            return None

        # 1. Calculate explainable risk score
        risk_score: RiskScore = self.scorer.calculate_score(finding)

        # 2. Enforce minimum score threshold
        if risk_score.score < self.alert_config.min_alert_score:
            logger.debug(
                f"Finding {finding.finding_id} score ({risk_score.score}) below "
                f"min_alert_score ({self.alert_config.min_alert_score}); alert not created."
            )
            with self._lock:
                self._alerts_suppressed += 1
            return None

        ep_id = endpoint_id or EndpointIdentity.resolve().endpoint_id
        current_epoch = parse_event_time(finding.timestamp)
        deception_id = self._extract_deception_id(finding)

        # 3. Deduplication and cooldown check
        # Key uses endpoint + rule + PID + process identity to prevent cross-process collisions
        dedup_key = self._build_dedup_key(
            endpoint_id=ep_id,
            rule_id=finding.rule_id,
            pid=finding.pid,
            process_name=finding.process_name,
            executable_path=finding.executable_path,
            deception_id=deception_id,
        )

        with self._lock:
            existing_entry = self._dedup_cache.get(dedup_key)
            if existing_entry:
                last_epoch = existing_entry["last_seen_epoch"]
                time_since_last = current_epoch - last_epoch

                # If within dedup window or cooldown window: suppress new alert, record occurrence
                if time_since_last < max(self.alert_config.dedup_window_seconds, self.alert_config.cooldown_seconds):
                    existing_alert_id = existing_entry["alert_id"]
                    existing_entry["last_seen_epoch"] = current_epoch
                    self._occurrences_recorded += 1
                    self._alerts_suppressed += 1

                    # Update persistent alert in repository
                    alert = self.repository.get_by_id(existing_alert_id)
                    if alert:
                        alert.record_occurrence(finding, event_timestamp=finding.timestamp)
                        self.repository.update(alert)
                        logger.debug(
                            f"Suppressed duplicate alert creation for rule {finding.rule_id}; "
                            f"updated existing alert {existing_alert_id} (count={alert.occurrence_count})"
                        )
                        return alert

        # 4. Create new first-class Alert
        title = f"[{risk_score.severity.to_name()}] {finding.rule_name or finding.rule_id} detected on {finding.process_name or f'PID {finding.pid}' or 'system'}"
        alert = Alert(
            title=title,
            severity=risk_score.severity,
            risk_score=risk_score.score,
            status=AlertStatus.OPEN,
            created_at=finding.timestamp,
            updated_at=finding.timestamp,
            first_seen=finding.start_time or finding.timestamp,
            last_seen=finding.end_time or finding.timestamp,
            occurrence_count=1,
            endpoint_id=ep_id,
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            pid=finding.pid,
            process_name=finding.process_name,
            executable_path=finding.executable_path,
            deception_id=deception_id,
            description=finding.description,
            scoring_reasons=[r.to_dict() for r in risk_score.reasons],
            related_event_ids=list(finding.related_event_ids),
            evidence=list(finding.evidence),
            extra={
                "confidence": finding.confidence,
                "matched_conditions": list(finding.matched_conditions),
                "raw_calculated_score": risk_score.raw_calculated_score,
            },
        )

        # 5. Persist alert
        self.repository.save(alert)

        with self._lock:
            self._alerts_generated += 1
            self._dedup_cache[dedup_key] = {
                "alert_id": alert.alert_id,
                "first_seen_epoch": current_epoch,
                "last_seen_epoch": current_epoch,
            }
            self._prune_dedup_cache(current_epoch)

        logger.info(
            f"Generated Alert {alert.alert_id}: {alert.title} "
            f"(Score: {alert.risk_score}, Severity: {alert.severity.to_name()})"
        )
        return alert

    def process_finding_event(self, event: SecurityEvent) -> Alert | None:
        """Process a canonical SecurityEvent containing behavioral context."""
        if not self.alert_config.enabled:
            return None

        # Verify event category is BEHAVIOR
        if event.event_type.category != EventCategory.BEHAVIOR:
            return None

        finding = self.scorer.extract_finding_from_event(event)
        endpoint_id = event.endpoint.endpoint_id if event.endpoint else None
        return self.process_finding(finding, endpoint_id=endpoint_id)

    def get_alert(self, alert_id: str) -> Alert | None:
        """Retrieve an alert by unique identifier."""
        return self.repository.get_by_id(alert_id)

    def query_alerts(
        self,
        filters: AlertQueryFilter | None = None,
    ) -> tuple[list[Alert], int]:
        """Query alerts with filtering and pagination."""
        return self.repository.query(filters)

    def acknowledge_alert(
        self,
        alert_id: str,
        comment: str | None = None,
    ) -> Alert | None:
        """Transition alert to ACKNOWLEDGED state."""
        alert = self.repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.acknowledge(comment=comment)
        self.repository.update(alert)
        logger.info(f"Alert {alert_id} acknowledged")
        return alert

    def resolve_alert(
        self,
        alert_id: str,
        comment: str | None = None,
    ) -> Alert | None:
        """Transition alert to RESOLVED state."""
        alert = self.repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.resolve(comment=comment)
        self.repository.update(alert)
        logger.info(f"Alert {alert_id} resolved")
        return alert

    def reopen_alert(
        self,
        alert_id: str,
        comment: str | None = None,
    ) -> Alert | None:
        """Reopen an alert back to OPEN state."""
        alert = self.repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.reopen(comment=comment)
        self.repository.update(alert)
        logger.info(f"Alert {alert_id} reopened")
        return alert

    def clear(self) -> None:
        """Reset deduplication state and metrics."""
        with self._lock:
            self._dedup_cache.clear()
            self._alerts_generated = 0
            self._alerts_suppressed = 0
            self._occurrences_recorded = 0

    def _build_dedup_key(
        self,
        endpoint_id: str,
        rule_id: str,
        pid: int | None,
        process_name: str | None,
        executable_path: str | None,
        deception_id: str | None,
    ) -> str:
        """Construct a deduplication key resilient against PID reuse on Windows."""
        proc_str = f"{pid}_{process_name or ''}_{executable_path or ''}"
        decoy_str = deception_id or ""
        return f"{endpoint_id}::{rule_id}::{proc_str}::{decoy_str}"

    def _extract_deception_id(self, finding: BehaviorFinding) -> str | None:
        """Extract decoy or honeytoken ID if present in finding evidence or conditions."""
        for ev in finding.evidence:
            if not isinstance(ev, dict):
                continue
            d_id = ev.get("deception_id") or ev.get("decoy_id")
            if d_id:
                return str(d_id)

        for cond in finding.matched_conditions:
            if "decoy_id=" in cond:
                try:
                    part = cond.split("decoy_id=")[1]
                    d_id = part.split(",")[0].split()[0]
                    if d_id:
                        return d_id.strip()
                except Exception:
                    pass

        return None

    def _prune_dedup_cache(self, current_epoch: float) -> None:
        """Prune dedup cache entries older than twice the cooldown period."""
        max_retention = max(self.alert_config.cooldown_seconds, self.alert_config.dedup_window_seconds) * 2
        cutoff = current_epoch - max_retention
        expired = [
            k for k, entry in self._dedup_cache.items()
            if entry["last_seen_epoch"] < cutoff
        ]
        for k in expired:
            del self._dedup_cache[k]
