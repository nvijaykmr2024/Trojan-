"""Backend EventService encapsulating business logic for event ingestion,
validation, normalization, deduplication, and query dispatching.
"""

from collections.abc import Sequence
from typing import Any

from trojan_defense.alerting.models import Alert, AlertStatus
from trojan_defense.alerting.repository import AlertQueryFilter, SQLiteAlertRepository
from trojan_defense.core.exceptions import PersistenceError, ValidationError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.persistence.base import BaseEventRepository, EventQueryFilter
from trojan_defense.core.pipeline.normalizer import EventNormalizer
from trojan_defense.core.pipeline.validator import EventValidator
from trojan_defense.response.auth import Permission, UserContext
from trojan_defense.response.executor import ResponseExecutor
from trojan_defense.response.models import (
    AuditActionType,
    AuditLogEntry,
    Incident,
    IncidentNote,
    IncidentStatus,
    ResponseAction,
    ResponseActionType,
)
from trojan_defense.response.recommender import ActionRecommendation, ResponseRecommender
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)

logger = get_logger("backend.service")


class EventService:
    """Authoritative service for telemetry ingestion, querying, alerting, and incident response."""

    def __init__(
        self,
        repository: BaseEventRepository,
        validator: EventValidator | None = None,
        normalizer: EventNormalizer | None = None,
        alert_repository: SQLiteAlertRepository | None = None,
        alert_engine: Any | None = None,
        incident_repository: SQLiteIncidentRepository | None = None,
        response_action_repository: SQLiteResponseActionRepository | None = None,
        response_executor: ResponseExecutor | None = None,
        response_recommender: ResponseRecommender | None = None,
        audit_repository: SQLiteAuditRepository | None = None,
    ) -> None:
        self.repository = repository
        self.validator = validator or EventValidator()
        self.normalizer = normalizer or EventNormalizer()
        self.alert_repository = alert_repository
        self.alert_engine = alert_engine
        self.incident_repository = incident_repository
        self.response_action_repository = response_action_repository
        self.response_executor = response_executor
        self.response_recommender = response_recommender or ResponseRecommender()
        self.audit_repository = audit_repository

    def ingest_event(self, event_data: dict[str, Any] | SecurityEvent) -> tuple[SecurityEvent, bool]:
        """Validate, normalize, and persist an incoming security event.

        Args:
            event_data: Raw JSON-parsed dictionary or pre-constructed SecurityEvent.

        Returns:
            tuple[SecurityEvent, bool]: (event, is_new)
                is_new is True if persisted as a new event, False if it was a duplicate.

        Raises:
            ValidationError: If event structure or fields violate schema.
            PersistenceError: If database storage encounters an unrecoverable failure.
        """
        # 1. Parse into canonical SecurityEvent
        if isinstance(event_data, dict):
            try:
                event = SecurityEvent.from_dict(event_data)
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning(f"Event parsing rejected: {exc}")
                raise ValidationError(f"Invalid event structure: {exc}") from exc
        elif isinstance(event_data, SecurityEvent):
            event = event_data
        else:
            raise ValidationError(f"Unsupported event payload type: '{type(event_data).__name__}'")

        # 2. Normalize
        normalized_event = self.normalizer.normalize(event)

        # 3. Validate
        self.validator.validate(normalized_event)

        # 4. Check for duplicate and persist
        is_new = self.repository.save(normalized_event)
        if not is_new:
            logger.info(
                f"Duplicate event detected and preserved without mutation: '{normalized_event.event_id}' "
                f"(endpoint: '{normalized_event.endpoint.endpoint_id}')"
            )
            return normalized_event, False

        logger.info(
            f"Successfully ingested event '{normalized_event.event_id}' "
            f"[{normalized_event.event_type.value}] from endpoint '{normalized_event.endpoint.endpoint_id}'"
        )
        return normalized_event, True

    def ingest_batch(
        self,
        events_data: Sequence[dict[str, Any] | SecurityEvent],
    ) -> tuple[list[SecurityEvent], int]:
        """Ingest a batch of events with individual validation and deduplication."""
        processed: list[SecurityEvent] = []
        new_count = 0

        for item in events_data:
            ev, is_new = self.ingest_event(item)
            processed.append(ev)
            if is_new:
                new_count += 1

        return processed, new_count

    def get_event(self, event_id: str) -> SecurityEvent | None:
        """Retrieve a single event by ID."""
        clean_id = event_id.strip()
        if not clean_id:
            return None
        return self.repository.get_by_id(clean_id)

    def query_events(self, filter_params: EventQueryFilter | None = None) -> tuple[list[SecurityEvent], int]:
        """Query events with filtering, pagination, and deterministic ordering."""
        return self.repository.query(filter_params)

    def count(self) -> int:
        """Return total stored events count."""
        return self.repository.count()

    # =========================================================================
    # Phase 10: Alerting & Risk Query Operations
    # =========================================================================

    def get_alert(self, alert_id: str) -> Alert | None:
        """Retrieve a single alert by ID."""
        if not self.alert_repository:
            return None
        clean_id = alert_id.strip()
        if not clean_id:
            return None
        return self.alert_repository.get_by_id(clean_id)

    def query_alerts(
        self, filter_params: AlertQueryFilter | None = None
    ) -> tuple[list[Alert], int]:
        """Query alerts with filtering, pagination, and deterministic ordering."""
        if not self.alert_repository:
            return [], 0
        return self.alert_repository.query(filter_params)

    def get_alert_evidence(self, alert_id: str) -> dict[str, Any] | None:
        """Retrieve complete evidence lineage for an alert, including underlying events."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        # Resolve raw underlying security events if present in repository
        resolved_events = []
        for eid in alert.related_event_ids:
            try:
                ev = self.get_event(eid)
                if ev:
                    resolved_events.append(ev.to_dict())
            except Exception as exc:
                logger.debug(f"Could not load related event {eid}: {exc}")

        return {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "status": alert.status.value,
            "severity": alert.severity.to_name(),
            "risk_score": alert.risk_score,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "finding_id": alert.finding_id,
            "scoring_reasons": alert.scoring_reasons,
            "evidence": alert.evidence,
            "related_event_ids": alert.related_event_ids,
            "resolved_events": resolved_events,
            "extra": alert.extra,
        }

    def acknowledge_alert(self, alert_id: str, comment: str | None = None) -> Alert | None:
        """Acknowledge an alert."""
        if not self.alert_repository:
            return None
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.acknowledge(comment=comment)
        self.alert_repository.update(alert)
        return alert

    def resolve_alert(self, alert_id: str, comment: str | None = None) -> Alert | None:
        """Resolve an alert."""
        if not self.alert_repository:
            return None
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.resolve(comment=comment)
        self.alert_repository.update(alert)
        return alert

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        comment: str | None = None,
    ) -> Alert | None:
        """Update alert lifecycle status with transition validation."""
        if not self.alert_repository:
            return None
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            return None
        alert.update_status(status, comment=comment)
        self.alert_repository.update(alert)
        return alert

    def count_alerts(
        self, status: str | None = None, severity: str | None = None
    ) -> int:
        """Return total stored alerts count, optionally filtered."""
        if not self.alert_repository:
            return 0
        return self.alert_repository.count(status=status, severity=severity)

    # -------------------------------------------------------------------------
    # Incident Management
    # -------------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        description: str = "",
        severity: str = "HIGH",
        assigned_to: str | None = None,
        alert_ids: list[str] | None = None,
        user_context: UserContext | None = None,
    ) -> Incident:
        """Create a new incident."""
        if user_context:
            user_context.require_permission(Permission.MANAGE_INCIDENT)

        if not self.incident_repository:
            raise PersistenceError("Incident repository is not configured")

        incident = Incident(
            title=title,
            description=description,
            severity=severity.upper(),
            assigned_to=assigned_to,
            alert_ids=list(alert_ids or []),
        )
        saved = self.incident_repository.create(incident)

        if self.audit_repository:
            actor = user_context.username if user_context else "analyst"
            role = user_context.role.value if user_context else "ANALYST"
            self.audit_repository.append(
                AuditLogEntry(
                    actor=actor,
                    role=role,
                    action=AuditActionType.INCIDENT_CREATED,
                    target_type="incident",
                    target_id=saved.incident_id,
                    details={"title": title, "severity": severity, "alert_ids": alert_ids or []},
                )
            )

        return saved

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get incident by ID."""
        if not self.incident_repository:
            return None
        return self.incident_repository.get(incident_id)

    def update_incident_status(
        self,
        incident_id: str,
        new_status: str | IncidentStatus,
        user_context: UserContext | None = None,
    ) -> Incident:
        """Update incident lifecycle status."""
        if user_context:
            user_context.require_permission(Permission.MANAGE_INCIDENT)

        if not self.incident_repository:
            raise PersistenceError("Incident repository is not configured")

        incident = self.incident_repository.get(incident_id)
        if not incident:
            raise PersistenceError(f"Incident '{incident_id}' not found")

        old_status = incident.status.value
        incident.transition_to(new_status)
        updated = self.incident_repository.update(incident)

        if self.audit_repository:
            actor = user_context.username if user_context else "analyst"
            role = user_context.role.value if user_context else "ANALYST"
            self.audit_repository.append(
                AuditLogEntry(
                    actor=actor,
                    role=role,
                    action=AuditActionType.INCIDENT_STATUS_CHANGED,
                    target_type="incident",
                    target_id=incident_id,
                    details={"from": old_status, "to": incident.status.value},
                )
            )

        return updated

    def add_incident_note(
        self,
        incident_id: str,
        author: str,
        content: str,
        user_context: UserContext | None = None,
    ) -> IncidentNote:
        """Add an analyst note to an incident."""
        if user_context:
            user_context.require_permission(Permission.MANAGE_INCIDENT)

        if not self.incident_repository:
            raise PersistenceError("Incident repository is not configured")

        note = IncidentNote(
            incident_id=incident_id,
            author=author,
            content=content,
        )
        self.incident_repository.add_note(incident_id, note)

        if self.audit_repository:
            actor = user_context.username if user_context else author
            role = user_context.role.value if user_context else "ANALYST"
            self.audit_repository.append(
                AuditLogEntry(
                    actor=actor,
                    role=role,
                    action=AuditActionType.INCIDENT_NOTE_ADDED,
                    target_type="incident",
                    target_id=incident_id,
                    details={"note_id": note.note_id, "author": author},
                )
            )

        return note

    def associate_incident_alert(
        self,
        incident_id: str,
        alert_id: str,
        user_context: UserContext | None = None,
    ) -> Incident:
        """Link an alert to an incident."""
        if user_context:
            user_context.require_permission(Permission.MANAGE_INCIDENT)

        if not self.incident_repository:
            raise PersistenceError("Incident repository is not configured")

        return self.incident_repository.associate_alert(incident_id, alert_id)

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        """List incidents with filtering and pagination."""
        if not self.incident_repository:
            return [], 0
        return self.incident_repository.list(
            status=status,
            severity=severity,
            assigned_to=assigned_to,
            limit=limit,
            offset=offset,
        )

    def count_incidents(self) -> int:
        """Count total incidents."""
        if not self.incident_repository:
            return 0
        return self.incident_repository.count()

    # -------------------------------------------------------------------------
    # Response Action Management
    # -------------------------------------------------------------------------

    def request_response_action(
        self,
        action_type: str | ResponseActionType,
        target_params: dict[str, Any],
        incident_id: str | None = None,
        alert_id: str | None = None,
        user_context: UserContext | None = None,
    ) -> ResponseAction:
        """Request a defensive response action."""
        if not self.response_executor:
            raise PersistenceError("Response executor is not configured")
        return self.response_executor.request_action(
            action_type=action_type,
            target_params=target_params,
            incident_id=incident_id,
            alert_id=alert_id,
            user_context=user_context,
        )

    def authorize_response_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Authorize a requested action."""
        if not self.response_executor:
            raise PersistenceError("Response executor is not configured")
        return self.response_executor.authorize_action(action_id, user_context)

    def reject_response_action(
        self,
        action_id: str,
        reason: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Reject a requested action."""
        if not self.response_executor:
            raise PersistenceError("Response executor is not configured")
        return self.response_executor.reject_action(action_id, reason, user_context)

    def execute_response_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Execute an authorized action."""
        if not self.response_executor:
            raise PersistenceError("Response executor is not configured")
        return self.response_executor.execute_action(action_id, user_context)

    def rollback_response_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Rollback a previously executed action."""
        if not self.response_executor:
            raise PersistenceError("Response executor is not configured")
        return self.response_executor.rollback_action(action_id, user_context)

    def get_response_action(self, action_id: str) -> ResponseAction | None:
        """Get response action by ID."""
        if not self.response_action_repository:
            return None
        return self.response_action_repository.get(action_id)

    def list_response_actions(
        self,
        status: str | None = None,
        action_type: str | None = None,
        incident_id: str | None = None,
        alert_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ResponseAction], int]:
        """List response actions with filtering."""
        if not self.response_action_repository:
            return [], 0
        return self.response_action_repository.list(
            status=status,
            action_type=action_type,
            incident_id=incident_id,
            alert_id=alert_id,
            limit=limit,
            offset=offset,
        )

    def count_response_actions(self) -> int:
        """Total response actions."""
        if not self.response_action_repository:
            return 0
        return self.response_action_repository.count()

    # -------------------------------------------------------------------------
    # Advisory Recommendations
    # -------------------------------------------------------------------------

    def get_alert_recommendations(self, alert_id: str) -> list[dict[str, Any]]:
        """Generate advisory recommendations for an alert."""
        if not self.alert_repository:
            return []
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            return []
        recs = self.response_recommender.recommend_for_alert(alert)
        return [r.to_dict() for r in recs]

    # -------------------------------------------------------------------------
    # Audit Logs
    # -------------------------------------------------------------------------

    def list_audit_logs(
        self,
        target_id: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLogEntry], int]:
        """Query immutable audit log entries."""
        if not self.audit_repository:
            return [], 0
        return self.audit_repository.list(
            target_id=target_id,
            action=action,
            actor=actor,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )

    def get_audit_log(self, audit_id: str) -> AuditLogEntry | None:
        """Get single audit log entry."""
        if not self.audit_repository:
            return None
        return self.audit_repository.get(audit_id)

    def count_audit_logs(self) -> int:
        """Total audit logs."""
        if not self.audit_repository:
            return 0
        return self.audit_repository.count()

