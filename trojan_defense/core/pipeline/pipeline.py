"""Central event processing pipeline for the Trojan Defense framework.

Orchestrates validation, normalization, persistence, and transport of security
telemetry without implementing any detection or threat correlation logic.
"""

from collections.abc import Sequence
import logging
import threading
from typing import Any

from trojan_defense.core.config.schema import PipelineConfig
from trojan_defense.core.exceptions import PersistenceError, PipelineError, TransportError, ValidationError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory
from trojan_defense.core.persistence.base import BaseEventRepository
from trojan_defense.core.pipeline.normalizer import EventNormalizer
from trojan_defense.core.pipeline.validator import EventValidator
from trojan_defense.core.transport.base import BaseEventTransport

logger = get_logger("pipeline")


class EventPipeline:
    """Synchronous and batch event pipeline for processing incoming telemetry."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        validator: EventValidator | None = None,
        normalizer: EventNormalizer | None = None,
        repository: BaseEventRepository | None = None,
        transport: BaseEventTransport | None = None,
        correlation_engine: Any | None = None,
        alert_engine: Any | None = None,
    ) -> None:
        self.config = config or PipelineConfig()
        self.validator = validator or EventValidator()
        self.normalizer = normalizer or EventNormalizer()
        self.repository = repository
        self.transport = transport
        self.correlation_engine = correlation_engine
        self.alert_engine = alert_engine

        self._lock = threading.Lock()
        self._events_received: int = 0
        self._events_processed: int = 0
        self._events_failed: int = 0

    def set_correlation_engine(self, engine: Any) -> None:
        """Attach a behavioral correlation engine to the pipeline."""
        self.correlation_engine = engine

    def set_alert_engine(self, engine: Any) -> None:
        """Attach an alert engine to the pipeline."""
        self.alert_engine = engine


    @property
    def stats(self) -> dict[str, int]:
        """Return pipeline telemetry processing metrics."""
        with self._lock:
            return {
                "events_received": self._events_received,
                "events_processed": self._events_processed,
                "events_failed": self._events_failed,
            }

    def process(self, event: SecurityEvent) -> SecurityEvent:
        """Process a single event through normalization, validation, persistence, and transport.

        Returns:
            The normalized and validated SecurityEvent.

        Raises:
            ValidationError: If the event is malformed.
            PipelineError: If persistence or transport encounters an unrecoverable failure.
        """
        with self._lock:
            self._events_received += 1

        try:
            # 1. Normalization
            normalized_event = self.normalizer.normalize(event)

            # 2. Validation
            if self.config.validate_events:
                self.validator.validate(normalized_event)

            # 3. Persistence
            if self.repository:
                try:
                    self.repository.save(normalized_event)
                except PersistenceError as exc:
                    logger.error(f"Persistence error for event '{normalized_event.event_id}': {exc}")
                    raise PipelineError(f"Persistence failed: {exc}") from exc

            # 4. Transport
            if self.transport:
                try:
                    self.transport.send(normalized_event)
                except TransportError as exc:
                    logger.error(f"Transport error for event '{normalized_event.event_id}': {exc}")
                    raise PipelineError(f"Transport failed: {exc}") from exc

            # 5. Behavioral Correlation Analysis
            if (
                self.correlation_engine is not None
                and normalized_event.event_type.category != EventCategory.BEHAVIOR
            ):
                try:
                    self.correlation_engine.analyze_event(normalized_event)
                except Exception as exc:
                    logger.error(
                        f"Error during behavioral correlation analysis of event '{normalized_event.event_id}': {exc}",
                        exc_info=True,
                    )

            # 6. Risk Scoring and Alert Generation (Phase 10)
            if (
                self.alert_engine is not None
                and normalized_event.event_type.category == EventCategory.BEHAVIOR
                and normalized_event.event_type.action == "FINDING"
            ):
                try:
                    self.alert_engine.process_finding_event(normalized_event)
                except Exception as exc:
                    logger.error(
                        f"Error during alert generation for behavioral event '{normalized_event.event_id}': {exc}",
                        exc_info=True,
                    )

            with self._lock:
                self._events_processed += 1

            return normalized_event

        except Exception as exc:
            with self._lock:
                self._events_failed += 1
            if not isinstance(exc, (ValidationError, PipelineError)):
                logger.error(f"Unexpected error processing event: {exc}", exc_info=True)
                raise PipelineError(f"Pipeline processing failed: {exc}") from exc
            raise

    def process_batch(self, events: Sequence[SecurityEvent]) -> list[SecurityEvent]:
        """Process a batch of events through the pipeline."""
        if not events:
            return []

        processed_events: list[SecurityEvent] = []
        for event in events:
            processed = self.process(event)
            processed_events.append(processed)

        return processed_events
