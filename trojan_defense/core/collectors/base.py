"""Abstract base class and lifecycle status for telemetry collectors.

Defines the contract that future collectors (ProcessMonitor, FileMonitor,
NetworkMonitor, etc.) must fulfill to plug into the application lifecycle.
"""

from abc import ABC, abstractmethod
from enum import Enum
import logging

from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.pipeline.pipeline import EventPipeline

logger = get_logger("collector")


class CollectorStatus(str, Enum):
    """Lifecycle status states for telemetry collectors."""
    UNINITIALIZED = "UNINITIALIZED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class BaseCollector(ABC):
    """Abstract base class for all telemetry and cyber deception collectors."""

    def __init__(
        self,
        name: str,
        category: EventCategory,
        pipeline: EventPipeline | None = None,
        endpoint: EndpointIdentity | None = None,
    ) -> None:
        self.name = name.strip()
        self.category = category
        self.pipeline = pipeline
        self.endpoint = endpoint
        self._status: CollectorStatus = CollectorStatus.UNINITIALIZED
        self._error_message: str | None = None

    @property
    def status(self) -> CollectorStatus:
        """Current operational lifecycle status."""
        return self._status

    @property
    def error_message(self) -> str | None:
        """Last error message if in ERROR state."""
        return self._error_message

    def set_pipeline(self, pipeline: EventPipeline) -> None:
        """Bind the event pipeline to this collector."""
        self.pipeline = pipeline

    def set_endpoint(self, endpoint: EndpointIdentity) -> None:
        """Bind the endpoint identity to this collector."""
        self.endpoint = endpoint

    def emit(self, event: SecurityEvent) -> SecurityEvent:
        """Emit a security event directly to the pipeline.

        Raises:
            CollectorError: If no pipeline is configured or pipeline fails.
        """
        if not self.pipeline:
            raise CollectorError(f"Collector '{self.name}' has no active event pipeline configured")
        return self.pipeline.process(event)

    @abstractmethod
    def start(self) -> None:
        """Start collecting telemetry.

        Transitions status to RUNNING on success, or ERROR on failure.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop collecting telemetry and release collector resources.

        Transitions status to STOPPED.
        """
        pass

    def health_check(self) -> bool:
        """Return True if collector is healthy and running."""
        return self._status == CollectorStatus.RUNNING

    def __repr__(self) -> str:
        return f"<Collector name='{self.name}' category='{self.category.value}' status='{self._status.value}'>"
