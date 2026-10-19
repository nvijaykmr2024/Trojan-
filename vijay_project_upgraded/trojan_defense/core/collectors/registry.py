"""Collector registry for centralized telemetry lifecycle coordination.

Provides safe multi-collector startup, status inspection, and shutdown
with isolated failure containment.
"""

import threading

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger

logger = get_logger("registry")


class CollectorRegistry:
    """Registry managing the registration and lifecycle of collectors."""

    def __init__(self) -> None:
        self._collectors: dict[str, BaseCollector] = {}
        self._lock = threading.Lock()

    def register(self, collector: BaseCollector) -> None:
        """Register a new collector instance.

        Raises:
            CollectorError: If a collector with the same name is already registered.
        """
        with self._lock:
            if collector.name in self._collectors:
                raise CollectorError(f"Collector '{collector.name}' is already registered")
            self._collectors[collector.name] = collector
            logger.debug(f"Registered collector '{collector.name}' ({collector.category.value})")

    def unregister(self, name: str) -> BaseCollector | None:
        """Unregister a collector by name."""
        with self._lock:
            col = self._collectors.pop(name, None)
            if col:
                logger.debug(f"Unregistered collector '{name}'")
            return col

    def get(self, name: str) -> BaseCollector | None:
        """Retrieve a registered collector by name."""
        with self._lock:
            return self._collectors.get(name)

    def list_collectors(self) -> list[BaseCollector]:
        """Return a snapshot list of all registered collectors."""
        with self._lock:
            return list(self._collectors.values())

    def start_all(self, fail_fast: bool = False) -> dict[str, bool]:
        """Start all registered collectors.

        Returns:
            dict mapping collector name to start success (True/False).
        """
        results: dict[str, bool] = {}
        with self._lock:
            collectors = list(self._collectors.values())

        for collector in collectors:
            try:
                logger.info(f"Starting collector '{collector.name}'...")
                collector.start()
                results[collector.name] = True
            except Exception as exc:
                logger.error(f"Failed to start collector '{collector.name}': {exc}", exc_info=True)
                results[collector.name] = False
                if fail_fast:
                    raise CollectorError(f"Fatal error starting '{collector.name}': {exc}") from exc

        return results

    def stop_all(self) -> dict[str, bool]:
        """Stop all registered collectors gracefully.

        Returns:
            dict mapping collector name to stop success (True/False).
        """
        results: dict[str, bool] = {}
        with self._lock:
            collectors = list(self._collectors.values())

        for collector in collectors:
            try:
                logger.info(f"Stopping collector '{collector.name}'...")
                collector.stop()
                results[collector.name] = True
            except Exception as exc:
                logger.error(f"Error stopping collector '{collector.name}': {exc}", exc_info=True)
                results[collector.name] = False

        return results

    def get_statuses(self) -> dict[str, CollectorStatus]:
        """Return a mapping of collector names to their operational status."""
        with self._lock:
            return {name: col.status for name, col in self._collectors.items()}
