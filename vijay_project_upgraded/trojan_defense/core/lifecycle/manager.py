"""Application lifecycle coordinator for the Trojan Defense framework.

Controls initialization, service wiring, collector coordination, and clean
graceful shutdown across all subsystems.
"""

from enum import Enum
from pathlib import Path
import threading
from typing import Any

from trojan_defense.core.collectors.registry import CollectorRegistry
from trojan_defense.core.config.loader import load_config
from trojan_defense.core.config.schema import RootConfig
from trojan_defense.core.exceptions import LifecycleError
from trojan_defense.core.logging.setup import get_logger, setup_logging
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.persistence.base import BaseEventRepository
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.normalizer import EventNormalizer
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.core.pipeline.validator import EventValidator
from trojan_defense.core.transport.base import BaseEventTransport
from trojan_defense.core.transport.file import JsonLineFileTransport
from trojan_defense.core.transport.http import HttpEventTransport
from trojan_defense.core.transport.mock import MockEventTransport

logger = get_logger("lifecycle")


class LifecycleState(str, Enum):
    """Application lifecycle states."""
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZING = "INITIALIZING"
    INITIALIZED = "INITIALIZED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class ApplicationManager:
    """Coordinates lifecycle of all application components."""

    def __init__(self) -> None:
        self._state: LifecycleState = LifecycleState.UNINITIALIZED
        self._lock = threading.Lock()

        self.config: RootConfig | None = None
        self.endpoint: EndpointIdentity | None = None
        self.repository: BaseEventRepository | None = None
        self.transport: BaseEventTransport | None = None
        self.pipeline: EventPipeline | None = None
        self.registry: CollectorRegistry = CollectorRegistry()
        self.deception_engine: Any = None
        self.deception_detector: Any = None
        self.behavior_engine: Any = None
        self.alert_repository: Any = None
        self.risk_scorer: Any = None
        self.alert_engine: Any = None
        self.incident_repository: Any = None
        self.response_action_repository: Any = None
        self.response_executor: Any = None
        self.response_recommender: Any = None
        self.audit_repository: Any = None

    @property
    def state(self) -> LifecycleState:
        """Current operational lifecycle state."""
        return self._state

    def initialize(
        self,
        config: RootConfig | None = None,
        config_file: str | Path | None = None,
        environment: str | None = None,
    ) -> None:
        """Execute full initialization sequence.

        Loads configuration, initializes structured logging, resolves endpoint identity,
        and constructs the persistence, transport, and pipeline layers.
        """
        with self._lock:
            if self._state not in (LifecycleState.UNINITIALIZED, LifecycleState.STOPPED):
                raise LifecycleError(f"Cannot initialize from state '{self._state.value}'")

            self._state = LifecycleState.INITIALIZING

        try:
            # 1. Load Configuration
            self.config = config or load_config(config_file=config_file, environment=environment)

            # 2. Setup Centralized Logging
            setup_logging(self.config.logging)
            logger.info(
                f"Initializing Trojan Defense framework (Environment: {self.config.app.environment})"
            )

            # 3. Resolve Endpoint Identity
            self.endpoint = EndpointIdentity.resolve(
                endpoint_id_override=self.config.endpoint.endpoint_id,
                hostname_override=self.config.endpoint.hostname,
                agent_version=self.config.endpoint.agent_version,
            )
            logger.info(f"Resolved endpoint identity: {self.endpoint.endpoint_id} ({self.endpoint.hostname})")

            # 4. Initialize Persistence Boundary
            if self.config.persistence.enabled:
                if self.config.persistence.driver == "sqlite":
                    self.repository = SQLiteEventRepository(db_path=self.config.persistence.db_path)
                elif self.config.persistence.driver == "memory":
                    self.repository = InMemoryEventRepository()
                logger.info(f"Persistence initialized with driver: '{self.config.persistence.driver}'")
            else:
                self.repository = None
                logger.info("Persistence is disabled by configuration")

            # 5. Initialize Transport Boundary
            if self.config.transport.enabled:
                if self.config.transport.driver == "mock":
                    self.transport = MockEventTransport()
                elif self.config.transport.driver == "file":
                    self.transport = JsonLineFileTransport(file_path=self.config.transport.output_file)
                elif self.config.transport.driver == "http":
                    self.transport = HttpEventTransport(
                        endpoint_url=self.config.transport.endpoint_url,
                        timeout=self.config.transport.timeout_seconds,
                        retries=self.config.transport.retry_count,
                    )
                logger.info(f"Transport initialized with driver: '{self.config.transport.driver}'")
            else:
                self.transport = None
                logger.info("Transport is disabled by configuration")

            # 6. Initialize Event Pipeline
            validator = EventValidator() if self.config.pipeline.validate_events else None
            normalizer = EventNormalizer(default_endpoint=self.endpoint)
            self.pipeline = EventPipeline(
                config=self.config.pipeline,
                validator=validator,
                normalizer=normalizer,
                repository=self.repository,
                transport=self.transport,
            )
            logger.info("Event pipeline initialized successfully")

            # 7. Initialize Telemetry Collectors
            is_process_enabled = (
                self.config.process_collector.enabled or self.config.collectors.process
            )
            if is_process_enabled:
                from trojan_defense.platform.windows.process_monitor import WindowsProcessMonitor

                self.config.process_collector.enabled = True
                self.config.collectors.process = True

                process_monitor = WindowsProcessMonitor(
                    config=self.config.process_collector,
                    pipeline=self.pipeline,
                    endpoint=self.endpoint,
                )
                self.registry.register(process_monitor)
                logger.info(
                    f"WindowsProcessMonitor registered (poll_interval={self.config.process_collector.polling_interval}s)"
                )

            # Windows File Monitor
            is_file_enabled = (
                self.config.file_collector.enabled or self.config.collectors.file
            )
            if is_file_enabled:
                from trojan_defense.platform.windows.file_monitor import WindowsFileMonitor

                self.config.file_collector.enabled = True
                self.config.collectors.file = True

                file_monitor = WindowsFileMonitor(
                    config=self.config.file_collector,
                    pipeline=self.pipeline,
                    endpoint=self.endpoint,
                )
                self.registry.register(file_monitor)
                logger.info(
                    f"WindowsFileMonitor registered (roots={self.config.file_collector.monitored_paths}, recursive={self.config.file_collector.recursive})"
                )

            # Windows Network Monitor
            is_network_enabled = (
                self.config.network_collector.enabled or self.config.collectors.network
            )
            if is_network_enabled:
                from trojan_defense.platform.windows.network_monitor import WindowsNetworkMonitor

                self.config.network_collector.enabled = True
                self.config.collectors.network = True

                network_monitor = WindowsNetworkMonitor(
                    config=self.config.network_collector,
                    pipeline=self.pipeline,
                    endpoint=self.endpoint,
                )
                self.registry.register(network_monitor)
                logger.info(
                    f"WindowsNetworkMonitor registered (interval={self.config.network_collector.polling_interval}s, "
                    f"loopback={self.config.network_collector.include_loopback}, listening={self.config.network_collector.include_listening})"
                )

            # Windows System & Privilege Monitor
            is_system_enabled = (
                self.config.system_collector.enabled
                or self.config.collectors.system
                or self.config.collectors.privilege
            )
            if is_system_enabled:
                from trojan_defense.platform.windows.system_monitor import WindowsSystemMonitor

                self.config.system_collector.enabled = True
                self.config.collectors.system = True
                self.config.collectors.privilege = True

                system_monitor = WindowsSystemMonitor(
                    config=self.config.system_collector,
                    pipeline=self.pipeline,
                    endpoint=self.endpoint,
                )
                self.registry.register(system_monitor)
                logger.info(
                    f"WindowsSystemMonitor registered (interval={self.config.system_collector.polling_interval}s, "
                    f"sessions={self.config.system_collector.monitor_sessions}, privileges={self.config.system_collector.monitor_privileges})"
                )

            # Cyber Deception Engine
            is_deception_enabled = (
                self.config.deception.enabled or self.config.collectors.deception
            )
            if is_deception_enabled:
                from trojan_defense.deception.engine import CyberDeceptionEngine

                self.config.deception.enabled = True
                self.config.collectors.deception = True

                self.deception_engine = CyberDeceptionEngine(
                    config=self.config.deception,
                    repository=self.repository,
                    pipeline=self.pipeline,
                    endpoint=self.endpoint,
                )
                self.deception_engine.initialize()
                logger.info(
                    f"CyberDeceptionEngine initialized (root='{self.deception_engine.root_path}', "
                    f"auto_create={self.config.deception.auto_create_on_startup})"
                )

                # Ensure Phase 4 File Monitor covers the deception root
                if is_file_enabled or self.config.file_collector.enabled or self.config.collectors.file:
                    decoy_root_str = str(self.deception_engine.root_path)
                    if decoy_root_str not in self.config.file_collector.monitored_paths:
                        self.config.file_collector.monitored_paths.append(decoy_root_str)

                # Deception Interaction Detector (Phase 8)
                if self.config.deception.interaction_detection_enabled:
                    from trojan_defense.deception.detector import DeceptionInteractionDetector

                    self.deception_detector = DeceptionInteractionDetector(
                        registry=self.deception_engine.registry,
                        pipeline=self.pipeline,
                        config=self.config.deception,
                        endpoint=self.endpoint,
                    )
                    file_monitor_collector = self.registry.get("windows_file_monitor")
                    if file_monitor_collector and hasattr(file_monitor_collector, "set_deception_detector"):
                        file_monitor_collector.set_deception_detector(self.deception_detector)
                    logger.info("DeceptionInteractionDetector initialized and wired to WindowsFileMonitor")

            # 8. Behavioral Correlation and Detection Engine (Phase 9)
            is_behavior_enabled = (
                self.config.behavior.enabled or self.config.collectors.behavior
            )
            if is_behavior_enabled:
                from trojan_defense.behavior.engine import BehaviorCorrelationEngine

                self.config.behavior.enabled = True
                self.config.collectors.behavior = True

                self.behavior_engine = BehaviorCorrelationEngine(
                    config=self.config.behavior,
                    pipeline=self.pipeline,
                )
                if self.pipeline:
                    self.pipeline.set_correlation_engine(self.behavior_engine)

                logger.info(
                    f"BehaviorCorrelationEngine initialized and attached to pipeline "
                    f"(window={self.config.behavior.correlation_window_seconds}s, "
                    f"dedup={self.config.behavior.dedup_window_seconds}s)"
                )

            # 9. Risk Scoring and Alert Generation Engine (Phase 10)
            is_alerting_enabled = (
                self.config.alerting.enabled or self.config.collectors.alerting
            )
            if is_alerting_enabled:
                from trojan_defense.alerting.engine import AlertEngine
                from trojan_defense.alerting.repository import SQLiteAlertRepository
                from trojan_defense.alerting.scorer import RiskScoringEngine

                self.config.alerting.enabled = True
                self.config.collectors.alerting = True

                alert_db_path = "trojan_defense.db"
                if self.config.persistence.driver == "sqlite":
                    alert_db_path = self.config.persistence.db_path
                elif self.config.persistence.driver == "memory":
                    alert_db_path = ":memory:"

                self.alert_repository = SQLiteAlertRepository(db_path=alert_db_path)
                self.risk_scorer = RiskScoringEngine(config=self.config.risk)
                self.alert_engine = AlertEngine(
                    alert_config=self.config.alerting,
                    risk_config=self.config.risk,
                    repository=self.alert_repository,
                    scorer=self.risk_scorer,
                )
                if self.pipeline:
                    self.pipeline.set_alert_engine(self.alert_engine)

                logger.info(
                    f"AlertEngine initialized and attached to pipeline "
                    f"(min_score={self.config.alerting.min_alert_score}, "
                    f"dedup={self.config.alerting.dedup_window_seconds}s, "
                    f"cooldown={self.config.alerting.cooldown_seconds}s)"
                )

            # Controlled Defensive Response Subsystem
            is_response_enabled = (
                self.config.response.enabled or self.config.collectors.response
            )
            if is_response_enabled:
                from trojan_defense.response.executor import ResponseExecutor
                from trojan_defense.response.recommender import ResponseRecommender
                from trojan_defense.response.repository import (
                    SQLiteAuditRepository,
                    SQLiteIncidentRepository,
                    SQLiteResponseActionRepository,
                )

                self.config.response.enabled = True
                self.config.collectors.response = True

                resp_db_path = "trojan_defense.db"
                if self.config.persistence.driver == "sqlite":
                    resp_db_path = self.config.persistence.db_path
                elif self.config.persistence.driver == "memory":
                    resp_db_path = ":memory:"

                self.incident_repository = SQLiteIncidentRepository(db_path=resp_db_path)
                self.response_action_repository = SQLiteResponseActionRepository(db_path=resp_db_path)
                self.audit_repository = SQLiteAuditRepository(db_path=resp_db_path)
                self.response_executor = ResponseExecutor(
                    action_repo=self.response_action_repository,
                    audit_repo=self.audit_repository,
                    incident_repo=self.incident_repository,
                    config=self.config.response,
                )
                self.response_recommender = ResponseRecommender()

                logger.info(
                    f"Controlled Defensive Response Subsystem initialized "
                    f"(quarantine_dir='{self.config.response.quarantine_dir}', "
                    f"require_auth={self.config.response.require_authorization})"
                )

            with self._lock:
                self._state = LifecycleState.INITIALIZED


        except Exception as exc:
            with self._lock:
                self._state = LifecycleState.UNINITIALIZED
            logger.error(f"Failed to initialize application: {exc}", exc_info=True)
            raise

    def start(self) -> None:
        """Start enabled application components and collectors."""
        with self._lock:
            if self._state != LifecycleState.INITIALIZED:
                raise LifecycleError(f"Cannot start application from state '{self._state.value}'")
            self._state = LifecycleState.STARTING

        try:
            logger.info("Starting Trojan Defense collectors and background services...")
            self.registry.start_all(fail_fast=False)

            # Auto-deploy deception decoys if configured
            if self.deception_engine and self.config.deception.auto_create_on_startup:
                try:
                    self.deception_engine.deploy()
                except Exception as exc:
                    logger.error(f"Error during automatic decoy deployment: {exc}", exc_info=True)

            with self._lock:
                self._state = LifecycleState.RUNNING

            logger.info("Trojan Defense framework is RUNNING and ready for telemetry ingestion")
        except Exception as exc:
            with self._lock:
                self._state = LifecycleState.INITIALIZED
            logger.error(f"Failed during startup transition: {exc}", exc_info=True)
            raise

    def stop(self) -> None:
        """Gracefully stop running collectors and clean up resources."""
        with self._lock:
            if self._state not in (LifecycleState.RUNNING, LifecycleState.STARTING):
                logger.debug(f"Stop called while in state '{self._state.value}', no action needed")
                return
            self._state = LifecycleState.STOPPING

        logger.info("Initiating graceful shutdown...")

        # 1. Stop collectors
        self.registry.stop_all()

        # 2. Cleanup deception decoys if configured
        if self.deception_engine and self.config.deception.cleanup_on_shutdown:
            try:
                self.deception_engine.cleanup()
            except Exception as exc:
                logger.error(f"Error during deception cleanup on shutdown: {exc}")

        # 3. Close transport
        if self.transport:
            try:
                self.transport.close()
            except Exception as exc:
                logger.error(f"Error closing transport: {exc}")

        # 4. Close persistence
        if self.repository:
            try:
                self.repository.close()
            except Exception as exc:
                logger.error(f"Error closing repository: {exc}")

        # 5. Clear behavior correlation state
        if self.behavior_engine:
            try:
                self.behavior_engine.clear()
            except Exception as exc:
                logger.error(f"Error clearing behavior engine: {exc}")

        # 6. Clear alert engine and close alert repository
        if self.alert_engine:
            try:
                self.alert_engine.clear()
            except Exception as exc:
                logger.error(f"Error clearing alert engine: {exc}")

        if self.alert_repository:
            try:
                self.alert_repository.close()
            except Exception as exc:
                logger.error(f"Error closing alert repository: {exc}")

        # 7. Close response repositories
        if self.incident_repository:
            try:
                self.incident_repository.close()
            except Exception as exc:
                logger.error(f"Error closing incident repository: {exc}")

        if self.response_action_repository:
            try:
                self.response_action_repository.close()
            except Exception as exc:
                logger.error(f"Error closing response action repository: {exc}")

        if self.audit_repository:
            try:
                self.audit_repository.close()
            except Exception as exc:
                logger.error(f"Error closing audit repository: {exc}")

        with self._lock:
            self._state = LifecycleState.STOPPED

        logger.info("Application shutdown complete. State: STOPPED")

    def is_healthy(self) -> bool:
        """Assess overall framework health."""
        if self._state != LifecycleState.RUNNING:
            return False
        # Collectors health: all running collectors should be healthy
        for collector in self.registry.list_collectors():
            if not collector.health_check():
                return False
        return True
