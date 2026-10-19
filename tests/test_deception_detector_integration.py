"""Integration tests for Phase 8 Deception Interaction Detection.

Validates end-to-end interaction detection across WindowsFileMonitor,
CyberDeceptionEngine, DeceptionInteractionDetector, EventPipeline,
and SQLite persistence repository.
"""

from pathlib import Path
import tempfile
import time
import pytest

from trojan_defense.core.config.schema import (
    DeceptionConfig,
    FileCollectorConfig,
    PersistenceConfig,
    PipelineConfig,
    RootConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager, LifecycleState
from trojan_defense.core.models.event import EventCategory
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.deception.detector import DeceptionInteractionDetector
from trojan_defense.deception.engine import CyberDeceptionEngine
from trojan_defense.platform.windows.file_monitor import WindowsFileMonitor


@pytest.fixture
def temp_environment():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        root = Path(td)
        decoy_dir = root / "runtime" / "deception"
        decoy_dir.mkdir(parents=True, exist_ok=True)
        db_path = root / "events.db"
        yield {
            "root": root,
            "decoy_dir": decoy_dir,
            "db_path": db_path,
        }


@pytest.fixture
def test_endpoint():
    return EndpointIdentity(
        endpoint_id="ep-phase8-integration",
        hostname="INTEGRATION-HOST",
        platform="Windows",
        os_version="10.0.19045",
        architecture="AMD64",
    )


class TestDeceptionInteractionIntegration:
    """Integration tests verifying end-to-end telemetry and persistence."""

    def test_end_to_end_decoy_modification_pipeline(self, temp_environment, test_endpoint):
        """Modifying a decoy file emits FILE.MODIFY and DECEPTION.INTERACTION into repository."""
        db_path = temp_environment["db_path"]
        decoy_dir = temp_environment["decoy_dir"]

        repository = SQLiteEventRepository(db_path=db_path)
        try:
            pipeline = EventPipeline(repository=repository)

            # Initialize Deception Engine and deploy decoys
            deception_config = DeceptionConfig(
                enabled=True,
                deception_root=str(decoy_dir),
                auto_create_on_startup=False,
                interaction_detection_enabled=True,
                interaction_debounce_ms=100,
            )
            deception_engine = CyberDeceptionEngine(
                config=deception_config,
                repository=repository,
                pipeline=pipeline,
                endpoint=test_endpoint,
            )
            deception_engine.initialize()
            deployed = deception_engine.deploy()
            assert len(deployed) > 0

            # Wire Deception Detector
            detector = DeceptionInteractionDetector(
                registry=deception_engine.registry,
                pipeline=pipeline,
                config=deception_config,
                endpoint=test_endpoint,
            )

            # Wire Windows File Monitor
            file_config = FileCollectorConfig(
                enabled=True,
                monitored_paths=[str(decoy_dir)],
                debounce_ms=0,
                collect_hashes=False,
            )
            file_monitor = WindowsFileMonitor(
                config=file_config,
                pipeline=pipeline,
                endpoint=test_endpoint,
                deception_detector=detector,
            )

            # Pick a deployed decoy and simulate an interaction via file monitor
            target_decoy = deployed[0]
            decoy_file_path = Path(target_decoy.normalized_path)
            assert decoy_file_path.exists()

            # Simulate modification via file monitor
            file_event = file_monitor._process_event(
                action="MODIFY",
                path=str(decoy_file_path),
                is_directory=False,
                severity=Severity.LOW,
            )
            assert file_event is not None

            # Verify persisted events in SQLite
            events, _ = repository.query(EventQueryFilter(limit=50))
            categories = [e.event_type.category for e in events]
            assert EventCategory.FILE in categories
            assert EventCategory.DECEPTION in categories

            # Find the deception event
            deception_events = [e for e in events if e.event_type.category == EventCategory.DECEPTION]
            assert len(deception_events) == 1
            d_ev = deception_events[0]

            assert d_ev.event_type.action == "INTERACTION"
            assert d_ev.context.deception is not None
            assert d_ev.context.deception.is_decoy is True
            assert d_ev.context.deception.decoy_id == target_decoy.decoy_id
            assert d_ev.context.deception.interaction_type == "modified"
            assert d_ev.context.deception.original_event_id == file_event.event_id
        finally:
            repository.close()

    def test_ordinary_file_generates_no_deception_events(self, temp_environment, test_endpoint):
        """Modifying an ordinary file outside the deception registry generates NO deception event."""
        db_path = temp_environment["db_path"]
        decoy_dir = temp_environment["decoy_dir"]
        ordinary_dir = temp_environment["root"] / "legit_work"
        ordinary_dir.mkdir(parents=True, exist_ok=True)
        ordinary_file = ordinary_dir / "spreadsheet.xlsx"
        ordinary_file.write_text("dummy")

        repository = SQLiteEventRepository(db_path=db_path)
        try:
            pipeline = EventPipeline(repository=repository)

            deception_config = DeceptionConfig(
                enabled=True,
                deception_root=str(decoy_dir),
                interaction_detection_enabled=True,
            )
            deception_engine = CyberDeceptionEngine(
                config=deception_config,
                repository=repository,
                pipeline=pipeline,
                endpoint=test_endpoint,
            )
            deception_engine.initialize()

            detector = DeceptionInteractionDetector(
                registry=deception_engine.registry,
                pipeline=pipeline,
                config=deception_config,
                endpoint=test_endpoint,
            )

            file_config = FileCollectorConfig(
                enabled=True,
                monitored_paths=[str(ordinary_dir)],
                debounce_ms=0,
            )
            file_monitor = WindowsFileMonitor(
                config=file_config,
                pipeline=pipeline,
                endpoint=test_endpoint,
                deception_detector=detector,
            )

            file_event = file_monitor._process_event(
                action="MODIFY",
                path=str(ordinary_file),
                is_directory=False,
                severity=Severity.LOW,
            )
            assert file_event is not None

            # Verify SQLite has only FILE event, NO DECEPTION event
            events, _ = repository.query(EventQueryFilter(limit=50))
            deception_events = [e for e in events if e.event_type.category == EventCategory.DECEPTION]
            assert len(deception_events) == 0
        finally:
            repository.close()

    def test_unregistered_file_in_deception_root_generates_no_deception_event(
        self, temp_environment, test_endpoint
    ):
        """Unregistered file created directly inside deception root does not trigger deception event."""
        db_path = temp_environment["db_path"]
        decoy_dir = temp_environment["decoy_dir"]

        repository = SQLiteEventRepository(db_path=db_path)
        try:
            pipeline = EventPipeline(repository=repository)

            deception_config = DeceptionConfig(
                enabled=True,
                deception_root=str(decoy_dir),
                interaction_detection_enabled=True,
            )
            deception_engine = CyberDeceptionEngine(
                config=deception_config,
                repository=repository,
                pipeline=pipeline,
                endpoint=test_endpoint,
            )
            deception_engine.initialize()
            deception_engine.deploy()

            detector = DeceptionInteractionDetector(
                registry=deception_engine.registry,
                pipeline=pipeline,
                config=deception_config,
                endpoint=test_endpoint,
            )

            file_monitor = WindowsFileMonitor(
                pipeline=pipeline,
                endpoint=test_endpoint,
                deception_detector=detector,
            )

            # Unregistered file inside deception root
            unregistered = decoy_dir / "unregistered_noise.txt"
            file_event = file_monitor._process_event(
                action="CREATE",
                path=str(unregistered),
                is_directory=False,
                severity=Severity.LOW,
            )
            assert file_event is not None

            # Confirm no DECEPTION event exists
            events, _ = repository.query(EventQueryFilter(limit=50))
            deception_events = [e for e in events if e.event_type.category == EventCategory.DECEPTION]
            assert len(deception_events) == 0
        finally:
            repository.close()

    def test_application_manager_lifecycle_wires_detector(self, temp_environment):
        """ApplicationManager initializes and wires deception detector automatically."""
        decoy_dir = temp_environment["decoy_dir"]
        db_path = temp_environment["db_path"]

        config = RootConfig()
        config.persistence.db_path = str(db_path)
        config.file_collector.enabled = True
        config.file_collector.monitored_paths = [str(decoy_dir)]
        config.deception.enabled = True
        config.deception.deception_root = str(decoy_dir)
        config.deception.auto_create_on_startup = True
        config.deception.interaction_detection_enabled = True

        manager = ApplicationManager()
        try:
            manager.initialize(config=config)

            assert manager.state == LifecycleState.INITIALIZED
            assert manager.deception_engine is not None
            assert manager.deception_detector is not None

            # Verify detector was wired to file monitor
            file_mon = manager.registry.get("windows_file_monitor")
            assert file_mon is not None
            assert file_mon.deception_detector is manager.deception_detector

            manager.start()
            assert manager.state == LifecycleState.RUNNING

            # Verify decoys were deployed
            active_decoys = manager.deception_engine.registry.list_decoys(active_only=True)
            assert len(active_decoys) > 0

            # Simulate interaction on first active decoy
            target = active_decoys[0]
            file_mon._process_event(
                action="MODIFY",
                path=target.normalized_path,
                is_directory=False,
                severity=Severity.LOW,
            )

            # Verify persistence has DECEPTION event
            events, _ = manager.repository.query(EventQueryFilter(limit=50))
            deception_events = [e for e in events if e.event_type.category == EventCategory.DECEPTION]
            assert len(deception_events) >= 1
        finally:
            manager.stop()
            assert manager.state == LifecycleState.STOPPED
