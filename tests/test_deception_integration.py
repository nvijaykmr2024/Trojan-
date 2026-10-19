"""Integration tests for Phase 7 Cyber Deception Engine with Application Lifecycle and Event Pipeline."""

from pathlib import Path
import time
import pytest

from trojan_defense.core.config.schema import (
    AppConfig,
    DeceptionConfig,
    FileCollectorConfig,
    LoggingConfig,
    PersistenceConfig,
    PipelineConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models.context import DeceptionContext, EventContext, FileContext
from trojan_defense.core.models.event import (
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
    current_utc_timestamp,
)
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline


class TestDeceptionIntegration:
    def test_lifecycle_manager_initializes_and_deploys_decoys(self, tmp_path):
        db_path = tmp_path / "telemetry.db"
        deception_root = tmp_path / "deception_root"

        root_cfg = RootConfig(
            app=AppConfig(environment="test", debug=True),
            logging=LoggingConfig(level="DEBUG", log_to_file=False),
            deception=DeceptionConfig(
                enabled=True,
                deception_root=str(deception_root),
                auto_create_on_startup=True,
                cleanup_on_shutdown=True,
            ),
            persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=str(db_path)),
            transport=TransportConfig(enabled=True, driver="mock"),
            pipeline=PipelineConfig(batch_size=10, validate_events=True),
            file_collector=FileCollectorConfig(
                enabled=True,
                monitored_paths=[str(tmp_path / "other_monitored")],
            ),
        )

        app = ApplicationManager()
        app.initialize(config=root_cfg)

        assert app.deception_engine is not None
        assert app.deception_engine.root_path == deception_root.resolve()

        # Check that file_collector monitored_paths includes deception_root
        file_collector = app.registry.get("windows_file_monitor")
        if file_collector:
            assert str(deception_root.resolve()) in file_collector.config.monitored_paths

        # Start application (triggers auto_deploy)
        app.start()

        # Verify decoys are deployed on disk
        status = app.deception_engine.status()
        assert status["active_decoys"] == 8
        assert (deception_root / "documents" / "project_notes.txt").exists()

        # Stop application (triggers cleanup_on_shutdown)
        app.stop()

        # Verify decoys were safely cleaned up
        assert not (deception_root / "documents" / "project_notes.txt").exists()

    def test_deception_context_in_security_event_flow(self, tmp_path):
        db_path = tmp_path / "telemetry.db"
        repo = SQLiteEventRepository(db_path=db_path)
        pipeline = EventPipeline(repository=repo)

        # Create an event representing an interaction with a registered decoy
        decoy_path = tmp_path / "deception" / "credentials" / "cloud_tokens.txt"
        deception_ctx = DeceptionContext(
            is_decoy=True,
            decoy_id="decoy_file_cloud_tokens",
            decoy_type="file",
            path=str(decoy_path),
            action="read",
            status="active",
        )
        file_ctx = FileContext(
            path=str(decoy_path),
            operation="modify",
            is_directory=False,
            size_bytes=256,
        )
        event_ctx = EventContext(
            file=file_ctx,
            deception=deception_ctx,
        )

        event = SecurityEvent(
            event_id="decoy-test-evt-001",
            event_type=EventType(EventCategory.FILE, "MODIFY"),
            severity=Severity.HIGH,
            timestamp=current_utc_timestamp(),
            source="test_runner",
            endpoint=EndpointIdentity.resolve(),
            context=event_ctx,
        )

        # Process through pipeline
        pipeline.process(event)

        # Verify stored in SQLite repository
        retrieved = repo.get_by_id("decoy-test-evt-001")
        assert retrieved is not None
        assert retrieved.context is not None
        assert retrieved.context.deception is not None
        assert retrieved.context.deception.is_decoy is True
        assert retrieved.context.deception.decoy_id == "decoy_file_cloud_tokens"
        assert retrieved.context.deception.decoy_type == "file"
