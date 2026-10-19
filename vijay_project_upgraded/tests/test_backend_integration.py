"""Integration tests for the complete telemetry ingestion and persistence pipeline."""

from pathlib import Path
import pytest

from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.config.schema import BackendConfig, PipelineConfig
from trojan_defense.core.models.context import (
    EventContext,
    FileContext,
    ProcessContext,
)
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.normalizer import EventNormalizer
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.core.pipeline.validator import EventValidator
from trojan_defense.core.transport.http import HttpEventTransport


class TestIntegrationPipelineToBackend:
    def test_end_to_end_telemetry_flow(
        self, tmp_path: Path, sample_endpoint: EndpointIdentity
    ):
        # 1. Setup persistent SQLite repository for backend
        db_path = tmp_path / "integration_backend.db"
        server_repo = SQLiteEventRepository(db_path=db_path)
        service = EventService(repository=server_repo)

        # 2. Start Backend HTTP Server on ephemeral port
        backend_config = BackendConfig(host="127.0.0.1", port=0)
        server = BackendServer(service=service, config=backend_config)
        server.start(blocking=False)

        try:
            # 3. Setup client transport targeting the live backend
            backend_url = f"http://{server.host}:{server.port}/api/events"
            http_transport = HttpEventTransport(endpoint_url=backend_url)

            # 4. Setup client Phase 1 EventPipeline with HttpEventTransport
            client_pipeline = EventPipeline(
                config=PipelineConfig(validate_events=True),
                validator=EventValidator(),
                normalizer=EventNormalizer(default_endpoint=sample_endpoint),
                repository=None,  # Client does not store locally; sends to backend
                transport=http_transport,
            )

            # 5. Create a realistic test SecurityEvent
            event = SecurityEvent(
                event_id="e2e-integ-event-001",
                event_type=EventType(EventCategory.PROCESS, "CREATE"),
                severity=Severity.HIGH,
                source="integration_test_agent",
                endpoint=sample_endpoint,
                context=EventContext(
                    process=ProcessContext(
                        pid=4920,
                        name="powershell.exe",
                        executable_path="C:\\Windows\\System32\\powershell.exe",
                        command_line="powershell.exe -ExecutionPolicy Bypass",
                    )
                ),
            )

            # 6. Process event through client pipeline -> HTTP transport -> backend
            processed = client_pipeline.process(event)
            assert processed.event_id == event.event_id
            assert client_pipeline.stats["events_processed"] == 1

            # 7. Verify event exists in backend SQLite database
            assert server_repo.count() == 1
            stored = server_repo.get_by_id(event.event_id)
            assert stored is not None
            assert stored.event_id == event.event_id
            assert stored.event_type.value == "PROCESS.CREATE"
            assert stored.severity == Severity.HIGH
            assert stored.endpoint.endpoint_id == sample_endpoint.endpoint_id
            assert stored.context.process is not None
            assert stored.context.process.pid == 4920
            assert stored.context.process.name == "powershell.exe"

            # 8. Query backend using EventService
            events, total = service.query_events(
                EventQueryFilter(endpoint_id=sample_endpoint.endpoint_id, severity="HIGH")
            )
            assert total == 1
            assert events[0].event_id == event.event_id

            # 9. Verify duplicate event emission is handled without error or corruption
            client_pipeline.process(event)
            assert server_repo.count() == 1  # Unchanged count

        finally:
            server.stop()
            server_repo.close()

    def test_database_persistence_across_server_restarts(
        self, tmp_path: Path, sample_endpoint: EndpointIdentity
    ):
        db_path = tmp_path / "restart_test.db"

        # First run: start server, insert event, stop server
        repo1 = SQLiteEventRepository(db_path=db_path)
        service1 = EventService(repository=repo1)
        server1 = BackendServer(service=service1, config=BackendConfig(host="127.0.0.1", port=0))
        server1.start(blocking=False)

        event = SecurityEvent(
            event_id="persist-survive-001",
            event_type=EventType(EventCategory.FILE, "WRITE"),
            severity=Severity.LOW,
            source="file_audit",
            endpoint=sample_endpoint,
            context=EventContext(file=FileContext(path="C:\\temp\\log.txt", operation="write")),
        )
        service1.ingest_event(event)
        assert repo1.count() == 1

        server1.stop()
        repo1.close()

        # Second run: reopen database, start new server instance, verify data is intact
        repo2 = SQLiteEventRepository(db_path=db_path)
        service2 = EventService(repository=repo2)
        server2 = BackendServer(service=service2, config=BackendConfig(host="127.0.0.1", port=0))
        server2.start(blocking=False)

        try:
            assert repo2.count() == 1
            retrieved = repo2.get_by_id("persist-survive-001")
            assert retrieved is not None
            assert retrieved.event_id == "persist-survive-001"
            assert retrieved.context.file is not None
            assert retrieved.context.file.path == "C:\\temp\\log.txt"
        finally:
            server2.stop()
            repo2.close()
