"""Unit tests for the HttpEventTransport."""

import pytest

from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.config.schema import BackendConfig
from trojan_defense.core.exceptions import TransportError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.core.transport.http import HttpEventTransport


@pytest.fixture
def running_backend():
    repo = InMemoryEventRepository()
    service = EventService(repository=repo)
    config = BackendConfig(host="127.0.0.1", port=0)
    server = BackendServer(service=service, config=config)
    server.start(blocking=False)
    yield server, repo
    server.stop()


class TestHttpEventTransport:
    def test_send_single_event_success(
        self, running_backend, sample_event: SecurityEvent
    ):
        server, repo = running_backend
        url = f"http://{server.host}:{server.port}/api/events"
        transport = HttpEventTransport(endpoint_url=url)

        assert transport.send(sample_event) is True
        assert repo.count() == 1
        stored = repo.get_by_id(sample_event.event_id)
        assert stored is not None
        assert stored.event_id == sample_event.event_id
        transport.close()

    def test_send_duplicate_event_handled_deterministically(
        self, running_backend, sample_event: SecurityEvent
    ):
        server, repo = running_backend
        url = f"http://{server.host}:{server.port}/api/events"
        transport = HttpEventTransport(endpoint_url=url)

        # First send
        assert transport.send(sample_event) is True
        # Second send (backend returns 409 Conflict)
        assert transport.send(sample_event) is True
        assert repo.count() == 1  # No duplicate record
        transport.close()

    def test_send_batch_success(
        self, running_backend, sample_endpoint: EndpointIdentity
    ):
        server, repo = running_backend
        url = f"http://{server.host}:{server.port}/api/events"
        transport = HttpEventTransport(endpoint_url=url)

        events = [
            SecurityEvent(
                event_id=f"http-batch-{i}",
                event_type=EventType(EventCategory.PROCESS, "CREATE"),
                severity=Severity.MEDIUM,
                source="batch_runner",
                endpoint=sample_endpoint,
            )
            for i in range(4)
        ]

        sent = transport.send_batch(events)
        assert sent == 4
        assert repo.count() == 4
        transport.close()

    def test_backend_unavailable_raises_transport_error(
        self, sample_event: SecurityEvent
    ):
        # Port 59999 is unlikely to be listening
        url = "http://127.0.0.1:59999/api/events"
        transport = HttpEventTransport(endpoint_url=url, timeout=0.5, retries=0)

        with pytest.raises(TransportError, match="Failed to transmit event to backend"):
            transport.send(sample_event)
        transport.close()

    def test_send_on_closed_transport_raises(self, sample_event: SecurityEvent):
        transport = HttpEventTransport()
        transport.close()

        with pytest.raises(TransportError, match="Cannot send event via closed HTTP transport"):
            transport.send(sample_event)
