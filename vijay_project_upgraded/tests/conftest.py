"""Shared test fixtures for the Trojan Defense test suite."""

import pytest

from trojan_defense.core.config.schema import RootConfig
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.core.transport.mock import MockEventTransport


@pytest.fixture
def sample_endpoint() -> EndpointIdentity:
    """Provides a deterministic test endpoint identity."""
    return EndpointIdentity(
        endpoint_id="test-endpoint-001",
        hostname="test-host",
        platform="Windows",
        os_version="10.0.22631",
        architecture="AMD64",
        agent_version="0.1.0",
    )


@pytest.fixture
def sample_event(sample_endpoint: EndpointIdentity) -> SecurityEvent:
    """Provides a standard valid test SecurityEvent."""
    return SecurityEvent(
        event_id="test-event-uuid-1234",
        event_type=EventType(EventCategory.PROCESS, "CREATE"),
        severity=Severity.MEDIUM,
        source="test_collector",
        endpoint=sample_endpoint,
        context=EventContext(
            process=ProcessContext(
                pid=1001,
                ppid=450,
                name="notepad.exe",
                executable_path="C:\\Windows\\System32\\notepad.exe",
                command_line="notepad.exe test.txt",
                username="SYSTEM",
            )
        ),
    )


@pytest.fixture
def memory_repo() -> InMemoryEventRepository:
    """Provides a clean in-memory event repository."""
    return InMemoryEventRepository()


@pytest.fixture
def mock_transport() -> MockEventTransport:
    """Provides a mock event transport."""
    return MockEventTransport()


@pytest.fixture
def test_pipeline(
    memory_repo: InMemoryEventRepository,
    mock_transport: MockEventTransport,
    sample_endpoint: EndpointIdentity,
) -> EventPipeline:
    """Provides a fully wired EventPipeline with in-memory persistence and mock transport."""
    from trojan_defense.core.pipeline.normalizer import EventNormalizer
    from trojan_defense.core.pipeline.validator import EventValidator

    return EventPipeline(
        validator=EventValidator(),
        normalizer=EventNormalizer(default_endpoint=sample_endpoint),
        repository=memory_repo,
        transport=mock_transport,
    )
