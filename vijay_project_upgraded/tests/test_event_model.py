"""Tests for the SecurityEvent and related domain models."""

import pytest

from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    NetworkContext,
    ProcessContext,
    SystemContext,
)
from trojan_defense.core.models.event import SCHEMA_VERSION, SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity


class TestEventType:
    def test_event_type_from_category(self):
        et = EventType.from_category(EventCategory.PROCESS)
        assert et.category == EventCategory.PROCESS
        assert et.action is None
        assert et.value == "PROCESS"

    def test_event_type_with_action(self):
        et = EventType(EventCategory.FILE, "CREATE")
        assert et.category == EventCategory.FILE
        assert et.action == "CREATE"
        assert et.value == "FILE.CREATE"

    def test_event_type_from_string(self):
        et = EventType.from_string("NETWORK.CONNECT")
        assert et.category == EventCategory.NETWORK
        assert et.action == "CONNECT"
        assert et.value == "NETWORK.CONNECT"

    def test_invalid_category_raises_error(self):
        with pytest.raises(ValueError, match="Invalid event category"):
            EventType("INVALID_CAT")

    def test_event_type_equality(self):
        et1 = EventType(EventCategory.DECEPTION, "TRIGGER")
        et2 = EventType.from_string("DECEPTION.TRIGGER")
        assert et1 == et2
        assert et1 == "DECEPTION.TRIGGER"
        assert hash(et1) == hash(et2)


class TestSeverity:
    def test_severity_ordering(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_severity_from_string(self):
        assert Severity.from_string("info") == Severity.INFO
        assert Severity.from_string("HIGH") == Severity.HIGH

    def test_invalid_severity_raises_error(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            Severity.from_string("UNKNOWN")


class TestEventContext:
    def test_context_to_dict_omits_none_subcontexts(self):
        ctx = EventContext(
            process=ProcessContext(pid=123, name="svchost.exe"),
            file=FileContext(path="C:\\test.txt", operation="write"),
        )
        data = ctx.to_dict()
        assert "process" in data
        assert data["process"]["pid"] == 123
        assert "file" in data
        assert "network" not in data
        assert "system" not in data
        assert "deception" not in data

    def test_context_roundtrip(self):
        original = EventContext(
            network=NetworkContext(protocol="TCP", source_ip="127.0.0.1", source_port=8080),
            system=SystemContext(subsystem="registry", target="HKLM\\Software"),
            deception=DeceptionContext(decoy_id="decoy-01", decoy_type="canary_file"),
            extra={"note": "test"},
        )
        data = original.to_dict()
        reconstructed = EventContext.from_dict(data)

        assert reconstructed.network is not None
        assert reconstructed.network.protocol == "TCP"
        assert reconstructed.system is not None
        assert reconstructed.system.subsystem == "registry"
        assert reconstructed.deception is not None
        assert reconstructed.deception.decoy_id == "decoy-01"
        assert reconstructed.extra == {"note": "test"}


class TestSecurityEvent:
    def test_valid_event_creation(self, sample_endpoint: EndpointIdentity):
        event = SecurityEvent(
            event_type=EventType.from_category(EventCategory.SYSTEM),
            severity=Severity.INFO,
            source="system_test",
            endpoint=sample_endpoint,
        )
        assert event.event_id is not None
        assert event.schema_version == SCHEMA_VERSION
        assert event.timestamp is not None
        assert event.severity == Severity.INFO
        assert event.source == "system_test"
        assert event.endpoint.endpoint_id == sample_endpoint.endpoint_id

    def test_serialization_roundtrip_dict(self, sample_event: SecurityEvent):
        event_dict = sample_event.to_dict()
        reconstructed = SecurityEvent.from_dict(event_dict)

        assert reconstructed.event_id == sample_event.event_id
        assert reconstructed.schema_version == sample_event.schema_version
        assert reconstructed.timestamp == sample_event.timestamp
        assert reconstructed.event_type == sample_event.event_type
        assert reconstructed.severity == sample_event.severity
        assert reconstructed.source == sample_event.source
        assert reconstructed.endpoint.endpoint_id == sample_event.endpoint.endpoint_id
        assert reconstructed.context.process is not None
        assert reconstructed.context.process.pid == sample_event.context.process.pid

    def test_serialization_roundtrip_json(self, sample_event: SecurityEvent):
        json_str = sample_event.to_json()
        reconstructed = SecurityEvent.from_json(json_str)
        assert reconstructed.event_id == sample_event.event_id
        assert reconstructed.source == sample_event.source

    def test_missing_required_fields_raises_error(self):
        with pytest.raises(KeyError, match="Missing required field"):
            SecurityEvent.from_dict({"event_type": "PROCESS"})
