"""Tests for the Transport boundary (Mock and File transport)."""

import json
from pathlib import Path
import pytest

from trojan_defense.core.exceptions import TransportError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.transport.file import JsonLineFileTransport
from trojan_defense.core.transport.mock import MockEventTransport


class TestMockTransport:
    def test_mock_send_and_batch(self, sample_event: SecurityEvent):
        transport = MockEventTransport()
        assert transport.send(sample_event) is True
        assert len(transport.dispatched_events) == 1

        assert transport.send_batch([sample_event, sample_event]) == 2
        assert len(transport.dispatched_events) == 3

        transport.clear()
        assert len(transport.dispatched_events) == 0

    def test_mock_simulated_failure(self, sample_event: SecurityEvent):
        transport = MockEventTransport(fail_next=True)
        with pytest.raises(TransportError, match="Simulated transport transmission failure"):
            transport.send(sample_event)


class TestJsonLineFileTransport:
    def test_file_transport_writes_valid_jsonl(self, tmp_path: Path, sample_event: SecurityEvent):
        target_file = tmp_path / "transport_test.jsonl"
        transport = JsonLineFileTransport(file_path=target_file)

        assert transport.send(sample_event) is True
        transport.close()

        lines = target_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["event_id"] == sample_event.event_id
        assert data["source"] == sample_event.source

    def test_file_transport_batch_append(self, tmp_path: Path, sample_endpoint: EndpointIdentity):
        target_file = tmp_path / "transport_batch.jsonl"
        transport = JsonLineFileTransport(file_path=target_file)

        events = [
            SecurityEvent(
                event_type=EventType.from_category(EventCategory.PRIVILEGE),
                severity=Severity.HIGH,
                source=f"priv_{i}",
                endpoint=sample_endpoint,
            )
            for i in range(3)
        ]

        count = transport.send_batch(events)
        assert count == 3
        transport.close()

        lines = target_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3

    def test_send_to_closed_transport_raises(self, tmp_path: Path, sample_event: SecurityEvent):
        target_file = tmp_path / "closed.jsonl"
        transport = JsonLineFileTransport(file_path=target_file)
        transport.close()

        with pytest.raises(TransportError, match="Cannot send event via closed transport"):
            transport.send(sample_event)
