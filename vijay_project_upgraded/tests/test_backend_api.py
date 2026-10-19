"""Unit tests for the backend HTTP API server endpoints."""

import json
from pathlib import Path
import urllib.error
import urllib.request
import pytest

from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.config.schema import BackendConfig
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository


@pytest.fixture
def api_server():
    """Starts a live BackendServer on an ephemeral port (port=0) with in-memory persistence."""
    repo = InMemoryEventRepository()
    service = EventService(repository=repo)
    config = BackendConfig(host="127.0.0.1", port=0, max_content_length=10000)
    server = BackendServer(service=service, config=config)
    server.start(blocking=False)
    yield server
    server.stop()


def make_request(
    server: BackendServer,
    path: str,
    method: str = "GET",
    data: dict | list | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    """Helper to execute HTTP requests against test server."""
    url = f"http://{server.host}:{server.port}{path}"
    req_headers = headers or {}

    body_bytes = None
    if data is not None:
        if isinstance(data, bytes):
            body_bytes = data
        else:
            body_bytes = json.dumps(data).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json; charset=utf-8")
        req_headers.setdefault("Content-Length", str(len(body_bytes)))

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8")
            return code, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return exc.code, parsed


class TestBackendAPI:
    def test_health_check(self, api_server: BackendServer):
        status, data = make_request(api_server, "/api/health")
        assert status == 200
        assert data["status"] == "healthy"
        assert data["service"] == "trojan-defense-backend"
        assert "timestamp" in data
        assert data["total_events"] == 0

    def test_post_valid_event(self, api_server: BackendServer, sample_event: SecurityEvent):
        status, data = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=sample_event.to_dict(),
        )
        assert status == 201
        assert data["status"] == "created"
        assert data["event_id"] == sample_event.event_id

        # Verify event count increased in health check
        _, health = make_request(api_server, "/api/health")
        assert health["total_events"] == 1

    def test_post_duplicate_event_returns_409_conflict(
        self, api_server: BackendServer, sample_event: SecurityEvent
    ):
        # First submission
        status1, _ = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=sample_event.to_dict(),
        )
        assert status1 == 201

        # Second submission
        status2, data2 = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=sample_event.to_dict(),
        )
        assert status2 == 409
        assert data2["status"] == "duplicate"
        assert data2["event_id"] == sample_event.event_id

    def test_post_malformed_json_returns_400(self, api_server: BackendServer):
        status, data = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=b"{not_valid_json",
            headers={"Content-Type": "application/json", "Content-Length": "15"},
        )
        assert status == 400
        assert "Malformed JSON" in data.get("error", "")

    def test_post_invalid_schema_returns_400(self, api_server: BackendServer):
        bad_payload = {"event_id": "test", "severity": "INVALID"}
        status, data = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=bad_payload,
        )
        assert status == 400
        assert "Validation Error" in data.get("error", "")

    def test_post_oversized_payload_returns_413(self, api_server: BackendServer):
        # Test max_content_length is set to 10000 bytes
        huge_extra = "A" * 15000
        status, data = make_request(
            api_server,
            "/api/events",
            method="POST",
            data=huge_extra.encode("utf-8"),
            headers={"Content-Type": "application/json", "Content-Length": "15000"},
        )
        assert status == 413
        assert data["error"] == "Payload Too Large"

    def test_post_batch_events(
        self, api_server: BackendServer, sample_endpoint: EndpointIdentity
    ):
        events = [
            SecurityEvent(
                event_id=f"batch-http-{i}",
                event_type=EventType(EventCategory.PROCESS, "SPAWN"),
                severity=Severity.LOW,
                source="test",
                endpoint=sample_endpoint,
            ).to_dict()
            for i in range(3)
        ]

        status, data = make_request(
            api_server,
            "/api/events/batch",
            method="POST",
            data={"events": events},
        )
        assert status == 201
        assert data["status"] == "processed"
        assert data["total_received"] == 3
        assert data["new_stored"] == 3

    def test_get_single_event(
        self, api_server: BackendServer, sample_event: SecurityEvent
    ):
        # Post event first
        make_request(api_server, "/api/events", method="POST", data=sample_event.to_dict())

        # Retrieve existing
        status, data = make_request(api_server, f"/api/events/{sample_event.event_id}")
        assert status == 200
        assert data["event_id"] == sample_event.event_id
        assert data["source"] == sample_event.source

        # Retrieve non-existing
        status404, data404 = make_request(api_server, "/api/events/unknown-id")
        assert status404 == 404
        assert "Event not found" in data404.get("error", "")

    def test_query_events_with_pagination_and_filters(
        self, api_server: BackendServer, sample_endpoint: EndpointIdentity
    ):
        for i in range(8):
            sev = Severity.HIGH if i % 2 == 0 else Severity.LOW
            ev = SecurityEvent(
                event_id=f"query-ev-{i}",
                event_type=EventType(EventCategory.NETWORK, "CONNECT"),
                severity=sev,
                source="test_net",
                endpoint=sample_endpoint,
                timestamp=f"2026-10-01T10:0{i}:00+00:00",
            )
            make_request(api_server, "/api/events", method="POST", data=ev.to_dict())

        # Query all with pagination limit=3, offset=0
        status, data = make_request(api_server, "/api/events?limit=3&offset=0")
        assert status == 200
        assert data["total"] == 8
        assert data["count"] == 3
        assert len(data["events"]) == 3

        # Query filter by severity=HIGH
        status_high, data_high = make_request(api_server, "/api/events?severity=HIGH")
        assert status_high == 200
        assert data_high["total"] == 4
        assert all(e["severity"] == "HIGH" for e in data_high["events"])

    def test_not_found_endpoint(self, api_server: BackendServer):
        status, _ = make_request(api_server, "/nonexistent/endpoint")
        assert status == 404
