"""Automated test suite for Phase 10 REST API Endpoints.

Tests GET /api/alerts, GET /api/alerts/<id>, GET /api/alerts/<id>/evidence,
POST /api/alerts/<id>/acknowledge, POST /api/alerts/<id>/resolve,
and POST /api/alerts/<id>/status against a running BackendServer on ephemeral port.
"""

import json
from pathlib import Path
import urllib.error
import urllib.request
from typing import Any

import pytest

from trojan_defense.alerting.engine import AlertEngine
from trojan_defense.alerting.models import Alert, AlertStatus
from trojan_defense.alerting.repository import SQLiteAlertRepository
from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.config.schema import BackendConfig
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository


@pytest.fixture
def alert_api_server():
    """Starts a live BackendServer on ephemeral port (port=0) with alert repository."""
    event_repo = InMemoryEventRepository()
    alert_repo = SQLiteAlertRepository(db_path=":memory:")
    alert_engine = AlertEngine(repository=alert_repo)

    # Pre-populate sample events in event_repo to test evidence resolution
    ev1 = SecurityEvent(
        event_id="ev_raw_001",
        event_type=EventType("FILE", "CREATE"),
        severity=Severity.MEDIUM,
        source="file_monitor",
        endpoint=EndpointIdentity.resolve(),
    )
    event_repo.save(ev1)

    # Pre-populate 3 sample alerts in alert_repo
    a1 = Alert(
        alert_id="alt_test_001",
        title="Decoy Access Detected",
        severity=Severity.CRITICAL,
        risk_score=95,
        status=AlertStatus.OPEN,
        endpoint_id="ep_test_win",
        rule_id="RULE-BEH-005",
        rule_name="Decoy Rule",
        pid=1234,
        process_name="cmd.exe",
        scoring_reasons=[{"factor": "base_rule", "contribution": 75, "reason": "Base"}],
        related_event_ids=["ev_raw_001"],
        evidence=[{"category": "DECEPTION", "decoy_id": "fake_creds.txt"}],
    )
    a2 = Alert(
        alert_id="alt_test_002",
        title="Sensitive File Modification",
        severity=Severity.HIGH,
        risk_score=75,
        status=AlertStatus.OPEN,
        endpoint_id="ep_test_win",
        rule_id="RULE-BEH-001",
        rule_name="File Rule",
        pid=5678,
        process_name="powershell.exe",
        scoring_reasons=[{"factor": "base_rule", "contribution": 40, "reason": "Base"}],
        related_event_ids=[],
    )
    a3 = Alert(
        alert_id="alt_test_003",
        title="Network Beaconing",
        severity=Severity.MEDIUM,
        risk_score=45,
        status=AlertStatus.RESOLVED,
        endpoint_id="ep_test_win",
        rule_id="RULE-BEH-002",
        rule_name="Net Rule",
        pid=9999,
        process_name="beacon.exe",
        scoring_reasons=[{"factor": "base_rule", "contribution": 30, "reason": "Base"}],
        related_event_ids=[],
    )
    alert_repo.save(a1)
    alert_repo.save(a2)
    alert_repo.save(a3)

    service = EventService(
        repository=event_repo,
        alert_repository=alert_repo,
        alert_engine=alert_engine,
    )
    config = BackendConfig(host="127.0.0.1", port=0, max_content_length=50000)
    server = BackendServer(service=service, config=config)
    server.start(blocking=False)
    yield server
    server.stop()


def request_api(
    server: BackendServer,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Helper to execute HTTP requests against test server."""
    url = f"http://{server.host}:{server.port}{path}"
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body_bytes = None
    if data is not None:
        body_bytes = json.dumps(data).encode("utf-8")
        headers["Content-Length"] = str(len(body_bytes))

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8")
            return code, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body) if body else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": body}


class TestAlertAPIEndpoints:
    """Tests for REST API alert endpoints."""

    def test_health_includes_total_alerts(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/health includes total_alerts count."""
        code, body = request_api(alert_api_server, "/api/health")
        assert code == 200
        assert body["status"] == "healthy"
        assert body["total_alerts"] == 3

    def test_get_alerts_list(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts returns paginated alert list."""
        code, body = request_api(alert_api_server, "/api/alerts")
        assert code == 200
        assert body["total"] == 3
        assert body["count"] == 3
        assert len(body["alerts"]) == 3

    def test_get_alerts_filtered_by_status(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts?status=OPEN filters properly."""
        code, body = request_api(alert_api_server, "/api/alerts?status=OPEN")
        assert code == 200
        assert body["total"] == 2
        assert len(body["alerts"]) == 2
        assert all(a["status"] == "OPEN" for a in body["alerts"])

    def test_get_alerts_filtered_by_severity(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts?severity=CRITICAL returns matching alerts."""
        code, body = request_api(alert_api_server, "/api/alerts?severity=CRITICAL")
        assert code == 200
        assert body["total"] == 1
        assert body["alerts"][0]["alert_id"] == "alt_test_001"

    def test_get_alerts_filtered_by_min_score(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts?min_score=70 filters properly."""
        code, body = request_api(alert_api_server, "/api/alerts?min_score=70")
        assert code == 200
        assert body["total"] == 2  # 95 and 75

    def test_get_single_alert(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts/<id> returns specific alert or 404."""
        code, body = request_api(alert_api_server, "/api/alerts/alt_test_001")
        assert code == 200
        assert body["alert_id"] == "alt_test_001"
        assert body["severity"] == "CRITICAL"
        assert body["risk_score"] == 95

        # Non-existent alert
        code_nf, body_nf = request_api(alert_api_server, "/api/alerts/alt_nonexistent")
        assert code_nf == 404
        assert "error" in body_nf

    def test_get_alert_evidence(self, alert_api_server: BackendServer) -> None:
        """Verify GET /api/alerts/<id>/evidence returns evidence and resolved events."""
        code, body = request_api(alert_api_server, "/api/alerts/alt_test_001/evidence")
        assert code == 200
        assert body["alert_id"] == "alt_test_001"
        assert body["risk_score"] == 95
        assert len(body["evidence"]) == 1
        assert body["evidence"][0]["decoy_id"] == "fake_creds.txt"
        assert len(body["resolved_events"]) == 1
        assert body["resolved_events"][0]["event_id"] == "ev_raw_001"

    def test_acknowledge_alert(self, alert_api_server: BackendServer) -> None:
        """Verify POST /api/alerts/<id>/acknowledge transitions alert state."""
        code, body = request_api(
            alert_api_server,
            "/api/alerts/alt_test_001/acknowledge",
            method="POST",
            data={"comment": "Analyst investigating now"},
        )
        assert code == 200
        assert body["status"] == "acknowledged"
        assert body["alert"]["status"] == "ACKNOWLEDGED"

        # Verify state in repository via GET
        code_get, body_get = request_api(alert_api_server, "/api/alerts/alt_test_001")
        assert code_get == 200
        assert body_get["status"] == "ACKNOWLEDGED"

    def test_resolve_alert(self, alert_api_server: BackendServer) -> None:
        """Verify POST /api/alerts/<id>/resolve transitions alert state."""
        code, body = request_api(
            alert_api_server,
            "/api/alerts/alt_test_002/resolve",
            method="POST",
            data={"comment": "False positive, test build verified"},
        )
        assert code == 200
        assert body["status"] == "resolved"
        assert body["alert"]["status"] == "RESOLVED"

    def test_update_alert_status_custom(self, alert_api_server: BackendServer) -> None:
        """Verify POST /api/alerts/<id>/status handles valid and invalid transitions."""
        # Valid transition: OPEN -> ACKNOWLEDGED
        code, body = request_api(
            alert_api_server,
            "/api/alerts/alt_test_001/status",
            method="POST",
            data={"status": "ACKNOWLEDGED", "comment": "Triage in progress"},
        )
        assert code == 200
        assert body["status"] == "updated"
        assert body["alert"]["status"] == "ACKNOWLEDGED"

        # Invalid transition: invalid status string
        code_inv, body_inv = request_api(
            alert_api_server,
            "/api/alerts/alt_test_001/status",
            method="POST",
            data={"status": "INVALID_STATE"},
        )
        assert code_inv == 400
        assert "error" in body_inv
