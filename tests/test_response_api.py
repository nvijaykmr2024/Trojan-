"""End-to-end REST API tests for Incidents, Responses, Audit Logs, and RBAC."""

import json
from pathlib import Path
import pytest
import urllib.error
import urllib.request

from trojan_defense.alerting.models import Alert
from trojan_defense.alerting.repository import SQLiteAlertRepository
from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.config.schema import BackendConfig, ResponseConfig
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.in_memory import InMemoryEventRepository
from trojan_defense.response.executor import ResponseExecutor
from trojan_defense.response.recommender import ResponseRecommender
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)


@pytest.fixture
def api_server(tmp_path):
    event_repo = InMemoryEventRepository()
    alert_repo = SQLiteAlertRepository(db_path=tmp_path / "alerts.db")
    incident_repo = SQLiteIncidentRepository(db_path=tmp_path / "incidents.db")
    action_repo = SQLiteResponseActionRepository(db_path=tmp_path / "actions.db")
    audit_repo = SQLiteAuditRepository(db_path=tmp_path / "audit.db")

    response_config = ResponseConfig(
        quarantine_dir=str(tmp_path / "quarantine"),
        require_authorization=True,
        auth_tokens={
            "token-viewer": "VIEWER",
            "token-analyst": "ANALYST",
            "token-responder": "RESPONDER",
            "token-admin": "ADMIN",
        },
    )

    executor = ResponseExecutor(
        action_repo=action_repo,
        audit_repo=audit_repo,
        incident_repo=incident_repo,
        config=response_config,
    )

    recommender = ResponseRecommender()

    service = EventService(
        repository=event_repo,
        alert_repository=alert_repo,
        incident_repository=incident_repo,
        response_action_repository=action_repo,
        response_executor=executor,
        response_recommender=recommender,
        audit_repository=audit_repo,
    )

    config = BackendConfig(host="127.0.0.1", port=0)
    server = BackendServer(
        service=service,
        config=config,
        auth_tokens=response_config.auth_tokens,
    )
    server.start(blocking=False)
    base_url = f"http://127.0.0.1:{server.port}"

    yield {
        "server": server,
        "base_url": base_url,
        "alert_repo": alert_repo,
        "tmp_path": tmp_path,
    }

    server.stop()
    alert_repo.close()
    incident_repo.close()
    action_repo.close()
    audit_repo.close()


def _request(url: str, method: str = "GET", data: dict | None = None, headers: dict | None = None):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            resp_body = json.loads(resp.read().decode("utf-8"))
            return status, resp_body
    except urllib.error.HTTPError as exc:
        err_body = json.loads(exc.read().decode("utf-8"))
        return exc.code, err_body


class TestResponseAndIncidentAPI:
    """REST API tests for incidents, response actions, recommendations, and audit trail."""

    def test_incident_api_lifecycle(self, api_server):
        base = api_server["base_url"]
        auth = {"X-User-Role": "ANALYST", "X-Actor": "analyst_bob"}

        # 1. Create incident
        status, body = _request(
            f"{base}/api/incidents",
            method="POST",
            data={
                "title": "Trojan Campaign Detection",
                "severity": "CRITICAL",
                "description": "Multi-stage exfiltration",
            },
            headers=auth,
        )
        assert status == 201
        inc_id = body["incident"]["incident_id"]

        # 2. Get single incident
        status, body = _request(f"{base}/api/incidents/{inc_id}", headers=auth)
        assert status == 200
        assert body["incident_id"] == inc_id
        assert body["status"] == "OPEN"

        # 3. Add note
        status, body = _request(
            f"{base}/api/incidents/{inc_id}/notes",
            method="POST",
            data={"content": "Quarantine candidate identified"},
            headers=auth,
        )
        assert status == 201
        assert body["status"] == "created"

        # 4. Update status
        status, body = _request(
            f"{base}/api/incidents/{inc_id}/status",
            method="POST",
            data={"status": "INVESTIGATING"},
            headers=auth,
        )
        assert status == 200
        assert body["incident"]["status"] == "INVESTIGATING"

        # 5. List incidents
        status, body = _request(f"{base}/api/incidents?status=INVESTIGATING", headers=auth)
        assert status == 200
        assert body["total"] == 1
        assert len(body["incidents"]) == 1

    def test_response_action_api_workflow(self, api_server):
        base = api_server["base_url"]
        tmp_path = api_server["tmp_path"]

        # Create dummy file to quarantine
        test_file = tmp_path / "dropper.exe"
        test_file.write_bytes(b"DUMMY_EXE_CONTENT")

        analyst_auth = {"X-User-Role": "ANALYST", "X-Actor": "analyst1"}
        responder_auth = {"X-User-Role": "RESPONDER", "X-Actor": "responder1"}

        # 1. Request action
        status, body = _request(
            f"{base}/api/responses",
            method="POST",
            data={
                "action_type": "FILE_QUARANTINE",
                "target_params": {"file_path": str(test_file)},
            },
            headers=analyst_auth,
        )
        assert status == 201
        act_id = body["action"]["action_id"]
        assert body["action"]["status"] == "REQUESTED"

        # 2. Analyst tries to authorize -> 403 Forbidden
        status, err = _request(
            f"{base}/api/responses/{act_id}/authorize",
            method="POST",
            headers=analyst_auth,
        )
        assert status == 403
        assert err["error"] == "Forbidden"

        # 3. Responder authorizes -> 200 OK
        status, body = _request(
            f"{base}/api/responses/{act_id}/authorize",
            method="POST",
            headers=responder_auth,
        )
        assert status == 200
        assert body["action"]["status"] == "AUTHORIZED"

        # 4. Responder executes -> 200 OK
        status, body = _request(
            f"{base}/api/responses/{act_id}/execute",
            method="POST",
            headers=responder_auth,
        )
        assert status == 200
        assert body["status"] == "SUCCEEDED"
        assert not test_file.exists()

        # 5. Rollback -> 200 OK
        status, body = _request(
            f"{base}/api/responses/{act_id}/rollback",
            method="POST",
            headers=responder_auth,
        )
        assert status == 200
        assert body["status"] == "rolled_back"
        assert test_file.exists()

    def test_alert_recommendations_and_audit_api(self, api_server):
        base = api_server["base_url"]
        alert_repo = api_server["alert_repo"]

        # Insert a high risk alert
        alert = Alert(
            title="Trojan Exfiltration Alert",
            rule_id="RULE-BEH-005",
            rule_name="Exfiltration Rule",
            risk_score=92,
            severity=Severity.CRITICAL,
            pid=5555,
            extra={
                "pid": 5555,
                "remote_ip": "203.0.113.88",
                "remote_port": 443,
            },
        )
        alert_repo.save(alert)

        admin_auth = {"X-User-Role": "ADMIN"}

        # 1. Query recommendations
        status, body = _request(
            f"{base}/api/alerts/{alert.alert_id}/recommendations",
            headers=admin_auth,
        )
        assert status == 200
        assert body["alert_id"] == alert.alert_id
        recs = body["recommendations"]
        assert len(recs) >= 3  # termination, network block, host isolation

        # 2. Query audit trail
        status, body = _request(f"{base}/api/audit", headers=admin_auth)
        assert status == 200
        assert "audit_logs" in body
        assert isinstance(body["audit_logs"], list)

    def test_rbac_token_authentication(self, api_server):
        base = api_server["base_url"]

        # Viewer token attempting POST
        status, err = _request(
            f"{base}/api/incidents",
            method="POST",
            data={"title": "Unauthorized attempt"},
            headers={"Authorization": "Bearer token-viewer"},
        )
        assert status == 403
        assert err["error"] == "Forbidden"

        # Admin token attempting POST
        status, body = _request(
            f"{base}/api/incidents",
            method="POST",
            data={"title": "Authorized incident"},
            headers={"Authorization": "Bearer token-admin"},
        )
        assert status == 201
        assert body["incident"]["title"] == "Authorized incident"
