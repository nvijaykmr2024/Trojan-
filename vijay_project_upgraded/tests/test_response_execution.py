"""Integration tests for ResponseExecutor, remediation actions, rollback, and ResponseRecommender."""

import os
from pathlib import Path
import pytest
import subprocess
import sys

from trojan_defense.alerting.models import Alert
from trojan_defense.core.config.schema import ResponseConfig
from trojan_defense.core.models.severity import Severity
from trojan_defense.response.auth import Permission, Role, UserContext
from trojan_defense.response.executor import ResponseExecutionError, ResponseExecutor
from trojan_defense.response.models import (
    ActionStatus,
    AuditActionType,
    ResponseActionType,
)
from trojan_defense.response.recommender import ResponseRecommender
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)


@pytest.fixture
def executor_env(tmp_path):
    action_repo = SQLiteResponseActionRepository(db_path=tmp_path / "actions.db")
    audit_repo = SQLiteAuditRepository(db_path=tmp_path / "audit.db")
    incident_repo = SQLiteIncidentRepository(db_path=tmp_path / "incidents.db")
    config = ResponseConfig(
        quarantine_dir=str(tmp_path / "quarantine"),
        require_authorization=True,
    )
    executor = ResponseExecutor(
        action_repo=action_repo,
        audit_repo=audit_repo,
        incident_repo=incident_repo,
        config=config,
    )
    return {
        "executor": executor,
        "action_repo": action_repo,
        "audit_repo": audit_repo,
        "incident_repo": incident_repo,
        "config": config,
        "tmp_path": tmp_path,
    }


class TestResponseExecutor:
    """Tests for ResponseExecutor authorization and execution."""

    def test_authorization_enforcement(self, executor_env):
        executor: ResponseExecutor = executor_env["executor"]
        analyst = UserContext(username="analyst1", role=Role.ANALYST)
        responder = UserContext(username="responder1", role=Role.RESPONDER)

        # 1. Analyst requests action
        action = executor.request_action(
            action_type=ResponseActionType.FILE_QUARANTINE,
            target_params={"file_path": "C:\\temp\\dummy.txt"},
            user_context=analyst,
        )
        assert action.status == ActionStatus.REQUESTED

        # 2. Cannot execute directly without authorization
        with pytest.raises(ResponseExecutionError, match="requires explicit human authorization"):
            executor.execute_action(action.action_id, user_context=responder)

        # 3. Responder authorizes action
        authorized = executor.authorize_action(action.action_id, user_context=responder)
        assert authorized.status == ActionStatus.AUTHORIZED
        assert authorized.authorized_by == "responder1"

    def test_rejection_workflow(self, executor_env):
        executor: ResponseExecutor = executor_env["executor"]
        analyst = UserContext(username="analyst1", role=Role.ANALYST)
        responder = UserContext(username="responder1", role=Role.RESPONDER)

        action = executor.request_action(
            action_type=ResponseActionType.PROCESS_TERMINATION,
            target_params={"pid": 1234},
            user_context=analyst,
        )

        rejected = executor.reject_action(action.action_id, reason="False positive process", user_context=responder)
        assert rejected.status == ActionStatus.REJECTED
        assert rejected.error_message == "False positive process"

    def test_file_quarantine_and_rollback_lifecycle(self, executor_env):
        executor: ResponseExecutor = executor_env["executor"]
        tmp_path: Path = executor_env["tmp_path"]
        responder = UserContext(username="responder1", role=Role.RESPONDER)

        # Create real suspect file
        suspect_file = tmp_path / "monitored" / "suspicious_trojan_dropper.bat"
        suspect_file.parent.mkdir(parents=True, exist_ok=True)
        file_payload = b"@echo off\necho Simulated Trojan Activity\n"
        suspect_file.write_bytes(file_payload)

        # 1. Request quarantine
        action = executor.request_action(
            action_type=ResponseActionType.FILE_QUARANTINE,
            target_params={"file_path": str(suspect_file)},
            user_context=responder,
        )

        # 2. Authorize
        executor.authorize_action(action.action_id, user_context=responder)

        # 3. Execute quarantine
        executed = executor.execute_action(action.action_id, user_context=responder)
        assert executed.status == ActionStatus.SUCCEEDED
        assert not suspect_file.exists()  # Source file removed

        quar_path = Path(executed.execution_result["quarantine_path"])
        assert quar_path.exists()  # Moved to quarantine
        assert quar_path.read_bytes() == file_payload

        # 4. Rollback (Restoration)
        rolled_back = executor.rollback_action(action.action_id, user_context=responder)
        assert rolled_back.status == ActionStatus.ROLLED_BACK
        assert suspect_file.exists()  # Restored to original location
        assert suspect_file.read_bytes() == file_payload
        assert not quar_path.exists()  # Removed from quarantine folder

        # 5. Verify audit log trail
        audit_repo: SQLiteAuditRepository = executor_env["audit_repo"]
        entries, count = audit_repo.list(target_id=action.action_id)
        assert count >= 4  # REQUESTED, AUTHORIZED, EXECUTING, SUCCEEDED, ROLLED_BACK

    def test_process_termination_safe_execution(self, executor_env):
        executor: ResponseExecutor = executor_env["executor"]
        responder = UserContext(username="responder1", role=Role.RESPONDER)

        # Spawn a harmless sleep child process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            pid = proc.pid
            import psutil
            ps_proc = psutil.Process(pid)
            create_time = ps_proc.create_time()

            action = executor.request_action(
                action_type=ResponseActionType.PROCESS_TERMINATION,
                target_params={
                    "pid": pid,
                    "create_time": create_time,
                },
                user_context=responder,
            )
            executor.authorize_action(action.action_id, user_context=responder)
            executed = executor.execute_action(action.action_id, user_context=responder)

            assert executed.status == ActionStatus.SUCCEEDED
            assert executed.execution_result["status"] == "terminated"

            # Verify process is terminated
            proc.poll()
            assert not ps_proc.is_running()
        finally:
            if proc.poll() is None:
                proc.kill()


class TestResponseRecommender:
    """Tests for ResponseRecommender."""

    def test_process_and_network_recommendations(self):
        recommender = ResponseRecommender()
        alert = Alert(
            title="Trojan Exfiltration Detected",
            rule_id="RULE-BEH-005",
            rule_name="Exfiltration via Suspicious Process",
            risk_score=90,
            severity=Severity.CRITICAL,
            pid=2468,
            extra={
                "pid": 2468,
                "process_name": "malicious_trojan.exe",
                "remote_ip": "198.51.100.44",
                "remote_port": 8443,
                "file_path": "C:\\temp\\data.zip",
            },
        )

        recs = recommender.recommend_for_alert(alert)
        action_types = [r.action_type for r in recs]

        # Should recommend process termination, file quarantine, network block, and host isolation (score 90)
        assert ResponseActionType.PROCESS_TERMINATION.value in action_types
        assert ResponseActionType.FILE_QUARANTINE.value in action_types
        assert ResponseActionType.NETWORK_BLOCK.value in action_types
        assert ResponseActionType.HOST_ISOLATION.value in action_types

        # Verify recommendations remain advisory
        for r in recs:
            assert r.alert_id == alert.alert_id
            assert r.risk_score == 90
