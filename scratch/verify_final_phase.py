"""Windows Manual Validation Script for Final Phase: Controlled Defensive Response and Incident Management.

Executes an end-to-end operational verification demonstrating:
1. End-to-end pipeline: Ingestion -> Behavioral correlation -> Risk score -> Alert persistence.
2. Advisory recommendations generated via ResponseRecommender (strictly non-autonomous).
3. Incident management lifecycle: OPEN -> INVESTIGATING -> notes -> alert associations.
4. RBAC authorization gate: REQUESTED -> authorization rejected for VIEWER -> AUTHORIZED by RESPONDER/ADMIN.
5. Safe OS execution:
   - Controlled process termination with PID reuse validation.
   - Safe file quarantine with pre-quarantine SHA-256 calculation and sandboxing.
6. Non-destructive rollback:
   - Restoring quarantined file with SHA-256 verification.
7. Immutable audit logging: Complete audit trail stored in append-only SQLite repository.
8. REST API querying: Incidents, actions, recommendations, and audit logs.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trojan_defense.alerting.engine import AlertEngine
from trojan_defense.alerting.models import Alert, AlertStatus
from trojan_defense.alerting.repository import SQLiteAlertRepository
from trojan_defense.alerting.scorer import RiskScoringEngine
from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.core.config.loader import load_config
from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    ProcessContext,
)
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.response.auth import AuthorizationError, Role, UserContext
from trojan_defense.response.executor import ResponseExecutionError, ResponseExecutor
from trojan_defense.response.models import (
    ActionStatus,
    AuditActionType,
    AuditLogEntry,
    Incident,
    IncidentNote,
    IncidentStatus,
    ResponseAction,
    ResponseActionType,
)
from trojan_defense.response.recommender import ResponseRecommender
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)


def main() -> int:
    print("=" * 80)
    print("FINAL PHASE END-TO-END VERIFICATION: DEFENSIVE RESPONSE & INCIDENT MANAGEMENT")
    print("=" * 80)

    # 1. Setup isolated directories & database
    temp_dir = Path(tempfile.mkdtemp(prefix="trojan_defense_final_verify_"))
    db_file = temp_dir / "verification.db"
    quarantine_dir = temp_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Isolated workspace: {temp_dir}")
    print(f"[+] SQLite Database: {db_file}")
    print(f"[+] Quarantine Directory: {quarantine_dir}")

    endpoint = EndpointIdentity.resolve()
    print(f"[+] Endpoint: {endpoint.endpoint_id} ({endpoint.hostname}) [{endpoint.platform}]")

    # 2. Initialize Repositories
    event_repo = SQLiteEventRepository(db_path=str(db_file))
    alert_repo = SQLiteAlertRepository(db_path=str(db_file))
    incident_repo = SQLiteIncidentRepository(db_path=str(db_file))
    response_repo = SQLiteResponseActionRepository(db_path=str(db_file))
    audit_repo = SQLiteAuditRepository(db_path=str(db_file))

    config = load_config(environment="development")
    config.behavior.enabled = True
    config.alerting.enabled = True
    config.response.enabled = True
    config.response.quarantine_dir = str(quarantine_dir)

    risk_scorer = RiskScoringEngine(config=config.risk)
    alert_engine = AlertEngine(
        alert_config=config.alerting,
        risk_config=config.risk,
        repository=alert_repo,
        scorer=risk_scorer,
    )
    pipeline = EventPipeline(
        config=config.pipeline,
        repository=event_repo,
        alert_engine=alert_engine,
    )
    behavior_engine = BehaviorCorrelationEngine(
        config=config.behavior,
        pipeline=pipeline,
    )
    pipeline.set_correlation_engine(behavior_engine)

    recommender = ResponseRecommender()
    executor = ResponseExecutor(
        config=config.response,
        action_repo=response_repo,
        audit_repo=audit_repo,
    )

    print("[+] Core engines, repositories, and response executor wired successfully.")

    # 3. Simulate Attacker Activity triggering a Behavioral Finding & Persistent Alert
    print("\n" + "-" * 60)
    print("STEP 1: INGEST TELEMETRY -> CORRELATE -> ALERT GENERATION")
    print("-" * 60)

    sim_pid = 9182
    sim_proc_name = "trojan_stealer.exe"
    sim_exe = str(temp_dir / "trojan_stealer.exe")
    fake_token = "C:\\Decoy\\honey_credentials.txt"

    # Step A: Process creation
    ev_proc = SecurityEvent(
        event_id="sim_ev_01",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=EventType("PROCESS", "CREATE"),
        severity=Severity.INFO,
        source="process_monitor",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(
                pid=sim_pid,
                name=sim_proc_name,
                executable_path=sim_exe,
                command_line=f"{sim_exe} --harvest",
            )
        ),
    )
    pipeline.process(ev_proc)

    # Step B: Honeytoken access event
    ev_decoy = SecurityEvent(
        event_id="sim_ev_02",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=EventType("DECEPTION", "INTERACTION"),
        severity=Severity.CRITICAL,
        source="deception_engine",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(
                pid=sim_pid,
                name=sim_proc_name,
                executable_path=sim_exe,
            ),
            deception=DeceptionContext(
                decoy_id="honey_cred_01",
                decoy_type="CREDENTIAL_BAIT",
                is_decoy=True,
                path=fake_token,
            ),
        ),
    )
    pipeline.process(ev_decoy)

    alerts, total = alert_repo.query()
    assert len(alerts) >= 1, "Expected at least 1 alert generated from deception interaction!"
    alert = alerts[0]
    print(f"[+] Alert Generated: {alert.alert_id}")
    print(f"    Title: {alert.title}")
    print(f"    Risk Score: {alert.risk_score} (Severity: {alert.severity.value})")
    print(f"    PID: {alert.pid}, Process: {alert.process_name}")

    # 4. Generate Advisory Recommendations
    print("\n" + "-" * 60)
    print("STEP 2: ADVISORY RECOMMENDATIONS (HUMAN-IN-THE-LOOP)")
    print("-" * 60)
    recs = recommender.recommend_for_alert(alert)
    print(f"[+] Generated {len(recs)} advisory response recommendation(s):")
    for r in recs:
        print(f"    * [{r.priority}] {r.action_type}: {r.rationale}")
        print(f"      Target: {r.target_params}")

    # 5. Incident Management Lifecycle
    print("\n" + "-" * 60)
    print("STEP 3: INCIDENT MANAGEMENT LIFECYCLE")
    print("-" * 60)
    incident = Incident(
        title=f"Incident: Active Deception Breach by {alert.process_name}",
        description=f"Automated alert {alert.alert_id} triggered high risk score of {alert.risk_score}",
        severity="CRITICAL",
        status=IncidentStatus.OPEN,
        assigned_to="analyst_alice",
        alert_ids=[alert.alert_id],
    )
    incident_repo.create(incident)
    print(f"[+] Incident Created: {incident.incident_id} (Status: {incident.status.value})")

    # Add Note & Transition to INVESTIGATING
    incident.add_note("analyst_alice", "Investigating honeytoken access from suspicious process.")
    incident.transition_to(IncidentStatus.INVESTIGATING)
    incident_repo.update(incident)
    audit_repo.append(
        AuditLogEntry(
            action=AuditActionType.INCIDENT_STATUS_CHANGED,
            target_type="incident",
            target_id=incident.incident_id,
            actor="analyst_alice",
            role="ANALYST",
            details={"status": "INVESTIGATING", "notes": len(incident.notes)},
        )
    )
    print(f"[+] Incident {incident.incident_id} transitioned to: {incident.status.value} with notes recorded.")

    # 6. Response Action Lifecycle & RBAC Gate
    print("\n" + "-" * 60)
    print("STEP 4: RESPONSE ACTION AUTHORIZATION GATE & RBAC")
    print("-" * 60)

    # Create dummy target file to quarantine
    target_payload = temp_dir / "trojan_payload.dll"
    payload_content = b"DEFENSIVE_MONITORING_PAYLOAD_TEST_DATA_" + b"A" * 1024
    target_payload.write_bytes(payload_content)
    expected_sha256 = hashlib.sha256(payload_content).hexdigest()
    print(f"[+] Created test payload to quarantine: {target_payload}")
    print(f"    SHA-256: {expected_sha256}")

    # Request response action
    quarantine_action = executor.request_action(
        action_type=ResponseActionType.FILE_QUARANTINE,
        target_params={"file_path": str(target_payload)},
        incident_id=incident.incident_id,
        alert_id=alert.alert_id,
        user_context=UserContext(username="analyst_alice", role=Role.ANALYST),
    )
    print(f"[+] Response Action Requested: {quarantine_action.action_id} (Status: {quarantine_action.status.value})")

    # Check 1: Attempt execution with VIEWER (lacks EXECUTE_RESPONSE permission)
    viewer_user = UserContext(username="viewer_bob", role=Role.VIEWER)
    try:
        executor.execute_action(quarantine_action.action_id, user_context=viewer_user)
        print("[-] ERROR: Execution succeeded for VIEWER!")
        return 1
    except AuthorizationError as e:
        print(f"[+] Protected: Execution blocked by RBAC for VIEWER: {e}")

    # Check 2: Attempt execution without authorization (even with RESPONDER role)
    senior_user = UserContext(username="responder_charlie", role=Role.RESPONDER)
    try:
        executor.execute_action(quarantine_action.action_id, user_context=senior_user)
        print("[-] ERROR: Execution succeeded before authorization!")
        return 1
    except ResponseExecutionError as e:
        print(f"[+] Protected: Execution blocked by human-in-the-loop gate: {e}")

    # Check 3: Authorize action with RESPONDER role
    authorized_action = executor.authorize_action(quarantine_action.action_id, user_context=senior_user)
    print(f"[+] Response Action Authorized by {authorized_action.authorized_by} (Status: {authorized_action.status.value})")

    # 7. Safe Execution of File Quarantine
    print("\n" + "-" * 60)
    print("STEP 5: SAFE FILE QUARANTINE EXECUTION & SANDBOXING")
    print("-" * 60)
    quarantined_record = executor.execute_action(quarantine_action.action_id, user_context=senior_user)
    print(f"[+] File Quarantine Succeeded: Status={quarantined_record.status.value}")
    print(f"    Original file exists: {target_payload.exists()} (Expected: False)")
    assert not target_payload.exists(), "Original file should no longer exist after quarantine!"

    quarantine_path = Path(quarantined_record.execution_result["quarantine_path"])
    print(f"    Quarantined file exists: {quarantine_path.exists()} (Expected: True)")
    assert quarantine_path.exists(), "Quarantined file must exist in sandbox!"
    assert quarantined_record.execution_result["sha256"] == expected_sha256, "SHA-256 must match pre-quarantine hash!"
    print(f"    Preserved SHA-256 in audit details: {quarantined_record.execution_result['sha256']}")

    # 8. Safe Process Termination
    print("\n" + "-" * 60)
    print("STEP 6: CONTROLLED PROCESS TERMINATION WITH PID REUSE CHECK")
    print("-" * 60)
    dummy_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    proc_pid = dummy_proc.pid
    print(f"[+] Spawned safe dummy process PID: {proc_pid}")

    term_action = executor.request_action(
        action_type=ResponseActionType.PROCESS_TERMINATION,
        target_params={"pid": proc_pid, "process_name": "python.exe"},
        incident_id=incident.incident_id,
        alert_id=alert.alert_id,
        user_context=UserContext(username="analyst_alice", role=Role.ANALYST),
    )
    executor.authorize_action(term_action.action_id, user_context=senior_user)
    term_record = executor.execute_action(term_action.action_id, user_context=senior_user)

    time.sleep(0.5)
    poll_result = dummy_proc.poll()
    print(f"[+] Process termination result: exit_code={poll_result} (Expected: not None)")
    assert poll_result is not None, "Process should have been terminated!"
    print(f"[+] Process Action Status: {term_record.status.value}")

    # 9. Non-Destructive Rollback (File Restoration)
    print("\n" + "-" * 60)
    print("STEP 7: REVERSIBLE ROLLBACK (RESTORE QUARANTINED FILE)")
    print("-" * 60)
    rolled_back_record = executor.rollback_action(quarantine_action.action_id, user_context=senior_user)
    print(f"[+] Rollback completed: Status={rolled_back_record.status.value}")
    print(f"    Original file restored: {target_payload.exists()} (Expected: True)")
    assert target_payload.exists(), "Original file must be restored!"
    restored_hash = hashlib.sha256(target_payload.read_bytes()).hexdigest()
    assert restored_hash == expected_sha256, "Restored file hash must match original SHA-256!"
    print(f"    Restored file SHA-256 matches: {restored_hash == expected_sha256}")

    # 10. Incident Resolution & Closure
    print("\n" + "-" * 60)
    print("STEP 8: INCIDENT CONTAINMENT AND CLOSURE")
    print("-" * 60)
    incident.transition_to(IncidentStatus.CONTAINED)
    incident.transition_to(IncidentStatus.RESOLVED)
    incident.transition_to(IncidentStatus.CLOSED)
    incident_repo.update(incident)
    print(f"[+] Incident {incident.incident_id} successfully closed: {incident.status.value}")

    # 11. Immutable Audit Trail Inspection
    print("\n" + "-" * 60)
    print("STEP 9: IMMUTABLE AUDIT TRAIL VERIFICATION")
    print("-" * 60)
    audit_entries, audit_total = audit_repo.list(limit=50)
    print(f"[+] Total audit log entries recorded: {audit_total}")
    for entry in audit_entries[-6:]:
        action_name = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
        print(f"    [{entry.timestamp}] [{entry.actor} ({entry.role})] {action_name}: {entry.target_type} {entry.target_id}")

    assert audit_total >= 5, "Expected comprehensive audit logs for all operations!"

    # 12. REST API Integration Test
    print("\n" + "-" * 60)
    print("STEP 10: BACKEND REST API END-TO-END VERIFICATION")
    print("-" * 60)
    service = EventService(
        repository=event_repo,
        alert_repository=alert_repo,
        incident_repository=incident_repo,
        response_action_repository=response_repo,
        audit_repository=audit_repo,
        response_recommender=recommender,
        response_executor=executor,
    )
    backend_config = config.backend
    backend_config.host = "127.0.0.1"
    backend_config.port = 0

    with BackendServer(service=service, config=backend_config) as server:
        base_url = f"http://127.0.0.1:{server.port}"

        # Test 1: Query incidents
        req = urllib.request.Request(f"{base_url}/api/incidents", headers={"X-User-Role": "ADMIN"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] API GET /api/incidents -> {resp.status} OK (Total incidents: {data['total']})")
            assert data["total"] >= 1

        # Test 2: Query recommendations for alert
        req = urllib.request.Request(f"{base_url}/api/alerts/{alert.alert_id}/recommendations", headers={"X-User-Role": "ANALYST"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] API GET /api/alerts/{alert.alert_id}/recommendations -> {resp.status} OK ({len(data['recommendations'])} recommendations)")
            assert len(data["recommendations"]) >= 1

        # Test 3: Query audit logs
        req = urllib.request.Request(f"{base_url}/api/audit", headers={"X-User-Role": "ADMIN"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] API GET /api/audit -> {resp.status} OK ({data['total']} audit entries)")
            assert data["total"] >= 5

        # Test 4: Query responses
        req = urllib.request.Request(f"{base_url}/api/responses", headers={"X-User-Role": "ANALYST"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] API GET /api/responses -> {resp.status} OK ({data['total']} response actions)")
            assert data["total"] >= 2

    print("[+] Backend Server stopped cleanly.")

    print("\n" + "=" * 80)
    print("ALL VERIFICATION CHECKS PASSED: CONTROLLED DEFENSIVE RESPONSE SYSTEM FULLY OPERATIONAL")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
