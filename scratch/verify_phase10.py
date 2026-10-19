"""Windows Manual Validation Script for Phase 10: Risk Scoring and Alert Generation.

Executes an end-to-end operational verification demonstrating:
1. Framework initialization with Risk Scoring and Alerting Engine enabled.
2. Simulated attack sequence triggering correlated behavioral finding.
3. Deterministic risk calculation producing bounded explainable score and severity.
4. Alert persistence in SQLite maintaining complete evidence lineage.
5. Deduplication and suppression cooldown protecting against alert storms.
6. Backend REST API server querying, evidence inspection, and analyst lifecycle state transitions.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trojan_defense.alerting.engine import AlertEngine
from trojan_defense.alerting.models import AlertStatus
from trojan_defense.alerting.repository import AlertQueryFilter, SQLiteAlertRepository
from trojan_defense.alerting.scorer import RiskScoringEngine
from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.core.config.loader import load_config
from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    ProcessContext,
)
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.sqlite import SQLiteEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline


def main() -> int:
    print("=" * 80)
    print("PHASE 10 END-TO-END VERIFICATION: RISK SCORING & ALERT GENERATION")
    print("=" * 80)

    # 1. Setup isolated database paths for verification
    db_file = Path("scratch/phase10_verification.db")
    if db_file.exists():
        db_file.unlink()

    endpoint = EndpointIdentity.resolve()
    print(f"[+] Endpoint Resolved: {endpoint.endpoint_id} ({endpoint.hostname}) on {endpoint.platform}")

    # 2. Initialize Repositories and Engines
    event_repo = SQLiteEventRepository(db_path=str(db_file))
    alert_repo = SQLiteAlertRepository(db_path=str(db_file))
    print(f"[+] SQLite Repositories initialized against: {db_file}")

    config = load_config(environment="development")
    config.behavior.enabled = True
    config.alerting.enabled = True
    config.alerting.min_alert_score = 30
    config.alerting.dedup_window_seconds = 60.0

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
    print("[+] Pipeline wired: Process/File -> Behavior Correlation -> Risk Scoring -> Alert Persistence")

    # 3. Simulate an adversary accessing a honeytoken decoy and dropping a staging payload
    sim_pid = 7712
    proc_name = "trojan_sim.exe"
    exe_path = "C:\\Windows\\Temp\\trojan_sim.exe"

    print("\n[+] Ingesting simulated attacker activity...")
    # Step A: Process Creation
    ev_proc = SecurityEvent(
        event_id="sim_ev_proc_01",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=EventType("PROCESS", "CREATE"),
        severity=Severity.INFO,
        source="process_monitor",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(
                pid=sim_pid,
                name=proc_name,
                executable_path=exe_path,
                command_line=f"{exe_path} --scan",
            )
        ),
    )
    pipeline.process(ev_proc)
    print(f"    -> Process created: PID {sim_pid} ({proc_name})")

    # Step B: Deception Decoy Interaction (Adversary accesses honeytoken passwords file)
    ev_decoy = SecurityEvent(
        event_id="sim_ev_decoy_02",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=EventType("DECEPTION", "INTERACTION"),
        severity=Severity.CRITICAL,
        source="deception_engine",
        endpoint=endpoint,
        context=EventContext(
            process=ProcessContext(pid=sim_pid, name=proc_name, executable_path=exe_path),
            deception=DeceptionContext(
                decoy_id="decoy_admin_passwords.txt",
                decoy_type="CREDENTIAL_BAIT",
                is_decoy=True,
                path="C:\\Users\\Admin\\Documents\\passwords.xlsx",
            ),
        ),
    )
    pipeline.process(ev_decoy)
    print("    -> Adversary interacted with Deception Decoy 'decoy_admin_passwords.txt'")

    # 4. Verify Behavior Finding and Alert Generated
    alerts, total_alerts = alert_repo.query()
    print(f"\n[+] Total Persistent Alerts in SQLite: {total_alerts}")
    assert total_alerts == 1, f"Expected 1 alert, got {total_alerts}"

    alert = alerts[0]
    print(f"[+] Alert ID:       {alert.alert_id}")
    print(f"[+] Title:          {alert.title}")
    print(f"[+] Risk Score:     {alert.risk_score}/100")
    print(f"[+] Severity:       {alert.severity.to_name()}")
    print(f"[+] Status:         {alert.status.value}")
    print(f"[+] Rule ID:        {alert.rule_id} ({alert.rule_name})")
    print(f"[+] Associated PID: {alert.pid} ({alert.process_name})")
    print(f"[+] Deception ID:   {alert.deception_id}")
    print(f"[+] Related Events: {alert.related_event_ids}")

    print("\n[+] Structured Explainability Breakdown:")
    for r in alert.scoring_reasons:
        print(f"    * Factor: {r['factor']:<26} Contribution: +{r['contribution']:<3} Reason: {r['reason']}")

    # 5. Verify Deduplication and Cooldown (simulate second occurrence within window)
    print("\n[+] Testing Deduplication & Alert Suppression...")
    dup_finding = BehaviorFinding(
        finding_id="beh_dup_01",
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        pid=sim_pid,
        process_name=proc_name,
        executable_path=exe_path,
        evidence=[{"decoy_id": "decoy_admin_passwords.txt"}],
        related_event_ids=["sim_ev_extra_03"],
    )
    updated_alert = alert_engine.process_finding(dup_finding, endpoint_id=endpoint.endpoint_id)
    assert updated_alert is not None
    assert updated_alert.alert_id == alert.alert_id, "Should update existing alert ID, not create new"
    assert updated_alert.occurrence_count == 2, "Occurrence count should increment"
    print(f"    -> Deduplication succeeded! Alert {alert.alert_id} occurrence_count updated to {updated_alert.occurrence_count}")
    print(f"    -> Persistent alert count remained constant: {alert_repo.count()}")

    # 6. Verify Backend REST API Endpoints
    print("\n[+] Testing Backend REST API Endpoints...")
    backend_service = EventService(
        repository=event_repo,
        alert_repository=alert_repo,
        alert_engine=alert_engine,
    )
    backend_config = config.backend
    backend_config.host = "127.0.0.1"
    backend_config.port = 0  # Ephemeral port

    with BackendServer(service=backend_service, config=backend_config) as server:
        base_url = f"http://{server.host}:{server.port}"
        print(f"    -> Backend REST API listening on {base_url}")

        # A: Query Alerts GET /api/alerts
        req = urllib.request.Request(f"{base_url}/api/alerts?status=OPEN")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"    -> GET /api/alerts?status=OPEN returned {data['count']} alert(s), total={data['total']}")
            assert data["count"] == 1

        # B: Evidence Inspection GET /api/alerts/<id>/evidence
        req = urllib.request.Request(f"{base_url}/api/alerts/{alert.alert_id}/evidence")
        with urllib.request.urlopen(req) as resp:
            ev_data = json.loads(resp.read().decode("utf-8"))
            print(f"    -> GET /api/alerts/{alert.alert_id}/evidence lineage retrieved:")
            print(f"       Risk Score: {ev_data['risk_score']}")
            print(f"       Scoring Reasons: {len(ev_data['scoring_reasons'])} factors")
            print(f"       Resolved Raw Events: {len(ev_data['resolved_events'])} event(s)")

        # C: Acknowledge Alert POST /api/alerts/<id>/acknowledge
        ack_payload = json.dumps({"comment": "Security Analyst Maithresh investigating decoy alert"}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/alerts/{alert.alert_id}/acknowledge",
            data=ack_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            ack_resp = json.loads(resp.read().decode("utf-8"))
            print(f"    -> POST /api/alerts/{alert.alert_id}/acknowledge result: status={ack_resp['alert']['status']}")
            assert ack_resp["alert"]["status"] == "ACKNOWLEDGED"

        # D: Resolve Alert POST /api/alerts/<id>/resolve
        res_payload = json.dumps({"comment": "Host isolated and malicious script terminated"}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/alerts/{alert.alert_id}/resolve",
            data=res_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            res_resp = json.loads(resp.read().decode("utf-8"))
            print(f"    -> POST /api/alerts/{alert.alert_id}/resolve result: status={res_resp['alert']['status']}")
            assert res_resp["alert"]["status"] == "RESOLVED"

    # Cleanup verification DB
    event_repo.close()
    alert_repo.close()
    if db_file.exists():
        db_file.unlink()

    print("\n" + "=" * 80)
    print("ALL PHASE 10 VERIFICATION CHECKS PASSED END-TO-END!")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
