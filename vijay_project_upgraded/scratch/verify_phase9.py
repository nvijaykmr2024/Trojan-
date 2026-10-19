"""End-to-end verification script for Phase 9 Behavioral Correlation and Detection on Windows."""

import os
from pathlib import Path
import sys
import tempfile
import time

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.core.config.schema import RootConfig
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    NetworkContext,
    PrivilegeContext,
    ProcessContext,
)
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.persistence.base import EventQueryFilter


def run_verification() -> bool:
    print("=" * 70)
    print("PHASE 9 VERIFICATION: BEHAVIORAL CORRELATION AND DETECTION ENGINE")
    print("=" * 70)

    temp_dir = tempfile.mkdtemp(prefix="trojan_defense_p9_")
    db_path = os.path.join(temp_dir, "phase9_verify.db")
    deception_dir = os.path.join(temp_dir, "deception")

    try:
        cfg = RootConfig()
        cfg.persistence.enabled = True
        cfg.persistence.driver = "sqlite"
        cfg.persistence.db_path = db_path
        cfg.behavior.enabled = True
        cfg.behavior.correlation_window_seconds = 60.0
        cfg.behavior.dedup_window_seconds = 5.0
        cfg.deception.enabled = True
        cfg.deception.deception_root = deception_dir

        manager = ApplicationManager()
        print("\n[*] Initializing ApplicationManager with Behavior Engine enabled...")
        manager.initialize(config=cfg)
        manager.start()

        assert manager.behavior_engine is not None, "Behavior engine failed to initialize!"
        print(f"[+] Manager state: {manager.state.value}")
        print(f"[+] Behavior Engine initialized: window={cfg.behavior.correlation_window_seconds}s")
        print(f"[+] Registered Rules: {[r.rule_id for r in manager.behavior_engine.list_rules()]}")

        endpoint = manager.endpoint
        assert endpoint is not None

        pid = 4444
        pname = "trojan_sim.exe"

        # 1. Process Creation Telemetry
        print(f"\n[1] Emitting PROCESS.CREATE for PID {pid} ({pname})...")
        proc_event = SecurityEvent(
            event_type=EventType("PROCESS", "CREATE"),
            severity=Severity.INFO,
            source="process_monitor",
            endpoint=endpoint,
            context=EventContext(
                process=ProcessContext(
                    pid=pid,
                    name=pname,
                    executable_path=f"C:\\Users\\User\\AppData\\Local\\Temp\\{pname}",
                )
            ),
        )
        manager.pipeline.process(proc_event)

        # 2. File Creation in Sensitive / Startup location (triggers RULE-BEH-001)
        print("[2] Emitting sensitive FILE.CREATE in Startup directory...")
        file_event = SecurityEvent(
            event_type=EventType("FILE", "CREATE"),
            severity=Severity.INFO,
            source="file_monitor",
            endpoint=endpoint,
            context=EventContext(
                process=ProcessContext(pid=pid, name=pname),
                file=FileContext(
                    path="C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat",
                    operation="create",
                ),
            ),
        )
        manager.pipeline.process(file_event)

        # 3. Outbound Network Connection (triggers RULE-BEH-002 and RULE-BEH-004 multi-stage)
        print("[3] Emitting outbound NETWORK.CONNECT to remote IP 198.51.100.88:8443...")
        net_event = SecurityEvent(
            event_type=EventType("NETWORK", "CONNECT"),
            severity=Severity.INFO,
            source="network_monitor",
            endpoint=endpoint,
            context=EventContext(
                process=ProcessContext(pid=pid, name=pname),
                network=NetworkContext(
                    pid=pid,
                    remote_ip="198.51.100.88",
                    remote_port=8443,
                    protocol="TCP",
                ),
            ),
        )
        manager.pipeline.process(net_event)

        # 4. Decoy Interaction (triggers RULE-BEH-005)
        print("[4] Emitting DECEPTION.INTERACTION on canary token file...")
        decoy_event = SecurityEvent(
            event_type=EventType("DECEPTION", "INTERACTION"),
            severity=Severity.HIGH,
            source="deception_engine",
            endpoint=endpoint,
            context=EventContext(
                process=ProcessContext(pid=pid, name=pname),
                deception=DeceptionContext(
                    is_decoy=True,
                    decoy_id="decoy-canary-01",
                    decoy_type="honeytoken",
                    path=os.path.join(deception_dir, "credentials.kdbx"),
                    action="read",
                ),
            ),
        )
        manager.pipeline.process(decoy_event)

        # Query Database
        print("\n[*] Querying SQLite repository for correlated behavioral findings...")
        filter_all = EventQueryFilter()
        all_events, total_count = manager.repository.query(filter_all)
        print(f"[+] Total events stored in SQLite: {total_count}")

        filter_beh = EventQueryFilter(event_type="BEHAVIOR.FINDING")
        behavior_events, beh_count = manager.repository.query(filter_beh)
        print(f"[+] Correlated BEHAVIOR.FINDING events generated: {beh_count}")

        for i, be in enumerate(behavior_events, 1):
            bctx = be.context.behavior
            assert bctx is not None
            print(f"\n  --- Finding #{i} ---")
            print(f"  Finding ID : {bctx.finding_id}")
            print(f"  Rule ID    : {bctx.rule_id} ({bctx.rule_name})")
            print(f"  Severity   : {be.severity.to_name()}")
            print(f"  PID / Name : {bctx.pid} / {bctx.process_name}")
            print(f"  Description: {bctx.description}")
            print(f"  Related Evt: {len(bctx.related_event_ids)} event(s) -> {bctx.related_event_ids}")
            print(f"  Evidence   : {len(bctx.evidence)} evidence record(s)")

        # Assertions
        assert beh_count >= 3, f"Expected at least 3 behavioral findings, got {beh_count}"
        rule_ids_detected = {be.context.behavior.rule_id for be in behavior_events if be.context.behavior}
        print(f"\n[+] Rules successfully triggered: {sorted(rule_ids_detected)}")
        assert "RULE-BEH-001" in rule_ids_detected, "RULE-BEH-001 was not triggered!"
        assert "RULE-BEH-002" in rule_ids_detected, "RULE-BEH-002 was not triggered!"
        assert "RULE-BEH-004" in rule_ids_detected, "RULE-BEH-004 was not triggered!"
        assert "RULE-BEH-005" in rule_ids_detected, "RULE-BEH-005 was not triggered!"

        print("\n[*] Stopping ApplicationManager...")
        manager.stop()
        print(f"[+] Final State: {manager.state.value}")
        print("\n" + "=" * 70)
        print("PHASE 9 VERIFICATION SUCCESSFUL: ALL BEHAVIORAL CHECKS PASSED")
        print("=" * 70)
        return True

    except Exception as exc:
        print(f"\n[-] VERIFICATION FAILED: {exc}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
