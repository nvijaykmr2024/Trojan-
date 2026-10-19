"""Unit tests for Phase 9 Behavioral Correlation and Detection."""

from datetime import datetime, timezone, timedelta
import time
import pytest

from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.behavior.rules import (
    DecoyInteractionSequenceRule,
    PrivilegedProcessActivityRule,
    ProcessFileActivityRule,
    ProcessFileNetworkSequenceRule,
    ProcessNetworkActivityRule,
)
from trojan_defense.behavior.tracker import (
    ProcessCorrelationTracker,
    ProcessIdentityKey,
    TrackedProcess,
    parse_event_time,
)
from trojan_defense.core.config.schema import BehaviorConfig
from trojan_defense.core.models.context import (
    BehaviorContext,
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


@pytest.fixture
def test_endpoint() -> EndpointIdentity:
    return EndpointIdentity.resolve(endpoint_id_override="test-ep-01", hostname_override="test-host")



def make_event(
    event_type: str,
    endpoint: EndpointIdentity,
    context: EventContext,
    timestamp: str | None = None,
    severity: Severity = Severity.INFO,
    source: str = "test",
) -> SecurityEvent:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return SecurityEvent(
        event_type=EventType.from_string(event_type),
        severity=severity,
        source=source,
        endpoint=endpoint,
        timestamp=ts,
        context=context,
    )


# Test 1: Configuration defaults and overrides
def test_behavior_config_defaults_and_overrides() -> None:
    cfg = BehaviorConfig()
    assert cfg.enabled is False
    assert cfg.correlation_window_seconds == 60.0
    assert cfg.dedup_window_seconds == 30.0
    assert cfg.max_tracked_processes == 1000
    assert cfg.rules == {}

    custom_cfg = BehaviorConfig(
        enabled=True,
        correlation_window_seconds=120.0,
        dedup_window_seconds=45.0,
        max_tracked_processes=500,
        rules={"RULE-BEH-001": False},
    )
    assert custom_cfg.enabled is True
    assert custom_cfg.correlation_window_seconds == 120.0
    assert custom_cfg.dedup_window_seconds == 45.0
    assert custom_cfg.max_tracked_processes == 500
    assert custom_cfg.rules["RULE-BEH-001"] is False


# Test 2: Process File Activity Correlation (RULE-BEH-001)
def test_process_file_activity_correlation(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Process created
    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=1010, name="malware.exe", executable_path="C:\\test\\malware.exe")),
    )
    engine.analyze_event(proc_evt)

    # Process creates script or executable in startup
    file_evt = make_event(
        "FILE.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=1010, name="malware.exe"),
            file=FileContext(path="C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat", operation="create"),
        ),
    )
    findings = engine.analyze_event(file_evt)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE-BEH-001"
    assert f.pid == 1010
    assert f.process_name == "malware.exe"
    assert f.severity == Severity.HIGH
    assert file_evt.event_id in f.related_event_ids
    assert proc_evt.event_id in f.related_event_ids
    assert any("Startup\\run.bat" in c for c in f.matched_conditions)


# Test 3: Process Network Activity Correlation (RULE-BEH-002)
def test_process_network_activity_correlation(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Process created
    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=2020, name="beacon.exe")),
    )
    engine.analyze_event(proc_evt)

    # Process establishes outbound network connection
    net_evt = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=2020, name="beacon.exe"),
            network=NetworkContext(pid=2020, remote_ip="203.0.113.5", remote_port=443, protocol="TCP"),
        ),
    )
    findings = engine.analyze_event(net_evt)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE-BEH-002"
    assert f.pid == 2020
    assert f.severity == Severity.MEDIUM
    assert net_evt.event_id in f.related_event_ids
    assert proc_evt.event_id in f.related_event_ids
    assert any("203.0.113.5:443" in c for c in f.matched_conditions)


# Test 4: Privileged Process Activity Correlation (RULE-BEH-003)
def test_privileged_process_activity_correlation(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Elevated process starts
    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=3030, name="powershell.exe"),
            privilege=PrivilegeContext(is_elevated=True, integrity_level="High"),
        ),
    )
    engine.analyze_event(proc_evt)

    # Elevated process modifies sensitive file
    file_evt = make_event(
        "FILE.MODIFY",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=3030, name="powershell.exe"),
            file=FileContext(path="C:\\Windows\\System32\\drivers\\etc\\hosts", operation="modify"),
        ),
    )
    findings = engine.analyze_event(file_evt)

    assert any(f.rule_id == "RULE-BEH-003" for f in findings)
    f = next(f for f in findings if f.rule_id == "RULE-BEH-003")
    assert f.pid == 3030
    assert f.severity == Severity.HIGH
    assert file_evt.event_id in f.related_event_ids
    assert any("elevated" in c.lower() for c in f.matched_conditions)


# Test 5: Process Multi-Stage File-Network Sequence (RULE-BEH-004)
def test_process_file_network_sequence_multistage(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Process creates file
    file_evt = make_event(
        "FILE.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=4040, name="dropper.exe"),
            file=FileContext(path="C:\\temp\\payload.bin", operation="create"),
        ),
    )
    engine.analyze_event(file_evt)

    # Same process initiates network connection
    net_evt = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=4040, name="dropper.exe"),
            network=NetworkContext(pid=4040, remote_ip="198.51.100.22", remote_port=8080, protocol="TCP"),
        ),
    )
    findings = engine.analyze_event(net_evt)

    # Should trigger multi-stage sequence rule RULE-BEH-004
    assert any(f.rule_id == "RULE-BEH-004" for f in findings)
    f = next(f for f in findings if f.rule_id == "RULE-BEH-004")
    assert f.pid == 4040
    assert file_evt.event_id in f.related_event_ids
    assert net_evt.event_id in f.related_event_ids
    assert len(f.evidence) >= 2


# Test 6: Deception Decoy Interaction Sequence (RULE-BEH-005)
def test_decoy_interaction_sequence_correlation(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Process accesses honeytoken decoy file
    decoy_evt = make_event(
        "DECEPTION.INTERACTION",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=5050, name="intruder.exe"),
            deception=DeceptionContext(
                is_decoy=True,
                decoy_id="decoy-cred-01",
                decoy_type="credentials",
                path="C:\\deception\\passwords.txt",
                action="read",
            ),
        ),
        severity=Severity.HIGH,
    )
    findings = engine.analyze_event(decoy_evt)

    # Should trigger RULE-BEH-005 with CRITICAL severity
    assert len(findings) >= 1
    f = findings[0]
    assert f.rule_id == "RULE-BEH-005"
    assert f.severity == Severity.CRITICAL
    assert f.pid == 5050
    assert decoy_evt.event_id in f.related_event_ids
    assert any("decoy-cred-01" in c for c in f.matched_conditions)


# Test 7: Correlation Time Window Expiration
def test_correlation_time_window_expiration(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=30.0))

    base_time = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    old_time = base_time.isoformat()
    # 5 minutes later, exceeding 30-second correlation window
    new_time = (base_time + timedelta(minutes=5)).isoformat()

    # Step 1: Process created long ago
    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=6060, name="old_app.exe")),
        timestamp=old_time,
    )
    engine.analyze_event(proc_evt)

    # Step 2: Network event occurs 5 minutes later
    net_evt = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=6060, name="old_app.exe"),
            network=NetworkContext(pid=6060, remote_ip="203.0.113.99", remote_port=443, protocol="TCP"),
        ),
        timestamp=new_time,
    )
    findings = engine.analyze_event(net_evt)

    # Rule RULE-BEH-002 should NOT trigger because the process creation expired from the window
    assert not any(f.rule_id == "RULE-BEH-002" for f in findings)


# Test 8: PID Reuse Protection
def test_pid_reuse_protection(test_endpoint: EndpointIdentity) -> None:
    tracker = ProcessCorrelationTracker(correlation_window_seconds=60.0)

    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc).isoformat()
    t1 = datetime(2026, 10, 2, 12, 0, 5, tzinfo=timezone.utc).isoformat()
    t2 = datetime(2026, 10, 2, 12, 0, 10, tzinfo=timezone.utc).isoformat()

    # Process 1 creates PID 7777 (legit.exe)
    proc1_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=7777, name="legit.exe", executable_path="C:\\legit.exe", created_at=t0)),
        timestamp=t0,
    )
    tracker.track_event(proc1_evt)

    # Process 1 terminates
    term1_evt = make_event(
        "PROCESS.TERMINATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=7777, name="legit.exe")),
        timestamp=t1,
    )
    tracker.track_event(term1_evt)

    # Process 2 reuses PID 7777 (bad.exe)
    proc2_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=7777, name="bad.exe", executable_path="C:\\bad.exe", created_at=t2)),
        timestamp=t2,
    )
    tracked2 = tracker.track_event(proc2_evt)

    # Tracked process for active PID 7777 should be bad.exe, NOT legit.exe
    assert tracked2 is not None
    assert tracked2.name == "bad.exe"
    assert tracked2.executable_path == "C:\\bad.exe"
    # Event history for the new process should NOT contain proc1_evt
    assert proc1_evt not in tracked2.events
    assert proc2_evt in tracked2.events


# Test 9: False Correlation Prevention (different PIDs)
def test_false_correlation_prevention(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    # Process A creates file
    file_evt = make_event(
        "FILE.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=8001, name="writer.exe"),
            file=FileContext(path="C:\\temp\\notes.txt", operation="create"),
        ),
    )
    engine.analyze_event(file_evt)

    # Unrelated Process B connects to network
    net_evt = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=8002, name="browser.exe"),
            network=NetworkContext(pid=8002, remote_ip="203.0.113.1", remote_port=443, protocol="TCP"),
        ),
    )
    findings = engine.analyze_event(net_evt)

    # Multi-stage sequence RULE-BEH-004 must NOT correlate across differing PIDs
    assert not any(f.rule_id == "RULE-BEH-004" for f in findings)


# Test 10: Event Ordering Tolerance
def test_event_ordering_tolerance(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    t_earlier = datetime(2026, 10, 2, 14, 0, 5, tzinfo=timezone.utc).isoformat()
    t_later = datetime(2026, 10, 2, 14, 0, 15, tzinfo=timezone.utc).isoformat()

    # Network event arrives first (representing buffered or out-of-order network arrival)
    net_evt = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9090, name="agent.exe"),
            network=NetworkContext(pid=9090, remote_ip="198.51.100.5", remote_port=80, protocol="TCP"),
        ),
        timestamp=t_later,
    )
    engine.analyze_event(net_evt)

    # File event arrives slightly later with timestamp in the same window
    file_evt = make_event(
        "FILE.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9090, name="agent.exe"),
            file=FileContext(path="C:\\temp\\data.bin", operation="create"),
        ),
        timestamp=t_earlier,
    )
    findings = engine.analyze_event(file_evt)

    # Out of order sequence within the window still correlates
    assert any(f.rule_id == "RULE-BEH-004" for f in findings)


# Test 11: Finding Deduplication
def test_finding_deduplication(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0, dedup_window_seconds=30.0))

    # Process created
    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=9100, name="spammer.exe")),
    )
    engine.analyze_event(proc_evt)

    # First network event generates finding
    net1 = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9100, name="spammer.exe"),
            network=NetworkContext(pid=9100, remote_ip="203.0.113.1", remote_port=443, protocol="TCP"),
        ),
    )
    findings1 = engine.analyze_event(net1)
    assert len(findings1) == 1

    # Second network event immediately afterwards with same destination is deduplicated
    net2 = make_event(
        "NETWORK.CONNECT",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9100, name="spammer.exe"),
            network=NetworkContext(pid=9100, remote_ip="203.0.113.1", remote_port=443, protocol="TCP"),
        ),
    )
    findings2 = engine.analyze_event(net2)
    assert len(findings2) == 0


# Test 12: Bounded State Tracking and Pruning
def test_bounded_state_tracking_and_pruning(test_endpoint: EndpointIdentity) -> None:
    tracker = ProcessCorrelationTracker(correlation_window_seconds=5.0, max_tracked_processes=10)

    # Add 15 distinct processes exceeding max_tracked_processes of 10
    for i in range(15):
        evt = make_event(
            "PROCESS.CREATE",
            test_endpoint,
            EventContext(process=ProcessContext(pid=1000 + i, name=f"proc_{i}.exe")),
        )
        tracker.track_event(evt)

    # Total tracked processes must be bounded at 10
    assert tracker.tracked_count <= 10


# Test 13: Evidence Traceability
def test_evidence_traceability(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=True, correlation_window_seconds=60.0))

    proc_evt = make_event(
        "PROCESS.CREATE",
        test_endpoint,
        EventContext(process=ProcessContext(pid=9200, name="updater.exe")),
    )
    file_evt = make_event(
        "FILE.CREATE",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9200, name="updater.exe"),
            file=FileContext(path="C:\\startup\\run.exe", operation="create"),
        ),
    )
    engine.analyze_event(proc_evt)
    findings = engine.analyze_event(file_evt)

    assert len(findings) == 1
    f = findings[0]
    # Auditable evidence lineage
    assert proc_evt.event_id in f.related_event_ids
    assert file_evt.event_id in f.related_event_ids
    assert len(f.evidence) >= 2
    assert any(ev["event_id"] == proc_evt.event_id for ev in f.evidence)
    assert any(ev["event_id"] == file_evt.event_id for ev in f.evidence)


# Test 14: Disabled Behavior Engine
def test_disabled_behavior_engine(test_endpoint: EndpointIdentity) -> None:
    engine = BehaviorCorrelationEngine(config=BehaviorConfig(enabled=False))

    evt = make_event(
        "DECEPTION.INTERACTION",
        test_endpoint,
        EventContext(
            process=ProcessContext(pid=9300, name="attacker.exe"),
            deception=DeceptionContext(is_decoy=True, decoy_id="decoy-01"),
        ),
    )
    findings = engine.analyze_event(evt)
    assert findings == []
    assert engine.stats["events_analyzed"] == 0


# Test 15: BehaviorFinding to SecurityEvent Conversion
def test_behavior_finding_to_security_event(test_endpoint: EndpointIdentity) -> None:
    finding = BehaviorFinding(
        rule_id="RULE-BEH-001",
        rule_name="Process File Activity",
        severity=Severity.HIGH,
        pid=9400,
        process_name="test.exe",
        executable_path="C:\\test.exe",
        related_event_ids=["evt-1", "evt-2"],
        matched_conditions=["Condition matched"],
        description="Correlated behavioral activity",
    )

    sec_evt = finding.to_security_event(endpoint=test_endpoint)

    assert sec_evt.event_id == finding.finding_id
    assert sec_evt.event_type.category == EventCategory.BEHAVIOR
    assert sec_evt.event_type.action == "FINDING"
    assert sec_evt.severity == Severity.HIGH
    assert sec_evt.source == "behavior_engine"
    assert sec_evt.endpoint.endpoint_id == test_endpoint.endpoint_id
    assert sec_evt.context.behavior is not None
    assert sec_evt.context.behavior.rule_id == "RULE-BEH-001"
    assert sec_evt.context.behavior.related_event_ids == ["evt-1", "evt-2"]
    assert sec_evt.context.process is not None
    assert sec_evt.context.process.pid == 9400
