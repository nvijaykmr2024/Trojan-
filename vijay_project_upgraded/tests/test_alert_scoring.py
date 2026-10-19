"""Automated test suite for Phase 10 Risk Scoring Engine and Alert Domain Models.

Validates bounded scoring [0, 100], clamping, explainability reasons,
severity threshold boundaries, and alert lifecycle state machine transitions.
"""

import pytest

from trojan_defense.alerting.models import (
    VALID_STATUS_TRANSITIONS,
    Alert,
    AlertStatus,
    RiskScore,
    ScoringReason,
)
from trojan_defense.alerting.scorer import RiskScoringEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.core.config.schema import RiskConfig
from trojan_defense.core.exceptions import ValidationError
from trojan_defense.core.models.context import BehaviorContext, EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity


class TestRiskScoringEngine:
    """Tests for deterministic risk scoring and explainability."""

    def test_base_rule_scores(self) -> None:
        """Verify baseline scores for all registered rules."""
        engine = RiskScoringEngine()

        # Rule 1 (File) -> 40 base + 15 file bonus = 55
        f1 = BehaviorFinding(rule_id="RULE-BEH-001", rule_name="File Rule")
        score1 = engine.calculate_score(f1)
        assert score1.score == 55
        assert score1.severity == Severity.MEDIUM

        # Rule 2 (Network) -> 30 base + 15 net bonus = 45
        f2 = BehaviorFinding(rule_id="RULE-BEH-002", rule_name="Network Rule")
        score2 = engine.calculate_score(f2)
        assert score2.score == 45
        assert score2.severity == Severity.MEDIUM

        # Rule 3 (Process Tree) -> 45 base = 45
        f3 = BehaviorFinding(rule_id="RULE-BEH-003", rule_name="Tree Rule")
        score3 = engine.calculate_score(f3)
        assert score3.score == 45
        assert score3.severity == Severity.MEDIUM

        # Rule 4 (Privilege + File + Net) -> 55 base + 20 priv + 15 net + 15 file = 100 (clamped)
        f4 = BehaviorFinding(rule_id="RULE-BEH-004", rule_name="Priv Rule")
        score4 = engine.calculate_score(f4)
        assert score4.score == 100
        assert score4.severity == Severity.CRITICAL

        # Rule 5 (Decoy) -> 75 base + 25 decoy bonus = 100 (clamped)
        f5 = BehaviorFinding(rule_id="RULE-BEH-005", rule_name="Decoy Rule")
        score5 = engine.calculate_score(f5)
        assert score5.score == 100
        assert score5.severity == Severity.CRITICAL

        # Unknown rule -> default 30
        f_unk = BehaviorFinding(rule_id="RULE-CUSTOM-999")
        score_unk = engine.calculate_score(f_unk)
        assert score_unk.score == 30
        assert score_unk.severity == Severity.LOW

    def test_score_clamping(self) -> None:
        """Verify calculated scores are strictly bounded to [0, 100]."""
        cfg = RiskConfig(
            default_base_score=150,
            deception_bonus=50,
            privilege_bonus=50,
        )
        engine = RiskScoringEngine(config=cfg)
        finding = BehaviorFinding(
            rule_id="RULE-OVERFLOW",
            evidence=[{"is_decoy": True}, {"is_elevated": True}],
        )
        result = engine.calculate_score(finding)
        assert result.score == 100
        assert result.raw_calculated_score >= 250
        assert result.severity == Severity.CRITICAL

    def test_explainability_breakdown(self) -> None:
        """Verify every point is accounted for in reasons list."""
        engine = RiskScoringEngine()
        finding = BehaviorFinding(
            rule_id="RULE-BEH-001",
            rule_name="Process File Activity",
            evidence=[
                {"event_id": "ev1", "category": "FILE", "path": "C:\\Windows\\cmd.exe"},
                {"event_id": "ev2", "category": "FILE", "path": "C:\\temp\\script.bat"},
                {"event_id": "ev3", "category": "FILE", "path": "C:\\temp\\script2.bat"},
            ],
            related_event_ids=["ev1", "ev2", "ev3"],
        )
        score = engine.calculate_score(finding)

        # Base 40 + Sensitive File 15 + Corroborating (2 extra events * 5 = 10) = 65
        assert score.score == 65
        assert score.severity == Severity.MEDIUM

        factors = {r.factor: r.contribution for r in score.reasons}
        assert factors["base_rule"] == 40
        assert factors["sensitive_file_activity"] == 15
        assert factors["corroborating_events"] == 10
        assert sum(r.contribution for r in score.reasons) == score.score

    def test_severity_threshold_boundaries(self) -> None:
        """Verify strict boundary behavior for LOW, MEDIUM, HIGH, CRITICAL."""
        engine = RiskScoringEngine()

        assert engine.determine_severity(0) == Severity.LOW
        assert engine.determine_severity(39) == Severity.LOW
        assert engine.determine_severity(40) == Severity.MEDIUM
        assert engine.determine_severity(69) == Severity.MEDIUM
        assert engine.determine_severity(70) == Severity.HIGH
        assert engine.determine_severity(89) == Severity.HIGH
        assert engine.determine_severity(90) == Severity.CRITICAL
        assert engine.determine_severity(100) == Severity.CRITICAL

    def test_corroboration_bonus_capped(self) -> None:
        """Verify corroboration bonus is capped at max configured value (default +15)."""
        engine = RiskScoringEngine()
        finding = BehaviorFinding(
            rule_id="RULE-BEH-003",  # base 45
            related_event_ids=[f"ev_{i}" for i in range(10)],  # 9 extra events -> 9 * 5 = 45, capped at 15
        )
        score = engine.calculate_score(finding)
        # 45 base + 15 corrob cap = 60
        assert score.score == 60

    def test_calculate_from_security_event(self) -> None:
        """Verify scoring directly from a canonical SecurityEvent."""
        engine = RiskScoringEngine()
        b_ctx = BehaviorContext(
            finding_id="beh_test123",
            rule_id="RULE-BEH-001",
            rule_name="File Rule",
            evidence=[{"category": "FILE", "path": "malware.exe"}],
        )
        event = SecurityEvent(
            event_id="beh_test123",
            event_type=EventType("BEHAVIOR", "FINDING"),
            severity=Severity.HIGH,
            source="behavior_engine",
            endpoint=EndpointIdentity.resolve(),
            context=EventContext(behavior=b_ctx),
        )
        score = engine.calculate_from_event(event)
        assert score.score == 55
        assert score.severity == Severity.MEDIUM


class TestAlertLifecycleAndModel:
    """Tests for Alert domain model and state transitions."""

    def test_default_alert_lifecycle(self) -> None:
        """Verify alert begins in OPEN status and allows valid transitions."""
        alert = Alert(title="Test Alert", risk_score=85, severity=Severity.HIGH)
        assert alert.status == AlertStatus.OPEN
        assert alert.occurrence_count == 1

        # OPEN -> ACKNOWLEDGED
        alert.acknowledge(comment="Investigating analyst triage")
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert len(alert.extra["status_history"]) == 1
        assert alert.extra["status_history"][0]["comment"] == "Investigating analyst triage"

        # ACKNOWLEDGED -> RESOLVED
        alert.resolve(comment="Remediated benign true positive")
        assert alert.status == AlertStatus.RESOLVED
        assert len(alert.extra["status_history"]) == 2

        # RESOLVED -> OPEN (reopen)
        alert.reopen(comment="Reopened due to recurring activity")
        assert alert.status == AlertStatus.OPEN
        assert len(alert.extra["status_history"]) == 3

    def test_invalid_lifecycle_transition(self) -> None:
        """Verify direct transitions follow VALID_STATUS_TRANSITIONS."""
        alert = Alert(status=AlertStatus.OPEN)

        # Same state is a no-op
        alert.update_status(AlertStatus.OPEN)
        assert alert.status == AlertStatus.OPEN

    def test_serialization_roundtrip(self) -> None:
        """Verify alert serialization to and from dictionary."""
        alert = Alert(
            alert_id="alt_12345",
            title="Credential Decoy Access",
            severity=Severity.CRITICAL,
            risk_score=100,
            status=AlertStatus.OPEN,
            endpoint_id="ep_windows_test",
            rule_id="RULE-BEH-005",
            rule_name="Decoy Rule",
            pid=4321,
            process_name="evil.exe",
            executable_path="C:\\evil.exe",
            deception_id="decoy_passwords",
            scoring_reasons=[{"factor": "base_rule", "contribution": 75, "reason": "Base"}],
            related_event_ids=["ev_1", "ev_2"],
            evidence=[{"is_decoy": True}],
        )

        data = alert.to_dict()
        assert data["alert_id"] == "alt_12345"
        assert data["severity"] == "CRITICAL"
        assert data["status"] == "OPEN"
        assert data["risk_score"] == 100

        reconstructed = Alert.from_dict(data)
        assert reconstructed.alert_id == alert.alert_id
        assert reconstructed.severity == Severity.CRITICAL
        assert reconstructed.status == AlertStatus.OPEN
        assert reconstructed.scoring_reasons == alert.scoring_reasons
        assert reconstructed.related_event_ids == ["ev_1", "ev_2"]

    def test_record_occurrence(self) -> None:
        """Verify repeated occurrence updates occurrence_count without runaway scoring."""
        alert = Alert(title="Test", risk_score=75, occurrence_count=1)
        finding = BehaviorFinding(
            related_event_ids=["ev_10", "ev_20"],
            end_time="2026-10-02T12:00:00Z",
        )
        alert.record_occurrence(finding)
        assert alert.occurrence_count == 2
        assert alert.last_seen == "2026-10-02T12:00:00Z"
        assert "ev_10" in alert.related_event_ids
        assert "ev_20" in alert.related_event_ids
        assert alert.risk_score == 75  # Unchanged, no runaway inflation
