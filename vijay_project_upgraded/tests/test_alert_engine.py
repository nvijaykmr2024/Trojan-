"""Automated test suite for Phase 10 AlertEngine, Deduplication, and SQLiteAlertRepository.

Tests repository persistence, multi-dimensional query filters, deduplication,
cooldown suppression, Windows PID reuse protection, and pipeline event routing.
"""

from datetime import datetime, timezone
import tempfile
import time

import pytest

from trojan_defense.alerting.engine import AlertEngine
from trojan_defense.alerting.models import Alert, AlertStatus
from trojan_defense.alerting.repository import AlertQueryFilter, SQLiteAlertRepository
from trojan_defense.alerting.scorer import RiskScoringEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.core.config.schema import AlertingConfig, RiskConfig
from trojan_defense.core.models.context import BehaviorContext, EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline


class TestSQLiteAlertRepository:
    """Tests for durable alert persistence in SQLite."""

    @pytest.fixture
    def repo(self) -> SQLiteAlertRepository:
        """Create an in-memory SQLiteAlertRepository for isolated testing."""
        return SQLiteAlertRepository(db_path=":memory:")

    def test_save_and_get_by_id(self, repo: SQLiteAlertRepository) -> None:
        """Verify saving and retrieving an alert."""
        alert = Alert(
            alert_id="alt_repo_1",
            title="Suspicious Executable Dropped",
            severity=Severity.HIGH,
            risk_score=75,
            status=AlertStatus.OPEN,
            endpoint_id="ep_windows_node",
            rule_id="RULE-BEH-001",
            rule_name="Process File Activity",
            pid=5555,
            process_name="powershell.exe",
            executable_path="C:\\Windows\\System32\\powershell.exe",
            scoring_reasons=[{"factor": "base_rule", "contribution": 40, "reason": "Base"}],
            related_event_ids=["ev_101", "ev_102"],
            evidence=[{"file": "trojan.exe"}],
        )

        assert repo.save(alert) is True
        # Duplicate alert_id returns False
        assert repo.save(alert) is False

        fetched = repo.get_by_id("alt_repo_1")
        assert fetched is not None
        assert fetched.alert_id == "alt_repo_1"
        assert fetched.title == "Suspicious Executable Dropped"
        assert fetched.severity == Severity.HIGH
        assert fetched.risk_score == 75
        assert fetched.status == AlertStatus.OPEN
        assert fetched.pid == 5555
        assert fetched.process_name == "powershell.exe"
        assert fetched.related_event_ids == ["ev_101", "ev_102"]
        assert len(fetched.evidence) == 1

    def test_update_alert_lifecycle(self, repo: SQLiteAlertRepository) -> None:
        """Verify updating alert status and occurrences."""
        alert = Alert(
            alert_id="alt_repo_update",
            title="Initial Alert",
            risk_score=70,
            status=AlertStatus.OPEN,
            occurrence_count=1,
        )
        repo.save(alert)

        alert.acknowledge(comment="Analyst assigned")
        alert.occurrence_count = 3
        alert.last_seen = "2026-10-02T15:00:00Z"
        assert repo.update(alert) is True

        updated = repo.get_by_id("alt_repo_update")
        assert updated is not None
        assert updated.status == AlertStatus.ACKNOWLEDGED
        assert updated.occurrence_count == 3
        assert updated.last_seen == "2026-10-02T15:00:00Z"

    def test_query_filtering_and_pagination(self, repo: SQLiteAlertRepository) -> None:
        """Verify multi-parameter query filtering and pagination."""
        for i in range(10):
            status = AlertStatus.OPEN if i % 2 == 0 else AlertStatus.RESOLVED
            sev = Severity.CRITICAL if i >= 7 else (Severity.HIGH if i >= 4 else Severity.MEDIUM)
            score = 30 + (i * 7)
            alert = Alert(
                alert_id=f"alt_query_{i}",
                title=f"Alert #{i}",
                severity=sev,
                risk_score=score,
                status=status,
                endpoint_id="ep_test",
                rule_id=f"RULE-BEH-00{i % 3 + 1}",
                pid=1000 + i,
            )
            repo.save(alert)

        # Count total
        assert repo.count() == 10
        assert repo.count(status="OPEN") == 5
        assert repo.count(status="RESOLVED") == 5

        # Query by status
        alerts_open, total_open = repo.query(AlertQueryFilter(status="OPEN"))
        assert total_open == 5
        assert len(alerts_open) == 5
        assert all(a.status == AlertStatus.OPEN for a in alerts_open)

        # Query by min_score
        alerts_high_score, total_hs = repo.query(AlertQueryFilter(min_score=70))
        assert total_hs == 4  # i=6(72), 7(79), 8(86), 9(93)
        assert len(alerts_high_score) == 4

        # Pagination: limit 3, offset 2
        paginated, total_p = repo.query(AlertQueryFilter(limit=3, offset=2))
        assert total_p == 10
        assert len(paginated) == 3


class TestAlertEngine:
    """Tests for AlertEngine scoring, deduplication, and pipeline integration."""

    def test_process_finding_creates_alert(self) -> None:
        """Verify processing a behavior finding generates a persistent alert."""
        repo = SQLiteAlertRepository(db_path=":memory:")
        engine = AlertEngine(repository=repo)

        finding = BehaviorFinding(
            finding_id="beh_f1",
            rule_id="RULE-BEH-005",
            rule_name="Decoy Interaction Sequence",
            severity=Severity.CRITICAL,
            timestamp="2026-10-02T12:00:00Z",
            pid=2048,
            process_name="mimikatz.exe",
            executable_path="C:\\Tools\\mimikatz.exe",
            evidence=[{"is_decoy": True, "decoy_id": "decoy_passwords"}],
            related_event_ids=["ev_decoy_1"],
        )

        alert = engine.process_finding(finding, endpoint_id="ep_win_test")
        assert alert is not None
        assert alert.risk_score == 100
        assert alert.severity == Severity.CRITICAL
        assert alert.status == AlertStatus.OPEN
        assert alert.rule_id == "RULE-BEH-005"
        assert alert.pid == 2048
        assert alert.deception_id == "decoy_passwords"
        assert engine.stats["alerts_generated"] == 1

        # Check repository persistence
        persisted = repo.get_by_id(alert.alert_id)
        assert persisted is not None
        assert persisted.alert_id == alert.alert_id

    def test_min_alert_score_suppression(self) -> None:
        """Verify findings below min_alert_score do not generate alerts."""
        repo = SQLiteAlertRepository(db_path=":memory:")
        cfg = AlertingConfig(min_alert_score=50)
        risk_cfg = RiskConfig(default_base_score=25)
        engine = AlertEngine(
            alert_config=cfg,
            risk_config=risk_cfg,
            repository=repo,
        )

        # Finding with base score 25 (below min_alert_score 50)
        finding = BehaviorFinding(rule_id="RULE-LOW-SEV")
        alert = engine.process_finding(finding)
        assert alert is None
        assert repo.count() == 0
        assert engine.stats["alerts_suppressed"] == 1

    def test_deduplication_and_repeated_occurrences(self) -> None:
        """Verify multiple findings within dedup window update existing alert instead of creating new ones."""
        repo = SQLiteAlertRepository(db_path=":memory:")
        cfg = AlertingConfig(dedup_window_seconds=60.0, cooldown_seconds=300.0)
        engine = AlertEngine(alert_config=cfg, repository=repo)

        # Finding 1
        f1 = BehaviorFinding(
            finding_id="beh_d1",
            rule_id="RULE-BEH-001",
            rule_name="File Activity",
            timestamp="2026-10-02T10:00:00Z",
            pid=3333,
            process_name="cmd.exe",
            executable_path="C:\\Windows\\System32\\cmd.exe",
            evidence=[{"category": "FILE", "path": "test.bat"}],
            related_event_ids=["ev_1"],
        )
        alert1 = engine.process_finding(f1)
        assert alert1 is not None
        assert alert1.occurrence_count == 1
        assert repo.count() == 1

        # Finding 2 for same process + rule 10 seconds later (within 60s dedup window)
        f2 = BehaviorFinding(
            finding_id="beh_d2",
            rule_id="RULE-BEH-001",
            rule_name="File Activity",
            timestamp="2026-10-02T10:00:10Z",
            pid=3333,
            process_name="cmd.exe",
            executable_path="C:\\Windows\\System32\\cmd.exe",
            evidence=[{"category": "FILE", "path": "test2.bat"}],
            related_event_ids=["ev_2"],
        )
        alert2 = engine.process_finding(f2)
        assert alert2 is not None
        assert alert2.alert_id == alert1.alert_id  # Same alert
        assert alert2.occurrence_count == 2
        assert alert2.last_seen == "2026-10-02T10:00:10Z"
        assert "ev_2" in alert2.related_event_ids
        assert repo.count() == 1  # No duplicate row created

    def test_windows_pid_reuse_safety(self) -> None:
        """Verify that same PID with different executable path produces distinct alerts."""
        repo = SQLiteAlertRepository(db_path=":memory:")
        engine = AlertEngine(repository=repo)

        # Process A with PID 4000
        fA = BehaviorFinding(
            rule_id="RULE-BEH-001",
            pid=4000,
            process_name="first_proc.exe",
            executable_path="C:\\first_proc.exe",
            timestamp="2026-10-02T10:00:00Z",
        )
        alertA = engine.process_finding(fA)

        # Process B reusing PID 4000 after process A terminated
        fB = BehaviorFinding(
            rule_id="RULE-BEH-001",
            pid=4000,
            process_name="reused_proc.exe",
            executable_path="C:\\reused_proc.exe",
            timestamp="2026-10-02T10:00:05Z",
        )
        alertB = engine.process_finding(fB)

        assert alertA is not None
        assert alertB is not None
        assert alertA.alert_id != alertB.alert_id
        assert repo.count() == 2

    def test_pipeline_wires_to_alert_engine(self) -> None:
        """Verify EventPipeline automatically triggers alert generation for BEHAVIOR FINDING events."""
        repo = SQLiteAlertRepository(db_path=":memory:")
        engine = AlertEngine(repository=repo)
        pipeline = EventPipeline(alert_engine=engine)

        b_ctx = BehaviorContext(
            finding_id="beh_pipe_1",
            rule_id="RULE-BEH-004",
            rule_name="Privilege Escalation Rule",
            start_time="2026-10-02T11:00:00Z",
            end_time="2026-10-02T11:00:01Z",
            pid=8888,
            process_name="elevated.exe",
            evidence=[{"is_elevated": True}],
        )
        p_ctx = ProcessContext(pid=8888, name="elevated.exe")

        event = SecurityEvent(
            event_id="beh_pipe_1",
            event_type=EventType("BEHAVIOR", "FINDING"),
            severity=Severity.HIGH,
            source="behavior_engine",
            endpoint=EndpointIdentity.resolve(),
            context=EventContext(behavior=b_ctx, process=p_ctx),
        )

        pipeline.process(event)
        assert repo.count() == 1
        alerts, _ = repo.query()
        assert len(alerts) == 1
        assert alerts[0].rule_id == "RULE-BEH-004"
        assert alerts[0].pid == 8888
