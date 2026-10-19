"""Unit tests for SQLite repositories: Incidents, Response Actions, and Audit Logs."""

from pathlib import Path
import pytest

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
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)


@pytest.fixture
def temp_db(tmp_path):
    return tmp_path / "test_response.db"


class TestSQLiteIncidentRepository:
    """Tests for SQLiteIncidentRepository."""

    def test_create_get_update_incident(self, temp_db):
        repo = SQLiteIncidentRepository(db_path=temp_db)
        try:
            inc = Incident(
                title="Trojan Attack Detected",
                description="Rule 5 triggered",
                severity="CRITICAL",
                assigned_to="alice",
                alert_ids=["alt-1", "alt-2"],
            )
            saved = repo.create(inc)
            assert saved.incident_id == inc.incident_id

            fetched = repo.get(inc.incident_id)
            assert fetched is not None
            assert fetched.title == "Trojan Attack Detected"
            assert fetched.severity == "CRITICAL"
            assert fetched.alert_ids == ["alt-1", "alt-2"]

            # Update status
            fetched.transition_to(IncidentStatus.INVESTIGATING)
            repo.update(fetched)

            updated = repo.get(inc.incident_id)
            assert updated.status == IncidentStatus.INVESTIGATING
        finally:
            repo.close()

    def test_add_note_and_associations(self, temp_db):
        repo = SQLiteIncidentRepository(db_path=temp_db)
        try:
            inc = repo.create(Incident(title="Suspicious Activity"))
            note = IncidentNote(incident_id=inc.incident_id, author="bob", content="Examining memory dump")
            repo.add_note(inc.incident_id, note)

            repo.associate_alert(inc.incident_id, "alt-100")
            repo.associate_action(inc.incident_id, "act-200")

            fetched = repo.get(inc.incident_id)
            assert len(fetched.notes) == 1
            assert fetched.notes[0].content == "Examining memory dump"
            assert "alt-100" in fetched.alert_ids
            assert "act-200" in fetched.response_action_ids
        finally:
            repo.close()

    def test_list_and_filter_incidents(self, temp_db):
        repo = SQLiteIncidentRepository(db_path=temp_db)
        try:
            repo.create(Incident(title="Inc 1", severity="LOW", status=IncidentStatus.OPEN))
            repo.create(Incident(title="Inc 2", severity="HIGH", status=IncidentStatus.OPEN))
            repo.create(Incident(title="Inc 3", severity="CRITICAL", status=IncidentStatus.CLOSED))

            all_inc, total = repo.list()
            assert total == 3
            assert len(all_inc) == 3

            open_inc, open_total = repo.list(status="OPEN")
            assert open_total == 2

            crit_inc, crit_total = repo.list(severity="CRITICAL")
            assert crit_total == 1
            assert crit_inc[0].title == "Inc 3"
        finally:
            repo.close()


class TestSQLiteResponseActionRepository:
    """Tests for SQLiteResponseActionRepository."""

    def test_create_and_query_actions(self, temp_db):
        repo = SQLiteResponseActionRepository(db_path=temp_db)
        try:
            act = ResponseAction(
                action_type=ResponseActionType.PROCESS_TERMINATION,
                target_params={"pid": 1234},
                incident_id="inc-1",
                alert_id="alt-1",
            )
            saved = repo.create(act)
            assert saved.action_id == act.action_id

            fetched = repo.get(act.action_id)
            assert fetched is not None
            assert fetched.action_type == ResponseActionType.PROCESS_TERMINATION
            assert fetched.target_params["pid"] == 1234

            # Update
            fetched.transition_to(ActionStatus.AUTHORIZED)
            fetched.authorized_by = "lead_analyst"
            repo.update(fetched)

            updated = repo.get(act.action_id)
            assert updated.status == ActionStatus.AUTHORIZED
            assert updated.authorized_by == "lead_analyst"

            # Filter by status
            actions, count = repo.list(status="AUTHORIZED")
            assert count == 1
            assert actions[0].action_id == act.action_id
        finally:
            repo.close()


class TestSQLiteAuditRepository:
    """Tests for SQLiteAuditRepository."""

    def test_append_and_query_audit_logs(self, temp_db):
        repo = SQLiteAuditRepository(db_path=temp_db)
        try:
            e1 = AuditLogEntry(
                actor="alice",
                role="ANALYST",
                action=AuditActionType.INCIDENT_CREATED,
                target_type="incident",
                target_id="inc-1",
                details={"title": "New Incident"},
            )
            e2 = AuditLogEntry(
                actor="bob",
                role="RESPONDER",
                action=AuditActionType.RESPONSE_AUTHORIZED,
                target_type="response_action",
                target_id="act-1",
                details={"action_type": "PROCESS_TERMINATION"},
            )
            repo.append(e1)
            repo.append(e2)

            assert repo.count() == 2

            # Query by actor
            entries, total = repo.list(actor="alice")
            assert total == 1
            assert entries[0].target_id == "inc-1"

            # Query by target
            entries, total = repo.list(target_id="act-1")
            assert total == 1
            assert entries[0].action == AuditActionType.RESPONSE_AUTHORIZED
        finally:
            repo.close()
