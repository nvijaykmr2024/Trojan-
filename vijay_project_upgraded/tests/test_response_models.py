"""Unit tests for Response and Incident models, state machines, and RBAC."""

import pytest

from trojan_defense.response.auth import (
    AuthorizationError,
    Permission,
    Role,
    UserContext,
    resolve_user_context,
)
from trojan_defense.response.models import (
    ActionStatus,
    AuditActionType,
    AuditLogEntry,
    Incident,
    IncidentNote,
    IncidentStatus,
    ResponseAction,
    ResponseActionType,
    VALID_ACTION_TRANSITIONS,
    VALID_INCIDENT_TRANSITIONS,
)


class TestIncidentModel:
    """Tests for Incident domain model and state transitions."""

    def test_incident_creation_and_defaults(self):
        inc = Incident(title="Suspicious Trojan Execution", severity="CRITICAL")
        assert inc.incident_id.startswith("inc-")
        assert inc.status == IncidentStatus.OPEN
        assert inc.severity == "CRITICAL"
        assert inc.alert_ids == []
        assert inc.response_action_ids == []
        assert inc.notes == []
        assert inc.closed_at is None

    def test_incident_serialization_roundtrip(self):
        inc = Incident(
            title="Canary Token Accessed",
            description="Trojan touched sensitive canary",
            severity="HIGH",
            assigned_to="alice",
            alert_ids=["alt-123"],
            response_action_ids=["act-456"],
        )
        inc.add_note(author="alice", content="Confirmed honeypot traversal")
        data = inc.to_dict()
        assert data["incident_id"] == inc.incident_id
        assert data["status"] == "OPEN"
        assert len(data["notes"]) == 1

        restored = Incident.from_dict(data)
        assert restored.incident_id == inc.incident_id
        assert restored.title == inc.title
        assert restored.assigned_to == "alice"
        assert len(restored.notes) == 1
        assert restored.notes[0].content == "Confirmed honeypot traversal"

    def test_valid_incident_transitions(self):
        inc = Incident(title="Test Incident")
        assert inc.can_transition_to(IncidentStatus.INVESTIGATING)
        assert inc.can_transition_to(IncidentStatus.CONTAINED)
        assert inc.can_transition_to(IncidentStatus.CLOSED)

        inc.transition_to(IncidentStatus.INVESTIGATING)
        assert inc.status == IncidentStatus.INVESTIGATING

        inc.transition_to(IncidentStatus.CONTAINED)
        assert inc.status == IncidentStatus.CONTAINED

        inc.transition_to(IncidentStatus.RESOLVED)
        assert inc.status == IncidentStatus.RESOLVED

        inc.transition_to(IncidentStatus.CLOSED)
        assert inc.status == IncidentStatus.CLOSED
        assert inc.closed_at is not None

        # Reopen
        inc.transition_to(IncidentStatus.INVESTIGATING)
        assert inc.status == IncidentStatus.INVESTIGATING
        assert inc.closed_at is None

    def test_invalid_incident_transition_raises(self):
        inc = Incident(title="Test Incident")
        # Direct OPEN to RESOLVED is invalid
        assert not inc.can_transition_to(IncidentStatus.RESOLVED)
        with pytest.raises(ValueError, match="Invalid incident transition"):
            inc.transition_to(IncidentStatus.RESOLVED)


class TestResponseActionModel:
    """Tests for ResponseAction model and state machine."""

    def test_response_action_creation_and_defaults(self):
        act = ResponseAction(
            action_type=ResponseActionType.FILE_QUARANTINE,
            target_params={"file_path": "C:\\temp\\malware.exe"},
            requested_by="analyst_bob",
        )
        assert act.action_id.startswith("act-")
        assert act.status == ActionStatus.REQUESTED
        assert act.authorized_by is None
        assert act.executed_at is None
        assert act.execution_result is None

    def test_response_action_serialization_roundtrip(self):
        act = ResponseAction(
            action_type=ResponseActionType.PROCESS_TERMINATION,
            status=ActionStatus.AUTHORIZED,
            target_params={"pid": 4567},
            requested_by="bob",
            authorized_by="alice",
        )
        data = act.to_dict()
        assert data["action_type"] == "PROCESS_TERMINATION"
        assert data["status"] == "AUTHORIZED"
        assert data["target_params"]["pid"] == 4567

        restored = ResponseAction.from_dict(data)
        assert restored.action_id == act.action_id
        assert restored.action_type == ResponseActionType.PROCESS_TERMINATION
        assert restored.status == ActionStatus.AUTHORIZED
        assert restored.authorized_by == "alice"

    def test_valid_action_transitions(self):
        act = ResponseAction(action_type=ResponseActionType.PROCESS_TERMINATION)
        assert act.can_transition_to(ActionStatus.AUTHORIZED)
        assert act.can_transition_to(ActionStatus.REJECTED)

        act.transition_to(ActionStatus.AUTHORIZED)
        assert act.can_transition_to(ActionStatus.EXECUTING)

        act.transition_to(ActionStatus.EXECUTING)
        assert act.can_transition_to(ActionStatus.SUCCEEDED)

        act.transition_to(ActionStatus.SUCCEEDED)
        assert act.can_transition_to(ActionStatus.ROLLED_BACK)

        act.transition_to(ActionStatus.ROLLED_BACK)
        assert act.status == ActionStatus.ROLLED_BACK

    def test_invalid_action_transition_raises(self):
        act = ResponseAction(action_type=ResponseActionType.PROCESS_TERMINATION)
        # Cannot execute without authorization
        assert not act.can_transition_to(ActionStatus.EXECUTING)
        with pytest.raises(ValueError, match="Invalid response action transition"):
            act.transition_to(ActionStatus.EXECUTING)


class TestAuditLogEntry:
    """Tests for AuditLogEntry."""

    def test_audit_log_serialization(self):
        entry = AuditLogEntry(
            actor="sec_officer",
            role="RESPONDER",
            action=AuditActionType.RESPONSE_AUTHORIZED,
            target_type="response_action",
            target_id="act-1234",
            details={"approved_by": "sec_officer"},
            ip_address="192.168.1.50",
        )
        data = entry.to_dict()
        assert data["actor"] == "sec_officer"
        assert data["action"] == "RESPONSE_AUTHORIZED"
        assert data["target_id"] == "act-1234"

        restored = AuditLogEntry.from_dict(data)
        assert restored.audit_id == entry.audit_id
        assert restored.action == AuditActionType.RESPONSE_AUTHORIZED


class TestRBACAndUserContext:
    """Tests for Role-Based Access Control policies."""

    def test_viewer_role_permissions(self):
        ctx = UserContext(username="viewer1", role=Role.VIEWER)
        assert ctx.has_permission(Permission.READ_SECURITY_DATA)
        assert not ctx.has_permission(Permission.MANAGE_ALERT)
        assert not ctx.has_permission(Permission.MANAGE_INCIDENT)
        assert not ctx.has_permission(Permission.REQUEST_RESPONSE)
        assert not ctx.has_permission(Permission.AUTHORIZE_RESPONSE)
        assert not ctx.has_permission(Permission.EXECUTE_RESPONSE)

        with pytest.raises(AuthorizationError):
            ctx.require_permission(Permission.REQUEST_RESPONSE)

    def test_analyst_role_permissions(self):
        ctx = UserContext(username="analyst1", role=Role.ANALYST)
        assert ctx.has_permission(Permission.READ_SECURITY_DATA)
        assert ctx.has_permission(Permission.MANAGE_ALERT)
        assert ctx.has_permission(Permission.MANAGE_INCIDENT)
        assert ctx.has_permission(Permission.REQUEST_RESPONSE)
        # Analyst CANNOT authorize or execute actions
        assert not ctx.has_permission(Permission.AUTHORIZE_RESPONSE)
        assert not ctx.has_permission(Permission.EXECUTE_RESPONSE)

        with pytest.raises(AuthorizationError):
            ctx.require_permission(Permission.AUTHORIZE_RESPONSE)

    def test_responder_role_permissions(self):
        ctx = UserContext(username="responder1", role=Role.RESPONDER)
        assert ctx.has_permission(Permission.READ_SECURITY_DATA)
        assert ctx.has_permission(Permission.MANAGE_ALERT)
        assert ctx.has_permission(Permission.MANAGE_INCIDENT)
        assert ctx.has_permission(Permission.REQUEST_RESPONSE)
        assert ctx.has_permission(Permission.AUTHORIZE_RESPONSE)
        assert ctx.has_permission(Permission.EXECUTE_RESPONSE)

    def test_admin_role_permissions(self):
        ctx = UserContext(username="admin1", role=Role.ADMIN)
        for perm in Permission:
            assert ctx.has_permission(perm)

    def test_resolve_user_context_with_token(self):
        tokens = {
            "token-analyst-1": "ANALYST",
            "token-responder-1": "RESPONDER",
        }
        ctx = resolve_user_context(
            token="Bearer token-analyst-1",
            configured_tokens=tokens,
        )
        assert ctx.role == Role.ANALYST
        assert ctx.has_permission(Permission.REQUEST_RESPONSE)
        assert not ctx.has_permission(Permission.AUTHORIZE_RESPONSE)

    def test_resolve_user_context_with_role_header(self):
        ctx = resolve_user_context(role_header="responder", actor_header="alice")
        assert ctx.role == Role.RESPONDER
        assert ctx.username == "alice"
        assert ctx.has_permission(Permission.AUTHORIZE_RESPONSE)

    def test_resolve_user_context_invalid_role_header_raises(self):
        with pytest.raises(AuthorizationError, match="Invalid role header"):
            resolve_user_context(role_header="SUPERUSER_HACKER")
