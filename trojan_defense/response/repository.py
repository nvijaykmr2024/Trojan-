"""SQLite persistence repositories for Incidents, Response Actions, and Audit Logs.

Provides persistent, local, transaction-safe storage for:
- Incidents: Multi-alert grouping, notes, investigations.
- Response Actions: State machine execution tracking and rollback history.
- Audit Logs: Immutable, append-only operational audit records.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
from typing import Any

from trojan_defense.core.exceptions import PersistenceError
from trojan_defense.core.logging.setup import get_logger
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

logger = get_logger("response.repository")


class SQLiteIncidentRepository:
    """Local SQLite repository for persistent storage and lifecycle management of incidents."""

    def __init__(self, db_path: str | Path = "trojan_defense.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to connect to Incident database '{self.db_path}': {exc}") from exc

    def _init_schema(self) -> None:
        """Create incidents table and associated indices."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    assigned_to TEXT,
                    alert_ids TEXT NOT NULL,
                    response_action_ids TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at)")

    def create(self, incident: Incident) -> Incident:
        """Insert a new incident."""
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, description, status, severity, assigned_to,
                        alert_ids, response_action_ids, notes, created_at, updated_at, closed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.description,
                        incident.status.value,
                        incident.severity,
                        incident.assigned_to,
                        json.dumps(incident.alert_ids),
                        json.dumps(incident.response_action_ids),
                        json.dumps([n.to_dict() for n in incident.notes]),
                        incident.created_at,
                        incident.updated_at,
                        incident.closed_at,
                    ),
                )
                return incident
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to insert incident '{incident.incident_id}': {exc}") from exc

    def get(self, incident_id: str) -> Incident | None:
        """Fetch an incident by ID."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_incident(row)

    def update(self, incident: Incident) -> Incident:
        """Update an existing incident."""
        with self._lock:
            try:
                cur = self._conn.execute(
                    """
                    UPDATE incidents SET
                        title = ?,
                        description = ?,
                        status = ?,
                        severity = ?,
                        assigned_to = ?,
                        alert_ids = ?,
                        response_action_ids = ?,
                        notes = ?,
                        updated_at = ?,
                        closed_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        incident.title,
                        incident.description,
                        incident.status.value,
                        incident.severity,
                        incident.assigned_to,
                        json.dumps(incident.alert_ids),
                        json.dumps(incident.response_action_ids),
                        json.dumps([n.to_dict() for n in incident.notes]),
                        incident.updated_at,
                        incident.closed_at,
                        incident.incident_id,
                    ),
                )
                if cur.rowcount == 0:
                    raise PersistenceError(f"Incident '{incident.incident_id}' not found for update")
                return incident
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to update incident '{incident.incident_id}': {exc}") from exc

    def add_note(self, incident_id: str, note: IncidentNote) -> Incident:
        """Add an analyst note to an incident."""
        incident = self.get(incident_id)
        if not incident:
            raise PersistenceError(f"Incident '{incident_id}' not found")
        incident.notes.append(note)
        from datetime import datetime, timezone
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        return self.update(incident)

    def associate_alert(self, incident_id: str, alert_id: str) -> Incident:
        """Associate an alert with the incident."""
        incident = self.get(incident_id)
        if not incident:
            raise PersistenceError(f"Incident '{incident_id}' not found")
        if alert_id not in incident.alert_ids:
            incident.alert_ids.append(alert_id)
            from datetime import datetime, timezone
            incident.updated_at = datetime.now(timezone.utc).isoformat()
            self.update(incident)
        return incident

    def associate_action(self, incident_id: str, action_id: str) -> Incident:
        """Associate a response action with the incident."""
        incident = self.get(incident_id)
        if not incident:
            raise PersistenceError(f"Incident '{incident_id}' not found")
        if action_id not in incident.response_action_ids:
            incident.response_action_ids.append(action_id)
            from datetime import datetime, timezone
            incident.updated_at = datetime.now(timezone.utc).isoformat()
            self.update(incident)
        return incident

    def list(
        self,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        """List incidents with optional filtering and pagination."""
        with self._lock:
            clauses = []
            params: list[Any] = []
            if status:
                clauses.append("status = ?")
                params.append(status.upper())
            if severity:
                clauses.append("severity = ?")
                params.append(severity.upper())
            if assigned_to:
                clauses.append("assigned_to = ?")
                params.append(assigned_to)

            where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""

            count_cur = self._conn.execute(f"SELECT COUNT(*) FROM incidents {where_str}", params)
            total = count_cur.fetchone()[0]

            query_sql = f"""
                SELECT * FROM incidents
                {where_str}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """
            cur = self._conn.execute(query_sql, params + [limit, offset])
            incidents = [self._row_to_incident(row) for row in cur.fetchall()]
            return incidents, total

    def count(self) -> int:
        """Total incidents count."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM incidents")
            return cur.fetchone()[0]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        notes_raw = json.loads(row["notes"])
        notes = [IncidentNote.from_dict(n) for n in notes_raw]
        return Incident(
            incident_id=row["incident_id"],
            title=row["title"],
            description=row["description"] or "",
            status=IncidentStatus(row["status"]),
            severity=row["severity"],
            assigned_to=row["assigned_to"],
            alert_ids=json.loads(row["alert_ids"]),
            response_action_ids=json.loads(row["response_action_ids"]),
            notes=notes,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            closed_at=row["closed_at"],
        )


class SQLiteResponseActionRepository:
    """Local SQLite repository for persistent storage of Response Actions."""

    def __init__(self, db_path: str | Path = "trojan_defense.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to connect to Response Actions database '{self.db_path}': {exc}") from exc

    def _init_schema(self) -> None:
        """Create response_actions table and associated indices."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id TEXT PRIMARY KEY,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    incident_id TEXT,
                    alert_id TEXT,
                    target_params TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    authorized_by TEXT,
                    authorized_at TEXT,
                    executed_at TEXT,
                    execution_result TEXT,
                    error_message TEXT,
                    rollback_action_id TEXT,
                    rolled_back_at TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions (status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_type ON response_actions (action_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions (incident_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_alert ON response_actions (alert_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_requested_at ON response_actions (requested_at)")

    def create(self, action: ResponseAction) -> ResponseAction:
        """Insert a new response action."""
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, action_type, status, incident_id, alert_id,
                        target_params, requested_by, requested_at, authorized_by,
                        authorized_at, executed_at, execution_result, error_message,
                        rollback_action_id, rolled_back_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action.action_id,
                        action.action_type.value,
                        action.status.value,
                        action.incident_id,
                        action.alert_id,
                        json.dumps(action.target_params),
                        action.requested_by,
                        action.requested_at,
                        action.authorized_by,
                        action.authorized_at,
                        action.executed_at,
                        json.dumps(action.execution_result) if action.execution_result is not None else None,
                        action.error_message,
                        action.rollback_action_id,
                        action.rolled_back_at,
                    ),
                )
                return action
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to insert response action '{action.action_id}': {exc}") from exc

    def get(self, action_id: str) -> ResponseAction | None:
        """Fetch a response action by ID."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM response_actions WHERE action_id = ?",
                (action_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_action(row)

    def update(self, action: ResponseAction) -> ResponseAction:
        """Update an existing response action."""
        with self._lock:
            try:
                cur = self._conn.execute(
                    """
                    UPDATE response_actions SET
                        action_type = ?,
                        status = ?,
                        incident_id = ?,
                        alert_id = ?,
                        target_params = ?,
                        requested_by = ?,
                        requested_at = ?,
                        authorized_by = ?,
                        authorized_at = ?,
                        executed_at = ?,
                        execution_result = ?,
                        error_message = ?,
                        rollback_action_id = ?,
                        rolled_back_at = ?
                    WHERE action_id = ?
                    """,
                    (
                        action.action_type.value,
                        action.status.value,
                        action.incident_id,
                        action.alert_id,
                        json.dumps(action.target_params),
                        action.requested_by,
                        action.requested_at,
                        action.authorized_by,
                        action.authorized_at,
                        action.executed_at,
                        json.dumps(action.execution_result) if action.execution_result is not None else None,
                        action.error_message,
                        action.rollback_action_id,
                        action.rolled_back_at,
                        action.action_id,
                    ),
                )
                if cur.rowcount == 0:
                    raise PersistenceError(f"Response action '{action.action_id}' not found for update")
                return action
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to update response action '{action.action_id}': {exc}") from exc

    def list(
        self,
        status: str | None = None,
        action_type: str | None = None,
        incident_id: str | None = None,
        alert_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ResponseAction], int]:
        """List response actions with filtering and pagination."""
        with self._lock:
            clauses = []
            params: list[Any] = []
            if status:
                clauses.append("status = ?")
                params.append(status.upper())
            if action_type:
                clauses.append("action_type = ?")
                params.append(action_type.upper())
            if incident_id:
                clauses.append("incident_id = ?")
                params.append(incident_id)
            if alert_id:
                clauses.append("alert_id = ?")
                params.append(alert_id)

            where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""

            count_cur = self._conn.execute(f"SELECT COUNT(*) FROM response_actions {where_str}", params)
            total = count_cur.fetchone()[0]

            query_sql = f"""
                SELECT * FROM response_actions
                {where_str}
                ORDER BY requested_at DESC
                LIMIT ? OFFSET ?
            """
            cur = self._conn.execute(query_sql, params + [limit, offset])
            actions = [self._row_to_action(row) for row in cur.fetchall()]
            return actions, total

    def count(self) -> int:
        """Total response actions count."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM response_actions")
            return cur.fetchone()[0]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _row_to_action(self, row: sqlite3.Row) -> ResponseAction:
        exec_res_str = row["execution_result"]
        exec_res = json.loads(exec_res_str) if exec_res_str else None
        return ResponseAction(
            action_id=row["action_id"],
            action_type=ResponseActionType(row["action_type"]),
            status=ActionStatus(row["status"]),
            incident_id=row["incident_id"],
            alert_id=row["alert_id"],
            target_params=json.loads(row["target_params"]),
            requested_by=row["requested_by"],
            requested_at=row["requested_at"],
            authorized_by=row["authorized_by"],
            authorized_at=row["authorized_at"],
            executed_at=row["executed_at"],
            execution_result=exec_res,
            error_message=row["error_message"],
            rollback_action_id=row["rollback_action_id"],
            rolled_back_at=row["rolled_back_at"],
        )


class SQLiteAuditRepository:
    """Local SQLite repository for append-only, immutable audit logging."""

    def __init__(self, db_path: str | Path = "trojan_defense.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to connect to Audit Log database '{self.db_path}': {exc}") from exc

    def _init_schema(self) -> None:
        """Create audit_logs table and associated indices."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    details TEXT NOT NULL,
                    ip_address TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_target_id ON audit_logs (target_id)")

    def append(self, entry: AuditLogEntry) -> AuditLogEntry:
        """Append an immutable audit entry."""
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO audit_logs (
                        audit_id, timestamp, actor, role, action,
                        target_type, target_id, details, ip_address
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.audit_id,
                        entry.timestamp,
                        entry.actor,
                        entry.role,
                        entry.action.value if hasattr(entry.action, "value") else str(entry.action),
                        entry.target_type,
                        entry.target_id,
                        json.dumps(entry.details),
                        entry.ip_address,
                    ),
                )
                return entry
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to append audit entry '{entry.audit_id}': {exc}") from exc

    def get(self, audit_id: str) -> AuditLogEntry | None:
        """Fetch an audit log entry by ID."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM audit_logs WHERE audit_id = ?",
                (audit_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_audit(row)

    def list(
        self,
        target_id: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLogEntry], int]:
        """Query audit log entries with filtering and pagination."""
        with self._lock:
            clauses = []
            params: list[Any] = []
            if target_id:
                clauses.append("target_id = ?")
                params.append(target_id)
            if action:
                clauses.append("action = ?")
                params.append(action.upper())
            if actor:
                clauses.append("actor = ?")
                params.append(actor)
            if start_time:
                clauses.append("timestamp >= ?")
                params.append(start_time)
            if end_time:
                clauses.append("timestamp <= ?")
                params.append(end_time)

            where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""

            count_cur = self._conn.execute(f"SELECT COUNT(*) FROM audit_logs {where_str}", params)
            total = count_cur.fetchone()[0]

            query_sql = f"""
                SELECT * FROM audit_logs
                {where_str}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            cur = self._conn.execute(query_sql, params + [limit, offset])
            entries = [self._row_to_audit(row) for row in cur.fetchall()]
            return entries, total

    def count(self) -> int:
        """Total audit logs count."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM audit_logs")
            return cur.fetchone()[0]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _row_to_audit(self, row: sqlite3.Row) -> AuditLogEntry:
        return AuditLogEntry(
            audit_id=row["audit_id"],
            timestamp=row["timestamp"],
            actor=row["actor"],
            role=row["role"],
            action=AuditActionType(row["action"]),
            target_type=row["target_type"],
            target_id=row["target_id"],
            details=json.loads(row["details"]),
            ip_address=row["ip_address"],
        )
