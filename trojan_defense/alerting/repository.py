"""SQLite repository for persistent storage and querying of security alerts.

Provides durable, local database storage for first-class Alert entities,
including dynamic filtering, lifecycle state updates, and evidence lineage.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any

from trojan_defense.alerting.models import Alert, AlertStatus
from trojan_defense.core.exceptions import PersistenceError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.severity import Severity

logger = get_logger("alerting.repository")


@dataclass
class AlertQueryFilter:
    """Filter parameters for querying alerts with pagination."""
    status: str | None = None
    severity: str | None = None
    rule_id: str | None = None
    endpoint_id: str | None = None
    pid: int | None = None
    min_score: int | None = None
    max_score: int | None = None
    start_time: str | None = None
    end_time: str | None = None
    limit: int = 50
    offset: int = 0
    order_by: str = "created_at"
    desc: bool = True


class SQLiteAlertRepository:
    """Local SQLite repository for persistent storage and lifecycle management of alerts."""

    def __init__(self, db_path: str | Path = "trojan_defense.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # Autocommit mode
            )
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to initialize SQLite alerts database at '{self.db_path}': {exc}") from exc

    def _init_schema(self) -> None:
        """Create alerts table and indexes if not already present."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            endpoint_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            executable_path TEXT,
            username TEXT,
            deception_id TEXT,
            description TEXT,
            scoring_reasons_json TEXT,
            related_event_ids_json TEXT,
            evidence_json TEXT,
            extra_json TEXT
        );
        """
        create_indexes_sql = """
        CREATE INDEX IF NOT EXISTS idx_alerts_endpoint ON alerts(endpoint_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score);
        """
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(create_table_sql)
                self._conn.executescript(create_indexes_sql)
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to initialize alerts schema: {exc}") from exc

    def save(self, alert: Alert) -> bool:
        """Save a new alert to SQLite.

        Returns:
            bool: True if inserted, False if alert with this alert_id already exists.
        """
        insert_sql = """
        INSERT INTO alerts (
            alert_id, title, severity, risk_score, status, created_at, updated_at,
            first_seen, last_seen, occurrence_count, endpoint_id, finding_id,
            rule_id, rule_name, pid, process_name, executable_path, username,
            deception_id, description, scoring_reasons_json, related_event_ids_json,
            evidence_json, extra_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        severity_str = alert.severity.to_name() if hasattr(alert.severity, "to_name") else str(alert.severity)
        status_str = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(
                    insert_sql,
                    (
                        alert.alert_id,
                        alert.title,
                        severity_str,
                        alert.risk_score,
                        status_str,
                        alert.created_at,
                        alert.updated_at,
                        alert.first_seen,
                        alert.last_seen,
                        alert.occurrence_count,
                        alert.endpoint_id,
                        alert.finding_id,
                        alert.rule_id,
                        alert.rule_name,
                        alert.pid,
                        alert.process_name,
                        alert.executable_path,
                        alert.username,
                        alert.deception_id,
                        alert.description,
                        json.dumps(alert.scoring_reasons),
                        json.dumps(alert.related_event_ids),
                        json.dumps(alert.evidence),
                        json.dumps(alert.extra),
                    ),
                )
                logger.debug(f"Saved alert {alert.alert_id} (score={alert.risk_score}, severity={severity_str})")
                return True
            except sqlite3.IntegrityError:
                logger.warning(f"Alert {alert.alert_id} already exists, cannot save duplicate")
                return False
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to save alert {alert.alert_id}: {exc}") from exc

    def update(self, alert: Alert) -> bool:
        """Update an existing alert record in SQLite.

        Returns:
            bool: True if row updated, False if alert not found.
        """
        update_sql = """
        UPDATE alerts SET
            title = ?,
            severity = ?,
            risk_score = ?,
            status = ?,
            updated_at = ?,
            last_seen = ?,
            occurrence_count = ?,
            scoring_reasons_json = ?,
            related_event_ids_json = ?,
            evidence_json = ?,
            extra_json = ?
        WHERE alert_id = ?
        """
        severity_str = alert.severity.to_name() if hasattr(alert.severity, "to_name") else str(alert.severity)
        status_str = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(
                    update_sql,
                    (
                        alert.title,
                        severity_str,
                        alert.risk_score,
                        status_str,
                        alert.updated_at,
                        alert.last_seen,
                        alert.occurrence_count,
                        json.dumps(alert.scoring_reasons),
                        json.dumps(alert.related_event_ids),
                        json.dumps(alert.evidence),
                        json.dumps(alert.extra),
                        alert.alert_id,
                    ),
                )
                return cursor.rowcount > 0
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to update alert {alert.alert_id}: {exc}") from exc

    def get_by_id(self, alert_id: str) -> Alert | None:
        """Retrieve a single alert by its unique alert_id."""
        query_sql = "SELECT * FROM alerts WHERE alert_id = ?"
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(query_sql, (alert_id,))
                row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_alert(row)
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to get alert {alert_id}: {exc}") from exc

    def query(self, filters: AlertQueryFilter | None = None) -> tuple[list[Alert], int]:
        """Query alerts matching filter criteria with pagination.

        Returns:
            tuple[list[Alert], int]: Matched alerts and total count matching filters.
        """
        f = filters or AlertQueryFilter()
        clauses: list[str] = []
        params: list[Any] = []

        if f.status:
            clauses.append("status = ?")
            params.append(f.status.upper())

        if f.severity:
            clauses.append("severity = ?")
            params.append(f.severity.upper())

        if f.rule_id:
            clauses.append("rule_id = ?")
            params.append(f.rule_id)

        if f.endpoint_id:
            clauses.append("endpoint_id = ?")
            params.append(f.endpoint_id)

        if f.pid is not None:
            clauses.append("pid = ?")
            params.append(f.pid)

        if f.min_score is not None:
            clauses.append("risk_score >= ?")
            params.append(f.min_score)

        if f.max_score is not None:
            clauses.append("risk_score <= ?")
            params.append(f.max_score)

        if f.start_time:
            clauses.append("created_at >= ?")
            params.append(f.start_time)

        if f.end_time:
            clauses.append("created_at <= ?")
            params.append(f.end_time)

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        # Validate order_by column
        valid_cols = {"created_at", "updated_at", "risk_score", "last_seen", "occurrence_count"}
        order_col = f.order_by if f.order_by in valid_cols else "created_at"
        direction = "DESC" if f.desc else "ASC"

        count_sql = f"SELECT COUNT(*) FROM alerts {where_clause}"
        select_sql = f"SELECT * FROM alerts {where_clause} ORDER BY {order_col} {direction} LIMIT ? OFFSET ?"

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(count_sql, params)
                total_count = cursor.fetchone()[0]

                query_params = list(params)
                query_params.extend([max(1, min(1000, f.limit)), max(0, f.offset)])
                cursor.execute(select_sql, query_params)
                rows = cursor.fetchall()

                alerts = [self._row_to_alert(row) for row in rows]
                return alerts, total_count
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to query alerts: {exc}") from exc

    def count(self, status: str | None = None, severity: str | None = None) -> int:
        """Count total alerts, optionally filtered by status and/or severity."""
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query_sql = f"SELECT COUNT(*) FROM alerts {where_clause}"

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(query_sql, params)
                return cursor.fetchone()[0]
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to count alerts: {exc}") from exc

    def delete_all(self) -> int:
        """Delete all alerts from table. Primarily for tests."""
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute("DELETE FROM alerts")
                return cursor.rowcount
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to clear alerts: {exc}") from exc

    def close(self) -> None:
        """Close SQLite database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "SQLiteAlertRepository":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        """Convert a sqlite3.Row into an Alert domain object."""
        scoring_reasons = []
        if row["scoring_reasons_json"]:
            try:
                scoring_reasons = json.loads(row["scoring_reasons_json"])
            except json.JSONDecodeError:
                pass

        related_event_ids = []
        if row["related_event_ids_json"]:
            try:
                related_event_ids = json.loads(row["related_event_ids_json"])
            except json.JSONDecodeError:
                pass

        evidence = []
        if row["evidence_json"]:
            try:
                evidence = json.loads(row["evidence_json"])
            except json.JSONDecodeError:
                pass

        extra = {}
        if row["extra_json"]:
            try:
                extra = json.loads(row["extra_json"])
            except json.JSONDecodeError:
                pass

        raw_sev = row["severity"]
        severity = Severity.from_string(raw_sev) if isinstance(raw_sev, str) else Severity(raw_sev)
        status = AlertStatus.from_string(row["status"])

        return Alert(
            alert_id=row["alert_id"],
            title=row["title"],
            severity=severity,
            risk_score=row["risk_score"],
            status=status,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            occurrence_count=row["occurrence_count"],
            endpoint_id=row["endpoint_id"],
            finding_id=row["finding_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            pid=row["pid"],
            process_name=row["process_name"],
            executable_path=row["executable_path"],
            username=row["username"],
            deception_id=row["deception_id"],
            description=row["description"] or "",
            scoring_reasons=scoring_reasons,
            related_event_ids=related_event_ids,
            evidence=evidence,
            extra=extra,
        )
