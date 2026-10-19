"""SQLite event repository implementation for local-first persistent storage.

Provides durable, zero-configuration local database storage for normalized
security events using Python's built-in sqlite3, including query filtering,
bounded pagination, and deterministic deduplication.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading

from trojan_defense.core.exceptions import PersistenceError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.persistence.base import BaseEventRepository, EventQueryFilter

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON security_events(ingested_at);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_endpoint ON security_events(endpoint_id);
"""


class SQLiteEventRepository(BaseEventRepository):
    """Local SQLite repository for persistent storage of security events."""

    def __init__(self, db_path: str | Path = "trojan_defense.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()

        # If file path, ensure parent directory exists
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # Autocommit mode; transactions managed explicitly
            )
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to initialize SQLite database at '{self.db_path}': {exc}") from exc

    def _init_schema(self) -> None:
        """Create tables, migrate columns if needed, and create indexes."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ingested_at TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        """
        create_indexes_sql = """
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ingested ON security_events(ingested_at);
        CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_endpoint ON security_events(endpoint_id);
        """
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(create_table_sql)

                # Check for ingested_at column in case table was created with older schema
                cursor.execute("PRAGMA table_info(security_events)")
                columns = [col["name"] for col in cursor.fetchall()]
                if "ingested_at" not in columns:
                    cursor.execute("ALTER TABLE security_events ADD COLUMN ingested_at TEXT NOT NULL DEFAULT ''")

                # Create indexes
                self._conn.executescript(create_indexes_sql)
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to execute schema initialization: {exc}") from exc

    def save(self, event: SecurityEvent) -> bool:
        """Save a single event into SQLite.

        Returns:
            bool: True if newly inserted, False if already exists (duplicate).
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        query = """
        INSERT INTO security_events (
            event_id, schema_version, timestamp, ingested_at, event_type, severity, source, endpoint_id, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (
                        event.event_id,
                        event.schema_version,
                        event.timestamp,
                        now_utc,
                        event.event_type.value,
                        event.severity.to_name(),
                        event.source,
                        event.endpoint.endpoint_id,
                        event.to_json(),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                # Primary key constraint violation -> Duplicate event
                return False
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to persist event '{event.event_id}': {exc}") from exc

    def save_batch(self, events: Sequence[SecurityEvent]) -> int:
        """Save multiple events in a single SQLite transaction.

        Ignores duplicates and returns count of newly saved events.
        """
        if not events:
            return 0

        now_utc = datetime.now(timezone.utc).isoformat()
        query = """
        INSERT OR IGNORE INTO security_events (
            event_id, schema_version, timestamp, ingested_at, event_type, severity, source, endpoint_id, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                event.event_id,
                event.schema_version,
                event.timestamp,
                now_utc,
                event.event_type.value,
                event.severity.to_name(),
                event.source,
                event.endpoint.endpoint_id,
                event.to_json(),
            )
            for event in events
        ]

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute("BEGIN TRANSACTION")
                before_changes = self._conn.total_changes
                cursor.executemany(query, rows)
                self._conn.execute("COMMIT")
                return self._conn.total_changes - before_changes
            except sqlite3.Error as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise PersistenceError(f"Failed to execute batch insert: {exc}") from exc

    def get_by_id(self, event_id: str) -> SecurityEvent | None:
        """Retrieve a stored event by event_id."""
        query = "SELECT payload_json FROM security_events WHERE event_id = ?"
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(query, (event_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityEvent.from_json(row["payload_json"])
            except (sqlite3.Error, json.JSONDecodeError, KeyError, ValueError) as exc:
                raise PersistenceError(f"Failed to retrieve event '{event_id}': {exc}") from exc

    def exists(self, event_id: str) -> bool:
        """Check if an event ID already exists in storage."""
        query = "SELECT 1 FROM security_events WHERE event_id = ? LIMIT 1"
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(query, (event_id,))
                return cursor.fetchone() is not None
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to check event existence '{event_id}': {exc}") from exc

    def query(self, filter_params: EventQueryFilter | None = None) -> tuple[list[SecurityEvent], int]:
        """Query security events with filters, pagination, and deterministic ordering."""
        params = filter_params or EventQueryFilter()
        conditions: list[str] = []
        sql_params: list[str | int] = []

        if params.endpoint_id:
            conditions.append("endpoint_id = ?")
            sql_params.append(params.endpoint_id)

        if params.event_type:
            # Match exact event_type or category prefix
            conditions.append("(event_type = ? OR event_type LIKE ?)")
            type_val = params.event_type.strip().upper()
            sql_params.append(type_val)
            sql_params.append(f"{type_val}.%")

        if params.severity:
            conditions.append("severity = ?")
            sql_params.append(params.severity.strip().upper())

        if params.start_time:
            conditions.append("timestamp >= ?")
            sql_params.append(params.start_time)

        if params.end_time:
            conditions.append("timestamp <= ?")
            sql_params.append(params.end_time)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_sql = f"SELECT COUNT(*) AS total FROM security_events {where_clause}"
        select_sql = f"""
        SELECT payload_json FROM security_events
        {where_clause}
        ORDER BY timestamp DESC, event_id ASC
        LIMIT ? OFFSET ?
        """

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(count_sql, sql_params)
                count_row = cursor.fetchone()
                total = int(count_row["total"]) if count_row else 0

                fetch_params = list(sql_params)
                fetch_params.append(max(1, params.limit))
                fetch_params.append(max(0, params.offset))

                cursor.execute(select_sql, fetch_params)
                rows = cursor.fetchall()
                events = [SecurityEvent.from_json(row["payload_json"]) for row in rows]
                return events, total
            except (sqlite3.Error, json.JSONDecodeError, KeyError, ValueError) as exc:
                raise PersistenceError(f"Failed to execute query: {exc}") from exc

    def count(self) -> int:
        """Count total security events stored in the database."""
        query = "SELECT COUNT(*) AS total FROM security_events"
        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
                return int(row["total"]) if row else 0
            except sqlite3.Error as exc:
                raise PersistenceError(f"Failed to count security events: {exc}") from exc

    def close(self) -> None:
        """Close database connection safely."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
