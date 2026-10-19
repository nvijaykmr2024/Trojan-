"""Decoy Registry for managing ownership and lifecycle of synthetic deception artifacts."""

import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any

from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.deception.models import DecoyRecord, DecoyStatus
from trojan_defense.deception.path_safety import is_safe_relative_path

logger = get_logger("deception.registry")


class RegistryError(TrojanDefenseError):
    """Raised on registry operational failure or corruption."""
    pass


class DecoyRegistry:
    """Thread-safe registry of project-owned deception artifacts.

    Maintains authoritative ownership records, supports normalized path matching,
    reconciliation against disk state, and durable persistence via JSON manifest
    and optional SQLite integration.
    """

    def __init__(
        self,
        deception_root: Path,
        manifest_path: Path | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self.deception_root = deception_root.resolve()
        self.manifest_path = (manifest_path or (self.deception_root / ".decoy_manifest.json")).resolve()
        self.db_path = str(Path(db_path).resolve()) if db_path else None

        self._lock = threading.RLock()
        self._records: dict[str, DecoyRecord] = {}  # keyed by decoy_id
        self._path_index: dict[str, str] = {}  # keyed by lowercase canonical path -> decoy_id

        # Initialize storage if configured
        if self.db_path and self.db_path != ":memory:":
            self._init_sqlite_table()

    def _init_sqlite_table(self) -> None:
        """Create decoy_registry table in the existing SQLite database if db_path is provided."""
        assert self.db_path is not None
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            with conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS decoy_registry (
                    decoy_id TEXT PRIMARY KEY,
                    artifact_type TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    normalized_path TEXT NOT NULL,
                    content_hash TEXT,
                    purpose TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                """)
                conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_decoy_normalized_path ON decoy_registry(normalized_path);
                """)
        except sqlite3.Error as exc:
            logger.warning(f"Could not initialize SQLite decoy_registry table: {exc}")
        finally:
            if conn:
                conn.close()

    def load(self) -> None:
        """Load registered decoys from durable storage (manifest and/or SQLite)."""
        with self._lock:
            self._records.clear()
            self._path_index.clear()

            # 1. Try loading from SQLite if available
            loaded_from_db = False
            if self.db_path:
                conn = None
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM decoy_registry WHERE status != ?", (DecoyStatus.CLEANED.value,))
                    rows = cursor.fetchall()
                    for row in rows:
                        meta = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
                        rec = DecoyRecord(
                            decoy_id=row["decoy_id"],
                            artifact_type=row["artifact_type"],
                            relative_path=row["relative_path"],
                            normalized_path=row["normalized_path"],
                            content_hash=row["content_hash"],
                            purpose=row["purpose"],
                            created_at=row["created_at"],
                            status=row["status"],
                            metadata=meta,
                        )
                        if self._is_record_safe(rec):
                            self._records[rec.decoy_id] = rec
                            self._path_index[rec.normalized_path.lower()] = rec.decoy_id
                    loaded_from_db = True
                except Exception as exc:
                    logger.warning(f"Failed loading decoys from SQLite: {exc}")
                finally:
                    if conn:
                        conn.close()

            # 2. Try loading from manifest file if not loaded from db or to augment
            if self.manifest_path.exists():
                try:
                    with open(self.manifest_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    items = data.get("decoys", [])
                    for item in items:
                        rec = DecoyRecord.from_dict(item)
                        if self._is_record_safe(rec):
                            self._records[rec.decoy_id] = rec
                            self._path_index[rec.normalized_path.lower()] = rec.decoy_id
                except Exception as exc:
                    logger.warning(f"Failed loading decoy manifest '{self.manifest_path}': {exc}")

            logger.info(f"Decoy registry loaded {len(self._records)} active decoy records")

    def save(self) -> None:
        """Persist registry state to manifest and SQLite atomically."""
        with self._lock:
            # 1. Save to JSON manifest
            try:
                self.deception_root.mkdir(parents=True, exist_ok=True)
                payload = {
                    "version": "1.0",
                    "deception_root": str(self.deception_root),
                    "decoys": [r.to_dict() for r in self._records.values()],
                }
                tmp_path = self.manifest_path.with_suffix(".tmp")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                # Atomic replace
                tmp_path.replace(self.manifest_path)
            except Exception as exc:
                logger.error(f"Failed saving decoy manifest: {exc}")

            # 2. Save to SQLite if configured
            if self.db_path:
                conn = None
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    with conn:
                        for rec in self._records.values():
                            conn.execute("""
                            INSERT INTO decoy_registry (
                                decoy_id, artifact_type, relative_path, normalized_path, content_hash,
                                purpose, created_at, status, metadata_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(decoy_id) DO UPDATE SET
                                status=excluded.status,
                                content_hash=excluded.content_hash,
                                metadata_json=excluded.metadata_json;
                            """, (
                                rec.decoy_id,
                                rec.artifact_type,
                                rec.relative_path,
                                rec.normalized_path,
                                rec.content_hash,
                                rec.purpose,
                                rec.created_at,
                                rec.status,
                                json.dumps(rec.metadata),
                            ))
                except Exception as exc:
                    logger.warning(f"Failed syncing decoy registry to SQLite: {exc}")
                finally:
                    if conn:
                        conn.close()

    def _is_record_safe(self, record: DecoyRecord) -> bool:
        """Verify that a record strictly belongs to deception_root and has no traversal syntax."""
        try:
            p = Path(record.normalized_path).resolve()
            p.relative_to(self.deception_root)
            return is_safe_relative_path(record.relative_path)
        except (ValueError, RuntimeError):
            logger.error(
                f"Rejecting unsafe registry record '{record.decoy_id}' pointing outside root: '{record.normalized_path}'"
            )
            return False

    def register(self, record: DecoyRecord) -> None:
        """Register a new or updated decoy artifact.

        Raises:
            RegistryError: If the record points outside the deception root.
        """
        if not self._is_record_safe(record):
            raise RegistryError(
                f"Cannot register decoy '{record.decoy_id}': path '{record.normalized_path}' escapes deception root"
            )

        with self._lock:
            self._records[record.decoy_id] = record
            self._path_index[record.normalized_path.lower()] = record.decoy_id

    def unregister(self, decoy_id: str) -> DecoyRecord | None:
        """Remove a decoy from active tracking and update durable storage."""
        with self._lock:
            rec = self._records.pop(decoy_id, None)
            if rec:
                self._path_index.pop(rec.normalized_path.lower(), None)
                rec.status = DecoyStatus.CLEANED.value
                if self.db_path:
                    conn = None
                    try:
                        conn = sqlite3.connect(self.db_path, timeout=5.0)
                        with conn:
                            conn.execute(
                                "UPDATE decoy_registry SET status = ? WHERE decoy_id = ?",
                                (DecoyStatus.CLEANED.value, decoy_id),
                            )
                    except Exception as exc:
                        logger.warning(f"Failed updating decoy status in SQLite: {exc}")
                    finally:
                        if conn:
                            conn.close()
            return rec

    def clear(self) -> None:
        """Clear all decoys from active tracking and mark as cleaned in storage."""
        with self._lock:
            if self.db_path:
                conn = None
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    with conn:
                        conn.execute(
                            "UPDATE decoy_registry SET status = ? WHERE status != ?",
                            (DecoyStatus.CLEANED.value, DecoyStatus.CLEANED.value),
                        )
                except Exception as exc:
                    logger.warning(f"Failed updating decoy statuses in SQLite: {exc}")
                finally:
                    if conn:
                        conn.close()
            self._records.clear()
            self._path_index.clear()
            self.save()

    def get_by_id(self, decoy_id: str) -> DecoyRecord | None:
        """Retrieve a registered decoy by ID."""
        with self._lock:
            return self._records.get(decoy_id)

    def get_by_path(self, path: str | Path) -> DecoyRecord | None:
        """Retrieve a registered decoy matching the given path (canonicalized)."""
        try:
            norm_key = str(Path(path).resolve()).lower()
        except Exception:
            norm_key = str(path).lower()

        with self._lock:
            decoy_id = self._path_index.get(norm_key)
            if decoy_id:
                return self._records.get(decoy_id)
            return None

    def is_owned(self, path: str | Path) -> bool:
        """Check if a path corresponds to an active, project-owned decoy."""
        return self.get_by_path(path) is not None

    def list_decoys(self, active_only: bool = True) -> list[DecoyRecord]:
        """Return a copy of all registered decoys."""
        with self._lock:
            if active_only:
                return [r for r in self._records.values() if r.status == DecoyStatus.ACTIVE.value]
            return list(self._records.values())

    def reconcile(self) -> dict[str, str]:
        """Reconcile registry state against physical files on disk.

        Returns:
            dict[str, str]: Map of decoy_id to updated status.
        """
        results: dict[str, str] = {}
        with self._lock:
            for decoy_id, record in list(self._records.items()):
                p = Path(record.normalized_path)
                if not p.exists():
                    record.status = DecoyStatus.MISSING.value
                    results[decoy_id] = DecoyStatus.MISSING.value
                else:
                    if record.artifact_type == "file" and not p.is_file():
                        record.status = DecoyStatus.CORRUPTED.value
                        results[decoy_id] = DecoyStatus.CORRUPTED.value
                    elif record.artifact_type == "directory" and not p.is_dir():
                        record.status = DecoyStatus.CORRUPTED.value
                        results[decoy_id] = DecoyStatus.CORRUPTED.value
                    else:
                        record.status = DecoyStatus.ACTIVE.value
                        results[decoy_id] = DecoyStatus.ACTIVE.value

        self.save()
        return results
