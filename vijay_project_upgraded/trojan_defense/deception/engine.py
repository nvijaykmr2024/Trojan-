"""Cyber Deception Engine for deploying and managing synthetic decoy artifacts."""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import threading
from typing import Any

from trojan_defense.core.config.schema import DeceptionConfig
from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import current_utc_timestamp
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.persistence.base import BaseEventRepository
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.deception.defaults import get_default_decoy_definitions
from trojan_defense.deception.models import DecoyDefinition, DecoyRecord, DecoyStatus, DecoyType
from trojan_defense.deception.path_safety import (
    PathSecurityError,
    validate_deception_root,
    validate_decoy_path,
)
from trojan_defense.deception.registry import DecoyRegistry

logger = get_logger("deception.engine")


class DeceptionError(TrojanDefenseError):
    """Raised on deception engine initialization or deployment failure."""
    pass


class CyberDeceptionEngine:
    """Manages synthetic deception environments, idempotent decoy creation, and safe cleanup."""

    def __init__(
        self,
        config: DeceptionConfig | None = None,
        repository: BaseEventRepository | None = None,
        pipeline: EventPipeline | None = None,
        endpoint: EndpointIdentity | None = None,
    ) -> None:
        self.config = config or DeceptionConfig()
        self.repository = repository
        self.pipeline = pipeline
        self.endpoint = endpoint

        self._lock = threading.RLock()
        self._initialized = False

        # Validate and configure root
        db_path = getattr(repository, "db_path", None)
        try:
            self.root_path = validate_deception_root(self.config.deception_root)
        except PathSecurityError as exc:
            logger.error(f"Invalid deception root '{self.config.deception_root}': {exc}")
            raise DeceptionError(f"Deception root validation failed: {exc}") from exc

        self.registry = DecoyRegistry(
            deception_root=self.root_path,
            db_path=db_path,
        )

    def initialize(self) -> None:
        """Initialize deception engine state and load decoy registry."""
        with self._lock:
            if self._initialized:
                return

            if not self.config.enabled:
                logger.info("Cyber Deception Engine is disabled by configuration")
                self._initialized = True
                return

            logger.info(f"Initializing Cyber Deception Engine at root: {self.root_path}")
            try:
                self.root_path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise DeceptionError(f"Failed to create deception root directory '{self.root_path}': {exc}") from exc

            self.registry.load()
            self._initialized = True
            logger.info("Cyber Deception Engine initialized successfully")

    def deploy(self, custom_definitions: list[DecoyDefinition] | None = None) -> list[DecoyRecord]:
        """Deploy or reconcile synthetic decoys into the deception environment idempotently.

        If decoys already exist with matching content, they are preserved without re-writing.
        New decoys are created, verified, and recorded in the registry.

        Returns:
            list[DecoyRecord]: The list of active, registered decoys.
        """
        with self._lock:
            if not self.config.enabled:
                logger.warning("Attempted to deploy decoys while Deception Engine is disabled")
                return []

            if not self._initialized:
                self.initialize()

            # Prepare definitions
            definitions = custom_definitions or self._load_configured_definitions()
            logger.info(f"Deploying {len(definitions)} synthetic decoy blueprints to '{self.root_path}'")

            deployed: list[DecoyRecord] = []

            for defn in definitions:
                try:
                    record = self._deploy_single_decoy(defn)
                    if record:
                        deployed.append(record)
                except Exception as exc:
                    logger.error(f"Failed deploying decoy '{defn.decoy_id}': {exc}", exc_info=True)

            self.registry.save()
            logger.info(f"Decoy deployment complete. Active decoys: {len(deployed)}")
            return deployed

    def _load_configured_definitions(self) -> list[DecoyDefinition]:
        """Convert configured decoy dictionaries into DecoyDefinition objects, or use defaults."""
        if self.config.decoys:
            defs: list[DecoyDefinition] = []
            for item in self.config.decoys:
                defs.append(DecoyDefinition(
                    decoy_id=item["decoy_id"],
                    artifact_type=item.get("artifact_type", "file"),
                    relative_path=item["relative_path"],
                    content=item.get("content"),
                    purpose=item.get("purpose", "configured_canary"),
                    metadata=item.get("metadata", {}),
                ))
            return defs
        return get_default_decoy_definitions()

    def _deploy_single_decoy(self, defn: DecoyDefinition) -> DecoyRecord | None:
        """Instantiate or verify a single decoy on the filesystem and update registry."""
        # 1. Path Safety & Containment Verification
        target_path = validate_decoy_path(defn.relative_path, self.root_path)

        now_utc = current_utc_timestamp()
        norm_path = str(target_path)
        content_hash: str | None = None

        if defn.artifact_type == DecoyType.DIRECTORY:
            target_path.mkdir(parents=True, exist_ok=True)
        else:
            # File Decoy
            target_path.parent.mkdir(parents=True, exist_ok=True)
            content_bytes = (defn.content or "").encode("utf-8")
            content_hash = hashlib.sha256(content_bytes).hexdigest()

            # Check if file exists and matches content (Idempotency)
            should_write = True
            if target_path.exists() and target_path.is_file():
                try:
                    existing_hash = hashlib.sha256(target_path.read_bytes()).hexdigest()
                    if existing_hash == content_hash:
                        should_write = False
                except OSError:
                    should_write = True

            if should_write:
                # Write file safely
                tmp_path = target_path.with_suffix(f"{target_path.suffix}.tmp")
                tmp_path.write_bytes(content_bytes)
                tmp_path.replace(target_path)
                logger.debug(f"Created synthetic decoy file '{norm_path}'")

        # 2. Register Record
        existing_record = self.registry.get_by_id(defn.decoy_id)
        created_time = existing_record.created_at if existing_record else now_utc

        record = DecoyRecord(
            decoy_id=defn.decoy_id,
            artifact_type=defn.artifact_type.value if isinstance(defn.artifact_type, DecoyType) else str(defn.artifact_type),
            relative_path=defn.relative_path,
            normalized_path=norm_path,
            purpose=defn.purpose,
            created_at=created_time,
            status=DecoyStatus.ACTIVE.value,
            content_hash=content_hash,
            metadata=defn.metadata,
        )

        self.registry.register(record)
        return record

    def cleanup(self) -> list[str]:
        """Safely remove all registered, project-owned decoys.

        Safety Guarantees:
        1. ONLY artifacts registered as project-owned in DecoyRegistry are eligible.
        2. Every path is re-verified to reside strictly within deception_root.
        3. Files are removed first; directories are removed only if empty of unowned files.
        4. Unrelated/unowned user files are left completely untouched.

        Returns:
            list[str]: IDs of decoys successfully cleaned.
        """
        with self._lock:
            if not self._initialized:
                self.initialize()

            records = self.registry.list_decoys(active_only=False)
            logger.info(f"Initiating safe cleanup of {len(records)} registered decoys in '{self.root_path}'")

            cleaned_ids: list[str] = []

            # Partition into files and directories (files removed first, then deepest directories)
            files = [r for r in records if r.artifact_type == "file"]
            dirs = [r for r in records if r.artifact_type == "directory"]
            # Sort directories by path length descending (deepest first)
            dirs.sort(key=lambda d: len(d.normalized_path), reverse=True)

            # 1. Clean File Decoys
            for rec in files:
                if self._safe_delete_file(rec):
                    self.registry.unregister(rec.decoy_id)
                    cleaned_ids.append(rec.decoy_id)

            # 2. Clean Directory Decoys (only if empty or only contains owned cleaned decoys)
            for rec in dirs:
                if self._safe_delete_dir(rec):
                    self.registry.unregister(rec.decoy_id)
                    cleaned_ids.append(rec.decoy_id)

            self.registry.save()
            logger.info(f"Decoy cleanup completed. Successfully removed {len(cleaned_ids)} decoys")
            return cleaned_ids

    def _safe_delete_file(self, record: DecoyRecord) -> bool:
        """Safely delete a registered file decoy with containment validation."""
        try:
            target = Path(record.normalized_path).resolve()
            # Double containment check
            target.relative_to(self.root_path)

            if not target.exists():
                return True

            if not target.is_file():
                logger.warning(f"Decoy file target '{target}' is not a regular file, skipping deletion")
                return False

            target.unlink()
            logger.debug(f"Deleted registered decoy file '{target}'")
            return True
        except ValueError:
            logger.error(f"Refusing to delete decoy '{record.decoy_id}': path '{record.normalized_path}' escapes root")
            return False
        except OSError as exc:
            logger.warning(f"Could not delete decoy file '{record.normalized_path}': {exc}")
            return False

    def _safe_delete_dir(self, record: DecoyRecord) -> bool:
        """Safely delete a registered directory decoy if it contains no unowned files."""
        try:
            target = Path(record.normalized_path).resolve()
            # Double containment check
            target.relative_to(self.root_path)

            if target == self.root_path:
                # Do not delete the deception root directory itself
                return True

            if not target.exists():
                return True

            if not target.is_dir():
                return False

            # Check if directory has remaining files
            remaining = list(target.iterdir())
            if not remaining:
                target.rmdir()
                logger.debug(f"Removed empty decoy directory '{target}'")
                return True
            else:
                logger.debug(f"Decoy directory '{target}' has unowned or remaining files, leaving intact")
                return False
        except ValueError:
            logger.error(f"Refusing to delete decoy dir '{record.decoy_id}': escapes root")
            return False
        except OSError as exc:
            logger.warning(f"Could not delete decoy directory '{record.normalized_path}': {exc}")
            return False

    def is_decoy(self, path: str | Path) -> bool:
        """Query if a given path is an active project-owned decoy."""
        return self.registry.is_owned(path)

    def get_decoy(self, path: str | Path) -> DecoyRecord | None:
        """Retrieve the decoy record for a path, if it is a registered decoy."""
        return self.registry.get_by_path(path)

    def status(self) -> dict[str, Any]:
        """Return operational status summary of the Deception Engine."""
        with self._lock:
            if self._initialized:
                self.registry.reconcile()
            all_decoys = self.registry.list_decoys(active_only=False)
            active_count = sum(1 for d in all_decoys if d.status == DecoyStatus.ACTIVE.value)
            missing_count = sum(1 for d in all_decoys if d.status == DecoyStatus.MISSING.value)
            corrupted_count = sum(1 for d in all_decoys if d.status == DecoyStatus.CORRUPTED.value)
            return {
                "enabled": self.config.enabled,
                "initialized": self._initialized,
                "deception_root": str(self.root_path),
                "total_registered": len(all_decoys),
                "active_decoys": active_count,
                "missing_decoys": missing_count,
                "corrupted_decoys": corrupted_count,
                "decoys": [d.to_dict() for d in all_decoys],
            }
