"""Unit tests for Phase 7 Cyber Deception Engine, Path Safety, and Registry."""

import json
import os
from pathlib import Path
import sqlite3
import pytest

from trojan_defense.core.config.loader import load_config
from trojan_defense.core.config.schema import DeceptionConfig
from trojan_defense.deception.defaults import get_default_decoy_definitions
from trojan_defense.deception.engine import CyberDeceptionEngine, DeceptionError
from trojan_defense.deception.models import (
    DecoyDefinition,
    DecoyRecord,
    DecoyStatus,
    DecoyType,
)
from trojan_defense.deception.path_safety import (
    PathSecurityError,
    is_safe_relative_path,
    validate_deception_root,
    validate_decoy_path,
)
from trojan_defense.deception.registry import DecoyRegistry, RegistryError


# =====================================================================
# 1. Configuration Tests
# =====================================================================


class TestDeceptionConfig:
    def test_default_config(self):
        cfg = DeceptionConfig()
        assert cfg.enabled is False
        assert cfg.deception_root == "runtime/deception"
        assert cfg.auto_create_on_startup is True
        assert cfg.cleanup_on_shutdown is False
        assert cfg.decoys == []

    def test_custom_config_override(self):
        cfg = DeceptionConfig(
            enabled=True,
            deception_root="custom/deception_path",
            auto_create_on_startup=False,
            cleanup_on_shutdown=True,
            decoys=[{"decoy_id": "test_1", "relative_path": "a.txt"}],
        )
        assert cfg.enabled is True
        assert cfg.deception_root == "custom/deception_path"
        assert cfg.auto_create_on_startup is False
        assert cfg.cleanup_on_shutdown is True
        assert len(cfg.decoys) == 1

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("TROJAN_DEFENSE_DECEPTION_ENABLED", "true")
        monkeypatch.setenv("TROJAN_DEFENSE_DECEPTION_ROOT", "runtime/env_deception")
        monkeypatch.setenv("TROJAN_DEFENSE_DECEPTION_AUTO_CREATE_ON_STARTUP", "false")
        monkeypatch.setenv("TROJAN_DEFENSE_DECEPTION_CLEANUP_ON_SHUTDOWN", "true")

        root_cfg = load_config()
        assert root_cfg.deception.enabled is True
        assert root_cfg.deception.deception_root == "runtime/env_deception"
        assert root_cfg.deception.auto_create_on_startup is False
        assert root_cfg.deception.cleanup_on_shutdown is True


# =====================================================================
# 2. Path Safety & Containment Tests
# =====================================================================


class TestDeceptionPathSafety:
    def test_valid_deception_root(self, tmp_path):
        target = tmp_path / "custom_deception"
        resolved = validate_deception_root(target)
        assert resolved == target.resolve()

    def test_empty_or_whitespace_root_raises(self):
        with pytest.raises(PathSecurityError, match="cannot be empty"):
            validate_deception_root("")
        with pytest.raises(PathSecurityError, match="cannot be empty"):
            validate_deception_root("   ")

    def test_forbidden_drive_roots_raise(self):
        with pytest.raises(PathSecurityError, match="drive root"):
            validate_deception_root("C:\\")
        with pytest.raises(PathSecurityError, match="drive root"):
            validate_deception_root("D:\\")

    def test_forbidden_system_roots_raise(self):
        win_dir = os.environ.get("SystemRoot", "C:\\Windows")
        with pytest.raises(PathSecurityError, match="protected system path"):
            validate_deception_root(win_dir)

        system32 = Path(win_dir) / "System32"
        with pytest.raises(PathSecurityError, match="protected system path"):
            validate_deception_root(system32)

        prog_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        with pytest.raises(PathSecurityError, match="protected system path"):
            validate_deception_root(prog_files)

    def test_forbidden_broad_user_roots_raise(self):
        with pytest.raises(PathSecurityError, match="broad user or system root"):
            validate_deception_root("C:\\Users")

        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            with pytest.raises(PathSecurityError, match="broad user or system root"):
                validate_deception_root(user_profile)
            with pytest.raises(PathSecurityError, match="broad user or system root"):
                validate_deception_root(Path(user_profile) / "Desktop")

    def test_forbidden_sensitive_user_subtrees_raise(self):
        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            with pytest.raises(PathSecurityError, match="sensitive user credential directory"):
                validate_deception_root(Path(user_profile) / ".ssh")
            with pytest.raises(PathSecurityError, match="sensitive user credential directory"):
                validate_deception_root(Path(user_profile) / ".ssh" / "canary")

    def test_is_safe_relative_path(self):
        assert is_safe_relative_path("notes.txt") is True
        assert is_safe_relative_path("docs/notes.txt") is True
        assert is_safe_relative_path("a\\b\\c.txt") is True

        # Unsafe
        assert is_safe_relative_path("") is False
        assert is_safe_relative_path("  ") is False
        assert is_safe_relative_path("/root/file.txt") is False
        assert is_safe_relative_path("\\root\\file.txt") is False
        assert is_safe_relative_path("C:\\file.txt") is False
        assert is_safe_relative_path("../escape.txt") is False
        assert is_safe_relative_path("docs/../../escape.txt") is False
        assert is_safe_relative_path("docs/../notes.txt") is False

    def test_validate_decoy_path(self, tmp_path):
        root = tmp_path / "deception_root"
        root.mkdir()

        # Valid relative paths
        p1 = validate_decoy_path("documents/report.doc", root)
        assert p1 == (root / "documents" / "report.doc").resolve()

        # Root itself rejected
        with pytest.raises(PathSecurityError, match="cannot be the deception root itself"):
            validate_decoy_path(".", root)

        # Empty rejected
        with pytest.raises(PathSecurityError, match="empty"):
            validate_decoy_path("", root)

        # Traversal rejected
        with pytest.raises(PathSecurityError, match="traversal components or is absolute"):
            validate_decoy_path("../outside.txt", root)

        with pytest.raises(PathSecurityError, match="traversal components or is absolute"):
            validate_decoy_path("C:\\outside.txt", root)


# =====================================================================
# 3. Decoy Registry Tests
# =====================================================================


class TestDecoyRegistry:
    def test_register_and_lookup_by_id_and_path(self, tmp_path):
        root = tmp_path / "deception"
        root.mkdir()
        registry = DecoyRegistry(deception_root=root)

        rec = DecoyRecord(
            decoy_id="decoy_1",
            artifact_type="file",
            relative_path="docs/notes.txt",
            normalized_path=str((root / "docs" / "notes.txt").resolve()),
            purpose="test",
            created_at="2026-10-02T12:00:00Z",
            status="active",
        )
        registry.register(rec)

        # Lookup by ID
        assert registry.get_by_id("decoy_1") is rec
        assert registry.get_by_id("non_existent") is None

        # Lookup by Path (exact and mixed case / slash)
        by_path = registry.get_by_path(rec.normalized_path)
        assert by_path is rec
        assert registry.is_owned(rec.normalized_path) is True

        mixed_case_path = rec.normalized_path.lower()
        assert registry.get_by_path(mixed_case_path) is rec

        # Unowned path
        assert registry.is_owned(root / "unowned.txt") is False
        assert registry.get_by_path(root / "unowned.txt") is None

    def test_reject_registration_outside_root(self, tmp_path):
        root = tmp_path / "deception"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        registry = DecoyRegistry(deception_root=root)

        rec = DecoyRecord(
            decoy_id="bad_decoy",
            artifact_type="file",
            relative_path="../outside.txt",
            normalized_path=str(outside.resolve()),
            purpose="escape",
            created_at="2026-10-02T12:00:00Z",
            status="active",
        )
        with pytest.raises(RegistryError, match="escapes deception root"):
            registry.register(rec)

    def test_manifest_save_and_load(self, tmp_path):
        root = tmp_path / "deception"
        root.mkdir()
        manifest_file = root / ".decoy_manifest.json"

        registry1 = DecoyRegistry(deception_root=root, manifest_path=manifest_file)
        rec = DecoyRecord(
            decoy_id="canary_1",
            artifact_type="file",
            relative_path="canary.txt",
            normalized_path=str((root / "canary.txt").resolve()),
            purpose="canary",
            created_at="2026-10-02T12:00:00Z",
            status="active",
            content_hash="abc123hash",
            metadata={"sensitivity": "high"},
        )
        registry1.register(rec)
        registry1.save()

        assert manifest_file.exists()

        # Reload in a new registry instance
        registry2 = DecoyRegistry(deception_root=root, manifest_path=manifest_file)
        registry2.load()

        loaded_rec = registry2.get_by_id("canary_1")
        assert loaded_rec is not None
        assert loaded_rec.relative_path == "canary.txt"
        assert loaded_rec.content_hash == "abc123hash"
        assert loaded_rec.metadata == {"sensitivity": "high"}

    def test_sqlite_persistence_synchronization(self, tmp_path):
        root = tmp_path / "deception"
        root.mkdir()
        db_file = tmp_path / "telemetry.db"

        registry1 = DecoyRegistry(deception_root=root, db_path=db_file)
        rec = DecoyRecord(
            decoy_id="db_decoy_1",
            artifact_type="file",
            relative_path="secrets.txt",
            normalized_path=str((root / "secrets.txt").resolve()),
            purpose="secret_canary",
            created_at="2026-10-02T12:00:00Z",
            status="active",
        )
        registry1.register(rec)
        registry1.save()

        # Verify SQLite table content
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT decoy_id, relative_path, status FROM decoy_registry WHERE decoy_id = ?", ("db_decoy_1",))
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == "db_decoy_1"
            assert row[1] == "secrets.txt"
            assert row[2] == "active"

        # Verify unregister updates SQLite
        registry1.unregister("db_decoy_1")
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM decoy_registry WHERE decoy_id = ?", ("db_decoy_1",))
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == "cleaned"

    def test_reconcile_detects_missing_and_corrupted(self, tmp_path):
        root = tmp_path / "deception"
        root.mkdir()
        file_path = root / "valid_file.txt"
        file_path.write_text("hello", encoding="utf-8")

        missing_path = root / "missing_file.txt"

        registry = DecoyRegistry(deception_root=root)
        r1 = DecoyRecord(
            decoy_id="rec_valid",
            artifact_type="file",
            relative_path="valid_file.txt",
            normalized_path=str(file_path.resolve()),
            purpose="test",
            created_at="2026-10-02T12:00:00Z",
            status="active",
        )
        r2 = DecoyRecord(
            decoy_id="rec_missing",
            artifact_type="file",
            relative_path="missing_file.txt",
            normalized_path=str(missing_path.resolve()),
            purpose="test",
            created_at="2026-10-02T12:00:00Z",
            status="active",
        )
        registry.register(r1)
        registry.register(r2)

        results = registry.reconcile()
        assert results["rec_valid"] == DecoyStatus.ACTIVE.value
        assert results["rec_missing"] == DecoyStatus.MISSING.value

        assert registry.get_by_id("rec_missing").status == DecoyStatus.MISSING.value


# =====================================================================
# 4. Cyber Deception Engine Lifecycle & Operation Tests
# =====================================================================


class TestCyberDeceptionEngine:
    def test_initialization(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)
        assert engine.root_path == root.resolve()

        engine.initialize()
        assert root.exists()
        assert root.is_dir()

    def test_disabled_engine_does_not_deploy(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=False, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)
        engine.initialize()

        deployed = engine.deploy()
        assert deployed == []
        assert not root.exists()

    def test_deploy_default_synthetic_decoys(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)

        deployed = engine.deploy()
        assert len(deployed) == 8

        # 4 directories and 4 files
        dirs = [d for d in deployed if d.artifact_type == "directory"]
        files = [d for d in deployed if d.artifact_type == "file"]
        assert len(dirs) == 4
        assert len(files) == 4

        # Check physical existence on disk
        for d in deployed:
            p = Path(d.normalized_path)
            assert p.exists()
            assert engine.is_decoy(p) is True

        # Check file content
        notes_path = root / "documents" / "project_notes.txt"
        assert notes_path.exists()
        assert "INTERNAL RESEARCH CANARY DOCUMENT" in notes_path.read_text(encoding="utf-8")

        cloud_tokens_path = root / "credentials" / "cloud_tokens.txt"
        assert cloud_tokens_path.exists()
        assert "SYNTHETIC_CANARY_AKIA_NOT_REAL_001" in cloud_tokens_path.read_text(encoding="utf-8")

    def test_deploy_is_idempotent(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)

        deployed_1 = engine.deploy()
        mtime_1 = (root / "documents" / "project_notes.txt").stat().st_mtime_ns

        # Deploy a second time
        deployed_2 = engine.deploy()
        mtime_2 = (root / "documents" / "project_notes.txt").stat().st_mtime_ns

        assert len(deployed_1) == len(deployed_2)
        # Content was untouched, so mtime is preserved
        assert mtime_1 == mtime_2

    def test_engine_status(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)
        engine.deploy()

        status = engine.status()
        assert status["enabled"] is True
        assert status["initialized"] is True
        assert status["total_registered"] == 8
        assert status["active_decoys"] == 8
        assert status["missing_decoys"] == 0

        # Simulate missing file
        (root / "backup" / "inventory_manifest.csv").unlink()
        status_after = engine.status()
        assert status_after["missing_decoys"] == 1
        assert status_after["active_decoys"] == 7

    def test_safe_cleanup_removes_registered_decoys(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)
        engine.deploy()

        cleaned_ids = engine.cleanup()
        assert len(cleaned_ids) == 8

        # All decoys removed
        for cid in cleaned_ids:
            assert engine.registry.get_by_id(cid) is None

        # Verify physical removal
        assert not (root / "documents" / "project_notes.txt").exists()
        assert not (root / "documents").exists()
        assert not (root / "credentials").exists()

        # Deception root itself still exists
        assert root.exists()

    def test_safe_cleanup_preserves_unowned_files_and_directories(self, tmp_path):
        root = tmp_path / "deception_root"
        cfg = DeceptionConfig(enabled=True, deception_root=str(root))
        engine = CyberDeceptionEngine(config=cfg)
        engine.deploy()

        # Place an unowned user file inside deception root
        unowned_file = root / "unowned_user_script.py"
        unowned_file.write_text("print('user file')", encoding="utf-8")

        # Place an unowned user file inside a decoy directory
        user_doc = root / "documents" / "real_user_memo.docx"
        user_doc.write_text("user data", encoding="utf-8")

        # Create an unowned custom folder
        unowned_dir = root / "my_private_folder"
        unowned_dir.mkdir()

        # Run cleanup
        cleaned_ids = engine.cleanup()

        # Registered decoys were removed
        assert not (root / "documents" / "project_notes.txt").exists()

        # Unowned files and directories are completely preserved!
        assert unowned_file.exists()
        assert unowned_file.read_text(encoding="utf-8") == "print('user file')"
        assert user_doc.exists()
        assert user_doc.read_text(encoding="utf-8") == "user data"
        assert unowned_dir.exists()

        # And the "documents" directory was preserved because it still holds the unowned file!
        assert (root / "documents").exists()
