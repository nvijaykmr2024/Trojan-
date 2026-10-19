"""Manual verification script for Phase 7 — Cyber Deception Engine.

Executes real-world validation of:
1. Deception root path safety & containment validation.
2. Idempotent decoy deployment (synthetic directories and canary files).
3. Authoritative Decoy Registry operations and case-insensitive path lookup.
4. JSON manifest & SQLite database persistence.
5. Reconciliation against disk state (missing/corrupted detection).
6. Safe cleanup ensuring unowned user files and directories are strictly preserved.
7. End-to-end integration with ApplicationManager and file monitoring coverage.
"""

import json
import os
from pathlib import Path
import sqlite3
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trojan_defense.core.config.schema import (
    AppConfig,
    DeceptionConfig,
    FileCollectorConfig,
    LoggingConfig,
    PersistenceConfig,
    PipelineConfig,
    RootConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.deception.engine import CyberDeceptionEngine
from trojan_defense.deception.models import DecoyStatus
from trojan_defense.deception.path_safety import (
    PathSecurityError,
    validate_deception_root,
    validate_decoy_path,
)


def print_step(title: str):
    print(f"\n{'='*70}\n[STEP] {title}\n{'='*70}")


def main():
    print("=" * 70)
    print("PHASE 7 MANUAL VERIFICATION SUITE — CYBER DECEPTION ENGINE")
    print("=" * 70)

    # Step 1: Path Containment & Security Checks
    print_step("1. Verifying Path Containment & Security Controls")
    for bad_path in ["C:\\", "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Users"]:
        try:
            validate_deception_root(bad_path)
            print(f"[-] FAILED: {bad_path} was NOT rejected!")
            sys.exit(1)
        except PathSecurityError as e:
            print(f"[+] Protected path '{bad_path}' correctly rejected: {e}")

    test_root = Path("runtime/test_deception_sandbox").resolve()
    valid_root = validate_deception_root(test_root)
    print(f"[+] Valid deception root resolved: {valid_root}")

    # Decoy path traversal checks
    for bad_rel in ["../outside.txt", "C:\\abs.txt", "/etc/passwd"]:
        try:
            validate_decoy_path(bad_rel, valid_root)
            print(f"[-] FAILED: Traversal path '{bad_rel}' was NOT rejected!")
            sys.exit(1)
        except PathSecurityError as e:
            print(f"[+] Traversal path '{bad_rel}' correctly rejected: {e}")

    # Step 2: Engine Initialization & Idempotent Deployment
    print_step("2. Verifying Decoy Deployment & Idempotency")
    db_file = test_root.parent / "test_deception_telemetry.db"
    cfg = DeceptionConfig(
        enabled=True,
        deception_root=str(test_root),
        auto_create_on_startup=True,
        cleanup_on_shutdown=False,
    )
    engine = CyberDeceptionEngine(config=cfg)
    # inject sqlite db path into registry
    engine.registry.db_path = str(db_file)
    engine.registry._init_sqlite_table()

    engine.initialize()
    print(f"[+] CyberDeceptionEngine initialized at '{engine.root_path}'")

    deployed_1 = engine.deploy()
    print(f"[+] First deployment created {len(deployed_1)} synthetic decoys")
    assert len(deployed_1) == 8, f"Expected 8 decoys, got {len(deployed_1)}"

    # Check files exist
    canary_file = test_root / "credentials" / "cloud_tokens.txt"
    assert canary_file.exists(), "Canary file missing!"
    content = canary_file.read_text(encoding="utf-8")
    assert "SYNTHETIC_CANARY_AKIA_NOT_REAL_001" in content
    print(f"[+] Verified synthetic canary content in '{canary_file.name}'")

    # Second deployment (idempotency check)
    mtime_before = canary_file.stat().st_mtime_ns
    deployed_2 = engine.deploy()
    mtime_after = canary_file.stat().st_mtime_ns
    assert mtime_before == mtime_after, "File was re-written during idempotent deploy!"
    print(f"[+] Idempotent deployment verified: existing decoy files preserved without re-writing")

    # Step 3: Decoy Registry Queries & Path Canonicalization
    print_step("3. Verifying Decoy Registry Lookups & Windows Path Normalization")
    assert engine.is_decoy(canary_file), "Registry failed to identify active decoy!"
    assert engine.is_decoy(str(canary_file).upper()), "Failed case-insensitive Windows path match!"
    assert engine.is_decoy(str(canary_file).replace("\\", "/")), "Failed forward-slash path match!"
    assert not engine.is_decoy(test_root / "unowned_file.txt"), "False positive on unowned path!"

    rec = engine.get_decoy(canary_file)
    assert rec is not None
    print(f"[+] Decoy record retrieved: id='{rec.decoy_id}', type='{rec.artifact_type}', hash={rec.content_hash[:16]}...")

    # Step 4: Manifest & SQLite Persistence
    print_step("4. Verifying Manifest & SQLite Persistence")
    manifest_path = test_root / ".decoy_manifest.json"
    assert manifest_path.exists(), "Manifest file not created!"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    print(f"[+] Manifest contains {len(manifest_data['decoys'])} serialized records")

    conn = sqlite3.connect(db_file)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM decoy_registry WHERE status = 'active'")
        active_in_db = cursor.fetchone()[0]
    finally:
        conn.close()
    assert active_in_db == 8, f"Expected 8 active in SQLite, got {active_in_db}"
    print(f"[+] SQLite table 'decoy_registry' contains {active_in_db} active records")

    # Step 5: Reconciliation against Disk State
    print_step("5. Verifying Reconciliation of Missing & Corrupted Decoys")
    test_missing = test_root / "backup" / "inventory_manifest.csv"
    test_missing.unlink()
    print(f"[+] Deleted decoy file externally: {test_missing.name}")

    status_recon = engine.status()
    assert status_recon["missing_decoys"] == 1
    assert status_recon["active_decoys"] == 7
    print(f"[+] Reconciliation detected missing decoy accurately: active={status_recon['active_decoys']}, missing={status_recon['missing_decoys']}")

    # Restore missing decoy with deploy
    engine.deploy()
    status_restored = engine.status()
    assert status_restored["missing_decoys"] == 0
    assert status_restored["active_decoys"] == 8
    print(f"[+] Redeploy repaired missing decoy: active={status_restored['active_decoys']}")

    # Step 6: Safe Cleanup & Unowned File Protection
    print_step("6. Verifying Safe Cleanup & Preservation of Unowned Files")
    # Introduce unowned user file directly in root
    unowned_root_file = test_root / "user_notes.txt"
    unowned_root_file.write_text("IMPORTANT REAL DATA", encoding="utf-8")

    # Introduce unowned user file inside a decoy folder
    unowned_folder_file = test_root / "documents" / "real_user_memo.pdf"
    unowned_folder_file.write_text("REAL USER MEMO", encoding="utf-8")

    # Introduce an unowned user directory
    unowned_user_dir = test_root / "user_custom_dir"
    unowned_user_dir.mkdir()

    cleaned = engine.cleanup()
    print(f"[+] Cleaned up {len(cleaned)} registered decoys")

    # Verify project-owned decoys are removed
    assert not (test_root / "credentials" / "cloud_tokens.txt").exists(), "Decoy file not removed!"
    assert not (test_root / "credentials").exists(), "Empty decoy directory not removed!"

    # Verify unowned files and directories are completely untouched!
    assert unowned_root_file.exists(), "UNOWNED FILE WAS DELETED! CRITICAL FAILURE!"
    assert unowned_folder_file.exists(), "UNOWNED FILE IN DECOY DIR WAS DELETED! CRITICAL FAILURE!"
    assert unowned_user_dir.exists(), "UNOWNED DIRECTORY WAS DELETED! CRITICAL FAILURE!"
    assert (test_root / "documents").exists(), "Decoy directory containing unowned file was deleted! Should be preserved!"
    print("[+] Verified: All unowned user files and directories were strictly preserved!")

    # Clean test sandbox
    unowned_folder_file.unlink()
    (test_root / "documents").rmdir()
    unowned_root_file.unlink()
    unowned_user_dir.rmdir()
    (test_root / ".decoy_manifest.json").unlink(missing_ok=True)
    test_root.rmdir()
    db_file.unlink(missing_ok=True)
    print("[+] Test sandbox cleanly removed")

    # Step 7: ApplicationManager Lifecycle Integration
    print_step("7. Verifying ApplicationManager Lifecycle Integration")
    lifecycle_root = Path("runtime/lifecycle_deception_test").resolve()
    app_cfg = RootConfig(
        app=AppConfig(environment="test", debug=True),
        logging=LoggingConfig(level="INFO", log_to_file=False),
        deception=DeceptionConfig(
            enabled=True,
            deception_root=str(lifecycle_root),
            auto_create_on_startup=True,
            cleanup_on_shutdown=True,
        ),
        persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=str(Path("runtime/lifecycle_test.db").resolve())),
        transport=TransportConfig(enabled=True, driver="mock"),
        pipeline=PipelineConfig(batch_size=10, validate_events=True),
        file_collector=FileCollectorConfig(
            enabled=True,
            monitored_paths=[str(Path("runtime/monitored").resolve())],
        ),
    )

    app = ApplicationManager()
    app.initialize(config=app_cfg)
    assert app.deception_engine is not None
    print(f"[+] ApplicationManager initialized with deception engine: root={app.deception_engine.root_path}")

    # Verify file_collector includes deception root
    file_col = app.registry.get("windows_file_monitor")
    if file_col:
        assert str(lifecycle_root) in file_col.config.monitored_paths
        print(f"[+] Phase 4 WindowsFileMonitor monitored paths covered: {file_col.config.monitored_paths}")

    app.start()
    assert (lifecycle_root / "documents" / "project_notes.txt").exists(), "Auto-deploy failed on app start!"
    print("[+] Auto-deploy verified on application startup")

    app.stop()
    assert not (lifecycle_root / "documents" / "project_notes.txt").exists(), "Cleanup on shutdown failed!"
    print("[+] Cleanup on application shutdown verified")

    (lifecycle_root / ".decoy_manifest.json").unlink(missing_ok=True)
    lifecycle_root.rmdir()
    Path("runtime/lifecycle_test.db").unlink(missing_ok=True)

    print("\n" + "=" * 70)
    print("PHASE 7 MANUAL VERIFICATION SUCCEEDED: ALL 7 TEST GATES PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()
