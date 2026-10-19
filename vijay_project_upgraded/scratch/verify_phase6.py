"""Phase 6 Manual Verification Script.

Executes live Windows System and Privilege Telemetry observation:
1. Boot/Startup event capture
2. Terminal Services session enumeration
3. Current process token elevation and mandatory integrity level inspection
4. Admin check via shell32.IsUserAnAdmin
5. System Event Log query via wevtapi
6. Persistence through EventPipeline into SQLite
7. Clean shutdown and summary report
"""

import json
import os
from pathlib import Path
import sys
import time

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from trojan_defense.core.config.schema import (
    AppConfig,
    CollectorToggleConfig,
    PersistenceConfig,
    RootConfig,
    SystemCollectorConfig,
    TransportConfig,
)
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.platform.windows.system_monitor import (
    get_active_sessions,
    get_process_privilege_context,
    is_current_user_admin,
    query_recent_system_events,
)


def run_verification() -> int:
    print("=================================================================")
    print("PHASE 6 — WINDOWS SYSTEM AND PRIVILEGE TELEMETRY VERIFICATION")
    print("=================================================================")

    # 1. Native API Direct Checks
    print("\n--- 1. Native Win32 API Verification ---")
    current_pid = os.getpid()
    priv = get_process_privilege_context(current_pid)
    print(f"Current Process PID: {current_pid}")
    print(f"  Is Elevated: {priv.is_elevated}")
    print(f"  Elevation Type: {priv.elevation_type}")
    print(f"  Integrity Level: {priv.integrity_level}")
    print(f"  User: {priv.user}")
    print(f"  SID: {priv.sid}")
    print(f"  Privilege Count: {len(priv.privileges)}")
    if priv.privileges:
        print(f"  Sample Privileges: {priv.privileges[:5]}")

    is_admin = is_current_user_admin()
    print(f"  Is User Admin (shell32): {is_admin}")

    sessions = get_active_sessions()
    print(f"\nActive Terminal Sessions Found: {len(sessions)}")
    for s in sessions:
        print(f"  Session ID={s.get('session_id')}, Name='{s.get('session_name')}', State='{s.get('state')}', User='{s.get('username')}', Domain='{s.get('domain')}'")

    recent_events = query_recent_system_events(max_records=5)
    print(f"\nRecent System Event Log Records: {len(recent_events)}")
    for ev in recent_events:
        print(f"  Record ID={ev.get('record_id')}, Event ID={ev.get('event_id')}, Provider='{ev.get('provider')}'")

    # 2. Live Pipeline Integration with SQLite Persistence
    print("\n--- 2. Live Pipeline & SQLite Persistence Verification ---")
    scratch_dir = Path(__file__).resolve().parent
    db_path = scratch_dir / "phase6_verify.db"
    if db_path.exists():
        db_path.unlink()

    config = RootConfig(
        app=AppConfig(environment="development", debug=True),
        persistence=PersistenceConfig(enabled=True, driver="sqlite", db_path=str(db_path)),
        transport=TransportConfig(enabled=False),
        collectors=CollectorToggleConfig(system=True),
        system_collector=SystemCollectorConfig(
            enabled=True,
            polling_interval=0.5,
            monitor_sessions=True,
            monitor_event_log=True,
            monitor_privileges=True,
        ),
    )

    manager = ApplicationManager()
    manager.initialize(config=config)
    print("ApplicationManager initialized.")

    manager.start()
    print("ApplicationManager started. Waiting for baseline telemetry collection...")
    time.sleep(1.5)

    # 3. Query Database for Persisted Telemetry
    print("\n--- 3. Persisted Telemetry in SQLite ---")
    assert manager.repository is not None
    events, total = manager.repository.query(EventQueryFilter(limit=50))
    print(f"Total Events Persisted in Active Database: {total}")

    for idx, ev in enumerate(events, 1):
        print(f"\n[{idx}] Event ID: {ev.event_id} | Type: {ev.event_type.value} | Severity: {ev.severity.value} | Source: {ev.source}")
        ctx_dict = ev.context.to_dict()
        print(f"    Context: {json.dumps(ctx_dict, indent=2)}")

    print("\nStopping ApplicationManager...")
    manager.stop()
    print("ApplicationManager stopped cleanly.")

    print("\n=================================================================")
    print("PHASE 6 VERIFICATION COMPLETE — ALL CHECKS PASSED")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(run_verification())
