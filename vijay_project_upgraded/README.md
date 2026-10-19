# Cross-Platform Trojan Defense Using a Cyber Deception and Behavioral Monitoring Framework

## Academic Cybersecurity Project — Complete Framework (Phases 1 through 11: Controlled Defensive Response & Incident Management)

This repository implements a local, defensive, academic cybersecurity monitoring and response system designed to defend against Trojan activities using cyber deception, behavioral correlation, risk scoring, and controlled human-in-the-loop response.

> **Current Implementation State**: Complete end-to-end framework encompassing Phase 1 (Foundation), Phase 2 (Backend Event Ingestion & Persistence), Phase 3 (Windows Process Monitoring), Phase 4 (Windows File Monitoring), Phase 5 (Windows Network Telemetry), Phase 6 (Windows System and Privilege Telemetry), Phase 7 (Cyber Deception Engine), Phase 8 (Deception Interaction Detection), Phase 9 (Behavioral Correlation & Detection), Phase 10 (Risk Scoring & Alert Generation), and **Final Phase (Controlled Defensive Response and Incident Management)**.  
> **Strict Safety Guarantee**: Autonomous destructive remediation is strictly prohibited. All defensive response actions mandate explicit human analyst authorization via Role-Based Access Control (RBAC). Defensive operations are non-destructive and fully reversible where applicable.

---

## 1. System Architecture

The framework cleanly decouples telemetry collectors, event processing pipeline, egress transport, and backend event ingestion/persistence:

```text
  ProcessMonitor (Ph3)   FileMonitor (Ph4)   NetworkMonitor (Ph5)   SystemMonitor (Ph6)
          │                     │                    │                      │
          │                     ├────────────────────┼──────────────────────┘
          │                     │ (File Events)      │
          │                     ▼                    │
          │             ┌─────────────────────────┐  │
          │             │DeceptionDetector (Ph8)  │  │
          │             │  (DecoyRegistry Lookup) │  │
          │             └───────────┬─────────────┘  │
          │                         │ DECEPTION.     │
          │                         │ INTERACTION    │
          └─────────────────────────┼────────────────┘
                                    │ produces
                                    ▼
                         ┌─────────────────────┐
                         │    SecurityEvent    │
                         │  (canonical model)  │
                         └──────────┬──────────┘
                                    │ processed by
                                    ▼
                         ┌─────────────────────┐
                         │   Event Pipeline    │
                         │ (Normalizer/Valid.) │
                         └─────┬─────────┬─────┘
                               │         │
                   ┌───────────┘         └─────────────────────────┐
                   ▼                                               ▼
        ┌─────────────────────┐                       ┌─────────────────────────┐
        │  HttpEventTransport │                       │BehaviorCorrelationEngine│
        └──────────┬──────────┘                       └────────────┬────────────┘
                   │                                               │
                   ▼                                               ▼
        ┌─────────────────────┐                       ┌─────────────────────────┐
        │ Backend HTTP Server │                       │   RiskScoringEngine     │
        └──────────┬──────────┘                       └────────────┬────────────┘
                   │                                               │
                   ▼                                               ▼
        ┌─────────────────────┐                       ┌─────────────────────────┐
        │    EventService     │                       │       AlertEngine       │
        └──────────┬──────────┘                       └────────────┬────────────┘
                   │                                               │
                   ▼                                               ▼
        ┌─────────────────────┐                       ┌─────────────────────────┐
        │SQLiteEventRepository│                       │  SQLiteAlertRepository  │
        └─────────────────────┘                       └────────────┬────────────┘
                                                                   │
                                                                   ▼
                                                      ┌─────────────────────────┐
                                                      │   ResponseRecommender   │
                                                      │  (Advisory Only, HITL)  │
                                                      └────────────┬────────────┘
                                                                   │
                                                                   ▼
                                                      ┌─────────────────────────┐
                                                      │    Security Analyst     │
                                                      │(RBAC: REQUEST/AUTHORIZE)│
                                                      └────────────┬────────────┘
                                                                   │
                                                                   ▼
                                                      ┌─────────────────────────┐
                                                      │    ResponseExecutor     │
                                                      │(Process, File, Firewall)│
                                                      └─────┬──────────────┬────┘
                                                            │              │
                                    ┌───────────────────────┘              └───────────────────────┐
                                    ▼                                                              ▼
                         ┌──────────────────────┐                                       ┌──────────────────────┐
                         │ SQLiteIncidentRepo & │                                       │ SQLiteAuditRepo      │
                         │ SQLiteResponseRepo   │                                       │ (Immutable Log)      │
                         └──────────────────────┘                                       └──────────────────────┘
```

---

## 2. Core Modules

| Module Path | Purpose |
| :--- | :--- |
| `trojan_defense.core.models.event` | Canonical `SecurityEvent` model and serialization/deserialization. |
| `trojan_defense.core.models.event_type` | `EventType` and `EventCategory` controlled enumerations (`PROCESS`, `FILE`, `NETWORK`, `SYSTEM`, `PRIVILEGE`, `DECEPTION`). |
| `trojan_defense.core.models.severity` | `Severity` levels (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `trojan_defense.core.models.identity` | Deterministic `EndpointIdentity` resolution and host metadata. |
| `trojan_defense.core.models.context` | Structured `EventContext` (`ProcessContext`, `FileContext`, `NetworkContext`, `SystemContext`, `DeceptionContext`). |
| `trojan_defense.core.config` | Centralized typed configuration, JSON loading, and environment variable overrides. |
| `trojan_defense.core.logging` | Structured logging with JSON and standard formats, plus sensitive data sanitization. |
| `trojan_defense.core.pipeline` | Synchronous/batch `EventPipeline`, `EventValidator`, and `EventNormalizer`. |
| `trojan_defense.core.persistence` | `BaseEventRepository` contract with `SQLiteEventRepository` and `InMemoryEventRepository`. |
| `trojan_defense.core.transport` | `BaseEventTransport` contract with `HttpEventTransport`, `JsonLineFileTransport`, and `MockEventTransport`. |
| `trojan_defense.core.collectors` | `BaseCollector` lifecycle interface and `CollectorRegistry` for multi-collector coordination. |
| `trojan_defense.core.lifecycle` | `ApplicationManager` lifecycle states (`INITIALIZED`, `RUNNING`, `STOPPED`). |
| `trojan_defense.backend.service` | `EventService` handling event ingestion, schema verification, deduplication, and querying. |
| `trojan_defense.backend.server` | Multithreaded standard-library HTTP server (`BackendServer`, `EventIngestionHandler`). |
| `trojan_defense.platform.windows.process_monitor` | `WindowsProcessMonitor` and `ProcessSnapshot` for local Windows process telemetry. |
| `trojan_defense.platform.windows.file_monitor` | `WindowsFileMonitor` and `FileTelemetryEventHandler` for event-driven Windows filesystem telemetry via `watchdog` (`ReadDirectoryChangesW`). |
| `trojan_defense.platform.windows.network_monitor` | `WindowsNetworkMonitor` for endpoint network connection telemetry via native Win32 connection table APIs (`psutil`). |
| `trojan_defense.platform.windows.system_monitor` | `WindowsSystemMonitor` for session transitions, system startup/shutdown, and process privilege/elevation telemetry via native Win32 APIs (`wtsapi32`, `advapi32`, `wevtapi`, `shell32`). |
| `trojan_defense.deception.engine` | `CyberDeceptionEngine` managing synthetic decoy artifact deployment, verification, status tracking, and safe cleanup. |
| `trojan_defense.deception.registry` | `DecoyRegistry` providing authoritative project ownership tracking, case-insensitive Windows path index, manifest serialization, and SQLite sync. |
| `trojan_defense.deception.detector` | `DeceptionInteractionDetector` identifying interactions with registered decoys, debouncing bursts, and emitting authoritative `DECEPTION.INTERACTION` events. |
| `trojan_defense.deception.path_safety` | Path security controls enforcing strict root validation, containment verification, and blocking directory escape/traversal. |
| `trojan_defense.deception.defaults` | Harmless synthetic canary file and directory definitions (`documents`, `config`, `credentials`, `backup`). |
| `trojan_defense.behavior.engine` | `BehaviorCorrelationEngine` evaluating deterministic behavioral rules across sliding correlation windows. |
| `trojan_defense.behavior.tracker` | `ProcessCorrelationTracker` managing stateful event history per active process tree. |
| `trojan_defense.behavior.rules` | 5 deterministic correlation rules (`RULE-BEH-001` through `RULE-BEH-005`). |
| `trojan_defense.alerting.models` | `Alert` entity, `AlertStatus` lifecycle state machine, `ScoringReason`, and `RiskScore`. |
| `trojan_defense.alerting.scorer` | `RiskScoringEngine` generating bounded explainable scores (0-100) and authoritative severity. |
| `trojan_defense.alerting.repository` | `SQLiteAlertRepository` providing persistent storage and query filtering in `alerts` table. |
| `trojan_defense.alerting.engine` | `AlertEngine` coordinating risk scoring, deduplication, cooldown, and PID reuse protection. |
| `trojan_defense.response.models` | Incident & response models (`Incident`, `ResponseAction`, `AuditLogEntry`, `ActionStatus`, `IncidentStatus`). |
| `trojan_defense.response.auth` | Role-Based Access Control (`Role`, `Permission`, `UserContext`, permission validation). |
| `trojan_defense.response.safety` | OS remediation safety guards (`ProcessSafetyValidator`, `PathSafetyValidator`, `NetworkSafetyValidator`). |
| `trojan_defense.response.recommender` | Advisory response recommender mapping alerts to prioritized candidate actions (`ResponseRecommender`). |
| `trojan_defense.response.executor` | Controlled response executor enforcing authorization gate, safe execution, and rollback (`ResponseExecutor`). |
| `trojan_defense.response.repository` | Persistent repositories for incidents, response actions, and immutable audit logs (`SQLiteIncidentRepository`, etc.). |
| `trojan_defense.main` | CLI application runner and operational commands (`server`, `run`, `status`, `deception`, `incident`, `response`, `audit`). |

---

## 3. Windows Process Telemetry (Phase 3)

The `WindowsProcessMonitor` observes real-time Windows process activity and feeds canonical `SecurityEvent` instances into the existing pipeline:

* **Baseline Seeding**: On startup (`start()`), an initial snapshot of all running processes is taken without generating spurious `PROCESS.CREATE` alerts for pre-existing system processes.
* **Process Creation**: Detects newly spawned processes, capturing PID, PPID, executable path, command line, parent process name, username, and ISO 8601 start timestamp. Emitted as `PROCESS.CREATE` with `Severity.LOW`.
* **Process Termination**: Detects process exit, capturing the termination timestamp while preserving earlier process context. Emitted as `PROCESS.TERMINATE` with `Severity.INFO`.
* **PID Recycling Protection**: Internal process tracking is keyed by `(pid, create_time)` composite keys, preventing Windows PID reuse from causing false associations or missed process transitions.
* **Access-Denied Resilience**: Privileged and protected system processes (`NT AUTHORITY\SYSTEM`, anti-malware) that raise `psutil.AccessDenied` are handled gracefully with fallback identifiers, preventing collector crashes.
* **Command Line Bounding**: Command lines are safely bounded (default 2048 characters) and appended with `... [TRUNCATED]` to prevent buffer and memory exhaustion.
* **Clean Lifecycle**: Managed by `ApplicationManager` and `CollectorRegistry`. Starts a dedicated background reconciliation thread and shuts down cleanly within a bounded join timeout.

---

## 4. Windows Filesystem Telemetry (Phase 4)

The `WindowsFileMonitor` provides event-driven, low-overhead monitoring of Windows filesystem modifications across designated watch directories:

* **Event-Driven Architecture**: Powered by `watchdog.observers.Observer` (which maps directly to `WindowsApiObserver` leveraging Win32 `ReadDirectoryChangesW` kernel notifications on Windows). Avoids CPU-intensive polling loops.
* **Observed Filesystem Events**:
  * `FILE.CREATE` (`Severity.LOW`): Newly created files, capturing size, extension, directory, and UTC timestamps.
  * `FILE.MODIFY` (`Severity.LOW`): Existing files modified or overwritten.
  * `FILE.DELETE` (`Severity.INFO`): Deleted files.
  * `FILE.RENAME` (`Severity.LOW`): Moved or renamed files, capturing destination path as `path` and original path as `previous_path`.
  * `FILE.DIR_CREATE` (`Severity.INFO`): Newly created directories.
  * `FILE.DIR_DELETE` (`Severity.INFO`): Deleted directories.
* **Write Burst Debouncing**: Rapid repeated file writes (common during editor autosaves and chunked streams) are coalesced within a configurable sliding window (`debounce_ms`, default 200 ms) keyed by canonical normalized path.
* **Windows Path Normalization**: All paths are resolved to absolute canonical forms with uniform uppercase drive letters, normalized separators (`/` or `\`), and case-normalized directory containment validation.
* **Resilience to File Locks & Errors**: Files that are exclusively locked (`PermissionError`), deleted immediately after creation (`FileNotFoundError`), or temporary editor swap files (`.tmp`, `~*`) are handled gracefully without collector failures.
* **Monitoring Scope Boundaries**: Watched directories can be monitored recursively or non-recursively, strictly ignoring events occurring outside configured watch boundaries.

---

## 5. Windows Network Telemetry (Phase 5)

The `WindowsNetworkMonitor` provides observational endpoint network connection telemetry across Windows sockets:

* **Native Windows Mechanism**: Interfaces native Windows connection table APIs (`GetExtendedTcpTable` and `GetExtendedUdpTable` from `iphlpapi.dll` via `psutil.net_connections`). No external network commands (`netstat`), raw packet captures, or packet sniffing drivers are used.
* **Observed Connection Lifecycle Events**:
  * `NETWORK.LISTEN` (`Severity.INFO`): Sockets bound and opened in listening state.
  * `NETWORK.CONNECT` (`Severity.LOW`): Outgoing or incoming TCP/UDP connections opened or transitioned into active state (`ESTABLISHED`).
  * `NETWORK.CLOSE` (`Severity.INFO`): Previously observed active connections that have closed or disappeared.
* **Protocol & Addressing Support**:
  * Distinguishes TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`).
  * Robust normalization of IPv4 (`127.0.0.1`, `192.168.x.x`) and IPv6 (`::1`, `fe80::...`) without classifying IPv6 as malformed.
  * Neutral classification of loopback and RFC 1918 traffic (no false alarms solely for local communication).
* **Process Correlation**:
  * Associates active connections to local PIDs where provided by the Windows kernel.
  * Resolves process name and executable path with safe fallbacks if the process terminates or access is denied.
  * Never fabricates PIDs or process attributes.
* **Duplicate Control**:
  * State-aware connection tracking keyed by `(protocol, local_ip, local_port, remote_ip, remote_port, pid)` ensures unchanged active connections do NOT generate duplicate events on subsequent polling intervals.
* **Observational Boundary**:
  * Strictly records endpoint connection metadata (local/remote IP and ports, socket state, protocol, PID).
  * Absolutely NO packet payload inspection, packet sniffing, TLS interception, or active scanning.

---

## 6. Windows System and Privilege Telemetry (Phase 6)

The `WindowsSystemMonitor` observes system lifecycle state, interactive/remote session transitions, and process privilege tokens using unprivileged native Win32 APIs:

* **System Boot & Startup Baseline**:
  * Captures initial system boot timestamp via `psutil.boot_time()` and emits a baseline `SYSTEM.STARTUP` event on initialization with `boot_time` in ISO 8601 UTC.
* **Session Lifecycle & State Transitions**:
  * Enumerates terminal sessions via `wtsapi32.dll` (`WTSEnumerateSessionsW`, `WTSQuerySessionInformationW`).
  * Emits `SYSTEM.LOGON` on new interactive/remote session detection.
  * Emits `SYSTEM.LOCK` when session state transitions to `Disconnected`.
  * Emits `SYSTEM.UNLOCK` when session state returns to `Active`.
  * Emits `SYSTEM.LOGOFF` when session terminates.
* **Process Privilege & Token Elevation Context**:
  * Safely queries process tokens via `advapi32.dll` (`OpenProcessToken`, `GetTokenInformation`).
  * Resolves token elevation (`TokenElevation`: `is_elevated`), elevation type (`TokenElevationType`: `Default`, `Full`, `Limited`), and mandatory integrity level (`TokenIntegrityLevel`: `Low`, `Medium`, `High`, `System`).
  * Retrieves token user SID via `ConvertSidToStringSidW` and account name via `LookupAccountSidW`.
  * Resolves held privileges (`TokenPrivileges`) via `LookupPrivilegeNameW`.
  * Checks administrator rights via `shell32.dll` (`IsUserAnAdmin`).
* **Windows Event Log Reconciliation**:
  * Queries recent events from the `System` channel via `wevtapi.dll` (`EvtQuery`, `EvtNext`, `EvtRender`) for event IDs 7001 (Logon), 7002 (Logoff), 6005 (Startup), 6006 (Shutdown), and 1074 (User Shutdown).
  * Tracks high-watermark `EventRecordID` to ensure events are never double-processed.
* **Observational Safety Boundary**:
  * Strictly observational telemetry. Absolutely NO token impersonation, NO credential dumping, NO UAC bypass, and NO privilege manipulation.

---

## 7. Cyber Deception Engine (Phase 7)

The `CyberDeceptionEngine` deploys and manages high-interaction, defensive synthetic decoy artifacts designed to serve as early warning canaries for unauthorized file interactions and exploration activities:

* **Strict Path Containment & Safety Controls (`path_safety.py`)**:
  * Prevents directory escape and traversal syntax (`..`, absolute paths, leading slashes).
  * Hard-rejects filesystem drive roots (`C:\`, `D:\`), critical Windows OS trees (`C:\Windows`, `C:\Windows\System32`), and application installations (`C:\Program Files`, `C:\Program Files (x86)`).
  * Protects broad user parent directories (`C:\Users`), direct user home roots (`C:\Users\<user>`), Desktop roots, and sensitive credential stores (`.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`).
  * Enforces placement inside a dedicated project subdirectory (e.g. `runtime/deception`).
* **Harmless Synthetic Decoy Artifacts (`defaults.py`)**:
  * Deploys 4 synthetic directory decoys (`documents`, `config`, `credentials`, `backup`).
  * Deploys 4 realistic synthetic canary files (`documents/project_notes.txt`, `config/application.ini`, `credentials/cloud_tokens.txt`, `backup/inventory_manifest.csv`).
  * All files contain non-operational, explicitly tagged canary data (e.g. `SYNTHETIC_CANARY_AKIA_NOT_REAL_001`). Contains NO real credentials, NO executables, and NO active scripts.
* **Authoritative Decoy Registry (`registry.py`)**:
  * Maintains an in-memory thread-safe registry indexed by canonical lowercase paths for case-insensitive Windows filesystem lookups (`is_decoy()`, `get_decoy()`).
  * Synchronizes durable records atomically via `.decoy_manifest.json` and optional SQLite `decoy_registry` table.
  * Reconciles physical disk state on command to flag externally deleted decoys (`missing`) or altered decoys (`corrupted`).
* **Idempotent Deployment & Safe Cleanup Guarantees**:
  * `deploy()` creates missing decoys and verifies existing decoys without re-writing if contents match.
  * `cleanup()` removes ONLY project-registered, owned decoys inside the validated deception root. Files are removed first; directories are removed only if empty of unowned files.
  * Unowned non-decoy user files and custom directories placed inside the deception root are strictly preserved.
* **Seamless Telemetry Monitoring Reuse**:
  * Fully integrated into `ApplicationManager`. When enabled, the deception root is automatically added to Phase 4 `WindowsFileMonitor` monitored paths.
  * Avoids duplicate filesystem watchers while ensuring all filesystem actions on decoys generate rich `SecurityEvent` records.

---

## 8. Deception Interaction Detection (Phase 8)

The `DeceptionInteractionDetector` provides passive, real-time recognition of unauthorized access and manipulation targeting registered cyber deception decoys:

* **Telemetric Source of Truth**:
  * Consumes raw filesystem activity strictly from the Phase 4 `WindowsFileMonitor` via `set_deception_detector`.
  * Creates **zero duplicate filesystem watchers**, background threads, or polling loops.
* **Authoritative Decoy Ownership Verification**:
  * Queries the Phase 7 `DecoyRegistry` using case-insensitive, canonical Windows path index lookups (`registry.get_by_path()`).
  * Emits `DECEPTION.INTERACTION` events **only** for registered, active decoys.
* **Strict False Positive Prevention**:
  * Ordinary legitimate files residing anywhere on the system return `None` and generate no deception telemetry.
  * Unregistered user files or benign scanner logs created inside the `runtime/deception` folder return `None` and generate no deception telemetry.
  * Substring matching (e.g. `if "deception" in path`) is strictly prohibited.
* **Granular Interaction Categorization**:
  * Maps filesystem actions to canonical interaction types:
    * `CREATE` → `created`
    * `MODIFY` → `modified` (Severity: `HIGH`)
    * `DELETE` → `deleted` (Severity: `HIGH`)
    * `RENAME` → `renamed` (resolves original decoy from either target or `previous_path`)
    * `DIR_CREATE` / `DIR_DELETE` → `dir_created` / `dir_deleted` (Severity: `MEDIUM`)
* **Burst Debouncing & Storm Suppression**:
  * Coalesces rapid duplicate bursts on the same decoy `(decoy_id, interaction_type)` within a configurable sliding window (default: 200 ms).
  * Permits distinct interaction types on the same decoy and concurrent operations across distinct decoys.
* **Multi-Layer Context Preservation & Correlation Linking**:
  * Preserves full triggering telemetry: original `file`, `process` (PID, executable), `system` (user context), and host identity.
  * Directly links the triggering event via `context.deception.original_event_id` and `extra.original_event_id`.
* **Strictly Observational Boundary**:
  * Operates exclusively as passive telemetry.
  * Performs **NO** automated process termination, file quarantine, host isolation, threat scoring, or Trojan classification.

---

## 9. Behavioral Correlation and Detection (Phase 9)

The `BehaviorCorrelationEngine` introduces deterministic, multi-event behavioral correlation across earlier telemetry layers (`PROCESS`, `FILE`, `NETWORK`, `SYSTEM`, `PRIVILEGE`, `DECEPTION`):

* **Deterministic Behavioral Rules**:
  * `RULE-BEH-001` (**Process File Activity Correlation**): Detects processes creating or modifying sensitive files (executables, scripts, or startup directories).
  * `RULE-BEH-002` (**Process Network Communication Correlation**): Detects spawned processes establishing external/outbound network connections within the correlation window.
  * `RULE-BEH-003` (**Privileged Process Activity Correlation**): Detects elevated/privileged processes performing sensitive filesystem modifications or administrative binary executions.
  * `RULE-BEH-004` (**Process Multi-Stage File-Network Sequence**): Detects single processes executing multi-stage sequences involving both file operations and network communications within the window.
  * `RULE-BEH-005` (**Deception Decoy Interaction Sequence**): Correlates high-fidelity cyber deception decoy/honeytoken access with subsequent system activity by the actor process.
* **PID Reuse Protection & Process Identity**:
  * Employs composite process identity keys `ProcessIdentityKey(pid, created_at, executable_path)` to eliminate PID recycling false positives on Windows.
  * Retires and archives prior instances on `PROCESS.TERMINATE` or new `PROCESS.CREATE` arrival for the recycled PID.
* **Sliding Time Windows & Bounded In-Memory State**:
  * Configurable correlation window (`correlation_window_seconds`, default 60s) and deduplication window (`dedup_window_seconds`, default 30s).
  * LRU/FIFO capacity bounding (`max_tracked_processes`, default 1000) prevents memory leaks during continuous telemetry ingestion.
* **Auditable Evidence Lineage & Canonical Schema Integration**:
  * Generates structured `BehaviorFinding` models containing full lists of contributing event IDs (`related_event_ids`), matched conditions, and evidence summaries.
  * Emits canonical `SecurityEvent` instances with `EventCategory.BEHAVIOR` (`BEHAVIOR.FINDING`) and structured `BehaviorContext` routed through `EventPipeline` and persisted in SQLite.
* **Recursion Guard**:
  * Automatically ignores incoming `BEHAVIOR` category events to prevent self-triggering correlation loops.


All events generated by collectors instantiate `SecurityEvent`:

### Process Event Example
```json
{
  "event_id": "ba7cd3c5-beb5-4d93-ab10-cf64ab5e14e9",
  "schema_version": "1.0.0",
  "timestamp": "2026-10-01T12:58:35.446182+00:00",
  "event_type": "PROCESS.CREATE",
  "severity": "LOW",
  "source": "windows_process_monitor",
  "endpoint": {
    "endpoint_id": "6d013934b674186f",
    "hostname": "LAPTOP-PTDK5FK4",
    "platform": "Windows",
    "os_version": "10.0.26200",
    "architecture": "AMD64",
    "agent_version": "0.1.0"
  },
  "context": {
    "process": {
      "pid": 27024,
      "ppid": 27432,
      "name": "python.exe",
      "executable_path": "C:\\Users\\Maithresh\\Desktop\\vijay project\\.venv\\Scripts\\python.exe",
      "command_line": "python.exe -c import time; time.sleep(2.0)",
      "username": "LAPTOP-PTDK5FK4\\Maithresh",
      "parent_name": "python.exe",
      "created_at": "2026-10-01T12:58:35.446182+00:00"
    }
  }
}
```

### File Event Example
```json
{
  "event_id": "31b0e515-db14-411a-8bb7-d8677c77da20",
  "schema_version": "1.0.0",
  "timestamp": "2026-10-01T13:08:44.205934+00:00",
  "event_type": "FILE.RENAME",
  "severity": "LOW",
  "source": "windows_file_monitor",
  "endpoint": {
    "endpoint_id": "6d013934b674186f",
    "hostname": "LAPTOP-PTDK5FK4",
    "platform": "Windows",
    "os_version": "10.0.26200",
    "architecture": "AMD64",
    "agent_version": "0.1.0"
  },
  "context": {
    "file": {
      "path": "C:\\Users\\Maithresh\\Desktop\\vijay project\\scratch\\watch_target\\renamed.txt",
      "file_name": "renamed.txt",
      "directory": "C:\\Users\\Maithresh\\Desktop\\vijay project\\scratch\\watch_target",
      "extension": ".txt",
      "previous_path": "C:\\Users\\Maithresh\\Desktop\\vijay project\\scratch\\watch_target\\sample.txt",
      "size_bytes": 18
    }
  }
}
```

### Network Event Example
```json
{
  "event_id": "19b4cf75-2630-4e3d-82d8-693f18e980f7",
  "schema_version": "1.0.0",
  "timestamp": "2026-10-01T13:25:18.234125+00:00",
  "event_type": "NETWORK.CONNECT",
  "severity": "LOW",
  "source": "windows_network_monitor",
  "endpoint": {
    "endpoint_id": "6d013934b674186f",
    "hostname": "LAPTOP-PTDK5FK4",
    "platform": "Windows",
    "os_version": "10.0.26200",
    "architecture": "AMD64",
    "agent_version": "0.1.0"
  },
  "context": {
    "network": {
      "protocol": "TCP",
      "local_ip": "127.0.0.1",
      "local_port": 55789,
      "remote_ip": "127.0.0.1",
      "remote_port": 55788,
      "state": "ESTABLISHED",
      "pid": 504
    },
    "process": {
      "pid": 504,
      "name": "python.exe",
      "executable_path": "C:\\Users\\Maithresh\\Desktop\\vijay project\\.venv\\Scripts\\python.exe"
    }
  }
}
```

### System & Session Event Example
```json
{
  "event_id": "791ba7f9-b26c-463a-aeb4-efa5acf7deb3",
  "schema_version": "1.0.0",
  "timestamp": "2026-10-01T13:48:50.123456+00:00",
  "event_type": "SYSTEM.LOGON",
  "severity": "INFO",
  "source": "windows_system_monitor",
  "endpoint": {
    "endpoint_id": "6d013934b674186f",
    "hostname": "LAPTOP-PTDK5FK4",
    "platform": "Windows",
    "os_version": "10.0.26200",
    "architecture": "AMD64",
    "agent_version": "0.1.0"
  },
  "context": {
    "system": {
      "subsystem": "SESSION",
      "target": "Console",
      "action": "LOGON",
      "username": "Maithresh",
      "session_id": 2,
      "session_name": "Console",
      "domain": "LAPTOP-PTDK5FK4",
      "state": "Active"
    }
  }
}
```

---

## 10. Backend REST API Endpoints

| Method | Path | Description | Response Codes |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health check and total stored event and alert count. | `200 OK` |
| `POST` | `/api/events` | Ingest a single `SecurityEvent`. Performs validation and deduplication. | `201 Created`, `409 Conflict` (duplicate), `400 Bad Request`, `413 Payload Too Large` |
| `POST` | `/api/events/batch` | Ingest a list of `SecurityEvent`s atomically. | `201 Created`, `400 Bad Request`, `413 Payload Too Large` |
| `GET` | `/api/events` | Query stored events with filtering and bounded pagination. | `200 OK` |
| `GET` | `/api/events/<event_id>` | Retrieve a single event by unique ID. | `200 OK`, `404 Not Found` |
| `GET` | `/api/alerts` | Query stored security alerts with filtering and pagination. | `200 OK` |
| `GET` | `/api/alerts/<alert_id>` | Retrieve a single alert with structured scoring explanation. | `200 OK`, `404 Not Found` |
| `GET` | `/api/alerts/<alert_id>/evidence` | Inspect complete evidence lineage and underlying raw events. | `200 OK`, `404 Not Found` |
| `POST` | `/api/alerts/<alert_id>/acknowledge` | Transition alert status to `ACKNOWLEDGED`. | `200 OK`, `404 Not Found`, `400 Bad Request` |
| `POST` | `/api/alerts/<alert_id>/resolve` | Transition alert status to `RESOLVED`. | `200 OK`, `404 Not Found`, `400 Bad Request` |
| `POST` | `/api/alerts/<alert_id>/status` | Update alert lifecycle status with transition validation. | `200 OK`, `404 Not Found`, `400 Bad Request` |
| `GET` | `/api/alerts/<alert_id>/recommendations` | Get structured advisory candidate response actions for an alert. | `200 OK`, `404 Not Found` |
| `GET` | `/api/incidents` | Query security incidents with status, severity, and pagination filters. | `200 OK` |
| `POST` | `/api/incidents` | Create a new security incident linking alerts, indicators, and assignees. | `201 Created`, `400 Bad Request` |
| `GET` | `/api/incidents/<incident_id>` | Retrieve a single incident with notes and linked response actions. | `200 OK`, `404 Not Found` |
| `PATCH` | `/api/incidents/<incident_id>` | Update incident attributes (title, severity, assignee, description). | `200 OK`, `404 Not Found` |
| `POST` | `/api/incidents/<incident_id>/notes` | Add an immutable investigation note to the incident timeline. | `201 Created`, `404 Not Found`, `400 Bad Request` |
| `POST` | `/api/incidents/<incident_id>/status` | Transition incident lifecycle status (`OPEN`, `INVESTIGATING`, etc.). | `200 OK`, `404 Not Found`, `400 Bad Request` |
| `GET` | `/api/responses` | Query defensive response actions by status, type, or incident. | `200 OK` |
| `POST` | `/api/responses` | Request a defensive response action (status: `REQUESTED`). | `201 Created`, `400 Bad Request`, `403 Forbidden` |
| `GET` | `/api/responses/<action_id>` | Retrieve a response action record including parameters and outcome. | `200 OK`, `404 Not Found` |
| `POST` | `/api/responses/<action_id>/authorize` | Senior authorization of a requested response action (status: `AUTHORIZED`). | `200 OK`, `400 Bad Request`, `403 Forbidden` |
| `POST` | `/api/responses/<action_id>/execute` | Execute an authorized defensive response action via OS safety guards. | `200 OK`, `400 Bad Request`, `403 Forbidden` |
| `POST` | `/api/responses/<action_id>/rollback` | Rollback a previously succeeded response action (e.g. restore file). | `200 OK`, `400 Bad Request`, `403 Forbidden` |
| `POST` | `/api/responses/<action_id>/reject` | Reject a requested or authorized response action. | `200 OK`, `400 Bad Request`, `403 Forbidden` |
| `GET` | `/api/audit` | Query append-only audit trail logs with filtering and pagination. | `200 OK`, `403 Forbidden` |
| `GET` | `/api/audit/<audit_id>` | Retrieve an individual audit log entry by ID. | `200 OK`, `404 Not Found` |

### Query Parameters for `GET /api/events`
* `endpoint_id`: Filter events originating from a specific endpoint ID.
* `event_type`: Filter events by category (e.g. `PROCESS`, `FILE`, `NETWORK`, `SYSTEM`, `PRIVILEGE`, `DECEPTION`) or full type (e.g. `SYSTEM.LOGON`).
* `severity`: Filter events by severity level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `start_time`: Filter events with timestamp on or after ISO 8601 string.
* `end_time`: Filter events with timestamp on or before ISO 8601 string.
* `limit`: Max records to return (default: 50, maximum bounded: 200).
* `offset`: Number of records to skip (default: 0).

### Query Parameters for `GET /api/alerts`
* `endpoint_id`: Filter alerts originating from a specific endpoint ID.
* `status`: Filter by alert lifecycle status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`).
* `severity`: Filter by severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `rule_id`: Filter by triggering behavioral correlation rule ID.
* `pid`: Filter by associated process ID.
* `min_score`: Filter alerts with risk score greater than or equal to minimum.
* `max_score`: Filter alerts with risk score less than or equal to maximum.
* `order_by`: Ordering field (`created_at`, `risk_score`, `updated_at`).
* `desc`: Boolean direction for sorting (default: `true`).
* `limit`: Max records to return (default: 50, maximum bounded: 1000).
* `offset`: Number of records to skip (default: 0).

---

## 11. Controlled Defensive Response & Incident Management (Final Phase)

The Final Phase completes the defensive architecture by introducing a controlled, non-destructive, and human-in-the-loop incident response subsystem.

### Human-in-the-Loop & Safety Philosophy
* **Strict Non-Autonomous Separation**: Detection, risk scoring, and alert generation NEVER automatically trigger destructive operating system modifications.
* **Advisory Recommendations**: The `ResponseRecommender` analyzes high-risk alerts and generates prioritized candidate response actions. These actions are purely advisory and cannot execute without human analyst intervention.
* **Two-Step Authorization Gate**: Any requested defensive response (`ActionStatus.REQUESTED`) requires explicit authorization (`ActionStatus.AUTHORIZED`) by a privileged operator (`RESPONDER` or `ADMIN`) before execution is permitted.

### Role-Based Access Control (RBAC)
User permissions are strictly enforced across all API endpoints and CLI operations:
* **`VIEWER`**: Read-only inspection of telemetry, alerts, incidents, responses, and audit logs.
* **`ANALYST`**: Full incident lifecycle management, adding investigation notes, triaging alerts, and submitting response action requests (`REQUEST_RESPONSE`).
* **`RESPONDER`**: Senior authorization (`AUTHORIZE_RESPONSE`) and execution/rollback (`EXECUTE_RESPONSE`) of defensive remediations.
* **`ADMIN`**: Unrestricted management across all platform capabilities.

Authentication headers (`X-User-Role`, `X-User-Name`, or bearer tokens configured in `config/default.json`) authenticate incoming requests.

### Incident Management Lifecycle
Incidents (`Incident`) group correlated alerts, indicators, analyst notes, and response actions into a unified investigation:
* **Lifecycle State Transitions**: `OPEN` $\to$ `INVESTIGATING` $\to$ `CONTAINED` $\to$ `RESOLVED` $\to$ `CLOSED` (with reopening support to `INVESTIGATING`).
* **Analyst Notes**: Immutable, timestamped notes (`IncidentNote`) document forensic observations and decisions.
* **Alert Associations**: Bidirectional traceability between security alerts and parent incidents.

### Response Action Lifecycle & Safe Execution
Every response action (`ResponseAction`) progresses through strict lifecycle states:
$$\text{REQUESTED} \longrightarrow \text{AUTHORIZED} \longrightarrow \text{EXECUTING} \longrightarrow \text{SUCCEEDED} \text{ / } \text{FAILED} \longrightarrow \text{ROLLED\_BACK}$$

#### Safe OS Remediation Guardrails:
1. **Process Termination (`PROCESS_TERMINATION`)**:
   - **PID Reuse Protection**: Validates creation timestamps against snapshot history to prevent terminating recycled PIDs.
   - **Protected Process Whitelist**: Refuses termination of critical Windows system processes (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `svchost.exe`, `wininit.exe`, `winlogon.exe`, `explorer.exe`).
   - **Self-Protection**: Prevents terminating the monitoring agent or backend server process itself.
2. **File Quarantine (`FILE_QUARANTINE`)**:
   - **Pre-Quarantine SHA-256**: Hashes target files before moving them into the quarantine sandbox (`runtime/quarantine/`).
   - **Path Traversal Protection**: Rejects root directory paths (`C:\`), critical system directories (`Windows`, `System32`), and path traversal attempts (`..`).
   - **Reversibility (`RESTORE_FILE`)**: Non-destructive quarantine allows analysts to rollback actions, restoring files to their original location with SHA-256 integrity verification.
3. **Network Blocking (`NETWORK_BLOCK`)**:
   - **Parameterized Firewall Rules**: Modifies Windows Firewall via `netsh advfirewall firewall` using secure parameter arrays (`subprocess.run(..., shell=False)`).
   - **Loopback & Management Exemption**: Explicitly forbids blocking `127.0.0.1`, `::1`, subnet broadcast addresses, or local management subnets.
   - **Rollback (`UNBLOCK_NETWORK`)**: Removes injected firewall rules by precise rule name without affecting standard system firewall policies.
4. **Host Isolation (`HOST_ISOLATION`)**:
   - **Containment**: Blocks all outbound non-local traffic while preserving loopback and localhost communications for administrative access.
   - **Rollback (`RESTORE_HOST`)**: Restores original outbound network state cleanly.

### Immutable Audit Trail
All security-relevant actions — incident updates, note additions, response requests, authorizations, rejections, execution outcomes, and rollbacks — are recorded in the append-only `audit_logs` SQLite table. Audit entries capture `timestamp`, `actor`, `role`, `action`, `target_type`, `target_id`, `details`, and `ip_address`, providing a forensically sound audit trail.

---

## 12. Persistence & Deduplication

* **Database Engine**: Local SQLite database via Python's built-in `sqlite3` module.
* **Schema & Indexes**:
  * `security_events`: Indexed on `timestamp`, `ingested_at`, `event_type`, `severity`, and `endpoint_id`.
  * `decoy_registry`: Tracks active/missing synthetic decoys.
  * `alerts`: Persistent alerts indexed on `endpoint_id`, `severity`, `status`, `rule_id`, `created_at`, and `risk_score`.
  * `incidents`: Security incident cases indexed on `status`, `severity`, `assigned_to`, and `created_at`.
  * `incident_notes`: Timestamped investigation notes indexed on `incident_id` and `created_at`.
  * `response_actions`: Defensive remediation records indexed on `status`, `action_type`, `incident_id`, and `alert_id`.
  * `audit_logs`: Append-only immutable log indexed on `timestamp`, `actor`, `action`, and `target_id`.
* **Separate Timestamps**: The original event creation time is preserved in `timestamp`, while server arrival time is recorded in `ingested_at`.
* **Deterministic Deduplication**: Enforced via primary key constraints on `event_id`. Duplicate event submissions return `HTTP 409 Conflict` (`{"status": "duplicate"}`), preserving the existing event without mutation.
* **Alert Deduplication & Cooldown**: In-memory and persistent deduplication cache keyed by `(endpoint_id, rule_id, pid, process_name, executable_path, deception_id)`. Subsequent triggers update `occurrence_count` and `last_seen` without runaway score inflation.

---

## 13. How to Run Locally

### Requirements
* Python 3.11+ (tested on Python 3.14 on Windows)
* Virtual environment (`.venv`) with dependencies installed (`pip install -r requirements.txt`)

### Run Complete Monitoring & Response Agent
```powershell
.\.venv\Scripts\python.exe -m trojan_defense run --enable-process-monitor --enable-file-monitor --enable-network-monitor --enable-system-monitor --enable-deception --enable-behavior --enable-alerting --enable-response --correlation-window 60.0 --system-interval 2.0
```

### Start the Backend Ingestion, Alerting & Incident Response Server
```powershell
.\.venv\Scripts\python.exe -m trojan_defense server --port 8080
```

### Manage Incidents & Defensive Responses (CLI)
```powershell
# List all open incidents
.\.venv\Scripts\python.exe -m trojan_defense incident list --status OPEN

# View incident details
.\.venv\Scripts\python.exe -m trojan_defense incident show <incident-id>

# Add analyst investigation note
.\.venv\Scripts\python.exe -m trojan_defense incident note <incident-id> --content "Malicious binary confirmed in temp directory" --author analyst1

# Update incident status
.\.venv\Scripts\python.exe -m trojan_defense incident set-status <incident-id> --status CONTAINED

# List defensive response actions
.\.venv\Scripts\python.exe -m trojan_defense response list

# Request file quarantine
.\.venv\Scripts\python.exe -m trojan_defense response request --action-type FILE_QUARANTINE --param file_path=C:\temp\trojan.exe --incident-id <incident-id>

# Authorize and execute response action (requires RESPONDER or ADMIN role)
.\.venv\Scripts\python.exe -m trojan_defense response authorize <action-id> --role RESPONDER
.\.venv\Scripts\python.exe -m trojan_defense response execute <action-id> --role RESPONDER

# Rollback a response action (e.g. restore file)
.\.venv\Scripts\python.exe -m trojan_defense response rollback <action-id> --role RESPONDER

# Query immutable audit logs
.\.venv\Scripts\python.exe -m trojan_defense audit list --limit 20
```

### Manage Cyber Deception Decoys (CLI)
```powershell
# Deploy synthetic decoys into the deception sandbox
.\.venv\Scripts\python.exe -m trojan_defense deception deploy

# Check active, missing, and corrupted decoy inventory
.\.venv\Scripts\python.exe -m trojan_defense deception status

# Safely remove all project-owned decoys while preserving unowned files
.\.venv\Scripts\python.exe -m trojan_defense deception cleanup
```

### Check System Status
```powershell
.\.venv\Scripts\python.exe -m trojan_defense --enable-process-monitor --enable-file-monitor --enable-network-monitor --enable-system-monitor --enable-deception --enable-behavior --enable-alerting --enable-response status
```

### Run End-to-End Windows Manual Verification
```powershell
.\.venv\Scripts\python.exe scratch/verify_final_phase.py
```

---

## 14. Running the Automated Test Suite

Run the full automated test suite (290 unit and integration tests across Phases 1 through 11):

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Web Security Operations Dashboard

The project now includes a professional browser dashboard served directly by the Python backend.

Open `http://127.0.0.1:8080/` after starting the backend.

The interface provides:
- real-time backend health and protection status
- security-event and alert counters
- alert severity/status filtering
- alert acknowledgement
- event telemetry
- incident tracking
- response-action authorization
- cyber-deception overview
- system/configuration status

See `HOW_TO_RUN_DASHBOARD.md` for the exact run steps.
