### Step 1: Open Two PowerShell Terminals in the Project Root

Open two PowerShell windows at `c:\Users\Maithresh\Desktop\vijay project`.

---

### Step 2: (Terminal 1) Start the Backend Server

Start the backend ingestion, alerting, and incident response HTTP server:

```powershell
.\.venv\Scripts\python.exe -m trojan_defense server --port 8080
```

> **What it does:** Starts the multithreaded REST API server on `http://127.0.0.1:8080`. It handles telemetry ingestion, SQLite persistence, risk scoring, alert querying, incident case management, and the response execution engine.

---

### Step 3: (Terminal 2) Deploy Cyber Deception Decoys

Deploy harmless canary trap files into the deception sandbox:

```powershell
.\.venv\Scripts\python.exe -m trojan_defense deception deploy
```

> **What it does:** Creates synthetic bait artifacts (e.g. `passwords.txt`, database configs, financial sheets) in `runtime\deception\` and indexes them into the local SQLite database.

You can inspect the deployed traps anytime with:
```powershell
.\.venv\Scripts\python.exe -m trojan_defense deception status
```

---

### Step 4: (Terminal 2) Start the Active Defensive Monitoring Agent

Launch the defensive agent with all native Windows monitors, behavioral correlation, alerting, and controlled response enabled:

```powershell
.\.venv\Scripts\python.exe -m trojan_defense run `
  --enable-process-monitor `
  --enable-file-monitor `
  --enable-network-monitor `
  --enable-system-monitor `
  --enable-deception `
  --enable-behavior `
  --enable-alerting `
  --enable-response
```

> **What it does:** The agent observes live Windows telemetry (processes, files, network connections, system privileges), monitors interactions with honeytokens, feeds events through the sliding correlation window, scores risk, and prepares advisory response recommendations.

---

### Step 5: How to Test Detection and Human-in-the-Loop Response

#### 1. Trigger a Deception Breach (Adversary Simulation)
In a third terminal (or via Windows Explorer/Notepad), open and view one of the deployed canary files:

```powershell
Get-Content runtime\deception\credentials\passwords.txt
```

Within seconds, the monitoring terminal will capture:
1. `FILE.READ` filesystem telemetry.
2. `DECEPTION.INTERACTION` detection.
3. Behavioral rule trigger (`RULE-BEH-005: Honeytoken / Decoy Interaction`).
4. **Risk Score: 100 (CRITICAL)**.
5. Persistent alert generation with complete forensic evidence lineage.

#### 2. Query Alerts and Advisory Recommendations
In your browser or via curl/PowerShell:
- **View all alerts**:
  ```powershell
  curl http://127.0.0.1:8080/api/alerts -H "X-User-Role: ANALYST"
  ```
- **Inspect advisory recommendations for an alert**:
  ```powershell
  curl http://127.0.0.1:8080/api/alerts/<alert_id>/recommendations -H "X-User-Role: ANALYST"
  ```
  *(The system provides recommendations like process termination, file quarantine, or network blocking without executing them autonomously).*

#### 3. Manage Incidents (CLI)
```powershell
# List open incidents
.\.venv\Scripts\python.exe -m trojan_defense incident list --status OPEN

# View incident details
.\.venv\Scripts\python.exe -m trojan_defense incident show <incident_id>

# Add analyst investigation notes
.\.venv\Scripts\python.exe -m trojan_defense incident note <incident_id> --author "analyst1" --content "Confirmed unauthorized access to honeytoken"
```

#### 4. Authorize and Execute a Controlled Defensive Response (Human-in-the-Loop)
Under the strict safety philosophy, all response actions require explicit two-step authorization by a senior responder:

```powershell
# 1. Request an action (e.g. quarantine a suspicious file)
.\.venv\Scripts\python.exe -m trojan_defense response request --action-type FILE_QUARANTINE --param file_path="C:\temp\test_suspicious_payload.exe"

# 2. Authorize the action (requires RESPONDER or ADMIN role)
.\.venv\Scripts\python.exe -m trojan_defense response authorize <action_id> --role RESPONDER

# 3. Execute the authorized action
.\.venv\Scripts\python.exe -m trojan_defense response execute <action_id> --role RESPONDER
```
*(The file is moved to `runtime\quarantine\` with its SHA-256 hash verified and saved)*.

#### 5. Non-Destructive Rollback
If a quarantined file needs to be restored:
```powershell
.\.venv\Scripts\python.exe -m trojan_defense response rollback <action_id> --role RESPONDER
```
*(The file is restored to its original path and its SHA-256 checksum is re-verified)*.

#### 6. Inspect the Immutable Audit Trail
Verify that all requests, authorizations, and execution outcomes are recorded:
```powershell
.\.venv\Scripts\python.exe -m trojan_defense audit list --limit 10
```

---

### Instant End-to-End Automated Verification Script

If you want to watch the entire pipeline execute from end-to-end automatically (telemetry $\to$ detection $\to$ risk score $\to$ advisory recommendations $\to$ incident $\to$ RBAC gate rejection $\to$ authorization $\to$ safe quarantine & process kill $\to$ rollback $\to$ audit log $\to$ REST API), you can run:

```powershell
.\.venv\Scripts\python.exe scratch/verify_final_phase.py
```

# How to run it on the other system (Step-by-Step)

On the destination Windows computer:

Unzip the archive into any folder (e.g. C:\Users\<NewUser>\Desktop\vijay project).
Open PowerShell in that folder.
Create a fresh virtual environment and install the dependencies:
powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Verify that everything works on the new system:
powershell
.\.venv\Scripts\python.exe -m pytest -q
(All 290 automated tests will run and pass).
Run the manual verification or start the system:
powershell
# Instant full-pipeline test:
.\.venv\Scripts\python.exe scratch/verify_final_phase.py
# Or start the server:
.\.venv\Scripts\python.exe -m trojan_defense server --port 8080