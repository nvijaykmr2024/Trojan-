"""Deterministic behavioral correlation rules.

Implements rule evaluations across process, file, network, privilege,
and cyber deception telemetry within sliding correlation windows.
"""

from abc import ABC, abstractmethod
from typing import Any

from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.behavior.tracker import ProcessCorrelationTracker, TrackedProcess, parse_event_time
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory
from trojan_defense.core.models.severity import Severity

logger = get_logger("behavior.rules")

SENSITIVE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".sys", ".reg"
}

SENSITIVE_PATHS = [
    "startup",
    "system32",
    "syswow64",
    "windows\\temp",
    "appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
]

SUSPICIOUS_SPAWN_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "vssadmin.exe", "bitsadmin.exe"
}


class BehaviorRule(ABC):
    """Abstract base class for deterministic behavioral correlation rules."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        description: str,
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description

    @abstractmethod
    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        """Evaluate incoming event and tracked process state against this rule."""
        raise NotImplementedError


class ProcessFileActivityRule(BehaviorRule):
    """RULE-BEH-001: Process File Activity Correlation.

    Detects processes creating or modifying sensitive files (executables, scripts,
    or startup locations) within the correlation window.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE-BEH-001",
            name="Process File Activity Correlation",
            severity=Severity.HIGH,
            description="Process created or modified sensitive executable, script, or startup files.",
        )

    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []

        if event.event_type.category != EventCategory.FILE:
            return findings

        file_ctx = event.context.file if event.context else None
        if not file_ctx or not file_ctx.path:
            return findings

        path_lower = file_ctx.path.lower()
        is_sensitive_ext = any(path_lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS)
        is_sensitive_path = any(sp in path_lower for sp in SENSITIVE_PATHS)

        if not (is_sensitive_ext or is_sensitive_path):
            return findings

        # Check associated process
        proc_ctx = event.context.process if event.context else None
        pid = proc_ctx.pid if proc_ctx else None
        tracked = tracker.get_process(pid) if pid else None

        related_ids = [event.event_id]
        evidence: list[dict[str, Any]] = [
            {
                "event_id": event.event_id,
                "category": "FILE",
                "path": file_ctx.path,
                "operation": file_ctx.operation,
                "timestamp": event.timestamp,
            }
        ]
        conditions = [
            f"File activity on sensitive target: {file_ctx.path} (operation: {file_ctx.operation or 'unknown'})"
        ]

        proc_name = proc_ctx.name if proc_ctx else (tracked.name if tracked else None)
        exe_path = proc_ctx.executable_path if proc_ctx else (tracked.executable_path if tracked else None)

        if tracked:
            recent_events = tracked.get_events_in_window(
                window_seconds,
                reference_time_epoch=parse_event_time(event.timestamp),
            )
            for pe in recent_events:

                if pe.event_id != event.event_id and pe.event_id not in related_ids:
                    related_ids.append(pe.event_id)
                    evidence.append({
                        "event_id": pe.event_id,
                        "category": pe.event_type.category.value,
                        "action": pe.event_type.action,
                        "timestamp": pe.timestamp,
                    })
            conditions.append(f"Correlated to active process PID {tracked.pid} ({tracked.name or 'unknown'})")

        findings.append(
            BehaviorFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                pid=pid,
                process_name=proc_name,
                executable_path=exe_path,
                start_time=event.timestamp,
                end_time=event.timestamp,
                related_event_ids=related_ids,
                matched_conditions=conditions,
                evidence=evidence,
                confidence=1.0,
                description=f"Process '{proc_name or pid or 'unknown'}' modified or created sensitive file: {file_ctx.path}",
            )
        )
        return findings


class ProcessNetworkActivityRule(BehaviorRule):
    """RULE-BEH-002: Process Network Communication Correlation.

    Detects recently spawned processes initiating external network connections
    within the correlation window.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE-BEH-002",
            name="Process Network Communication Correlation",
            severity=Severity.MEDIUM,
            description="Process established remote network connection within correlation window.",
        )

    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []

        if event.event_type.category != EventCategory.NETWORK:
            return findings

        net_ctx = event.context.network if event.context else None
        if not net_ctx:
            return findings

        # Ignore loopback connections (127.0.0.1, ::1)
        remote_ip = net_ctx.remote_ip or net_ctx.destination_ip
        if not remote_ip or remote_ip in ("127.0.0.1", "::1", "localhost"):
            return findings

        pid = net_ctx.pid or (event.context.process.pid if event.context and event.context.process else None)
        if pid is None:
            return findings

        tracked = tracker.get_process(pid)
        if not tracked:
            return findings

        event_epoch = parse_event_time(event.timestamp)
        recent_events = tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch)
        # Look for process lifecycle event or creation within correlation window
        process_events = [
            e for e in recent_events
            if e.event_type.category == EventCategory.PROCESS
        ]

        if not process_events:
            return findings

        related_ids = [event.event_id]

        evidence: list[dict[str, Any]] = [
            {
                "event_id": event.event_id,
                "category": "NETWORK",
                "remote_ip": remote_ip,
                "remote_port": net_ctx.remote_port or net_ctx.destination_port,
                "protocol": net_ctx.protocol,
                "timestamp": event.timestamp,
            }
        ]

        for pe in process_events:
            if pe.event_id not in related_ids:
                related_ids.append(pe.event_id)
                evidence.append({
                    "event_id": pe.event_id,
                    "category": "PROCESS",
                    "action": pe.event_type.action,
                    "timestamp": pe.timestamp,
                })

        findings.append(
            BehaviorFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                pid=tracked.pid,
                process_name=tracked.name,
                executable_path=tracked.executable_path,
                start_time=process_events[0].timestamp if process_events else event.timestamp,
                end_time=event.timestamp,
                related_event_ids=related_ids,
                matched_conditions=[
                    f"Process PID {tracked.pid} ({tracked.name or 'unknown'}) established network connection to {remote_ip}:{net_ctx.remote_port or net_ctx.destination_port}",
                    f"Connection occurred within {window_seconds}s correlation window of process activity",
                ],
                evidence=evidence,
                confidence=1.0,
                description=f"Process '{tracked.name or tracked.pid}' established network communication with {remote_ip}",
            )
        )
        return findings


class PrivilegedProcessActivityRule(BehaviorRule):
    """RULE-BEH-003: Privileged Process Activity Correlation.

    Detects elevated or privileged processes performing sensitive operations
    such as modifying system files or executing administrative binaries.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE-BEH-003",
            name="Privileged Process Activity Correlation",
            severity=Severity.HIGH,
            description="Elevated process performed sensitive filesystem or execution operations.",
        )

    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []

        pid = None
        if event.context:
            if event.context.process and event.context.process.pid:
                pid = event.context.process.pid
            elif event.context.network and event.context.network.pid:
                pid = event.context.network.pid

        if pid is None:
            return findings

        tracked = tracker.get_process(pid)
        is_elevated = (
            (tracked and tracked.is_elevated)
            or (event.context and event.context.privilege and event.context.privilege.is_elevated)
            or (event.event_type.category == EventCategory.PRIVILEGE)
        )

        if not is_elevated:
            return findings

        # Check for sensitive operations
        is_sensitive = False
        operation_desc = ""

        if event.event_type.category == EventCategory.FILE and event.context and event.context.file:
            path = (event.context.file.path or "").lower()
            if any(ext in path for ext in SENSITIVE_EXTENSIONS) or any(sp in path for sp in SENSITIVE_PATHS):
                is_sensitive = True
                operation_desc = f"Elevated file operation on: {event.context.file.path}"

        elif event.event_type.category == EventCategory.PROCESS and event.event_type.action == "CREATE":
            proc_ctx = event.context.process if event.context else None
            pname = (proc_ctx.name or "").lower() if proc_ctx else ""
            if pname in SUSPICIOUS_SPAWN_NAMES:
                is_sensitive = True
                operation_desc = f"Elevated execution of administrative binary: {proc_ctx.name}"

        event_epoch = parse_event_time(event.timestamp)
        if event.event_type.category == EventCategory.PRIVILEGE and event.event_type.action in ("ELEVATION", "TOKEN"):
            # Check if this process already performed sensitive actions in window
            if tracked:
                recent_events = tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch)
                for re in recent_events:
                    if re.event_type.category in (EventCategory.FILE, EventCategory.PROCESS) and re.event_id != event.event_id:
                        is_sensitive = True
                        operation_desc = f"Privilege elevation event correlated with prior activity {re.event_id}"
                        break

        if not is_sensitive:
            return findings

        related_ids = [event.event_id]
        evidence: list[dict[str, Any]] = [
            {
                "event_id": event.event_id,
                "category": event.event_type.category.value,
                "action": event.event_type.action,
                "timestamp": event.timestamp,
                "operation_desc": operation_desc,
            }
        ]

        if tracked:
            for pe in tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch):
                if pe.event_id not in related_ids:

                    related_ids.append(pe.event_id)
                    evidence.append({
                        "event_id": pe.event_id,
                        "category": pe.event_type.category.value,
                        "action": pe.event_type.action,
                        "timestamp": pe.timestamp,
                    })

        proc_name = tracked.name if tracked else (event.context.process.name if event.context and event.context.process else None)
        exe_path = tracked.executable_path if tracked else (event.context.process.executable_path if event.context and event.context.process else None)

        findings.append(
            BehaviorFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                pid=pid,
                process_name=proc_name,
                executable_path=exe_path,
                start_time=event.timestamp,
                end_time=event.timestamp,
                related_event_ids=related_ids,
                matched_conditions=[
                    f"Process running with elevated privileges (PID: {pid})",
                    operation_desc,
                ],
                evidence=evidence,
                confidence=1.0,
                description=f"Privileged process '{proc_name or pid}' executed sensitive operation: {operation_desc}",
            )
        )
        return findings


class ProcessFileNetworkSequenceRule(BehaviorRule):
    """RULE-BEH-004: Process Multi-Stage File-Network Sequence.

    Detects multi-stage activity where a single process performs both file modifications
    and network communications within the correlation window.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE-BEH-004",
            name="Process Multi-Stage File-Network Sequence",
            severity=Severity.HIGH,
            description="Process performed both file modifications and network communication within correlation window.",
        )

    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []

        if event.event_type.category not in (EventCategory.FILE, EventCategory.NETWORK):
            return findings

        pid = None
        if event.context:
            if event.context.process and event.context.process.pid:
                pid = event.context.process.pid
            elif event.context.network and event.context.network.pid:
                pid = event.context.network.pid

        if pid is None:
            return findings

        tracked = tracker.get_process(pid)
        if not tracked:
            return findings

        event_epoch = parse_event_time(event.timestamp)
        recent_events = tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch)

        file_events = [e for e in recent_events if e.event_type.category == EventCategory.FILE]
        network_events = [e for e in recent_events if e.event_type.category == EventCategory.NETWORK]


        # Require AT LEAST one file event AND AT LEAST one network event in the window
        if not file_events or not network_events:
            return findings

        related_ids: list[str] = []
        evidence: list[dict[str, Any]] = []

        for fe in file_events:
            if fe.event_id not in related_ids:
                related_ids.append(fe.event_id)
                evidence.append({
                    "event_id": fe.event_id,
                    "category": "FILE",
                    "path": fe.context.file.path if fe.context and fe.context.file else None,
                    "timestamp": fe.timestamp,
                })

        for ne in network_events:
            if ne.event_id not in related_ids:
                related_ids.append(ne.event_id)
                evidence.append({
                    "event_id": ne.event_id,
                    "category": "NETWORK",
                    "remote_ip": ne.context.network.remote_ip if ne.context and ne.context.network else None,
                    "remote_port": ne.context.network.remote_port if ne.context and ne.context.network else None,
                    "timestamp": ne.timestamp,
                })

        timestamps = [parse_event_time(e.timestamp) for e in (file_events + network_events)]
        min_ts = min(timestamps)
        max_ts = max(timestamps)

        findings.append(
            BehaviorFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                pid=tracked.pid,
                process_name=tracked.name,
                executable_path=tracked.executable_path,
                start_time=file_events[0].timestamp if file_events else event.timestamp,
                end_time=event.timestamp,
                related_event_ids=related_ids,
                matched_conditions=[
                    f"Process PID {tracked.pid} executed {len(file_events)} file event(s) and {len(network_events)} network event(s)",
                    f"Activities occurred within {window_seconds}s time window (span: {max_ts - min_ts:.2f}s)",
                ],
                evidence=evidence,
                confidence=1.0,
                description=f"Multi-stage behavioral sequence: Process '{tracked.name or tracked.pid}' performed file operations and network communications",
            )
        )
        return findings


class DecoyInteractionSequenceRule(BehaviorRule):
    """RULE-BEH-005: Deception Decoy Interaction Sequence.

    Correlates a cyber deception decoy or honeytoken interaction with subsequent
    or concurrent process, file, or network activity.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE-BEH-005",
            name="Deception Decoy Interaction Sequence",
            severity=Severity.CRITICAL,
            description="Deception decoy was accessed, correlated with subsequent or concurrent system activity.",
        )

    def evaluate(
        self,
        event: SecurityEvent,
        tracker: ProcessCorrelationTracker,
        window_seconds: float,
    ) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []

        is_deception_event = event.event_type.category == EventCategory.DECEPTION
        has_deception_ctx = bool(
            event.context and event.context.deception and event.context.deception.is_decoy
        )

        # Trigger on deception event or on events related to a process that touched a decoy
        pid = None
        if event.context:
            if event.context.process and event.context.process.pid:
                pid = event.context.process.pid
            elif event.context.network and event.context.network.pid:
                pid = event.context.network.pid

        tracked = tracker.get_process(pid) if pid else None

        # Check if the tracked process has any DECEPTION event in its recent window
        process_has_decoy_interaction = False
        decoy_events: list[SecurityEvent] = []
        event_epoch = parse_event_time(event.timestamp)

        if tracked:
            for re in tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch):
                if re.event_type.category == EventCategory.DECEPTION or (
                    re.context and re.context.deception and re.context.deception.is_decoy
                ):
                    process_has_decoy_interaction = True
                    decoy_events.append(re)

        if not (is_deception_event or has_deception_ctx or process_has_decoy_interaction):
            return findings

        related_ids = [event.event_id]
        evidence: list[dict[str, Any]] = [
            {
                "event_id": event.event_id,
                "category": event.event_type.category.value,
                "action": event.event_type.action,
                "timestamp": event.timestamp,
            }
        ]

        conditions: list[str] = []

        decoy_ctx = event.context.deception if (event.context and event.context.deception) else None
        if decoy_ctx:
            conditions.append(
                f"Decoy interaction detected: decoy_id={decoy_ctx.decoy_id}, type={decoy_ctx.decoy_type}, path={decoy_ctx.path}"
            )

        if tracked:
            for pe in tracked.get_events_in_window(window_seconds, reference_time_epoch=event_epoch):
                if pe.event_id not in related_ids:

                    related_ids.append(pe.event_id)
                    evidence.append({
                        "event_id": pe.event_id,
                        "category": pe.event_type.category.value,
                        "action": pe.event_type.action,
                        "timestamp": pe.timestamp,
                    })
            conditions.append(
                f"Correlated with active actor process PID {tracked.pid} ({tracked.name or 'unknown'}) with {len(tracked.events)} event(s)"
            )

        proc_name = tracked.name if tracked else (event.context.process.name if event.context and event.context.process else None)
        exe_path = tracked.executable_path if tracked else (event.context.process.executable_path if event.context and event.context.process else None)

        findings.append(
            BehaviorFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                pid=pid,
                process_name=proc_name,
                executable_path=exe_path,
                start_time=event.timestamp,
                end_time=event.timestamp,
                related_event_ids=related_ids,
                matched_conditions=conditions or ["Decoy interaction matched in behavioral correlation window"],
                evidence=evidence,
                confidence=1.0,
                description=f"High-fidelity decoy interaction correlated with system activity by process '{proc_name or pid or 'unknown'}'",
            )
        )
        return findings
