"""Safety verification and containment controls for defensive response actions.

Guarantees:
- ProcessSafetyValidator: PID reuse protection, creation time verification, system process exemption whitelist, self-protection.
- PathSafetyValidator: Traversal prevention, system directory protection, decoy protection, SHA-256 integrity verification.
- NetworkSafetyValidator: Loopback/gateway protection, parameter sanitization, shell-less netsh command construction.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import psutil
from typing import Any

from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger

logger = get_logger("response.safety")

DEFAULT_PROTECTED_PROCESSES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "spoolsv.exe",
    "explorer.exe",
    "dwm.exe",
    "conhost.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "sihost.exe",
}


class ResponseSafetyError(TrojanDefenseError):
    """Raised when a defensive response action fails safety validation."""
    pass


class ProcessSafetyValidator:
    """Verifies that a process targeted for termination is safe, active, and matching."""

    def __init__(self, protected_processes: list[str] | set[str] | None = None) -> None:
        self.protected_names = {p.lower() for p in (protected_processes or DEFAULT_PROTECTED_PROCESSES)}

    def validate_termination(
        self,
        pid: int,
        target_process_name: str | None = None,
        target_create_time: float | None = None,
        target_exe: str | None = None,
    ) -> tuple[bool, str, psutil.Process | None]:
        """Validate process target for termination.
        
        Returns:
            (is_safe, message, process_instance_or_none)
        """
        # 1. Disallow system idle (0) and kernel system (4)
        if pid <= 4:
            return False, f"PID {pid} is a critical Windows kernel/system process and cannot be terminated", None

        # 2. Self-protection: never terminate the defensive monitor/agent
        current_pid = os.getpid()
        if pid == current_pid:
            return False, f"Refusing to terminate PID {pid} (monitoring agent self-protection)", None

        # 3. Check process existence
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return False, f"Process with PID {pid} does not exist", None
        except psutil.AccessDenied:
            return False, f"Access denied inspecting process PID {pid} (system-protected process)", None

        # 4. Check protected process whitelist
        try:
            proc_name = proc.name().lower()
            if proc_name in self.protected_names:
                return False, f"Process '{proc_name}' (PID {pid}) is protected from termination", None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False, f"Could not determine name for PID {pid}", None

        # 5. PID Reuse Protection: Creation time verification
        if target_create_time is not None:
            try:
                curr_create_time = proc.create_time()
                # 2.0s tolerance for clock drift / floating-point conversions
                if abs(curr_create_time - target_create_time) > 2.0:
                    return (
                        False,
                        f"PID reuse detected: running PID {pid} was created at {curr_create_time}, "
                        f"expected {target_create_time}",
                        None,
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False, f"Could not verify creation time for PID {pid}", None

        # 6. Process name verification (if target name provided)
        if target_process_name:
            if proc_name != target_process_name.lower():
                return (
                    False,
                    f"Process identity mismatch: running PID {pid} is '{proc_name}', expected '{target_process_name}'",
                    None,
                )

        # 7. Executable path verification (if target exe path provided)
        if target_exe:
            try:
                curr_exe = proc.exe().lower()
                if Path(curr_exe).resolve() != Path(target_exe).resolve():
                    return (
                        False,
                        f"Executable path mismatch for PID {pid}: running '{curr_exe}', expected '{target_exe}'",
                        None,
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # In some environments proc.exe() is restricted

        return True, f"Process '{proc_name}' (PID {pid}) verified safe for termination", proc


class PathSafetyValidator:
    """Verifies paths for quarantine, preventing directory traversal and OS tampering."""

    def __init__(self, quarantine_root: str | Path = "runtime/quarantine") -> None:
        self.quarantine_root = Path(quarantine_root).resolve()

    def get_system_forbidden_prefixes(self) -> list[Path]:
        """Paths of OS critical directories that must never be quarantined or altered."""
        prefixes = []
        win_dir = os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows"
        prefixes.append(Path(win_dir).resolve())

        prog_files = os.environ.get("ProgramFiles") or "C:\\Program Files"
        prefixes.append(Path(prog_files).resolve())

        prog_files_x86 = os.environ.get("ProgramFiles(x86)") or "C:\\Program Files (x86)"
        prefixes.append(Path(prog_files_x86).resolve())

        return prefixes

    def validate_file_for_quarantine(self, file_path: str | Path) -> tuple[bool, str, Path | None, str | None]:
        """Validate source file for quarantine and compute pre-quarantine SHA-256.
        
        Returns:
            (is_safe, message, resolved_path, pre_quarantine_sha256)
        """
        raw_str = str(file_path)
        if not raw_str or not raw_str.strip():
            return False, "File path cannot be empty", None, None

        # Traversal check
        if ".." in raw_str:
            return False, "Path traversal sequence ('..') detected in target path", None, None

        path = Path(file_path).resolve()

        # Drive root check (e.g. C:\)
        if path.parent == path:
            return False, f"Target path is a filesystem drive root: {path}", None, None

        # Check existence
        if not path.exists():
            return False, f"Target file does not exist: {path}", None, None

        if not path.is_file():
            return False, f"Target path is not a regular file: {path}", None, None

        # Check against system forbidden paths
        for prefix in self.get_system_forbidden_prefixes():
            try:
                # If target is identical to prefix or is inside C:\Windows etc.
                if path == prefix or prefix in path.parents:
                    return False, f"Target file is within protected Windows system directory: {prefix}", None, None
            except Exception:
                continue

        # Check not already inside quarantine directory
        try:
            if path == self.quarantine_root or self.quarantine_root in path.parents:
                return False, "Target file is already within quarantine directory", None, None
        except Exception:
            pass

        # Compute SHA-256
        try:
            sha256 = self.compute_sha256(path)
        except OSError as exc:
            return False, f"Failed to compute file hash: {exc}", None, None

        return True, "File verified safe for quarantine", path, sha256

    def compute_sha256(self, path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_quarantine_destination(self, source_path: Path, sha256: str) -> Path:
        """Generate safe quarantine destination file path."""
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        sanitized_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in source_path.name)
        quar_name = f"{sha256[:16]}_{sanitized_name}.quar"
        return self.quarantine_root / quar_name

    def validate_restore(self, quarantine_file: str | Path, original_destination: str | Path, expected_sha256: str) -> tuple[bool, str, Path | None, Path | None]:
        """Validate restoration of a quarantined file.
        
        Returns:
            (is_safe, message, resolved_quar_path, resolved_dest_path)
        """
        quar_path = Path(quarantine_file).resolve()
        dest_path = Path(original_destination).resolve()

        if not quar_path.exists() or not quar_path.is_file():
            return False, f"Quarantined file not found: {quar_path}", None, None

        # Verify integrity
        actual_sha = self.compute_sha256(quar_path)
        if actual_sha.lower() != expected_sha256.lower():
            return (
                False,
                f"Quarantine integrity failure: hash {actual_sha} does not match expected {expected_sha256}",
                None,
                None,
            )

        # Ensure destination is not drive root or inside forbidden system directory
        if dest_path.parent == dest_path:
            return False, f"Restoration destination is a filesystem drive root: {dest_path}", None, None

        for prefix in self.get_system_forbidden_prefixes():
            if dest_path == prefix or prefix in dest_path.parents:
                return False, f"Restoration destination is within protected Windows system directory: {prefix}", None, None

        return True, "File verified safe for restoration", quar_path, dest_path


class NetworkSafetyValidator:
    """Validates network blocking parameters and formats safe commands."""

    def __init__(self) -> None:
        self.protected_ips = {
            "127.0.0.1",
            "::1",
            "localhost",
            "0.0.0.0",
            "255.255.255.255",
        }

    def validate_ip(self, ip_str: str) -> tuple[bool, str, str | None]:
        """Validate IP address, rejecting loopback, broadcast, and invalid formats."""
        if not ip_str or not ip_str.strip():
            return False, "IP address cannot be empty", None

        ip_clean = ip_str.strip().lower()
        if ip_clean in self.protected_ips:
            return False, f"Cannot block loopback or broadcast address '{ip_clean}'", None

        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            if ip_obj.is_loopback:
                return False, f"Refusing to block loopback address '{ip_clean}'", None
            if ip_obj.is_multicast:
                return False, f"Refusing to block multicast address '{ip_clean}'", None
            if ip_obj.is_unspecified:
                return False, f"Refusing to block unspecified address '{ip_clean}'", None
            return True, f"IP '{ip_clean}' is valid", str(ip_obj)
        except ValueError:
            return False, f"Invalid IP address format: '{ip_str}'", None

    def validate_port(self, port: int | None) -> tuple[bool, str]:
        """Validate network port range."""
        if port is None:
            return True, "No specific port specified"
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, f"Invalid port {port}. Must be between 1 and 65535"
        return True, f"Port {port} is valid"

    def format_block_rule_name(self, action_id: str) -> str:
        """Create sanitized unique Windows firewall rule name."""
        clean_id = "".join(c for c in action_id if c.isalnum() or c in "_-")
        return f"TrojanDefense_Block_{clean_id}"

    def build_netsh_block_args(
        self,
        rule_name: str,
        remote_ip: str,
        port: int | None = None,
        direction: str = "out",
    ) -> list[str]:
        """Build argument list for netsh firewall rule creation (shell=False)."""
        args = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={remote_ip}",
        ]
        if port:
            args.extend(["protocol=TCP", f"remoteport={port}"])
        return args

    def build_netsh_delete_args(self, rule_name: str) -> list[str]:
        """Build argument list for netsh firewall rule deletion (shell=False)."""
        return [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
