"""Unit tests for defensive response safety validators."""

import os
from pathlib import Path
import psutil
import pytest

from trojan_defense.response.safety import (
    NetworkSafetyValidator,
    PathSafetyValidator,
    ProcessSafetyValidator,
)


class TestProcessSafetyValidator:
    """Tests for ProcessSafetyValidator."""

    def test_reject_kernel_system_pids(self):
        validator = ProcessSafetyValidator()
        # PID 0
        safe, msg, proc = validator.validate_termination(0)
        assert not safe
        assert "kernel/system" in msg

        # PID 4
        safe, msg, proc = validator.validate_termination(4)
        assert not safe
        assert "kernel/system" in msg

    def test_reject_self_pid_protection(self):
        validator = ProcessSafetyValidator()
        current_pid = os.getpid()
        safe, msg, proc = validator.validate_termination(current_pid)
        assert not safe
        assert "self-protection" in msg

    def test_reject_non_existent_pid(self):
        validator = ProcessSafetyValidator()
        safe, msg, proc = validator.validate_termination(99999999)
        assert not safe
        assert "does not exist" in msg

    def test_reject_protected_system_processes(self):
        validator = ProcessSafetyValidator(protected_processes=["explorer.exe", "svchost.exe"])
        # Find any running protected process or verify logic
        for p in psutil.process_iter(["name", "pid"]):
            try:
                name = p.info["name"]
                if name and name.lower() == "explorer.exe":
                    safe, msg, _ = validator.validate_termination(p.info["pid"])
                    assert not safe
                    assert "protected" in msg
                    break
            except Exception:
                continue

    def test_pid_reuse_detection(self):
        validator = ProcessSafetyValidator()
        # Find a running process that is not self or protected
        target_proc = None
        for p in psutil.process_iter(["name", "pid"]):
            try:
                if p.pid > 100 and p.pid != os.getpid() and p.name().lower() not in validator.protected_names:
                    target_proc = p
                    break
            except Exception:
                continue

        if target_proc:
            real_create_time = target_proc.create_time()
            # Pass bogus expected create time (1000 seconds older)
            bogus_time = real_create_time - 1000.0
            safe, msg, _ = validator.validate_termination(
                pid=target_proc.pid,
                target_create_time=bogus_time,
            )
            assert not safe
            assert "PID reuse detected" in msg

    def test_process_name_mismatch_detection(self):
        validator = ProcessSafetyValidator()
        target_proc = None
        for p in psutil.process_iter(["name", "pid"]):
            try:
                if p.pid > 100 and p.pid != os.getpid() and p.name().lower() not in validator.protected_names:
                    target_proc = p
                    break
            except Exception:
                continue

        if target_proc:
            safe, msg, _ = validator.validate_termination(
                pid=target_proc.pid,
                target_process_name="totally_wrong_name_123.exe",
            )
            assert not safe
            assert "identity mismatch" in msg


class TestPathSafetyValidator:
    """Tests for PathSafetyValidator."""

    def test_reject_empty_and_traversal_paths(self, tmp_path):
        validator = PathSafetyValidator(quarantine_root=tmp_path / "quarantine")

        safe, msg, _, _ = validator.validate_file_for_quarantine("")
        assert not safe
        assert "empty" in msg

        safe, msg, _, _ = validator.validate_file_for_quarantine("..\\..\\malware.exe")
        assert not safe
        assert "traversal" in msg

    def test_reject_system_directories(self, tmp_path):
        validator = PathSafetyValidator(quarantine_root=tmp_path / "quarantine")
        win_dir = os.environ.get("SystemRoot", "C:\\Windows")
        sys_file = Path(win_dir) / "notepad.exe"
        if sys_file.exists():
            safe, msg, _, _ = validator.validate_file_for_quarantine(sys_file)
            assert not safe
            assert "protected Windows system directory" in msg

    def test_valid_file_quarantine_validation(self, tmp_path):
        quar_dir = tmp_path / "quarantine"
        validator = PathSafetyValidator(quarantine_root=quar_dir)

        test_file = tmp_path / "trojan_payload.bin"
        test_file.write_bytes(b"MALICIOUS_SIMULATED_CONTENT_FOR_DEFENSIVE_TEST")

        safe, msg, resolved, sha256 = validator.validate_file_for_quarantine(test_file)
        assert safe
        assert resolved == test_file.resolve()
        assert sha256 is not None
        assert len(sha256) == 64

        dest = validator.get_quarantine_destination(resolved, sha256)
        assert dest.parent == quar_dir.resolve()
        assert dest.suffix == ".quar"
        assert sha256[:16] in dest.name

    def test_restore_validation(self, tmp_path):
        quar_dir = tmp_path / "quarantine"
        validator = PathSafetyValidator(quarantine_root=quar_dir)

        quar_file = quar_dir / "abc123_payload.bin.quar"
        quar_file.parent.mkdir(parents=True, exist_ok=True)
        content = b"RESTORABLE_CONTENT"
        quar_file.write_bytes(content)

        import hashlib
        correct_sha = hashlib.sha256(content).hexdigest()
        dest = tmp_path / "restored" / "payload.bin"

        # Valid restore
        safe, msg, q_path, d_path = validator.validate_restore(
            quarantine_file=quar_file,
            original_destination=dest,
            expected_sha256=correct_sha,
        )
        assert safe
        assert q_path == quar_file.resolve()

        # Integrity failure
        safe, msg, _, _ = validator.validate_restore(
            quarantine_file=quar_file,
            original_destination=dest,
            expected_sha256="wrong_hash_value_0000000000000000000000000000000000000000000000000",
        )
        assert not safe
        assert "integrity failure" in msg


class TestNetworkSafetyValidator:
    """Tests for NetworkSafetyValidator."""

    def test_reject_loopback_and_broadcast(self):
        validator = NetworkSafetyValidator()
        for bad_ip in ["127.0.0.1", "::1", "localhost", "255.255.255.255", "0.0.0.0"]:
            safe, msg, _ = validator.validate_ip(bad_ip)
            assert not safe
            assert "loopback" in msg or "broadcast" in msg or "unspecified" in msg

    def test_reject_multicast(self):
        validator = NetworkSafetyValidator()
        safe, msg, _ = validator.validate_ip("224.0.0.1")
        assert not safe
        assert "multicast" in msg

    def test_valid_external_ip(self):
        validator = NetworkSafetyValidator()
        safe, msg, clean = validator.validate_ip("198.51.100.25")
        assert safe
        assert clean == "198.51.100.25"

    def test_port_validation(self):
        validator = NetworkSafetyValidator()
        assert validator.validate_port(None)[0]
        assert validator.validate_port(80)[0]
        assert validator.validate_port(443)[0]
        assert validator.validate_port(65535)[0]
        assert not validator.validate_port(0)[0]
        assert not validator.validate_port(70000)[0]
        assert not validator.validate_port(-1)[0]

    def test_netsh_command_construction(self):
        validator = NetworkSafetyValidator()
        rule_name = validator.format_block_rule_name("act-98765")
        assert rule_name == "TrojanDefense_Block_act-98765"

        args = validator.build_netsh_block_args(
            rule_name=rule_name,
            remote_ip="198.51.100.25",
            port=4444,
            direction="out",
        )
        assert args == [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=TrojanDefense_Block_act-98765",
            "dir=out",
            "action=block",
            "remoteip=198.51.100.25",
            "protocol=TCP",
            "remoteport=4444",
        ]

        del_args = validator.build_netsh_delete_args(rule_name=rule_name)
        assert del_args == [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=TrojanDefense_Block_act-98765",
        ]
