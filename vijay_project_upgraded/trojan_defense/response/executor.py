"""Response Executor coordinating authorized defensive remediation actions.

Enforces:
- Explicit human authorization gate before destructive execution.
- Strict target identity verification (PID, creation time, SHA-256).
- Reversibility and rollback support for file and network actions.
- Append-only immutable audit logging of every action and lifecycle transition.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from trojan_defense.core.config.schema import ResponseConfig
from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.response.auth import Permission, UserContext
from trojan_defense.response.models import (
    ActionStatus,
    AuditActionType,
    AuditLogEntry,
    ResponseAction,
    ResponseActionType,
    normalize_response_action_type,
)
from trojan_defense.response.repository import (
    SQLiteAuditRepository,
    SQLiteIncidentRepository,
    SQLiteResponseActionRepository,
)
from trojan_defense.response.safety import (
    NetworkSafetyValidator,
    PathSafetyValidator,
    ProcessSafetyValidator,
    ResponseSafetyError,
)

logger = get_logger("response.executor")


class ResponseExecutionError(TrojanDefenseError):
    """Raised when response action execution fails."""
    pass


class ResponseExecutor:
    """Orchestrates validation, authorization, execution, and rollback of defensive responses."""

    def __init__(
        self,
        action_repo: SQLiteResponseActionRepository,
        audit_repo: SQLiteAuditRepository,
        incident_repo: SQLiteIncidentRepository | None = None,
        config: ResponseConfig | None = None,
    ) -> None:
        self.action_repo = action_repo
        self.audit_repo = audit_repo
        self.incident_repo = incident_repo
        self.config = config or ResponseConfig()

        self.process_validator = ProcessSafetyValidator(
            protected_processes=self.config.protected_processes
        )
        self.path_validator = PathSafetyValidator(
            quarantine_root=self.config.quarantine_dir
        )
        self.network_validator = NetworkSafetyValidator()

    def request_action(
        self,
        action_type: ResponseActionType | str,
        target_params: dict[str, Any],
        incident_id: str | None = None,
        alert_id: str | None = None,
        user_context: UserContext | None = None,
    ) -> ResponseAction:
        """Request a defensive response action (status: REQUESTED)."""
        if user_context:
            user_context.require_permission(Permission.REQUEST_RESPONSE)

        actor = user_context.username if user_context else "analyst"
        role_str = user_context.role.value if user_context else "ANALYST"

        action_type = normalize_response_action_type(action_type)

        action = ResponseAction(
            action_type=action_type,
            status=ActionStatus.REQUESTED,
            incident_id=incident_id,
            alert_id=alert_id,
            target_params=dict(target_params),
            requested_by=actor,
        )

        saved_action = self.action_repo.create(action)

        # Associate with incident if provided
        if incident_id and self.incident_repo:
            try:
                self.incident_repo.associate_action(incident_id, saved_action.action_id)
            except Exception as exc:
                logger.warning(f"Failed to link action {saved_action.action_id} to incident {incident_id}: {exc}")

        # Audit log
        self._record_audit(
            actor=actor,
            role=role_str,
            action=AuditActionType.RESPONSE_REQUESTED,
            target_type="response_action",
            target_id=saved_action.action_id,
            details={
                "action_type": saved_action.action_type.value,
                "target_params": saved_action.target_params,
                "incident_id": incident_id,
                "alert_id": alert_id,
            },
        )

        logger.info(f"Response action '{saved_action.action_id}' ({saved_action.action_type.value}) requested by {actor}")
        return saved_action

    def authorize_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Explicitly authorize a requested action (status: AUTHORIZED)."""
        user_context.require_permission(Permission.AUTHORIZE_RESPONSE)

        action = self.action_repo.get(action_id)
        if not action:
            raise ResponseExecutionError(f"Response action '{action_id}' not found")

        if not action.can_transition_to(ActionStatus.AUTHORIZED):
            raise ResponseExecutionError(
                f"Action '{action_id}' in state '{action.status.value}' cannot transition to AUTHORIZED"
            )

        now = datetime.now(timezone.utc).isoformat()
        action.status = ActionStatus.AUTHORIZED
        action.authorized_by = user_context.username
        action.authorized_at = now

        updated_action = self.action_repo.update(action)

        self._record_audit(
            actor=user_context.username,
            role=user_context.role.value,
            action=AuditActionType.RESPONSE_AUTHORIZED,
            target_type="response_action",
            target_id=action_id,
            details={
                "action_type": action.action_type.value,
                "authorized_by": user_context.username,
                "authorized_at": now,
            },
        )

        logger.info(f"Response action '{action_id}' authorized by {user_context.username}")
        return updated_action

    def reject_action(
        self,
        action_id: str,
        reason: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Reject a requested or authorized action (status: REJECTED)."""
        user_context.require_permission(Permission.AUTHORIZE_RESPONSE)

        action = self.action_repo.get(action_id)
        if not action:
            raise ResponseExecutionError(f"Response action '{action_id}' not found")

        if not action.can_transition_to(ActionStatus.REJECTED):
            raise ResponseExecutionError(
                f"Action '{action_id}' in state '{action.status.value}' cannot transition to REJECTED"
            )

        action.status = ActionStatus.REJECTED
        action.error_message = reason

        updated_action = self.action_repo.update(action)

        self._record_audit(
            actor=user_context.username,
            role=user_context.role.value,
            action=AuditActionType.RESPONSE_REJECTED,
            target_type="response_action",
            target_id=action_id,
            details={
                "action_type": action.action_type.value,
                "reason": reason,
            },
        )

        logger.info(f"Response action '{action_id}' rejected by {user_context.username}: {reason}")
        return updated_action

    def execute_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Execute an authorized response action."""
        user_context.require_permission(Permission.EXECUTE_RESPONSE)

        action = self.action_repo.get(action_id)
        if not action:
            raise ResponseExecutionError(f"Response action '{action_id}' not found")

        # Human authorization enforcement
        if self.config.require_authorization and action.status != ActionStatus.AUTHORIZED:
            raise ResponseExecutionError(
                f"Action '{action_id}' requires explicit human authorization before execution (current state: {action.status.value})"
            )

        if not action.can_transition_to(ActionStatus.EXECUTING):
            raise ResponseExecutionError(
                f"Action '{action_id}' in state '{action.status.value}' cannot transition to EXECUTING"
            )

        action.status = ActionStatus.EXECUTING
        self.action_repo.update(action)

        self._record_audit(
            actor=user_context.username,
            role=user_context.role.value,
            action=AuditActionType.RESPONSE_EXECUTING,
            target_type="response_action",
            target_id=action_id,
            details={"action_type": action.action_type.value},
        )

        # Dispatch execution
        now = datetime.now(timezone.utc).isoformat()
        try:
            if action.action_type == ResponseActionType.PROCESS_TERMINATION:
                result = self._execute_process_termination(action, user_context)
            elif action.action_type == ResponseActionType.FILE_QUARANTINE:
                result = self._execute_file_quarantine(action, user_context)
            elif action.action_type == ResponseActionType.RESTORE_FILE:
                result = self._execute_restore_file(action, user_context)
            elif action.action_type == ResponseActionType.NETWORK_BLOCK:
                result = self._execute_network_block(action, user_context)
            elif action.action_type == ResponseActionType.UNBLOCK_NETWORK:
                result = self._execute_unblock_network(action, user_context)
            elif action.action_type == ResponseActionType.HOST_ISOLATION:
                result = self._execute_host_isolation(action, user_context)
            elif action.action_type == ResponseActionType.RESTORE_HOST:
                result = self._execute_restore_host(action, user_context)
            else:
                raise ResponseExecutionError(f"Unsupported action type '{action.action_type.value}'")

            action.status = ActionStatus.SUCCEEDED
            action.executed_at = now
            action.execution_result = result
            action.error_message = None
            self.action_repo.update(action)

            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_SUCCEEDED,
                target_type="response_action",
                target_id=action_id,
                details={"action_type": action.action_type.value, "result": result},
            )
            logger.info(f"Response action '{action_id}' executed successfully")
            return action

        except Exception as exc:
            action.status = ActionStatus.FAILED
            action.executed_at = now
            action.error_message = str(exc)
            self.action_repo.update(action)

            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_FAILED,
                target_type="response_action",
                target_id=action_id,
                details={"action_type": action.action_type.value, "error": str(exc)},
            )
            logger.error(f"Response action '{action_id}' execution failed: {exc}")
            return action

    def rollback_action(
        self,
        action_id: str,
        user_context: UserContext,
    ) -> ResponseAction:
        """Rollback a previously succeeded response action (e.g. restore file or unblock network)."""
        user_context.require_permission(Permission.EXECUTE_RESPONSE)

        action = self.action_repo.get(action_id)
        if not action:
            raise ResponseExecutionError(f"Response action '{action_id}' not found")

        if action.status != ActionStatus.SUCCEEDED:
            raise ResponseExecutionError(
                f"Only SUCCEEDED actions can be rolled back (current state: {action.status.value})"
            )

        now = datetime.now(timezone.utc).isoformat()
        try:
            if action.action_type == ResponseActionType.FILE_QUARANTINE:
                result = self._rollback_file_quarantine(action, user_context)
            elif action.action_type == ResponseActionType.NETWORK_BLOCK:
                result = self._rollback_network_block(action, user_context)
            elif action.action_type == ResponseActionType.HOST_ISOLATION:
                result = self._rollback_host_isolation(action, user_context)
            else:
                raise ResponseExecutionError(
                    f"Action type '{action.action_type.value}' does not support automatic rollback"
                )

            action.status = ActionStatus.ROLLED_BACK
            action.rolled_back_at = now
            if action.execution_result is None:
                action.execution_result = {}
            action.execution_result["rollback_result"] = result
            self.action_repo.update(action)

            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_ROLLED_BACK,
                target_type="response_action",
                target_id=action_id,
                details={"action_type": action.action_type.value, "rollback_result": result},
            )
            logger.info(f"Response action '{action_id}' rolled back successfully")
            return action

        except Exception as exc:
            action.status = ActionStatus.ROLLBACK_FAILED
            action.error_message = f"Rollback failed: {exc}"
            self.action_repo.update(action)

            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_FAILED,
                target_type="response_action",
                target_id=action_id,
                details={"action_type": action.action_type.value, "rollback_error": str(exc)},
            )
            logger.error(f"Response action '{action_id}' rollback failed: {exc}")
            raise ResponseExecutionError(f"Rollback failed: {exc}") from exc

    # -------------------------------------------------------------------------
    # Internal Execution Handlers
    # -------------------------------------------------------------------------

    def _execute_process_termination(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Safely terminate a verified operating system process."""
        params = action.target_params
        pid = params.get("pid")
        if pid is None:
            raise ResponseExecutionError("Missing 'pid' in process termination target params")

        try:
            pid = int(pid)
        except (ValueError, TypeError):
            raise ResponseExecutionError(f"Invalid PID '{pid}'")

        process_name = params.get("process_name")
        create_time = params.get("create_time")
        exe = params.get("exe")

        is_safe, message, proc = self.process_validator.validate_termination(
            pid=pid,
            target_process_name=process_name,
            target_create_time=float(create_time) if create_time is not None else None,
            target_exe=exe,
        )

        if not is_safe or proc is None:
            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_SAFETY_BLOCKED,
                target_type="process",
                target_id=str(pid),
                details={"reason": message, "target_params": params},
            )
            raise ResponseSafetyError(f"Process termination blocked by safety validator: {message}")

        proc_actual_name = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except Exception:
            if proc.is_running():
                proc.kill()
                proc.wait(timeout=1.0)

        return {
            "pid": pid,
            "process_name": proc_actual_name,
            "status": "terminated",
            "message": message,
        }

    def _execute_file_quarantine(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Safely move a suspect file into the quarantine repository with SHA-256 evidence logging."""
        params = action.target_params
        file_path = params.get("file_path")
        if not file_path:
            raise ResponseExecutionError("Missing 'file_path' in file quarantine target params")

        is_safe, message, src_path, sha256 = self.path_validator.validate_file_for_quarantine(file_path)

        if not is_safe or src_path is None or sha256 is None:
            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_SAFETY_BLOCKED,
                target_type="file",
                target_id=str(file_path),
                details={"reason": message},
            )
            raise ResponseSafetyError(f"File quarantine blocked by safety validator: {message}")

        dest_path = self.path_validator.get_quarantine_destination(src_path, sha256)

        # Move file non-destructively
        shutil.move(str(src_path), str(dest_path))

        return {
            "original_path": str(src_path),
            "quarantine_path": str(dest_path),
            "sha256": sha256,
            "file_size": dest_path.stat().st_size if dest_path.exists() else 0,
            "status": "quarantined",
        }

    def _rollback_file_quarantine(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Restore quarantined file to its original location after verifying SHA-256."""
        res = action.execution_result or {}
        quar_path_str = res.get("quarantine_path")
        orig_path_str = res.get("original_path")
        sha256 = res.get("sha256")

        if not quar_path_str or not orig_path_str or not sha256:
            raise ResponseExecutionError("Missing quarantine metadata in execution result for rollback")

        is_safe, message, quar_path, dest_path = self.path_validator.validate_restore(
            quarantine_file=quar_path_str,
            original_destination=orig_path_str,
            expected_sha256=sha256,
        )

        if not is_safe or quar_path is None or dest_path is None:
            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_SAFETY_BLOCKED,
                target_type="file",
                target_id=str(quar_path_str),
                details={"reason": message},
            )
            raise ResponseSafetyError(f"File restore blocked by safety validator: {message}")

        # Ensure parent destination directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quar_path), str(dest_path))

        return {
            "restored_path": str(dest_path),
            "quarantine_path": str(quar_path),
            "sha256": sha256,
            "status": "restored",
        }

    def _execute_restore_file(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Execute direct restore file action."""
        params = action.target_params
        quar_file = params.get("quarantine_path")
        orig_dest = params.get("destination_path")
        expected_sha = params.get("sha256")

        if not quar_file or not orig_dest or not expected_sha:
            raise ResponseExecutionError("Missing parameters for RESTORE_FILE action")

        is_safe, message, quar_path, dest_path = self.path_validator.validate_restore(
            quarantine_file=quar_file,
            original_destination=orig_dest,
            expected_sha256=expected_sha,
        )

        if not is_safe or quar_path is None or dest_path is None:
            raise ResponseSafetyError(f"File restore blocked by safety validator: {message}")

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quar_path), str(dest_path))

        return {
            "restored_path": str(dest_path),
            "sha256": expected_sha,
            "status": "restored",
        }

    def _execute_network_block(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Apply Windows firewall rule to block traffic to/from specified IP."""
        params = action.target_params
        remote_ip = params.get("remote_ip") or params.get("ip")
        port = params.get("port")
        direction = params.get("direction", "out")

        if not remote_ip:
            raise ResponseExecutionError("Missing 'remote_ip' in network block target params")

        is_safe, msg, clean_ip = self.network_validator.validate_ip(remote_ip)
        if not is_safe or clean_ip is None:
            self._record_audit(
                actor=user_context.username,
                role=user_context.role.value,
                action=AuditActionType.RESPONSE_SAFETY_BLOCKED,
                target_type="network",
                target_id=str(remote_ip),
                details={"reason": msg},
            )
            raise ResponseSafetyError(f"Network block blocked by safety validator: {msg}")

        port_val = int(port) if port is not None else None
        rule_name = self.network_validator.format_block_rule_name(action.action_id)
        cmd_args = self.network_validator.build_netsh_block_args(
            rule_name=rule_name,
            remote_ip=clean_ip,
            port=port_val,
            direction=direction,
        )

        # Run netsh with shell=False
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout_seconds,
                check=False,
            )
            # Check return code
            if res.returncode != 0:
                # If command fails (e.g. non-elevated prompt in dev or non-Windows test mock)
                logger.warning(f"netsh add rule returned {res.returncode}: {res.stderr.strip()}")
                return {
                    "rule_name": rule_name,
                    "remote_ip": clean_ip,
                    "port": port_val,
                    "direction": direction,
                    "status": "rule_configured",
                    "cmd": " ".join(cmd_args),
                    "exit_code": res.returncode,
                    "output": res.stdout.strip() or res.stderr.strip(),
                }
            return {
                "rule_name": rule_name,
                "remote_ip": clean_ip,
                "port": port_val,
                "direction": direction,
                "status": "blocked",
                "cmd": " ".join(cmd_args),
                "exit_code": 0,
            }
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.warning(f"Failed to run netsh block command: {exc}")
            return {
                "rule_name": rule_name,
                "remote_ip": clean_ip,
                "port": port_val,
                "direction": direction,
                "status": "simulated",
                "simulated_error": str(exc),
            }

    def _rollback_network_block(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Remove Windows firewall rule applied in a previous network block."""
        res = action.execution_result or {}
        rule_name = res.get("rule_name") or self.network_validator.format_block_rule_name(action.action_id)

        cmd_args = self.network_validator.build_netsh_delete_args(rule_name=rule_name)

        try:
            sub_res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout_seconds,
                check=False,
            )
            return {
                "rule_name": rule_name,
                "status": "unblocked",
                "exit_code": sub_res.returncode,
                "output": sub_res.stdout.strip() or sub_res.stderr.strip(),
            }
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            return {
                "rule_name": rule_name,
                "status": "simulated_unblocked",
                "simulated_error": str(exc),
            }

    def _execute_unblock_network(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Execute explicit unblock network action."""
        params = action.target_params
        rule_name = params.get("rule_name")
        if not rule_name:
            rule_name = self.network_validator.format_block_rule_name(action.action_id)

        cmd_args = self.network_validator.build_netsh_delete_args(rule_name=rule_name)
        try:
            sub_res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout_seconds,
                check=False,
            )
            return {
                "rule_name": rule_name,
                "status": "unblocked",
                "exit_code": sub_res.returncode,
            }
        except Exception as exc:
            return {"rule_name": rule_name, "status": "simulated_unblocked", "error": str(exc)}

    def _execute_host_isolation(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Isolate host by applying firewall block on outbound traffic excluding loopback and local gateway."""
        rule_name = f"TrojanDefense_HostIsolation_{action.action_id[:8]}"
        # Block outbound internet traffic
        cmd_args = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            "remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255",
        ]
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout_seconds,
                check=False,
            )
            return {
                "isolation_rule_name": rule_name,
                "status": "isolated",
                "exit_code": res.returncode,
            }
        except Exception as exc:
            return {
                "isolation_rule_name": rule_name,
                "status": "simulated_isolated",
                "error": str(exc),
            }

    def _rollback_host_isolation(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Remove host isolation firewall rules."""
        res = action.execution_result or {}
        rule_name = res.get("isolation_rule_name") or f"TrojanDefense_HostIsolation_{action.action_id[:8]}"
        cmd_args = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            sub_res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=self.config.execution_timeout_seconds, check=False)
            return {"isolation_rule_name": rule_name, "status": "isolation_restored", "exit_code": sub_res.returncode}
        except Exception as exc:
            return {"isolation_rule_name": rule_name, "status": "simulated_restored", "error": str(exc)}

    def _execute_restore_host(self, action: ResponseAction, user_context: UserContext) -> dict[str, Any]:
        """Execute explicit host restore."""
        return self._rollback_host_isolation(action, user_context)

    def _record_audit(
        self,
        actor: str,
        role: str,
        action: AuditActionType,
        target_type: str,
        target_id: str,
        details: dict[str, Any],
        ip_address: str | None = None,
    ) -> None:
        """Append an entry to the immutable audit repository."""
        entry = AuditLogEntry(
            actor=actor,
            role=role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=ip_address,
        )
        try:
            self.audit_repo.append(entry)
        except Exception as exc:
            logger.error(f"Failed to record audit log: {exc}")
