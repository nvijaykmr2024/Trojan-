"""Response Recommender for generating structured advisory response options.

Analyzes security alerts, behavioral findings, and telemetry to propose
safe, recommended remediation actions to human analysts.

Under NO circumstances does this module autonomously execute destructive actions.
All recommendations are strictly advisory and require human authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from trojan_defense.alerting.models import Alert
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.response.models import ResponseActionType

logger = get_logger("response.recommender")


@dataclass
class ActionRecommendation:
    """An advisory recommendation for defensive response."""
    recommendation_id: str
    action_type: str
    priority: str
    rationale: str
    target_params: dict[str, Any]
    risk_score: int
    rule_id: str | None = None
    alert_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResponseRecommender:
    """Generates structured advisory response recommendations for security alerts."""

    def recommend_for_alert(self, alert: Alert) -> list[ActionRecommendation]:
        """Produce advisory recommendations for a given security alert."""
        recommendations: list[ActionRecommendation] = []
        alert_id = alert.alert_id
        rule_id = alert.rule_id
        score = alert.risk_score
        # Collect contextual attributes across alert fields, extra, and evidence
        context: dict[str, Any] = dict(getattr(alert, "extra", {}) or {})
        for ev in (getattr(alert, "evidence", []) or []):
            if isinstance(ev, dict):
                context.update(ev)
        if hasattr(alert, "context") and isinstance(alert.context, dict):
            context.update(alert.context)

        rec_idx = 1

        # 1. Process termination recommendation
        pid = alert.pid or context.get("pid")
        process_name = getattr(alert, "process_name", None) or context.get("process_name") or context.get("name")
        create_time = context.get("create_time") or context.get("process_create_time")
        exe = getattr(alert, "executable_path", None) or context.get("exe") or context.get("process_path") or context.get("path")

        if pid and pid > 4:
            priority = "HIGH" if score >= 70 else "MEDIUM"
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"{alert_id}-rec-{rec_idx}",
                    action_type=ResponseActionType.PROCESS_TERMINATION.value,
                    priority=priority,
                    rationale=f"Terminate suspicious process '{process_name or f'PID {pid}'}' implicated in rule {rule_id} (Score: {score})",
                    target_params={
                        "pid": int(pid),
                        "process_name": process_name,
                        "create_time": create_time,
                        "exe": exe,
                    },
                    risk_score=score,
                    rule_id=rule_id,
                    alert_id=alert_id,
                )
            )
            rec_idx += 1

        # 2. File quarantine recommendation
        target_path = context.get("target_path") or context.get("file_path") or context.get("path")
        if target_path and isinstance(target_path, str) and not target_path.lower().endswith(".exe") and pid:
            # File operation
            priority = "HIGH" if score >= 70 else "MEDIUM"
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"{alert_id}-rec-{rec_idx}",
                    action_type=ResponseActionType.FILE_QUARANTINE.value,
                    priority=priority,
                    rationale=f"Quarantine suspicious file '{target_path}' for forensic analysis",
                    target_params={
                        "file_path": target_path,
                    },
                    risk_score=score,
                    rule_id=rule_id,
                    alert_id=alert_id,
                )
            )
            rec_idx += 1
        elif exe and isinstance(exe, str):
            # Executable file quarantine
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"{alert_id}-rec-{rec_idx}",
                    action_type=ResponseActionType.FILE_QUARANTINE.value,
                    priority="MEDIUM",
                    rationale=f"Quarantine malicious executable binary '{exe}' to prevent re-execution",
                    target_params={
                        "file_path": exe,
                    },
                    risk_score=score,
                    rule_id=rule_id,
                    alert_id=alert_id,
                )
            )
            rec_idx += 1

        # 3. Network block recommendation
        remote_ip = context.get("remote_ip") or context.get("destination_ip") or context.get("ip")
        remote_port = context.get("remote_port") or context.get("destination_port") or context.get("port")
        if remote_ip and isinstance(remote_ip, str) and remote_ip not in ("127.0.0.1", "::1", "localhost"):
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"{alert_id}-rec-{rec_idx}",
                    action_type=ResponseActionType.NETWORK_BLOCK.value,
                    priority="HIGH",
                    rationale=f"Block outbound communications to suspicious remote endpoint {remote_ip}:{remote_port or '*'}",
                    target_params={
                        "remote_ip": remote_ip,
                        "port": int(remote_port) if remote_port else None,
                        "direction": "out",
                    },
                    risk_score=score,
                    rule_id=rule_id,
                    alert_id=alert_id,
                )
            )
            rec_idx += 1

        # 4. Host isolation recommendation for critical threat scores
        if score >= 85:
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"{alert_id}-rec-{rec_idx}",
                    action_type=ResponseActionType.HOST_ISOLATION.value,
                    priority="CRITICAL",
                    rationale=f"Isolate host from external network traffic due to critical threat level ({score}) under rule {rule_id}",
                    target_params={
                        "reason": f"High risk alert {alert_id} (Score {score})",
                    },
                    risk_score=score,
                    rule_id=rule_id,
                    alert_id=alert_id,
                )
            )
            rec_idx += 1

        return recommendations
