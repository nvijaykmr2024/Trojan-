"""Deterministic Risk Scoring Engine for Phase 10.

Evaluates behavioral correlation findings to produce bounded, explainable
risk scores (0-100) and authoritative severity classifications.
"""

from typing import Any

from trojan_defense.alerting.models import RiskScore, ScoringReason
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.core.config.schema import RiskConfig
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory
from trojan_defense.core.models.severity import Severity

logger = get_logger("alerting.scorer")

_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


class RiskScoringEngine:
    """Deterministic, transparent risk scoring engine.

    Scores behavioral findings into a bounded [0, 100] range with explicit,
    explainable scoring reasons and deterministic severity classification.
    """

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def calculate_score(self, finding: BehaviorFinding) -> RiskScore:
        """Calculate a bounded risk score and breakdown for a BehaviorFinding."""
        reasons: list[ScoringReason] = []

        # 1. Base Rule Score
        base_score = self.config.rule_base_scores.get(
            finding.rule_id, self.config.default_base_score
        )
        reasons.append(
            ScoringReason(
                factor="base_rule",
                contribution=base_score,
                reason=f"Base risk score for behavioral rule {finding.rule_id} ({finding.rule_name or 'unnamed'})",
            )
        )

        # 2. Deception Decoy / Honeytoken Bonus
        if self._has_deception_interaction(finding):
            bonus = self.config.deception_bonus
            if bonus > 0:
                reasons.append(
                    ScoringReason(
                        factor="deception_interaction",
                        contribution=bonus,
                        reason="Correlated interaction with cyber deception decoy or honeytoken asset",
                    )
                )

        # 3. Privilege Escalation / Elevated Context Bonus
        if self._has_elevated_privilege(finding):
            bonus = self.config.privilege_bonus
            if bonus > 0:
                reasons.append(
                    ScoringReason(
                        factor="privilege_escalation",
                        contribution=bonus,
                        reason="Activity performed with elevated privileges or privilege escalation detected",
                    )
                )

        # 4. External Network Activity Bonus
        if self._has_network_activity(finding):
            bonus = self.config.network_bonus
            if bonus > 0:
                reasons.append(
                    ScoringReason(
                        factor="network_communication",
                        contribution=bonus,
                        reason="Correlated outbound or external network activity detected",
                    )
                )

        # 5. Sensitive File Activity Bonus
        if self._has_sensitive_file_activity(finding):
            bonus = self.config.sensitive_file_bonus
            if bonus > 0:
                reasons.append(
                    ScoringReason(
                        factor="sensitive_file_activity",
                        contribution=bonus,
                        reason="Operations targeting sensitive executables, scripts, or system directories",
                    )
                )

        # 6. Corroborating Evidence Bonus
        corrob_count = self._count_corroborating_events(finding)
        if corrob_count > 0:
            potential_bonus = corrob_count * self.config.corroboration_bonus_per_event
            bonus = min(self.config.max_corroboration_bonus, potential_bonus)
            if bonus > 0:
                reasons.append(
                    ScoringReason(
                        factor="corroborating_events",
                        contribution=bonus,
                        reason=f"{corrob_count} corroborating telemetry event(s) observed (+{bonus} pts, max +{self.config.max_corroboration_bonus})",
                    )
                )

        # 7. Raw Calculation and Clamping
        raw_score = sum(r.contribution for r in reasons)
        clamped_score = max(self.config.min_score, min(self.config.max_score, raw_score))

        # 8. Determine Severity
        severity = self.determine_severity(clamped_score)

        return RiskScore(
            score=clamped_score,
            severity=severity,
            reasons=reasons,
            raw_calculated_score=raw_score,
        )

    def calculate_from_event(self, event: SecurityEvent) -> RiskScore:
        """Calculate score from a canonical SecurityEvent containing behavioral context."""
        finding = self.extract_finding_from_event(event)
        return self.calculate_score(finding)

    def extract_finding_from_event(self, event: SecurityEvent) -> BehaviorFinding:
        """Extract or reconstruct a BehaviorFinding from a SecurityEvent."""
        ctx = event.context
        b_ctx = ctx.behavior if ctx else None
        p_ctx = ctx.process if ctx else None
        extra = (ctx.extra if ctx else None) or {}

        rule_id = (b_ctx.rule_id if b_ctx else None) or extra.get("rule_id", "RULE-BEH-UNKNOWN")
        rule_name = (b_ctx.rule_name if b_ctx else None) or extra.get("rule_name", "Unknown Behavioral Rule")
        finding_id = (b_ctx.finding_id if b_ctx else None) or event.event_id
        pid = (p_ctx.pid if p_ctx else None) or (b_ctx.pid if b_ctx else None)
        process_name = (p_ctx.name if p_ctx else None) or (b_ctx.process_name if b_ctx else None)
        executable_path = (p_ctx.executable_path if p_ctx else None) or (b_ctx.executable_path if b_ctx else None)
        related_ids = (b_ctx.related_event_ids if b_ctx else None) or []
        evidence = (b_ctx.evidence if b_ctx else None) or []
        matched_conditions = (b_ctx.matched_conditions if b_ctx else None) or []
        description = (b_ctx.description if b_ctx else None) or extra.get("description", "")

        return BehaviorFinding(
            finding_id=finding_id,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=event.severity,
            category=event.event_type.category.value,
            timestamp=event.timestamp,
            start_time=(b_ctx.start_time if b_ctx else "") or event.timestamp,
            end_time=(b_ctx.end_time if b_ctx else "") or event.timestamp,
            pid=pid,
            process_name=process_name,
            executable_path=executable_path,
            related_event_ids=list(related_ids),
            matched_conditions=list(matched_conditions),
            evidence=list(evidence),
            confidence=(b_ctx.confidence if b_ctx else 1.0),
            description=description,
        )

    def determine_severity(self, score: int) -> Severity:
        """Determine canonical Severity enum based on configured thresholds.

        Default boundaries:
            >= 90: CRITICAL
            >= 70: HIGH
            >= 40: MEDIUM
            < 40:  LOW
        """
        th = self.config.severity_thresholds
        crit_th = th.get("critical", 90)
        high_th = th.get("high", 70)
        med_th = th.get("medium", 40)

        if score >= crit_th:
            return Severity.CRITICAL
        if score >= high_th:
            return Severity.HIGH
        if score >= med_th:
            return Severity.MEDIUM
        return Severity.LOW

    def _has_deception_interaction(self, finding: BehaviorFinding) -> bool:
        """Check if finding is associated with deception decoys or honeytokens."""
        if finding.rule_id == "RULE-BEH-005":
            return True

        text_to_check = f"{finding.rule_name} {finding.description} {' '.join(finding.matched_conditions)}".lower()
        if any(w in text_to_check for w in ("decoy", "honeytoken", "deception")):
            return True

        for ev in finding.evidence:
            if not isinstance(ev, dict):
                continue
            cat = str(ev.get("category", "")).upper()
            if cat == "DECEPTION" or ev.get("is_decoy") or ev.get("decoy_id"):
                return True
            for val in ev.values():
                if isinstance(val, str) and ("decoy" in val.lower() or "honeytoken" in val.lower()):
                    return True

        return False

    def _has_elevated_privilege(self, finding: BehaviorFinding) -> bool:
        """Check if finding involves elevated privileges or privilege escalation."""
        if finding.rule_id == "RULE-BEH-004":
            return True

        text_to_check = f"{finding.rule_name} {finding.description} {' '.join(finding.matched_conditions)}".lower()
        if any(w in text_to_check for w in ("privilege", "elevated", "system", "administrator")):
            return True

        for ev in finding.evidence:
            if not isinstance(ev, dict):
                continue
            if ev.get("is_elevated") is True:
                return True
            cat = str(ev.get("category", "")).upper()
            if cat in ("PRIVILEGE", "SYSTEM"):
                return True
            priv = str(ev.get("privilege_level", "")).upper()
            if priv in ("HIGH", "SYSTEM", "ADMINISTRATOR"):
                return True

        return False

    def _has_network_activity(self, finding: BehaviorFinding) -> bool:
        """Check if finding involves external/remote network activity."""
        if finding.rule_id in ("RULE-BEH-002", "RULE-BEH-004"):
            # RULE-BEH-002 is network, RULE-BEH-004 is file+network sequence
            return True

        for ev in finding.evidence:
            if not isinstance(ev, dict):
                continue
            cat = str(ev.get("category", "")).upper()
            if cat == "NETWORK":
                return True
            remote_ip = ev.get("remote_ip") or ev.get("destination_ip")
            if remote_ip and str(remote_ip) not in _LOOPBACK_IPS:
                return True

        return False

    def _has_sensitive_file_activity(self, finding: BehaviorFinding) -> bool:
        """Check if finding involves sensitive file activity."""
        if finding.rule_id in ("RULE-BEH-001", "RULE-BEH-004"):
            # RULE-BEH-001 is file, RULE-BEH-004 is file+network sequence
            return True

        for ev in finding.evidence:
            if not isinstance(ev, dict):
                continue
            cat = str(ev.get("category", "")).upper()
            if cat == "FILE":
                return True
            path = str(ev.get("path", "")).lower()
            if any(path.endswith(ext) for ext in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                return True
            if any(p in path for p in ("startup", "system32", "syswow64", "temp")):
                return True

        return False

    def _count_corroborating_events(self, finding: BehaviorFinding) -> int:
        """Count distinct corroborating events beyond the primary trigger."""
        # Check related_event_ids
        ids = set(finding.related_event_ids)
        if len(ids) > 1:
            return len(ids) - 1

        # Check evidence list
        evidence_ids = {
            ev.get("event_id")
            for ev in finding.evidence
            if isinstance(ev, dict) and ev.get("event_id")
        }
        if len(evidence_ids) > 1:
            return len(evidence_ids) - 1

        if len(finding.evidence) > 1:
            return len(finding.evidence) - 1

        return 0
