"""Phase 10 — Risk Scoring and Alert Generation subsystem.

Provides deterministic risk scoring, structured explanation breakdown,
alert persistence, lifecycle management, and REST API interfaces.
"""

from trojan_defense.alerting.engine import AlertEngine
from trojan_defense.alerting.models import (
    VALID_STATUS_TRANSITIONS,
    Alert,
    AlertStatus,
    RiskScore,
    ScoringReason,
)
from trojan_defense.alerting.repository import AlertQueryFilter, SQLiteAlertRepository
from trojan_defense.alerting.scorer import RiskScoringEngine

__all__ = [
    "Alert",
    "AlertEngine",
    "AlertQueryFilter",
    "AlertStatus",
    "RiskScore",
    "RiskScoringEngine",
    "SQLiteAlertRepository",
    "ScoringReason",
    "VALID_STATUS_TRANSITIONS",
]
