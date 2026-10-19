"""Behavioral Correlation and Detection package.

Provides deterministic multi-event telemetry correlation, state tracking
with PID reuse protection, and generation of auditable BehaviorFinding events.
"""

from trojan_defense.behavior.engine import BehaviorCorrelationEngine
from trojan_defense.behavior.models import BehaviorFinding
from trojan_defense.behavior.rules import (
    BehaviorRule,
    DecoyInteractionSequenceRule,
    PrivilegedProcessActivityRule,
    ProcessFileActivityRule,
    ProcessFileNetworkSequenceRule,
    ProcessNetworkActivityRule,
)
from trojan_defense.behavior.tracker import (
    ProcessCorrelationTracker,
    ProcessIdentityKey,
    TrackedProcess,
)

__all__ = [
    "BehaviorCorrelationEngine",
    "BehaviorFinding",
    "BehaviorRule",
    "DecoyInteractionSequenceRule",
    "PrivilegedProcessActivityRule",
    "ProcessCorrelationTracker",
    "ProcessFileActivityRule",
    "ProcessFileNetworkSequenceRule",
    "ProcessIdentityKey",
    "ProcessNetworkActivityRule",
    "TrackedProcess",
]
