"""Controlled severity representation for security telemetry events.

Severity is strictly an attribute of events in Phase 1.
No risk scoring, threat scoring, or automatic escalation logic is included.
"""

from enum import IntEnum


class Severity(IntEnum):
    """Event severity levels with integer ranking for comparison/filtering."""
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string (e.g., 'info', 'INFO', 'HIGH')."""
        if not value or not isinstance(value, str):
            raise ValueError("Severity string cannot be empty")
        key = value.strip().upper()
        try:
            return cls[key]
        except KeyError as exc:
            valid = [s.name for s in cls]
            raise ValueError(f"Invalid severity '{value}'. Must be one of: {valid}") from exc

    def to_name(self) -> str:
        """Return the standard uppercase name string."""
        return self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"Severity.{self.name}"
