"""Centralized exception hierarchy for the Trojan Defense framework.

All custom errors inherit from TrojanDefenseError to ensure structured
and predictable error handling across the application lifecycle.
"""


class TrojanDefenseError(Exception):
    """Base exception for all errors in the Trojan Defense system."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigurationError(TrojanDefenseError):
    """Raised when configuration loading, parsing, or validation fails."""
    pass


class ValidationError(TrojanDefenseError):
    """Raised when security event data fails schema or integrity validation."""
    pass


class CollectorError(TrojanDefenseError):
    """Raised when a telemetry collector encounters an unrecoverable error."""
    pass


class PipelineError(TrojanDefenseError):
    """Raised when an event cannot be processed through the event pipeline."""
    pass


class PersistenceError(TrojanDefenseError):
    """Raised when event storage or retrieval operations fail."""
    pass


class TransportError(TrojanDefenseError):
    """Raised when event transmission or dispatch operations fail."""
    pass


class LifecycleError(TrojanDefenseError):
    """Raised when an invalid application lifecycle state transition is attempted."""
    pass
