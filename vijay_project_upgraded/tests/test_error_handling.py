"""Tests for domain error handling and exception hierarchy."""

import pytest

from trojan_defense.core.exceptions import (
    CollectorError,
    ConfigurationError,
    LifecycleError,
    PersistenceError,
    PipelineError,
    TransportError,
    TrojanDefenseError,
    ValidationError,
)


class TestErrorHandling:
    def test_exception_inheritance(self):
        errors = [
            ConfigurationError("config failure"),
            ValidationError("validation failure"),
            CollectorError("collector failure"),
            PipelineError("pipeline failure"),
            PersistenceError("persistence failure"),
            TransportError("transport failure"),
            LifecycleError("lifecycle failure"),
        ]

        for err in errors:
            assert isinstance(err, TrojanDefenseError)
            assert isinstance(err, Exception)

    def test_error_details_formatting(self):
        err = ValidationError("Bad field", details={"field": "timestamp", "value": "xyz"})
        assert "Bad field" in str(err)
        assert "timestamp" in str(err)
        assert err.details["field"] == "timestamp"

    def test_error_without_details(self):
        err = ConfigurationError("Simple message")
        assert str(err) == "Simple message"
        assert err.details == {}
