"""Tests for the Centralized Logging subsystem."""

import json
import logging
from pathlib import Path

from trojan_defense.core.config.schema import LoggingConfig
from trojan_defense.core.logging.setup import (
    JsonLogFormatter,
    StandardLogFormatter,
    get_logger,
    sanitize_data,
    setup_logging,
)


class TestLogging:
    def test_sanitize_data_redacts_sensitive_keys(self):
        sensitive_dict = {
            "user": "analyst",
            "password": "supersecretpassword",
            "api_key": "xyz12345",
            "nested": {
                "auth_token": "bearer 9876",
                "normal": "value",
            },
        }

        sanitized = sanitize_data(sensitive_dict)
        assert sanitized["user"] == "analyst"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["nested"]["auth_token"] == "[REDACTED]"
        assert sanitized["nested"]["normal"] == "value"

    def test_json_log_formatter(self):
        formatter = JsonLogFormatter()
        record = logging.LogRecord(
            name="trojan_defense.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Structured log test message",
            args=(),
            exc_info=None,
        )

        formatted_str = formatter.format(record)
        parsed = json.loads(formatted_str)

        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "trojan_defense.test"
        assert parsed["message"] == "Structured log test message"
        assert "timestamp" in parsed

    def test_standard_log_formatter(self):
        formatter = StandardLogFormatter("%(levelname)s: %(message)s")
        record = logging.LogRecord(
            name="trojan_defense.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=20,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        assert formatted == "WARNING: Warning message"

    def test_setup_logging_with_file_output(self, tmp_path: Path):
        cfg = LoggingConfig(
            level="DEBUG",
            log_to_file=True,
            log_dir=str(tmp_path / "logs"),
            json_format=False,
        )

        logger = setup_logging(cfg)
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 2  # StreamHandler + FileHandler

        sub_logger = get_logger("unit_test")
        sub_logger.info("Test message written to log")

        log_file = tmp_path / "logs" / "trojan_defense.log"
        assert log_file.is_file()
        content = log_file.read_text(encoding="utf-8")
        assert "Test message written to log" in content
