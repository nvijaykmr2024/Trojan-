"""Centralized structured logging setup for the Trojan Defense framework.

Provides uniform logging formatting, file and console outputs, structured JSON
support, and log sanitization to prevent sensitive data leaks.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any

from trojan_defense.core.config.schema import LoggingConfig

SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "credential", "auth"}


def sanitize_data(data: Any) -> Any:
    """Recursively redact sensitive key names in dictionaries."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(s in str(k).lower() for s in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_data(v)
        return sanitized
    if isinstance(data, list):
        return [sanitize_data(item) for item in data]
    return data


class JsonLogFormatter(logging.Formatter):
    """Formats log records as single-line structured JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom extra fields if present
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_entry["extra"] = sanitize_data(record.extra)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class StandardLogFormatter(logging.Formatter):
    """Human-readable formatter with timestamp and logger context."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            clean_extra = sanitize_data(record.extra)
            formatted = f"{formatted} | context: {clean_extra}"
        return formatted


def setup_logging(config: LoggingConfig) -> logging.Logger:
    """Initialize root logger with configured handlers and formatters.

    Ensures handlers are not duplicated upon repeated calls.
    """
    root_logger = logging.getLogger("trojan_defense")
    level = getattr(logging, config.level.upper(), logging.INFO)
    root_logger.setLevel(level)

    # Clear existing handlers to allow safe re-initialization
    root_logger.handlers.clear()

    # Formatter selection
    if config.json_format:
        formatter: logging.Formatter = JsonLogFormatter()
    else:
        fmt = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        formatter = StandardLogFormatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    # Console Handler (writes to stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Optional File Handler
    if config.log_to_file:
        log_dir = Path(config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "trojan_defense.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(subsystem: str) -> logging.Logger:
    """Retrieve a hierarchical logger for a specific subsystem."""
    return logging.getLogger(f"trojan_defense.{subsystem}")
