"""Configuration loader and validator for the Trojan Defense framework.

Loads configurations from defaults, optional JSON configuration files,
and environment variables with clean validation and error reporting.
"""

import json
import os
from pathlib import Path
from typing import Any

from trojan_defense.core.config.schema import (
    AlertingConfig,
    AppConfig,
    BackendConfig,
    BehaviorConfig,
    CollectorToggleConfig,
    DeceptionConfig,
    EndpointConfig,
    FileCollectorConfig,
    LoggingConfig,
    NetworkCollectorConfig,
    PersistenceConfig,
    PipelineConfig,
    ProcessCollectorConfig,
    ResponseConfig,
    RiskConfig,
    RootConfig,
    SystemCollectorConfig,
    TransportConfig,
)
from trojan_defense.core.exceptions import ConfigurationError

VALID_ENVIRONMENTS = {"development", "test", "production"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_PERSISTENCE_DRIVERS = {"sqlite", "memory"}
VALID_TRANSPORT_DRIVERS = {"mock", "file", "http"}


def _deep_update(source: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Recursively update a dictionary without mutating the original."""
    result = dict(source)
    for key, value in overrides.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = _deep_update(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config_dict: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variables prefixed with TROJAN_DEFENSE_."""
    env_map = {
        "TROJAN_DEFENSE_ENV": ("app", "environment"),
        "TROJAN_DEFENSE_DEBUG": ("app", "debug"),
        "TROJAN_DEFENSE_LOG_LEVEL": ("logging", "level"),
        "TROJAN_DEFENSE_LOG_TO_FILE": ("logging", "log_to_file"),
        "TROJAN_DEFENSE_LOG_DIR": ("logging", "log_dir"),
        "TROJAN_DEFENSE_LOG_JSON": ("logging", "json_format"),
        "TROJAN_DEFENSE_ENDPOINT_ID": ("endpoint", "endpoint_id"),
        "TROJAN_DEFENSE_HOSTNAME": ("endpoint", "hostname"),
        "TROJAN_DEFENSE_PIPELINE_BATCH_SIZE": ("pipeline", "batch_size"),
        "TROJAN_DEFENSE_PERSISTENCE_ENABLED": ("persistence", "enabled"),
        "TROJAN_DEFENSE_PERSISTENCE_DRIVER": ("persistence", "driver"),
        "TROJAN_DEFENSE_DB_PATH": ("persistence", "db_path"),
        "TROJAN_DEFENSE_TRANSPORT_ENABLED": ("transport", "enabled"),
        "TROJAN_DEFENSE_TRANSPORT_DRIVER": ("transport", "driver"),
        "TROJAN_DEFENSE_TRANSPORT_OUTPUT_FILE": ("transport", "output_file"),
        "TROJAN_DEFENSE_TRANSPORT_URL": ("transport", "endpoint_url"),
        "TROJAN_DEFENSE_BACKEND_HOST": ("backend", "host"),
        "TROJAN_DEFENSE_BACKEND_PORT": ("backend", "port"),
        "TROJAN_DEFENSE_BACKEND_MAX_CONTENT_LENGTH": ("backend", "max_content_length"),
        "TROJAN_DEFENSE_PROCESS_ENABLED": ("process_collector", "enabled"),
        "TROJAN_DEFENSE_PROCESS_POLLING_INTERVAL": ("process_collector", "polling_interval"),
        "TROJAN_DEFENSE_PROCESS_COLLECT_CMDLINE": ("process_collector", "collect_command_line"),
        "TROJAN_DEFENSE_FILE_ENABLED": ("file_collector", "enabled"),
        "TROJAN_DEFENSE_FILE_PATHS": ("file_collector", "monitored_paths"),
        "TROJAN_DEFENSE_FILE_RECURSIVE": ("file_collector", "recursive"),
        "TROJAN_DEFENSE_FILE_DEBOUNCE_MS": ("file_collector", "debounce_ms"),
        "TROJAN_DEFENSE_NETWORK_ENABLED": ("network_collector", "enabled"),
        "TROJAN_DEFENSE_NETWORK_POLLING_INTERVAL": ("network_collector", "polling_interval"),
        "TROJAN_DEFENSE_NETWORK_INCLUDE_LOOPBACK": ("network_collector", "include_loopback"),
        "TROJAN_DEFENSE_NETWORK_INCLUDE_LISTENING": ("network_collector", "include_listening"),
        "TROJAN_DEFENSE_NETWORK_INCLUDE_UDP": ("network_collector", "include_udp"),
        "TROJAN_DEFENSE_NETWORK_RESOLVE_PROCESS": ("network_collector", "resolve_process_names"),
        "TROJAN_DEFENSE_SYSTEM_ENABLED": ("system_collector", "enabled"),
        "TROJAN_DEFENSE_SYSTEM_POLLING_INTERVAL": ("system_collector", "polling_interval"),
        "TROJAN_DEFENSE_SYSTEM_MONITOR_SESSIONS": ("system_collector", "monitor_sessions"),
        "TROJAN_DEFENSE_SYSTEM_MONITOR_EVENT_LOG": ("system_collector", "monitor_event_log"),
        "TROJAN_DEFENSE_SYSTEM_MONITOR_PRIVILEGES": ("system_collector", "monitor_privileges"),
        "TROJAN_DEFENSE_DECEPTION_ENABLED": ("deception", "enabled"),
        "TROJAN_DEFENSE_DECEPTION_ROOT": ("deception", "deception_root"),
        "TROJAN_DEFENSE_DECEPTION_AUTO_CREATE": ("deception", "auto_create_on_startup"),
        "TROJAN_DEFENSE_DECEPTION_AUTO_CREATE_ON_STARTUP": ("deception", "auto_create_on_startup"),
        "TROJAN_DEFENSE_DECEPTION_CLEANUP_ON_SHUTDOWN": ("deception", "cleanup_on_shutdown"),
        "TROJAN_DEFENSE_DECEPTION_INTERACTION_DETECTION": ("deception", "interaction_detection_enabled"),
        "TROJAN_DEFENSE_DECEPTION_DETECTION_ENABLED": ("deception", "interaction_detection_enabled"),
        "TROJAN_DEFENSE_DECEPTION_DEBOUNCE_MS": ("deception", "interaction_debounce_ms"),
        "TROJAN_DEFENSE_BEHAVIOR_ENABLED": ("behavior", "enabled"),
        "TROJAN_DEFENSE_BEHAVIOR_CORRELATION_WINDOW": ("behavior", "correlation_window_seconds"),
        "TROJAN_DEFENSE_BEHAVIOR_DEDUP_WINDOW": ("behavior", "dedup_window_seconds"),
        "TROJAN_DEFENSE_BEHAVIOR_MAX_TRACKED": ("behavior", "max_tracked_processes"),
        "TROJAN_DEFENSE_RISK_ENABLED": ("risk", "enabled"),
        "TROJAN_DEFENSE_RISK_MAX_SCORE": ("risk", "max_score"),
        "TROJAN_DEFENSE_RISK_MIN_SCORE": ("risk", "min_score"),
        "TROJAN_DEFENSE_ALERT_ENABLED": ("alerting", "enabled"),
        "TROJAN_DEFENSE_ALERT_MIN_SCORE": ("alerting", "min_alert_score"),
        "TROJAN_DEFENSE_ALERT_DEDUP_WINDOW": ("alerting", "dedup_window_seconds"),
        "TROJAN_DEFENSE_ALERT_COOLDOWN": ("alerting", "cooldown_seconds"),
        "TROJAN_DEFENSE_RESPONSE_ENABLED": ("response", "enabled"),
        "TROJAN_DEFENSE_RESPONSE_QUARANTINE_DIR": ("response", "quarantine_dir"),
        "TROJAN_DEFENSE_RESPONSE_EXECUTION_TIMEOUT": ("response", "execution_timeout_seconds"),
        "TROJAN_DEFENSE_RESPONSE_REQUIRE_AUTH": ("response", "require_authorization"),
        "TROJAN_DEFENSE_RESPONSE_AUTO_ROLLBACK": ("response", "auto_rollback_on_failure"),
    }

    res = dict(config_dict)
    for env_var, (section, key) in env_map.items():
        val = os.getenv(env_var)
        if val is not None:
            if section not in res:
                res[section] = {}
            orig_val = res[section].get(key)
            if isinstance(orig_val, bool) or key in (
                "debug",
                "log_to_file",
                "json_format",
                "enabled",
                "collect_command_line",
                "collect_hashes",
                "recursive",
                "include_loopback",
                "include_listening",
                "include_udp",
                "resolve_process_names",
                "monitor_sessions",
                "monitor_event_log",
                "monitor_privileges",
                "auto_create_on_startup",
                "cleanup_on_shutdown",
                "interaction_detection_enabled",
                "require_authorization",
                "auto_rollback_on_failure",
            ):
                res[section][key] = val.lower() in ("true", "1", "yes")
            elif key == "monitored_paths":
                res[section][key] = [p.strip() for p in val.split(",") if p.strip()]
            elif key in ("polling_interval", "correlation_window_seconds", "dedup_window_seconds", "cooldown_seconds", "execution_timeout_seconds"):
                try:
                    res[section][key] = float(val)
                except ValueError as exc:
                    raise ConfigurationError(
                        f"Environment variable {env_var} must be a float, got '{val}'"
                    ) from exc
            elif isinstance(orig_val, int) or key in (
                "batch_size",
                "max_queue_size",
                "port",
                "max_content_length",
                "debounce_ms",
                "interaction_debounce_ms",
                "max_tracked_processes",
                "max_score",
                "min_score",
                "min_alert_score",
            ):
                try:
                    res[section][key] = int(val)
                except ValueError as exc:
                    raise ConfigurationError(
                        f"Environment variable {env_var} must be an integer, got '{val}'"
                    ) from exc
            else:
                res[section][key] = val

    return res



def validate_config(config: RootConfig) -> None:
    """Validate configuration fields to ensure operational correctness."""
    if config.app.environment not in VALID_ENVIRONMENTS:
        raise ConfigurationError(
            f"Invalid environment '{config.app.environment}'. Must be one of {sorted(VALID_ENVIRONMENTS)}"
        )

    if config.logging.level.upper() not in VALID_LOG_LEVELS:
        raise ConfigurationError(
            f"Invalid log level '{config.logging.level}'. Must be one of {sorted(VALID_LOG_LEVELS)}"
        )

    if config.pipeline.batch_size <= 0:
        raise ConfigurationError(
            f"Pipeline batch_size must be positive, got {config.pipeline.batch_size}"
        )

    if config.pipeline.max_queue_size <= 0:
        raise ConfigurationError(
            f"Pipeline max_queue_size must be positive, got {config.pipeline.max_queue_size}"
        )

    if config.persistence.driver not in VALID_PERSISTENCE_DRIVERS:
        raise ConfigurationError(
            f"Invalid persistence driver '{config.persistence.driver}'. Must be one of {sorted(VALID_PERSISTENCE_DRIVERS)}"
        )

    if config.transport.driver not in VALID_TRANSPORT_DRIVERS:
        raise ConfigurationError(
            f"Invalid transport driver '{config.transport.driver}'. Must be one of {sorted(VALID_TRANSPORT_DRIVERS)}"
        )

    if config.backend.port < 0 or config.backend.port > 65535:
        raise ConfigurationError(
            f"Backend port must be between 0 and 65535, got {config.backend.port}"
        )

    if config.backend.max_content_length <= 0:
        raise ConfigurationError(
            f"Backend max_content_length must be positive, got {config.backend.max_content_length}"
        )

    if config.backend.default_page_limit <= 0:
        raise ConfigurationError(
            f"Backend default_page_limit must be positive, got {config.backend.default_page_limit}"
        )

    if config.backend.max_page_limit < config.backend.default_page_limit:
        raise ConfigurationError(
            f"Backend max_page_limit ({config.backend.max_page_limit}) cannot be less than default_page_limit ({config.backend.default_page_limit})"
        )

    if config.process_collector.polling_interval <= 0:
        raise ConfigurationError(
            f"Process collector polling_interval must be positive, got {config.process_collector.polling_interval}"
        )

    if config.file_collector.debounce_ms < 0:
        raise ConfigurationError(
            f"File collector debounce_ms must be non-negative, got {config.file_collector.debounce_ms}"
        )

    if config.network_collector.polling_interval <= 0:
        raise ConfigurationError(
            f"Network collector polling_interval must be positive, got {config.network_collector.polling_interval}"
        )

    if config.system_collector.polling_interval <= 0:
        raise ConfigurationError(
            f"System collector polling_interval must be positive, got {config.system_collector.polling_interval}"
        )

    if config.behavior.correlation_window_seconds <= 0:
        raise ConfigurationError(
            f"Behavior correlation_window_seconds must be positive, got {config.behavior.correlation_window_seconds}"
        )

    if config.behavior.dedup_window_seconds <= 0:
        raise ConfigurationError(
            f"Behavior dedup_window_seconds must be positive, got {config.behavior.dedup_window_seconds}"
        )

    if config.behavior.max_tracked_processes <= 0:
        raise ConfigurationError(
            f"Behavior max_tracked_processes must be positive, got {config.behavior.max_tracked_processes}"
        )

    if config.risk.min_score < 0:
        raise ConfigurationError(
            f"Risk min_score must be non-negative, got {config.risk.min_score}"
        )

    if config.risk.max_score <= config.risk.min_score:
        raise ConfigurationError(
            f"Risk max_score ({config.risk.max_score}) must be greater than min_score ({config.risk.min_score})"
        )

    if config.alerting.dedup_window_seconds < 0:
        raise ConfigurationError(
            f"Alerting dedup_window_seconds must be non-negative, got {config.alerting.dedup_window_seconds}"
        )

    if config.alerting.cooldown_seconds < 0:
        raise ConfigurationError(
            f"Alerting cooldown_seconds must be non-negative, got {config.alerting.cooldown_seconds}"
        )

    if config.deception.enabled:

        from trojan_defense.deception.path_safety import validate_deception_root, PathSecurityError
        try:
            validate_deception_root(config.deception.deception_root)
        except PathSecurityError as exc:
            raise ConfigurationError(
                f"Invalid deception root '{config.deception.deception_root}': {exc}"
            ) from exc

    if config.response.execution_timeout_seconds <= 0:
        raise ConfigurationError(
            f"Response execution_timeout_seconds must be positive, got {config.response.execution_timeout_seconds}"
        )

    if not config.response.quarantine_dir or not str(config.response.quarantine_dir).strip():
        raise ConfigurationError("Response quarantine_dir cannot be empty")


def load_config(
    config_file: str | Path | None = None,
    environment: str | None = None,
) -> RootConfig:
    """Load, merge, and validate configuration.

    Order of precedence:
      1. Default configuration
      2. Configuration file (if specified or found in config/<env>.json)
      3. Environment variables (TROJAN_DEFENSE_*)

    Raises:
        ConfigurationError: If the configuration cannot be loaded or is invalid.
    """
    base = RootConfig()
    data: dict[str, Any] = base.to_dict()

    target_env = environment or os.getenv("TROJAN_DEFENSE_ENV") or data["app"]["environment"]
    data["app"]["environment"] = target_env

    # Check for config file
    file_to_load: Path | None = None
    if config_file:
        file_to_load = Path(config_file)
        if not file_to_load.is_file():
            raise ConfigurationError(f"Specified configuration file not found: {config_file}")
    else:
        # Check standard config directory
        standard_path = Path("config") / f"{target_env}.json"
        default_path = Path("config") / "default.json"
        if standard_path.is_file():
            file_to_load = standard_path
        elif default_path.is_file():
            file_to_load = default_path

    if file_to_load:
        try:
            with open(file_to_load, "r", encoding="utf-8") as f:
                file_dict = json.load(f)
            data = _deep_update(data, file_dict)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"Malformed JSON in configuration file '{file_to_load}': {exc}"
            ) from exc
        except OSError as exc:
            raise ConfigurationError(
                f"Failed to read configuration file '{file_to_load}': {exc}"
            ) from exc

    # Apply environment variable overrides
    data = _apply_env_overrides(data)

    try:
        root_config = RootConfig(
            app=AppConfig(**data.get("app", {})),
            logging=LoggingConfig(**data.get("logging", {})),
            endpoint=EndpointConfig(**data.get("endpoint", {})),
            pipeline=PipelineConfig(**data.get("pipeline", {})),
            persistence=PersistenceConfig(**data.get("persistence", {})),
            transport=TransportConfig(**data.get("transport", {})),
            backend=BackendConfig(**data.get("backend", {})),
            collectors=CollectorToggleConfig(**data.get("collectors", {})),
            process_collector=ProcessCollectorConfig(**data.get("process_collector", {})),
            file_collector=FileCollectorConfig(**data.get("file_collector", {})),
            network_collector=NetworkCollectorConfig(**data.get("network_collector", {})),
            system_collector=SystemCollectorConfig(**data.get("system_collector", {})),
            deception=DeceptionConfig(**data.get("deception", {})),
            behavior=BehaviorConfig(**data.get("behavior", {})),
            risk=RiskConfig(**data.get("risk", {})),
            alerting=AlertingConfig(**data.get("alerting", {})),
            response=ResponseConfig(**data.get("response", {})),
        )
    except TypeError as exc:
        raise ConfigurationError(f"Unexpected configuration keys: {exc}") from exc

    # Synchronize process enable flag
    if root_config.collectors.process:
        root_config.process_collector.enabled = True
    elif root_config.process_collector.enabled:
        root_config.collectors.process = True

    # Synchronize file enable flag
    if root_config.collectors.file:
        root_config.file_collector.enabled = True
    elif root_config.file_collector.enabled:
        root_config.collectors.file = True

    # Synchronize network enable flag
    if root_config.collectors.network:
        root_config.network_collector.enabled = True
    elif root_config.network_collector.enabled:
        root_config.collectors.network = True

    # Synchronize system/privilege enable flag
    if root_config.collectors.system or root_config.collectors.privilege:
        root_config.system_collector.enabled = True
    elif root_config.system_collector.enabled:
        root_config.collectors.system = True
        root_config.collectors.privilege = True

    # Synchronize deception enable flag
    if root_config.collectors.deception:
        root_config.deception.enabled = True
    elif root_config.deception.enabled:
        root_config.collectors.deception = True

    # Synchronize behavior enable flag
    if root_config.collectors.behavior:
        root_config.behavior.enabled = True
    elif root_config.behavior.enabled:
        root_config.collectors.behavior = True

    # Synchronize alerting enable flag
    if root_config.collectors.alerting:
        root_config.alerting.enabled = True
    elif root_config.alerting.enabled:
        root_config.collectors.alerting = True

    # Synchronize response enable flag
    if root_config.collectors.response:
        root_config.response.enabled = True
    elif root_config.response.enabled:
        root_config.collectors.response = True

    validate_config(root_config)
    return root_config


