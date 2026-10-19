"""Configuration data models and schema for the Trojan Defense framework.

All configurations are strictly typed with sensible defaults, allowing override
via JSON files or environment variables.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AppConfig:
    """Core application environment configuration."""
    environment: str = "development"
    debug: bool = False


@dataclass
class LoggingConfig:
    """Centralized structured logging settings."""
    level: str = "INFO"
    log_to_file: bool = False
    log_dir: str = "logs"
    json_format: bool = False


@dataclass
class EndpointConfig:
    """Endpoint identity configuration overrides."""
    endpoint_id: str | None = None
    hostname: str | None = None
    agent_version: str = "0.1.0"


@dataclass
class PipelineConfig:
    """Event pipeline operational settings."""
    batch_size: int = 50
    max_queue_size: int = 1000
    validate_events: bool = True
    drop_on_overflow: bool = False


@dataclass
class PersistenceConfig:
    """Persistence layer settings."""
    enabled: bool = True
    driver: str = "sqlite"  # 'sqlite' or 'memory'
    db_path: str = "trojan_defense.db"


@dataclass
class TransportConfig:
    """Transport boundary settings."""
    enabled: bool = False
    driver: str = "mock"  # 'mock', 'file', or 'http'
    output_file: str = "events.jsonl"
    endpoint_url: str = "http://127.0.0.1:8080/api/events"
    timeout_seconds: float = 5.0
    retry_count: int = 2


@dataclass
class BackendConfig:
    """Backend server operational settings."""
    host: str = "127.0.0.1"
    port: int = 8080
    max_content_length: int = 1048576  # 1 MB
    default_page_limit: int = 50
    max_page_limit: int = 200


@dataclass
class ProcessCollectorConfig:
    """Settings for the Windows process telemetry collector."""
    enabled: bool = False
    polling_interval: float = 0.5  # seconds
    collect_command_line: bool = True
    collect_hashes: bool = False
    max_command_line_length: int = 2048


@dataclass
class FileCollectorConfig:
    """Settings for the Windows filesystem telemetry collector."""
    enabled: bool = False
    monitored_paths: list[str] = field(default_factory=lambda: ["runtime/monitored"])
    recursive: bool = True
    debounce_ms: int = 200  # milliseconds to coalesce rapid modification bursts
    collect_hashes: bool = False
    max_hash_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit for optional hashing
    ignore_patterns: list[str] = field(default_factory=lambda: ["*.tmp", "~*"])


@dataclass
class NetworkCollectorConfig:
    """Settings for the Windows network telemetry collector."""
    enabled: bool = False
    polling_interval: float = 1.0  # seconds
    include_loopback: bool = True  # whether to track loopback connections (127.0.0.1 / ::1)
    include_listening: bool = True  # whether to track listening sockets (LISTEN)
    include_udp: bool = True  # whether to track UDP endpoints
    resolve_process_names: bool = True  # whether to resolve PID to process metadata


@dataclass
class SystemCollectorConfig:
    """Settings for the Windows system and privilege telemetry collector."""
    enabled: bool = False
    polling_interval: float = 2.0  # seconds between system/session and privilege checks
    monitor_sessions: bool = True  # track logon, logoff, lock, unlock via WTS
    monitor_event_log: bool = True  # track system/winlogon events via Windows Event Log
    monitor_privileges: bool = True  # track process elevation and admin context


@dataclass
class DeceptionConfig:
    """Settings for the Cyber Deception Engine and Interaction Detection."""
    enabled: bool = False
    deception_root: str = "runtime/deception"
    auto_create_on_startup: bool = True
    cleanup_on_shutdown: bool = False
    interaction_detection_enabled: bool = True
    interaction_debounce_ms: int = 200
    decoys: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BehaviorConfig:
    """Settings for Behavioral Correlation and Detection Engine."""
    enabled: bool = False
    correlation_window_seconds: float = 60.0
    dedup_window_seconds: float = 30.0
    max_tracked_processes: int = 1000
    rules: dict[str, bool] = field(default_factory=dict)


@dataclass
class RiskConfig:
    """Settings for Risk Scoring Engine."""
    enabled: bool = True
    min_score: int = 0
    max_score: int = 100
    rule_base_scores: dict[str, int] = field(default_factory=lambda: {
        "RULE-BEH-001": 40,
        "RULE-BEH-002": 30,
        "RULE-BEH-003": 45,
        "RULE-BEH-004": 55,
        "RULE-BEH-005": 75,
    })
    default_base_score: int = 30
    deception_bonus: int = 25
    privilege_bonus: int = 20
    network_bonus: int = 15
    sensitive_file_bonus: int = 15
    corroboration_bonus_per_event: int = 5
    max_corroboration_bonus: int = 15
    severity_thresholds: dict[str, int] = field(default_factory=lambda: {
        "low": 0,
        "medium": 40,
        "high": 70,
        "critical": 90,
    })


@dataclass
class AlertingConfig:
    """Settings for Alert Generation and Deduplication."""
    enabled: bool = True
    min_alert_score: int = 20  # Minimum risk score to generate an alert
    dedup_window_seconds: float = 60.0
    cooldown_seconds: float = 300.0


@dataclass
class CollectorToggleConfig:
    """Feature flags for telemetry collectors (for later phases)."""
    process: bool = False
    file: bool = False
    network: bool = False
    system: bool = False
    privilege: bool = False
    deception: bool = False
    behavior: bool = False
    alerting: bool = False
    response: bool = False


@dataclass
class ResponseConfig:
    """Settings for Controlled Defensive Response and Incident Management."""
    enabled: bool = True
    quarantine_dir: str = "runtime/quarantine"
    execution_timeout_seconds: float = 10.0
    require_authorization: bool = True
    auto_rollback_on_failure: bool = True
    protected_processes: list[str] = field(default_factory=lambda: [
        "System",
        "Registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "spoolsv.exe",
        "explorer.exe",
        "dwm.exe",
        "conhost.exe",
    ])
    auth_tokens: dict[str, str] = field(default_factory=lambda: {
        "analyst-token": "ANALYST",
        "responder-token": "RESPONDER",
        "admin-token": "ADMIN",
        "viewer-token": "VIEWER",
    })


@dataclass
class RootConfig:
    """Root configuration tree containing all subsystem settings."""
    app: AppConfig = field(default_factory=AppConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    endpoint: EndpointConfig = field(default_factory=EndpointConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    collectors: CollectorToggleConfig = field(default_factory=CollectorToggleConfig)
    process_collector: ProcessCollectorConfig = field(default_factory=ProcessCollectorConfig)
    file_collector: FileCollectorConfig = field(default_factory=FileCollectorConfig)
    network_collector: NetworkCollectorConfig = field(default_factory=NetworkCollectorConfig)
    system_collector: SystemCollectorConfig = field(default_factory=SystemCollectorConfig)
    deception: DeceptionConfig = field(default_factory=DeceptionConfig)
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration tree to nested dictionary."""
        return asdict(self)



