"""Structured event context containers.

Allows collectors to attach domain-specific details without forcing irrelevant
fields onto every event or allowing uncontrolled arbitrary unstructured chaos.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProcessContext:
    """Telemetry context specific to process lifecycle and activity."""
    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    username: str | None = None
    hash_sha256: str | None = None
    created_at: str | None = None
    terminated_at: str | None = None
    parent_name: str | None = None

    @property
    def exe(self) -> str | None:
        """Alias for executable_path."""
        return self.executable_path

    @property
    def cmdline(self) -> str | None:
        """Alias for command_line."""
        return self.command_line


@dataclass(frozen=True)
class FileContext:
    """Telemetry context specific to filesystem activity."""
    path: str | None = None
    operation: str | None = None  # e.g., create, modify, delete, rename
    size_bytes: int | None = None
    hash_sha256: str | None = None
    is_directory: bool = False
    file_name: str | None = None
    directory: str | None = None
    extension: str | None = None
    previous_path: str | None = None


@dataclass(frozen=True)
class NetworkContext:
    """Telemetry context specific to network communication."""
    protocol: str | None = None  # TCP, UDP, etc.
    local_ip: str | None = None
    local_port: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    state: str | None = None  # e.g., ESTABLISHED, LISTEN, TIME_WAIT, NONE
    pid: int | None = None
    source_ip: str | None = None  # Backward-compatible alias for local_ip
    source_port: int | None = None  # Backward-compatible alias for local_port
    destination_ip: str | None = None  # Backward-compatible alias for remote_ip
    destination_port: int | None = None  # Backward-compatible alias for remote_port
    bytes_sent: int | None = None
    bytes_received: int | None = None

    def __post_init__(self) -> None:
        """Harmonize local/remote with source/destination fields."""
        if self.local_ip is None and self.source_ip is not None:
            object.__setattr__(self, "local_ip", self.source_ip)
        elif self.source_ip is None and self.local_ip is not None:
            object.__setattr__(self, "source_ip", self.local_ip)

        if self.local_port is None and self.source_port is not None:
            object.__setattr__(self, "local_port", self.source_port)
        elif self.source_port is None and self.local_port is not None:
            object.__setattr__(self, "source_port", self.local_port)

        if self.remote_ip is None and self.destination_ip is not None:
            object.__setattr__(self, "remote_ip", self.destination_ip)
        elif self.destination_ip is None and self.remote_ip is not None:
            object.__setattr__(self, "destination_ip", self.remote_ip)

        if self.remote_port is None and self.destination_port is not None:
            object.__setattr__(self, "remote_port", self.destination_port)
        elif self.destination_port is None and self.remote_port is not None:
            object.__setattr__(self, "destination_port", self.remote_port)



@dataclass(frozen=True)
class SystemContext:
    """Telemetry context specific to system, session, or registry operations."""
    subsystem: str | None = None  # e.g., "SESSION", "BOOT", "SERVICE", "REGISTRY"
    target: str | None = None
    action: str | None = None  # e.g., "STARTUP", "SHUTDOWN", "LOGON", "LOGOFF", "LOCK", "UNLOCK"
    status_code: int | None = None
    username: str | None = None
    session_id: int | None = None
    session_name: str | None = None
    domain: str | None = None
    state: str | None = None
    boot_time: str | None = None
    event_id: int | None = None  # Windows Event Log ID (e.g. 7001, 6005, 4624)

    def to_dict(self) -> dict[str, Any]:
        """Convert SystemContext to dictionary omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class PrivilegeContext:
    """Telemetry context specific to privilege and elevation operations."""
    is_elevated: bool | None = None
    elevation_type: str | None = None  # e.g., "Full", "Limited", "Default"
    integrity_level: str | None = None  # e.g., "Low", "Medium", "High", "System"
    user: str | None = None
    sid: str | None = None
    privileges: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert PrivilegeContext to dictionary omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class DeceptionContext:
    """Telemetry context specific to honeytokens, decoys, and deception triggers."""
    is_decoy: bool = True
    decoy_id: str | None = None
    decoy_type: str | None = None
    interaction_type: str | None = None
    path: str | None = None
    relative_path: str | None = None
    action: str | None = None
    status: str | None = None
    original_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert DeceptionContext to dictionary omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class BehaviorContext:
    """Telemetry context specific to behavioral detections and findings."""
    finding_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    category: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    pid: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    related_event_ids: list[str] = field(default_factory=list)
    matched_conditions: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float | None = 1.0
    description: str | None = None
    status: str | None = "DETECTED"

    def to_dict(self) -> dict[str, Any]:
        """Convert BehaviorContext to dictionary omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class EventContext:
    """Composite structured container for event-specific details.

    Collectors populate only the relevant sub-contexts.
    """
    process: ProcessContext | None = None
    file: FileContext | None = None
    network: NetworkContext | None = None
    system: SystemContext | None = None
    privilege: PrivilegeContext | None = None
    deception: DeceptionContext | None = None
    behavior: BehaviorContext | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert populated contexts to a dictionary, omitting None sections."""
        res: dict[str, Any] = {}
        if self.process:
            res["process"] = {k: v for k, v in asdict(self.process).items() if v is not None}
        if self.file:
            res["file"] = {k: v for k, v in asdict(self.file).items() if v is not None}
        if self.network:
            res["network"] = {k: v for k, v in asdict(self.network).items() if v is not None}
        if self.system:
            res["system"] = {k: v for k, v in asdict(self.system).items() if v is not None}
        if self.privilege:
            res["privilege"] = {k: v for k, v in asdict(self.privilege).items() if v is not None}
        if self.deception:
            res["deception"] = {k: v for k, v in asdict(self.deception).items() if v is not None}
        if self.behavior:
            res["behavior"] = {k: v for k, v in asdict(self.behavior).items() if v is not None}
        if self.extra:
            res["extra"] = self.extra
        return res

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "EventContext":
        """Reconstruct EventContext from dictionary representation."""
        if not data:
            return cls()

        process_data = data.get("process")
        file_data = data.get("file")
        network_data = data.get("network")
        system_data = data.get("system")
        privilege_data = data.get("privilege")
        deception_data = data.get("deception")
        behavior_data = data.get("behavior")
        extra_data = data.get("extra", {})

        return cls(
            process=ProcessContext(**process_data) if process_data else None,
            file=FileContext(**file_data) if file_data else None,
            network=NetworkContext(**network_data) if network_data else None,
            system=SystemContext(**system_data) if system_data else None,
            privilege=PrivilegeContext(**privilege_data) if privilege_data else None,
            deception=DeceptionContext(**deception_data) if deception_data else None,
            behavior=BehaviorContext(**behavior_data) if behavior_data else None,
            extra=extra_data if isinstance(extra_data, dict) else {},
        )

