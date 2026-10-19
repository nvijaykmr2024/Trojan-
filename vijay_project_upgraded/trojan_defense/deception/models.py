"""Data models and type definitions for the Cyber Deception Engine."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class DecoyType(str, Enum):
    """Supported deception artifact types."""
    FILE = "file"
    DIRECTORY = "directory"


class DecoyStatus(str, Enum):
    """Lifecycle status of a managed decoy artifact."""
    ACTIVE = "active"
    MISSING = "missing"
    CORRUPTED = "corrupted"
    CLEANED = "cleaned"


@dataclass(frozen=True)
class DecoyDefinition:
    """Blueprint for creating a synthetic decoy artifact."""
    decoy_id: str
    artifact_type: DecoyType | str
    relative_path: str
    content: str | None = None  # Synthetic deterministic content for files
    purpose: str = "deception_canary"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.artifact_type, str):
            object.__setattr__(self, "artifact_type", DecoyType(self.artifact_type.lower()))


@dataclass
class DecoyRecord:
    """Registered metadata for an instantiated project-owned decoy artifact."""
    decoy_id: str
    artifact_type: str  # "file" or "directory"
    relative_path: str
    normalized_path: str
    purpose: str
    created_at: str
    status: str = DecoyStatus.ACTIVE.value
    content_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> str:
        """Alias for normalized_path."""
        return self.normalized_path

    def to_dict(self) -> dict[str, Any]:
        """Convert DecoyRecord to a serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DecoyRecord":
        """Reconstruct DecoyRecord from dictionary representation."""
        return cls(
            decoy_id=data["decoy_id"],
            artifact_type=data.get("artifact_type", "file"),
            relative_path=data["relative_path"],
            normalized_path=data["normalized_path"],
            purpose=data.get("purpose", "deception_canary"),
            created_at=data["created_at"],
            status=data.get("status", DecoyStatus.ACTIVE.value),
            content_hash=data.get("content_hash"),
            metadata=data.get("metadata", {}),
        )
