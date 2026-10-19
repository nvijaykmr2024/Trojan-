"""Endpoint identity abstraction for telemetry origin tracking.

Produces deterministic local machine identity suitable for telemetry
correlation across local process and system boundaries.
"""

from dataclasses import asdict, dataclass
import hashlib
import platform
import socket
import uuid


@dataclass(frozen=True)
class EndpointIdentity:
    """Represents the host machine producing security events."""
    endpoint_id: str
    hostname: str
    platform: str
    os_version: str
    architecture: str
    agent_version: str = "0.1.0"

    def to_dict(self) -> dict:
        """Convert endpoint identity to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "EndpointIdentity":
        """Reconstruct endpoint identity from dictionary."""
        return cls(
            endpoint_id=data["endpoint_id"],
            hostname=data["hostname"],
            platform=data["platform"],
            os_version=data.get("os_version", ""),
            architecture=data.get("architecture", ""),
            agent_version=data.get("agent_version", "0.1.0"),
        )

    @classmethod
    def resolve(
        cls,
        endpoint_id_override: str | None = None,
        hostname_override: str | None = None,
        agent_version: str = "0.1.0",
    ) -> "EndpointIdentity":
        """Resolve current local endpoint identity deterministically.

        If overrides are provided (e.g. via configuration), they take precedence.
        Otherwise, an endpoint ID is derived deterministically from the host's
        hardware address and hostname.
        """
        host = hostname_override or socket.gethostname()
        plat = platform.system()
        os_ver = platform.version()
        arch = platform.machine()

        if endpoint_id_override:
            ep_id = endpoint_id_override
        else:
            # Deterministic hash of MAC address and hostname
            mac_node = uuid.getnode()
            seed = f"{mac_node}-{host}-{plat}".encode("utf-8")
            ep_id = hashlib.sha256(seed).hexdigest()[:16]

        return cls(
            endpoint_id=ep_id,
            hostname=host,
            platform=plat,
            os_version=os_ver,
            architecture=arch,
            agent_version=agent_version,
        )
