"""Cyber Deception Subsystem for the Trojan Defense framework."""

from trojan_defense.deception.detector import (
    DeceptionDetectionError,
    DeceptionInteractionDetector,
)
from trojan_defense.deception.engine import CyberDeceptionEngine, DeceptionError
from trojan_defense.deception.models import (
    DecoyDefinition,
    DecoyRecord,
    DecoyStatus,
    DecoyType,
)
from trojan_defense.deception.path_safety import (
    PathSecurityError,
    is_safe_relative_path,
    validate_deception_root,
    validate_decoy_path,
)
from trojan_defense.deception.registry import DecoyRegistry, RegistryError

__all__ = [
    "CyberDeceptionEngine",
    "DeceptionError",
    "DeceptionDetectionError",
    "DeceptionInteractionDetector",
    "DecoyDefinition",
    "DecoyRecord",
    "DecoyStatus",
    "DecoyType",
    "DecoyRegistry",
    "RegistryError",
    "PathSecurityError",
    "validate_deception_root",
    "validate_decoy_path",
    "is_safe_relative_path",
]

