"""Path validation and containment safety controls for Cyber Deception Engine.

Strictly prevents path traversal, directory escape, and placement of deception
roots or decoys inside critical Windows operating system or user directories.
"""

import os
from pathlib import Path
import sys

from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.logging.setup import get_logger

logger = get_logger("deception.path_safety")


class PathSecurityError(TrojanDefenseError):
    """Raised when a deception path violates containment or security boundaries."""
    pass


def _get_system_forbidden_prefixes() -> list[Path]:
    """Retrieve normalized paths of critical Windows directories whose trees can never contain deception roots."""
    prefixes: list[Path] = []

    # Windows OS directory tree (e.g. C:\Windows, C:\Windows\System32)
    win_dir = os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows"
    prefixes.append(Path(win_dir).resolve())

    # Program Files trees
    prog_files = os.environ.get("ProgramFiles") or "C:\\Program Files"
    prefixes.append(Path(prog_files).resolve())

    prog_files_x86 = os.environ.get("ProgramFiles(x86)") or "C:\\Program Files (x86)"
    prefixes.append(Path(prog_files_x86).resolve())

    return prefixes


def _get_forbidden_exact_directories() -> list[Path]:
    """Retrieve directories that cannot themselves be used as deception roots."""
    exact: list[Path] = []

    # C:\Users parent directory
    users_dir = Path("C:\\Users").resolve()
    exact.append(users_dir)

    # User profile root directory (e.g. C:\Users\<Username>)
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        up_path = Path(user_profile).resolve()
        exact.append(up_path)
        # Also protect direct Desktop, Documents, Downloads, AppData roots
        exact.append((up_path / "Desktop").resolve())
        exact.append((up_path / "Documents").resolve())
        exact.append((up_path / "Downloads").resolve())
        exact.append((up_path / "AppData").resolve())

    prog_data = os.environ.get("ProgramData") or "C:\\ProgramData"
    exact.append(Path(prog_data).resolve())

    return exact


def _get_sensitive_user_subtrees() -> list[Path]:
    """Retrieve sensitive user credential and system subdirectories that can never contain deception roots."""
    sensitive: list[Path] = []
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        up_path = Path(user_profile).resolve()
        sensitive.append((up_path / ".ssh").resolve())
        sensitive.append((up_path / ".aws").resolve())
        sensitive.append((up_path / ".azure").resolve())
        sensitive.append((up_path / ".kube").resolve())
        sensitive.append((up_path / ".gnupg").resolve())
    return sensitive


def validate_deception_root(root_path: str | Path) -> Path:
    """Validate and resolve a proposed deception root directory.

    Guarantees:
    1. Path is non-empty and well-formed.
    2. Path does not point to a drive root (e.g. C:\\).
    3. Path does not reside inside or encompass any critical Windows system
       directory (e.g. C:\\Windows, C:\\Program Files).
    4. Path does not equal critical user roots (e.g. C:\\Users, C:\\Users\\<user>, Desktop)
       or reside inside sensitive user directories (.ssh, .aws).

    Returns:
        Path: The validated, resolved canonical Path object.

    Raises:
        PathSecurityError: If the path is unsafe or violates security constraints.
    """
    if not root_path or not str(root_path).strip():
        raise PathSecurityError("Deception root path cannot be empty")

    try:
        resolved = Path(root_path).resolve()
    except Exception as exc:
        raise PathSecurityError(f"Failed to resolve deception root path '{root_path}': {exc}") from exc

    # 1. Drive Root check (e.g. C:\ or \\server\share)
    if resolved.parent == resolved or len(resolved.parts) <= 1:
        raise PathSecurityError(
            f"Deception root cannot be a filesystem drive root: '{resolved}'"
        )

    # 2. Check against strictly forbidden system prefix trees (Windows, Program Files)
    for sys_prefix in _get_system_forbidden_prefixes():
        if resolved == sys_prefix:
            raise PathSecurityError(
                f"Deception root cannot be placed at protected system path: '{resolved}'"
            )
        try:
            resolved.relative_to(sys_prefix)
            raise PathSecurityError(
                f"Deception root '{resolved}' cannot reside inside protected system path '{sys_prefix}'"
            )
        except ValueError:
            pass

        # Also cannot encompass the system prefix (e.g. root set to C:\ if not caught by drive root)
        try:
            sys_prefix.relative_to(resolved)
            raise PathSecurityError(
                f"Deception root '{resolved}' cannot encompass protected system path '{sys_prefix}'"
            )
        except ValueError:
            pass

    # 3. Check against forbidden exact directories (C:\Users, USERPROFILE, Desktop, etc.)
    for exact_dir in _get_forbidden_exact_directories():
        if resolved == exact_dir:
            raise PathSecurityError(
                f"Deception root cannot be placed directly at broad user or system root: '{resolved}'"
            )

    # 4. Check against sensitive user subtrees (.ssh, .aws, etc.)
    for sens_tree in _get_sensitive_user_subtrees():
        if resolved == sens_tree:
            raise PathSecurityError(
                f"Deception root cannot be placed at sensitive user credential directory: '{resolved}'"
            )
        try:
            resolved.relative_to(sens_tree)
            raise PathSecurityError(
                f"Deception root '{resolved}' cannot reside inside sensitive user credential directory '{sens_tree}'"
            )
        except ValueError:
            pass

    return resolved


def is_safe_relative_path(path_str: str) -> bool:
    """Verify that a path string is strictly relative with no traversal syntax.

    Returns False if the path:
    - is empty
    - is absolute (starts with '/' or '\\' or has a Windows drive specifier)
    - contains '..' components
    """
    if not path_str or not path_str.strip():
        return False

    cleaned = path_str.strip().replace("\\", "/")

    # Reject absolute indicators
    if cleaned.startswith("/") or ":" in cleaned:
        return False

    parts = cleaned.split("/")
    for part in parts:
        if part in ("..", ""):
            return False

    return True


def validate_decoy_path(relative_path: str | Path, deception_root: Path) -> Path:
    """Validate that a decoy path resolves strictly within the deception root.

    Guarantees:
    1. relative_path is strictly relative (no absolute paths or drive letters).
    2. No '..' traversal is permitted.
    3. Resolved target path strictly belongs to deception_root.
    4. Target path does not equal the deception root itself.

    Returns:
        Path: The validated, resolved canonical target Path.

    Raises:
        PathSecurityError: If any path containment or traversal violation occurs.
    """
    rel_str = str(relative_path).strip()
    if not rel_str:
        raise PathSecurityError("Decoy relative path cannot be empty")

    if not is_safe_relative_path(rel_str):
        raise PathSecurityError(
            f"Decoy path '{rel_str}' contains forbidden traversal components or is absolute"
        )

    resolved_root = deception_root.resolve()
    try:
        target = (resolved_root / rel_str).resolve()
    except Exception as exc:
        raise PathSecurityError(f"Failed to resolve decoy path '{rel_str}': {exc}") from exc

    # Target must be strictly inside resolved_root
    try:
        rel = target.relative_to(resolved_root)
        if str(rel) in (".", ""):
            raise PathSecurityError(
                f"Decoy path cannot be the deception root itself: '{target}'"
            )
    except ValueError as exc:
        raise PathSecurityError(
            f"Decoy path '{target}' escapes the deception root '{resolved_root}'"
        ) from exc

    return target
