"""Windows platform telemetry namespace.

Provides Windows-specific telemetry collectors and platform utilities.
"""

from trojan_defense.platform.windows.file_monitor import (
    WindowsFileMonitor,
    normalize_path,
)
from trojan_defense.platform.windows.network_monitor import WindowsNetworkMonitor
from trojan_defense.platform.windows.process_monitor import (
    ProcessSnapshot,
    WindowsProcessMonitor,
)
from trojan_defense.platform.windows.system_monitor import (
    WindowsSystemMonitor,
    get_active_sessions,
    get_process_privilege_context,
    is_current_user_admin,
)

__all__ = [
    "ProcessSnapshot",
    "WindowsFileMonitor",
    "WindowsNetworkMonitor",
    "WindowsProcessMonitor",
    "WindowsSystemMonitor",
    "get_active_sessions",
    "get_process_privilege_context",
    "is_current_user_admin",
    "normalize_path",
]
