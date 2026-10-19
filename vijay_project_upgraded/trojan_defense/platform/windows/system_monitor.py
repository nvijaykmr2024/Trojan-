"""Windows System and Privilege Telemetry Collector.

Observes real Windows system and privilege activity using native Win32 APIs:
- System boot time and lifecycle events via psutil and wevtapi.dll (Windows Event Log)
- User session changes (Logon, Logoff, Lock, Unlock) via wtsapi32.dll (Terminal Services)
- Process token elevation and mandatory integrity levels via advapi32.dll
- Emits canonical SecurityEvents into the existing event pipeline.
"""

from collections.abc import Sequence
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import os
from pathlib import Path
import threading
import time
from typing import Any
import xml.etree.ElementTree as ET

import psutil

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.config.schema import SystemCollectorConfig
from trojan_defense.core.exceptions import CollectorError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import (
    EventContext,
    PrivilegeContext,
    ProcessContext,
    SystemContext,
)
from trojan_defense.core.models.event import SecurityEvent, current_utc_timestamp
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.models.severity import Severity
from trojan_defense.core.pipeline.pipeline import EventPipeline

logger = get_logger("platform.windows.system_monitor")

# --- Native Win32 API Configuration ---
kernel32 = getattr(ctypes.windll, "kernel32", None)
advapi32 = getattr(ctypes.windll, "advapi32", None)
wtsapi32 = getattr(ctypes.windll, "wtsapi32", None)
wevtapi = getattr(ctypes.windll, "wevtapi", None)
shell32 = getattr(ctypes.windll, "shell32", None)

if kernel32:
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    if hasattr(kernel32, "LocalFree"):
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]

if advapi32:
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    if hasattr(advapi32, "ConvertSidToStringSidW"):
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    if hasattr(advapi32, "LookupAccountSidW"):
        advapi32.LookupAccountSidW.restype = wintypes.BOOL
        advapi32.LookupAccountSidW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
    if hasattr(advapi32, "LookupPrivilegeNameW"):
        advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL
        advapi32.LookupPrivilegeNameW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]

if wevtapi:
    EVT_HANDLE = wintypes.HANDLE
    wevtapi.EvtQuery.restype = EVT_HANDLE
    wevtapi.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    wevtapi.EvtClose.restype = wintypes.BOOL
    wevtapi.EvtClose.argtypes = [EVT_HANDLE]
    wevtapi.EvtNext.restype = wintypes.BOOL
    wevtapi.EvtNext.argtypes = [
        EVT_HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(EVT_HANDLE),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    wevtapi.EvtRender.restype = wintypes.BOOL
    wevtapi.EvtRender.argtypes = [
        EVT_HANDLE,
        EVT_HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]


class WTS_SESSION_INFOW(ctypes.Structure):
    """Win32 WTS_SESSION_INFO structure."""
    _fields_ = [
        ("SessionId", wintypes.DWORD),
        ("pWinStationName", wintypes.LPWSTR),
        ("State", wintypes.DWORD),
    ]


WTS_STATE_NAMES = {
    0: "Active",
    1: "Connected",
    2: "ConnectQuery",
    3: "Shadow",
    4: "Disconnected",
    5: "Idle",
    6: "Listen",
    7: "Reset",
    8: "Down",
    9: "Init",
}


def is_current_user_admin() -> bool:
    """Return True if the current user process holds administrative rights."""
    if not shell32:
        return False
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_process_privilege_context(pid: int | None = None) -> PrivilegeContext:
    """Safely query process token elevation, elevation type, and integrity level via Win32."""
    if not kernel32 or not advapi32:
        return PrivilegeContext(is_elevated=False, elevation_type="Unknown", integrity_level="Unknown")

    target_pid = pid if (pid is not None and pid > 0) else os.getpid()
    needs_close_process = False

    if target_pid == os.getpid():
        h_process = kernel32.GetCurrentProcess()
    else:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, target_pid)
        if not h_process:
            return PrivilegeContext(is_elevated=None, elevation_type="Unavailable", integrity_level="Unavailable")
        needs_close_process = True

    token = wintypes.HANDLE()
    TOKEN_QUERY = 0x0008

    try:
        if not advapi32.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(token)):
            return PrivilegeContext(is_elevated=None, elevation_type="Unavailable", integrity_level="Unavailable")

        try:
            ret_len = wintypes.DWORD()

            # 1. Query TokenElevation (20)
            elev = wintypes.DWORD()
            is_elevated: bool | None = None
            if advapi32.GetTokenInformation(
                token, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret_len)
            ):
                is_elevated = bool(elev.value)

            # 2. Query TokenElevationType (18)
            elev_type_val = wintypes.DWORD()
            elev_type_str = "Default"
            if advapi32.GetTokenInformation(
                token, 18, ctypes.byref(elev_type_val), ctypes.sizeof(elev_type_val), ctypes.byref(ret_len)
            ):
                mapping = {1: "Default", 2: "Full", 3: "Limited"}
                elev_type_str = mapping.get(elev_type_val.value, f"Type_{elev_type_val.value}")

            # 3. Query TokenIntegrityLevel (25)
            buf = (ctypes.c_byte * 128)()
            integrity_str = "Medium"
            if advapi32.GetTokenInformation(
                token, 25, ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(ret_len)
            ):
                p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
                p_count = advapi32.GetSidSubAuthorityCount(p_sid)
                if p_count:
                    count = p_count.contents.value
                    p_subauth = advapi32.GetSidSubAuthority(p_sid, count - 1)
                    if p_subauth:
                        rid = p_subauth.contents.value
                        if rid < 0x2000:
                            integrity_str = "Low"
                        elif rid < 0x3000:
                            integrity_str = "Medium"
                        elif rid < 0x4000:
                            integrity_str = "High"
                        else:
                            integrity_str = "System"

            # 4. Query TokenUser (1) for SID and user account
            sid_str: str | None = None
            user_str: str | None = None
            user_buf = (ctypes.c_byte * 256)()
            if advapi32.GetTokenInformation(
                token, 1, ctypes.byref(user_buf), ctypes.sizeof(user_buf), ctypes.byref(ret_len)
            ):
                p_user_sid = ctypes.cast(user_buf, ctypes.POINTER(ctypes.c_void_p))[0]
                if p_user_sid:
                    p_sid_str = wintypes.LPWSTR()
                    if hasattr(advapi32, "ConvertSidToStringSidW") and advapi32.ConvertSidToStringSidW(
                        p_user_sid, ctypes.byref(p_sid_str)
                    ):
                        sid_str = p_sid_str.value
                        if hasattr(kernel32, "LocalFree"):
                            kernel32.LocalFree(p_sid_str)

                    name_buf = ctypes.create_unicode_buffer(256)
                    name_len = wintypes.DWORD(256)
                    dom_buf = ctypes.create_unicode_buffer(256)
                    dom_len = wintypes.DWORD(256)
                    sid_type = wintypes.DWORD()
                    if hasattr(advapi32, "LookupAccountSidW") and advapi32.LookupAccountSidW(
                        None, p_user_sid, name_buf, ctypes.byref(name_len), dom_buf, ctypes.byref(dom_len), ctypes.byref(sid_type)
                    ):
                        user_str = f"{dom_buf.value}\\{name_buf.value}" if dom_buf.value else name_buf.value

            # 5. Query TokenPrivileges (3)
            privs: list[str] = []
            priv_buf = (ctypes.c_byte * 2048)()
            if hasattr(advapi32, "LookupPrivilegeNameW") and advapi32.GetTokenInformation(
                token, 3, ctypes.byref(priv_buf), ctypes.sizeof(priv_buf), ctypes.byref(ret_len)
            ):
                priv_count = ctypes.cast(priv_buf, ctypes.POINTER(wintypes.DWORD))[0]
                for idx in range(min(priv_count, 64)):
                    luid_offset = 4 + idx * 12
                    p_luid = ctypes.byref(priv_buf, luid_offset)
                    name_buf = ctypes.create_unicode_buffer(128)
                    n_len = wintypes.DWORD(128)
                    if advapi32.LookupPrivilegeNameW(None, p_luid, name_buf, ctypes.byref(n_len)):
                        if name_buf.value:
                            privs.append(name_buf.value)

            return PrivilegeContext(
                is_elevated=is_elevated,
                elevation_type=elev_type_str,
                integrity_level=integrity_str,
                user=user_str,
                sid=sid_str,
                privileges=privs,
            )
        finally:
            kernel32.CloseHandle(token)
    except Exception as exc:
        logger.debug(f"Failed to query privilege context for pid {target_pid}: {exc}")
        return PrivilegeContext(is_elevated=None, elevation_type="Error", integrity_level="Error")
    finally:
        if needs_close_process and h_process:
            kernel32.CloseHandle(h_process)


def get_active_sessions() -> list[dict[str, Any]]:
    """Enumerate Windows Terminal Services sessions via wtsapi32.dll."""
    if not wtsapi32:
        return []

    sessions: list[dict[str, Any]] = []
    p_info = ctypes.POINTER(WTS_SESSION_INFOW)()
    count = wintypes.DWORD()

    try:
        if not wtsapi32.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(p_info), ctypes.byref(count)):
            return []

        try:
            for i in range(count.value):
                s = p_info[i]
                state_str = WTS_STATE_NAMES.get(s.State, str(s.State))
                station_name = s.pWinStationName or ""

                # Query username (WTSUserName = 5)
                p_user = wintypes.LPWSTR()
                bytes_ret = wintypes.DWORD()
                user_val = ""
                if wtsapi32.WTSQuerySessionInformationW(
                    None, s.SessionId, 5, ctypes.byref(p_user), ctypes.byref(bytes_ret)
                ):
                    if p_user.value:
                        user_val = str(p_user.value)
                    wtsapi32.WTSFreeMemory(p_user)

                # Query domain (WTSDomainName = 7)
                p_domain = wintypes.LPWSTR()
                domain_val = ""
                if wtsapi32.WTSQuerySessionInformationW(
                    None, s.SessionId, 7, ctypes.byref(p_domain), ctypes.byref(bytes_ret)
                ):
                    if p_domain.value:
                        domain_val = str(p_domain.value)
                    wtsapi32.WTSFreeMemory(p_domain)

                sessions.append({
                    "session_id": s.SessionId,
                    "session_name": station_name,
                    "state": state_str,
                    "username": user_val,
                    "domain": domain_val,
                })
        finally:
            wtsapi32.WTSFreeMemory(p_info)
    except Exception as exc:
        logger.debug(f"WTS session enumeration encountered exception: {exc}")

    return sessions


def query_recent_system_events(
    channel: str = "System",
    min_record_id: int = 0,
    max_records: int = 20,
) -> list[dict[str, Any]]:
    """Query recent events from Windows Event Log channel using wevtapi.dll."""
    if not wevtapi:
        return []

    events: list[dict[str, Any]] = []
    # Event IDs: 7001 (Logon), 7002 (Logoff), 6005 (Startup), 6006 (Shutdown), 1074 (User Shutdown)
    query_str = "*[System[(EventID=7001 or EventID=7002 or EventID=6005 or EventID=6006 or EventID=1074)]]"

    try:
        h_query = wevtapi.EvtQuery(None, channel, query_str, 0x1 | 0x200)  # ChannelPath | ReverseDirection
        if not h_query:
            return []

        try:
            h_events = (EVT_HANDLE * max_records)()
            returned = wintypes.DWORD()

            if wevtapi.EvtNext(h_query, max_records, h_events, 2000, 0, ctypes.byref(returned)):
                ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                for i in range(returned.value):
                    h_ev = h_events[i]
                    buf_size = wintypes.DWORD(0)
                    prop_count = wintypes.DWORD(0)
                    wevtapi.EvtRender(None, h_ev, 1, 0, None, ctypes.byref(buf_size), ctypes.byref(prop_count))
                    if buf_size.value > 0:
                        buf = ctypes.create_unicode_buffer(buf_size.value)
                        if wevtapi.EvtRender(
                            None, h_ev, 1, buf_size.value * 2, ctypes.byref(buf), ctypes.byref(buf_size), ctypes.byref(prop_count)
                        ):
                            try:
                                root = ET.fromstring(buf.value)
                                ev_id_str = root.findtext(".//ns:EventID", namespaces=ns)
                                time_created = root.find(".//ns:TimeCreated", namespaces=ns)
                                sys_time = time_created.attrib.get("SystemTime") if time_created is not None else None
                                provider = root.find(".//ns:Provider", namespaces=ns)
                                prov_name = provider.attrib.get("Name") if provider is not None else ""
                                rec_id_str = root.findtext(".//ns:EventRecordID", namespaces=ns)

                                ev_id = int(ev_id_str) if ev_id_str and ev_id_str.isdigit() else 0
                                rec_id = int(rec_id_str) if rec_id_str and rec_id_str.isdigit() else 0

                                if rec_id > min_record_id:
                                    events.append({
                                        "event_id": ev_id,
                                        "time_created": sys_time or current_utc_timestamp(),
                                        "provider": prov_name,
                                        "record_id": rec_id,
                                        "channel": channel,
                                    })
                            except Exception:
                                pass
                    wevtapi.EvtClose(h_ev)
        finally:
            wevtapi.EvtClose(h_query)
    except Exception as exc:
        logger.debug(f"Event Log query encountered exception: {exc}")

    return events


class WindowsSystemMonitor(BaseCollector):
    """Monitors Windows system state, session changes, and privilege elevation."""

    def __init__(
        self,
        config: SystemCollectorConfig,
        pipeline: EventPipeline,
        endpoint: EndpointIdentity | None = None,
    ) -> None:
        super().__init__(
            name="windows_system_monitor",
            category=EventCategory.SYSTEM,
            pipeline=pipeline,
            endpoint=endpoint or EndpointIdentity.resolve(),
        )
        self.config = config
        self.endpoint = endpoint or EndpointIdentity.resolve()

        self._active_sessions: dict[int, dict[str, Any]] = {}
        self._last_event_record_id: int = 0
        self._known_elevated_pids: set[int] = set()
        self._boot_time_emitted: bool = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._event_count: int = 0
        self._scan_count: int = 0

    @property
    def is_running(self) -> bool:
        """Indicate whether the monitor is running."""
        return self._status == CollectorStatus.RUNNING

    def start(self) -> None:
        """Start the Windows system and privilege monitor."""
        with self._lock:
            if self._status in (CollectorStatus.STARTING, CollectorStatus.RUNNING):
                logger.warning("WindowsSystemMonitor is already running or starting")
                return
            self._status = CollectorStatus.STARTING
            self._stop_event.clear()

        try:
            logger.info("Initializing WindowsSystemMonitor baseline state...")
            # 1. Emit System Startup baseline event
            self._emit_system_startup_baseline()

            # 2. Seed active sessions
            if self.config.monitor_sessions:
                self._seed_sessions_baseline()

            # 3. Seed Event Log watermark
            if self.config.monitor_event_log:
                self._seed_event_log_watermark()

            # 4. Check initial privilege context of monitoring process
            if self.config.monitor_privileges:
                self._check_agent_privilege_context()

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="WindowsSystemMonitorThread",
                daemon=True,
            )
            self._thread.start()
            self._status = CollectorStatus.RUNNING
            logger.info(
                f"WindowsSystemMonitor started successfully (interval={self.config.polling_interval}s, "
                f"sessions={self.config.monitor_sessions}, event_log={self.config.monitor_event_log}, "
                f"privileges={self.config.monitor_privileges})"
            )
        except Exception as exc:
            self._status = CollectorStatus.ERROR
            logger.error(f"Failed to start WindowsSystemMonitor: {exc}", exc_info=True)
            raise CollectorError(f"WindowsSystemMonitor failed to start: {exc}") from exc

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the system monitor and join background worker thread."""
        with self._lock:
            if self._status in (CollectorStatus.STOPPED, CollectorStatus.STOPPING):
                return
            self._status = CollectorStatus.STOPPING

        logger.info("Stopping WindowsSystemMonitor...")
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("WindowsSystemMonitor thread did not exit cleanly within timeout")

        self._status = CollectorStatus.STOPPED
        logger.info(
            f"WindowsSystemMonitor stopped (total_scans={self._scan_count}, "
            f"total_events_emitted={self._event_count})"
        )

    def health_check(self) -> dict[str, Any]:
        """Return operational health status and telemetry counters."""
        with self._lock:
            return {
                "collector": self.name,
                "status": self.status.value,
                "running": self.is_running,
                "polling_interval": self.config.polling_interval,
                "tracked_sessions": len(self._active_sessions),
                "events_emitted": self._event_count,
                "scan_count": self._scan_count,
                "monitor_sessions": self.config.monitor_sessions,
                "monitor_event_log": self.config.monitor_event_log,
                "monitor_privileges": self.config.monitor_privileges,
            }

    def _monitor_loop(self) -> None:
        """Periodic background reconciliation loop."""
        interval = max(0.2, self.config.polling_interval)
        while not self._stop_event.is_set():
            try:
                self._scan_system_and_privileges()
            except Exception as exc:
                logger.error(f"Error during system/privilege scan: {exc}", exc_info=True)

            elapsed = 0.0
            slice_duration = 0.1
            while elapsed < interval and not self._stop_event.is_set():
                time.sleep(slice_duration)
                elapsed += slice_duration

    def _emit_system_startup_baseline(self) -> None:
        """Emit initial SYSTEM.STARTUP event based on system boot time."""
        if self._boot_time_emitted:
            return

        boot_iso = current_utc_timestamp()
        try:
            boot_epoch = psutil.boot_time()
            boot_iso = datetime.fromtimestamp(boot_epoch, tz=timezone.utc).isoformat()
        except Exception:
            pass

        sys_ctx = SystemContext(
            subsystem="BOOT",
            action="STARTUP",
            target="SYSTEM",
            boot_time=boot_iso,
        )

        event = SecurityEvent(
            event_type=EventType.with_action(EventCategory.SYSTEM, "STARTUP"),
            severity=Severity.INFO,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(system=sys_ctx),
        )
        self.pipeline.process(event)
        self._event_count += 1
        self._boot_time_emitted = True
        logger.debug(f"Emitted SYSTEM.STARTUP baseline event (boot_time={boot_iso})")

    def _seed_sessions_baseline(self) -> None:
        """Discover current active sessions on startup and emit baseline events."""
        sessions = get_active_sessions()
        for sess in sessions:
            sid = sess["session_id"]
            self._active_sessions[sid] = sess
            # Emit session observation
            if sess.get("username"):
                self._emit_session_event(
                    action="LOGON",
                    session_info=sess,
                    severity=Severity.INFO,
                )

    def _seed_event_log_watermark(self) -> None:
        """Set watermark to the newest EventRecordID to avoid processing old events."""
        recent = query_recent_system_events(max_records=1)
        if recent:
            self._last_event_record_id = max(e["record_id"] for e in recent)

    def _check_agent_privilege_context(self) -> None:
        """Check privilege context of current process."""
        priv = get_process_privilege_context(os.getpid())
        if priv and (priv.is_elevated or priv.integrity_level in ("High", "System")):
            self._emit_privilege_event(
                action="ELEVATION",
                pid=os.getpid(),
                process_name=Path(sys.executable if hasattr(sys, "executable") else "python.exe").name,
                priv_context=priv,
                severity=Severity.LOW,
            )

    def _scan_system_and_privileges(self) -> None:
        """Reconcile session state, Event Log records, and privilege elevations."""
        self._scan_count += 1

        # 1. Scan Sessions
        if self.config.monitor_sessions:
            current_sessions = {s["session_id"]: s for s in get_active_sessions()}
            with self._lock:
                # Detect new sessions
                for sid, sess in current_sessions.items():
                    if sid not in self._active_sessions:
                        self._active_sessions[sid] = sess
                        action = "LOGON" if sess.get("username") else "CREATED"
                        self._emit_session_event(action=action, session_info=sess, severity=Severity.INFO)
                    else:
                        # Detect state transitions (e.g. Active -> Disconnected [lock])
                        prev = self._active_sessions[sid]
                        if prev.get("state") != sess.get("state"):
                            old_state = prev.get("state")
                            new_state = sess.get("state")
                            self._active_sessions[sid] = sess

                            if new_state == "Disconnected":
                                self._emit_session_event(action="LOCK", session_info=sess, severity=Severity.INFO)
                            elif new_state == "Active":
                                self._emit_session_event(action="UNLOCK", session_info=sess, severity=Severity.INFO)
                            else:
                                self._emit_session_event(
                                    action="STATE_CHANGE",
                                    session_info=sess,
                                    severity=Severity.INFO,
                                    extra={"previous_state": old_state},
                                    )

                # Detect ended sessions
                missing_sids = [sid for sid in self._active_sessions if sid not in current_sessions]
                for sid in missing_sids:
                    ended = self._active_sessions.pop(sid)
                    self._emit_session_event(action="LOGOFF", session_info=ended, severity=Severity.INFO)

        # 2. Scan Windows Event Log
        if self.config.monitor_event_log:
            new_events = query_recent_system_events(
                channel="System",
                min_record_id=self._last_event_record_id,
                max_records=10,
            )
            for ev in new_events:
                if ev["record_id"] > self._last_event_record_id:
                    self._last_event_record_id = ev["record_id"]
                    ev_id = ev["event_id"]

                    if ev_id == 7001:
                        self._emit_event_log_telemetry("LOGON", ev)
                    elif ev_id == 7002:
                        self._emit_event_log_telemetry("LOGOFF", ev)
                    elif ev_id == 6005:
                        self._emit_event_log_telemetry("STARTUP", ev)
                    elif ev_id in (6006, 1074):
                        self._emit_event_log_telemetry("SHUTDOWN", ev)

        # 3. Scan Process Privilege Contexts
        if self.config.monitor_privileges:
            # Check current process
            curr_pid = os.getpid()
            if curr_pid not in self._known_elevated_pids:
                curr_priv = get_process_privilege_context(curr_pid)
                if curr_priv and (curr_priv.is_elevated or curr_priv.integrity_level in ("High", "System")):
                    self._known_elevated_pids.add(curr_pid)
                    self._emit_privilege_event(
                        action="ELEVATION",
                        pid=curr_pid,
                        process_name="python.exe",
                        priv_context=curr_priv,
                        severity=Severity.LOW,
                    )

    def _emit_session_event(
        self,
        action: str,
        session_info: dict[str, Any],
        severity: Severity,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit session-related security event."""
        event_action = action.upper()
        # Map user action if relevant, or SYSTEM.SESSION
        if event_action in ("LOGON", "LOGOFF", "LOCK", "UNLOCK"):
            category = EventCategory.SYSTEM
        else:
            category = EventCategory.SYSTEM

        sys_ctx = SystemContext(
            subsystem="SESSION",
            action=event_action,
            target=session_info.get("session_name"),
            username=session_info.get("username"),
            session_id=session_info.get("session_id"),
            session_name=session_info.get("session_name"),
            domain=session_info.get("domain"),
            state=session_info.get("state"),
        )

        event = SecurityEvent(
            event_type=EventType.with_action(category, event_action),
            severity=severity,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(system=sys_ctx, extra=extra or {}),
        )
        try:
            self.pipeline.process(event)
            self._event_count += 1
            logger.debug(f"Emitted SYSTEM.{event_action} event (session={session_info.get('session_id')})")
        except Exception as exc:
            logger.error(f"Failed to submit session event to pipeline: {exc}")

    def _emit_event_log_telemetry(self, action: str, ev_data: dict[str, Any]) -> None:
        """Emit security event derived from Windows Event Log."""
        sys_ctx = SystemContext(
            subsystem="EVENT_LOG",
            action=action,
            target=ev_data.get("channel"),
            event_id=ev_data.get("event_id"),
        )

        event = SecurityEvent(
            event_type=EventType.with_action(EventCategory.SYSTEM, action),
            severity=Severity.INFO,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(system=sys_ctx, extra={"provider": ev_data.get("provider")}),
        )
        try:
            self.pipeline.process(event)
            self._event_count += 1
            logger.debug(f"Emitted EVENT_LOG {action} event (EventID={ev_data.get('event_id')})")
        except Exception as exc:
            logger.error(f"Failed to submit event log telemetry to pipeline: {exc}")

    def _emit_privilege_event(
        self,
        action: str,
        pid: int,
        process_name: str | None,
        priv_context: PrivilegeContext,
        severity: Severity,
    ) -> None:
        """Emit privilege/elevation security event."""
        proc_ctx = ProcessContext(
            pid=pid,
            name=process_name,
        )

        event = SecurityEvent(
            event_type=EventType.with_action(EventCategory.PRIVILEGE, action),
            severity=severity,
            source=self.name,
            endpoint=self.endpoint,
            context=EventContext(
                process=proc_ctx,
                privilege=priv_context,
            ),
        )
        try:
            self.pipeline.process(event)
            self._event_count += 1
            logger.debug(f"Emitted PRIVILEGE.{action} event for PID={pid} (integrity={priv_context.integrity_level})")
        except Exception as exc:
            logger.error(f"Failed to submit privilege event to pipeline: {exc}")
