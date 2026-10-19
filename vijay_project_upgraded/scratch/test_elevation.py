import ctypes
from ctypes import wintypes
import os

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]

advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]

def check_process_elevation(pid: int = None):
    if pid is None or pid == os.getpid():
        h_process = kernel32.GetCurrentProcess()
        needs_close = False
    else:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_process:
            return None
        needs_close = True

    token = wintypes.HANDLE()
    TOKEN_QUERY = 0x0008
    try:
        if not advapi32.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            # 1. TokenElevation (20)
            elev = wintypes.DWORD()
            ret_len = wintypes.DWORD()
            is_elevated = False
            if advapi32.GetTokenInformation(
                token, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret_len)
            ):
                is_elevated = bool(elev.value)

            # 2. TokenElevationType (18)
            elev_type_val = wintypes.DWORD()
            elev_type_str = "Default"
            if advapi32.GetTokenInformation(
                token, 18, ctypes.byref(elev_type_val), ctypes.sizeof(elev_type_val), ctypes.byref(ret_len)
            ):
                mapping = {1: "Default", 2: "Full", 3: "Limited"}
                elev_type_str = mapping.get(elev_type_val.value, f"Type_{elev_type_val.value}")

            # 3. TokenIntegrityLevel (25)
            buf = (ctypes.c_byte * 128)()
            integrity_str = "Medium"
            if advapi32.GetTokenInformation(
                token, 25, ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(ret_len)
            ):
                p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
                advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
                advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
                advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
                advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]

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

            return {
                "is_elevated": is_elevated,
                "elevation_type": elev_type_str,
                "integrity_level": integrity_str,
            }
        finally:
            kernel32.CloseHandle(token)
    finally:
        if needs_close:
            kernel32.CloseHandle(h_process)

print("Current process privilege context:", check_process_elevation())
