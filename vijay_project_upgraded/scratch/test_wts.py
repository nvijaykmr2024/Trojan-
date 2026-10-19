import ctypes
from ctypes import wintypes
import psutil

print("Testing Windows native session and privilege APIs...")

# 1. psutil.users()
print("psutil.users():", psutil.users())
print("psutil.boot_time():", psutil.boot_time())

# 2. IsUserAnAdmin
shell32 = ctypes.windll.shell32
print("IsUserAnAdmin:", bool(shell32.IsUserAnAdmin()))

# 3. WTSEnumerateSessionsW
try:
    wts = ctypes.windll.wtsapi32
    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [
            ("SessionId", wintypes.DWORD),
            ("pWinStationName", wintypes.LPWSTR),
            ("State", wintypes.DWORD),
        ]
    
    p_info = ctypes.POINTER(WTS_SESSION_INFOW)()
    count = wintypes.DWORD()
    if wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(p_info), ctypes.byref(count)):
        print(f"WTSEnumerateSessionsW found {count.value} sessions:")
        state_names = {
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
        for i in range(count.value):
            s = p_info[i]
            st = state_names.get(s.State, str(s.State))
            print(f"  Session {s.SessionId}: Station={s.pWinStationName} State={st}")
            # Query username
            p_user = wintypes.LPWSTR()
            bytes_ret = wintypes.DWORD()
            if wts.WTSQuerySessionInformationW(None, s.SessionId, 5, ctypes.byref(p_user), ctypes.byref(bytes_ret)):
                user_val = p_user.value if p_user else ""
                print(f"    User: {user_val}")
                wts.WTSFreeMemory(p_user)
        wts.WTSFreeMemory(p_info)
except Exception as e:
    print("WTS error:", e)
