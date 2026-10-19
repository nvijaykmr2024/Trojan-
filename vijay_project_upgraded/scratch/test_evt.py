import ctypes
from ctypes import wintypes

wevtapi = ctypes.windll.wevtapi

EVT_HANDLE = wintypes.HANDLE
wevtapi.EvtQuery.restype = EVT_HANDLE
wevtapi.EvtQuery.argtypes = [
    EVT_HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
]

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

EvtQueryChannelPath = 0x1
EvtQueryReverseDirection = 0x200
EvtRenderEventXml = 1

h_query = wevtapi.EvtQuery(
    None,
    "System",
    "*[System[(EventID=6005 or EventID=6006 or EventID=7001 or EventID=7002 or EventID=1074)]]",
    EvtQueryChannelPath | EvtQueryReverseDirection,
)

print("EvtQuery handle:", h_query)
if h_query:
    h_event = EVT_HANDLE()
    returned = wintypes.DWORD()
    if wevtapi.EvtNext(h_query, 1, ctypes.byref(h_event), 2000, 0, ctypes.byref(returned)):
        buf_size = wintypes.DWORD(0)
        prop_count = wintypes.DWORD(0)
        # First call to get buffer size
        wevtapi.EvtRender(None, h_event, EvtRenderEventXml, 0, None, ctypes.byref(buf_size), ctypes.byref(prop_count))
        buf = ctypes.create_unicode_buffer(buf_size.value)
        if wevtapi.EvtRender(None, h_event, EvtRenderEventXml, buf_size.value * 2, ctypes.byref(buf), ctypes.byref(buf_size), ctypes.byref(prop_count)):
            print("Rendered XML:", buf.value[:300], "...")
        wevtapi.EvtClose(h_event)
    wevtapi.EvtClose(h_query)
