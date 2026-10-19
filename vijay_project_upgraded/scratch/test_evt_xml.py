import ctypes
from ctypes import wintypes
import xml.etree.ElementTree as ET

wevtapi = ctypes.windll.wevtapi
EVT_HANDLE = wintypes.HANDLE
wevtapi.EvtQuery.restype = EVT_HANDLE
wevtapi.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
wevtapi.EvtClose.restype = wintypes.BOOL
wevtapi.EvtClose.argtypes = [EVT_HANDLE]
wevtapi.EvtNext.restype = wintypes.BOOL
wevtapi.EvtNext.argtypes = [EVT_HANDLE, wintypes.DWORD, ctypes.POINTER(EVT_HANDLE), wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
wevtapi.EvtRender.restype = wintypes.BOOL
wevtapi.EvtRender.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]

h_query = wevtapi.EvtQuery(
    None,
    "System",
    "*[System[(EventID=7001 or EventID=7002 or EventID=6005 or EventID=6006 or EventID=1074)]]",
    0x1 | 0x200,  # ChannelPath | ReverseDirection
)

if h_query:
    h_event = EVT_HANDLE()
    returned = wintypes.DWORD()
    if wevtapi.EvtNext(h_query, 1, ctypes.byref(h_event), 1000, 0, ctypes.byref(returned)):
        buf_size = wintypes.DWORD(0)
        prop_count = wintypes.DWORD(0)
        wevtapi.EvtRender(None, h_event, 1, 0, None, ctypes.byref(buf_size), ctypes.byref(prop_count))
        buf = ctypes.create_unicode_buffer(buf_size.value)
        if wevtapi.EvtRender(None, h_event, 1, buf_size.value * 2, ctypes.byref(buf), ctypes.byref(buf_size), ctypes.byref(prop_count)):
            xml_text = buf.value
            root = ET.fromstring(xml_text)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            event_id = root.findtext(".//ns:EventID", namespaces=ns)
            time_created = root.find(".//ns:TimeCreated", namespaces=ns).attrib.get("SystemTime")
            provider = root.find(".//ns:Provider", namespaces=ns).attrib.get("Name")
            record_id = root.findtext(".//ns:EventRecordID", namespaces=ns)
            print("Parsed event:", {"event_id": event_id, "time": time_created, "provider": provider, "record_id": record_id})
        wevtapi.EvtClose(h_event)
    wevtapi.EvtClose(h_query)
