"""
sysmon_collector.py — Đọc sự kiện Sysmon từ Windows Event Log và chuẩn hóa thành JSON.

Dùng API Windows Event Log (win32evtlog) qua một subscription dạng "pull".
Có cơ chế bookmark: lưu vị trí sự kiện cuối đã đọc, sau khi restart đọc tiếp
từ đó để không bỏ sót và không đọc lại từ đầu.

Phụ thuộc: pywin32  (pip install pywin32) — chỉ chạy trên Windows.
"""
import os
import time
import logging
import xml.etree.ElementTree as ET

try:
    import win32evtlog
    import win32event
except ImportError:  # để import được trên máy không phải Windows (vd lúc dev/test)
    win32evtlog = None
    win32event = None

log = logging.getLogger("edr.collector")

# Namespace mặc định của event XML trên Windows
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Ánh xạ Sysmon Event ID -> tên loại sự kiện (đưa vào trường event_type)
EVENT_TYPE = {
    1: "process_create",
    3: "network_connect",
    10: "process_access",
    11: "file_create",
    13: "registry_set",
    22: "dns_query",
}


class SysmonCollector:
    def __init__(self, channel, event_ids, bookmark_file, poll_interval=2):
        if win32evtlog is None or win32event is None:
            raise RuntimeError("Thiếu pywin32. Cài bằng: pip install pywin32 (chạy trên Windows).")
        self.channel = channel
        self.event_ids = event_ids
        self.bookmark_file = bookmark_file
        self.poll_interval = poll_interval
        self._query = self._build_query(event_ids)
        self._signal_event = None

    @staticmethod
    def _build_query(event_ids):
        # Lọc ngay ở tầng Event Log cho nhẹ: chỉ lấy các Event ID quan tâm
        conds = " or ".join(f"EventID={i}" for i in event_ids)
        return f"*[System[({conds})]]"

    def _load_bookmark(self):
        if os.path.exists(self.bookmark_file):
            try:
                with open(self.bookmark_file, "r", encoding="utf-8") as f:
                    xml = f.read().strip()
                if xml:
                    return win32evtlog.EvtCreateBookmark(xml)
            except Exception as ex:
                log.warning("Không đọc được bookmark, đọc từ sự kiện mới: %s", ex)
        return None

    def _save_bookmark(self, event_handle):
        try:
            bm = win32evtlog.EvtCreateBookmark(None)
            win32evtlog.EvtUpdateBookmark(bm, event_handle)
            xml = win32evtlog.EvtRender(bm, win32evtlog.EvtRenderBookmark)
            with open(self.bookmark_file, "w", encoding="utf-8") as f:
                f.write(xml)
        except Exception as ex:
            log.warning("Không lưu được bookmark: %s", ex)

    def _subscribe(self):
        if self._signal_event is None:
            self._signal_event = win32event.CreateEvent(None, 0, 0, None)
        bookmark = self._load_bookmark()
        if bookmark is not None:
            flags = win32evtlog.EvtSubscribeStartAfterBookmark
            log.info("Đọc tiếp từ bookmark đã lưu.")
            return win32evtlog.EvtSubscribe(
                self.channel, flags, SignalEvent=self._signal_event,
                Bookmark=bookmark, Query=self._query)
        # Chưa có bookmark -> chỉ lấy sự kiện phát sinh từ bây giờ
        flags = win32evtlog.EvtSubscribeToFutureEvents
        log.info("Chưa có bookmark, bắt đầu từ sự kiện mới.")
        return win32evtlog.EvtSubscribe(
            self.channel, flags, SignalEvent=self._signal_event, Query=self._query)

    @staticmethod
    def _parse_event(xml_str):
        """Phân tích XML của một event -> dict đã chuẩn hóa."""
        root = ET.fromstring(xml_str)
        system = root.find("e:System", NS)
        eid = int(system.find("e:EventID", NS).text)
        time_created = system.find("e:TimeCreated", NS).get("SystemTime")
        computer = system.find("e:Computer", NS).text
        record_id = system.find("e:EventRecordID", NS).text

        # EventData gồm nhiều <Data Name="...">value</Data>
        data = {}
        edata = root.find("e:EventData", NS)
        if edata is not None:
            for d in edata.findall("e:Data", NS):
                data[d.get("Name")] = d.text

        return {
            "source": "sysmon",
            "sysmon_event_id": eid,
            "event_type": EVENT_TYPE.get(eid, f"sysmon_{eid}"),
            "timestamp": time_created,
            "computer": computer,
            "record_id": record_id,
            "data": data,
        }

    def stream(self):
        """Generator: liên tục yield từng event đã chuẩn hóa (dict)."""
        sub = self._subscribe()
        while True:
            try:
                events = win32evtlog.EvtNext(sub, 50)
            except Exception as ex:
                # Hết event trong hàng đợi -> nghỉ rồi quét tiếp
                if getattr(ex, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                    win32event.WaitForSingleObject(
                        self._signal_event, int(self.poll_interval * 1000))
                    continue
                log.error("Lỗi đọc Event Log, thử lại: %s", ex)
                time.sleep(self.poll_interval)
                sub = self._subscribe()
                continue

            for ev in events:
                try:
                    xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    yield self._parse_event(xml_str)
                    self._save_bookmark(ev)  # lưu vị trí sau mỗi event đã xử lý
                except Exception as ex:
                    log.warning("Bỏ qua 1 event lỗi parse: %s", ex)
