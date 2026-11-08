import json
import platform
import time
from typing import Any, Dict, List

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


def _safe_json(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def collect_processes(limit: int = 200) -> List[Dict[str, Any]]:
    if psutil is None:
        return []

    processes: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "status", "create_time"]):
        try:
            info = proc.info
            cmdline = info.get("cmdline") or []
            processes.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "ppid": info.get("ppid"),
                    "cmdline": " ".join(str(item) for item in cmdline),
                    "status": info.get("status"),
                    "create_time": info.get("create_time"),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes[:limit]


def collect_network_connections() -> List[Dict[str, Any]]:
    if psutil is None:
        return []

    try:
        connections = psutil.net_connections(kind="inet")
    except (AttributeError, OSError, PermissionError):
        return []

    items: List[Dict[str, Any]] = []
    for conn in connections:
        item = {
            "fd": conn.fd,
            "family": str(conn.family),
            "type": str(conn.type),
            "status": conn.status,
            "local_address": None,
            "remote_address": None,
            "pid": conn.pid,
        }
        if conn.laddr:
            item["local_address"] = str(conn.laddr)
        if conn.raddr:
            item["remote_address"] = str(conn.raddr)
        items.append(item)
    return items


def collect_windows_events(max_events: int = 20) -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []

    try:
        import win32evtlog  # type: ignore
        import win32evtlogutil  # type: ignore
    except Exception:
        return []

    events: List[Dict[str, Any]] = []
    try:
        server = "localhost"
        log_type = "System"
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in records:
            event_time = event.TimeGenerated
            if hasattr(event_time, "isoformat"):
                event_time = event_time.isoformat()
            events.append(
                {
                    "event_id": event.EventID,
                    "source": event.SourceName,
                    "time": str(event_time),
                    "message": win32evtlogutil.SafeFormatMessage(event, None),
                }
            )
            if len(events) >= max_events:
                break
    except Exception:
        return []
    return events


def collect_snapshot() -> Dict[str, Any]:
    return {
        "timestamp": int(time.time()),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "processes": collect_processes(),
        "network": collect_network_connections(),
        "windows_events": collect_windows_events(),
    }
