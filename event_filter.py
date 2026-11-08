"""Configurable event filtering before events enter the XDR sender queue."""
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from typing import Any

log = logging.getLogger("edr.filter")


class EventFilter:
    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.enabled = bool(config.get("enabled", True))
        self.exclude_event_ids = {int(value) for value in config.get("exclude_event_ids", [])}
        self.exclude_process_names = {
            str(value).casefold() for value in config.get("exclude_process_names", [])
        }
        self.exclude_path_contains = [
            str(value).casefold() for value in config.get("exclude_path_contains", [])
        ]
        self.exclude_data_contains = {
            str(key): [str(value).casefold() for value in values]
            for key, values in (config.get("exclude_data_contains", {}) or {}).items()
        }
        # For noisy event IDs, forward only events matching configured field values.
        # Example: keep Sysmon Event 10 only when TargetImage is lsass.exe.
        self.keep_event_ids_when = {
            int(event_id): {
                str(field): [str(value).casefold() for value in values]
                for field, values in (conditions or {}).items()
            }
            for event_id, conditions in (config.get("keep_event_ids_when", {}) or {}).items()
        }
        self.dedupe_window = max(0, float(config.get("dedupe_window_seconds", 10)))
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._max_seen = max(100, int(config.get("dedupe_cache_size", 10000)))
        self._log = log

    def should_send(self, event: dict[str, Any]) -> bool:
        if not self.enabled:
            return True

        event_id = event.get("sysmon_event_id")
        if event_id is not None and int(event_id) in self.exclude_event_ids:
            return False

        data = event.get("data") or {}
        keep_conditions = self.keep_event_ids_when.get(int(event_id)) if event_id is not None else None
        if keep_conditions:
            matched = any(
                any(needle in str(data.get(field) or "").casefold() for needle in needles)
                for field, needles in keep_conditions.items()
            )
            if not matched:
                return False

        image = str(data.get("Image") or data.get("ProcessName") or "")
        image_name = os.path.basename(image.replace("/", "\\")).casefold()
        if image_name in self.exclude_process_names:
            return False

        searchable = " ".join(str(value) for value in data.values()).casefold()
        if any(value in searchable for value in self.exclude_path_contains):
            return False
        for field, needles in self.exclude_data_contains.items():
            value = str(data.get(field) or "").casefold()
            if any(needle in value for needle in needles):
                return False

        if self.dedupe_window:
            # Exclude fields that make otherwise identical events unique.
            identity = {
                "event_type": event.get("event_type"),
                "sysmon_event_id": event_id,
                "computer": event.get("computer"),
                "data": data,
            }
            fingerprint = hashlib.sha256(
                json.dumps(identity, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
            ).hexdigest()
            now = time.monotonic()
            while self._seen:
                oldest_key, oldest_at = next(iter(self._seen.items()))
                if now - oldest_at <= self.dedupe_window:
                    break
                self._seen.pop(oldest_key)
            previous = self._seen.get(fingerprint)
            if previous is not None and now - previous <= self.dedupe_window:
                self._seen.move_to_end(fingerprint)
                return False
            self._seen[fingerprint] = now
            self._seen.move_to_end(fingerprint)
            while len(self._seen) > self._max_seen:
                self._seen.popitem(last=False)
        return True
