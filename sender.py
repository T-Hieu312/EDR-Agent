"""Durable batch sender for the XDR ingestion API."""
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

import requests

log = logging.getLogger("edr.sender")


class Sender:
    def __init__(self, url, agent_id, agent_key, queue_file,
                 batch_size=20, flush_interval=3, max_retries=3, timeout=5,
                 max_spool_mb=1024):
        self.url = url
        self.agent_id = agent_id
        self.queue_file = Path(queue_file)
        self.batch_size = max(1, int(batch_size))
        self.flush_interval = max(0.1, float(flush_interval))
        self.max_retries = max(1, int(max_retries))
        self.timeout = max(0.1, float(timeout))
        self.max_spool_bytes = max(1, int(float(max_spool_mb) * 1024 * 1024))

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-Agent-Id": agent_id,
            "X-Agent-Key": agent_key,
        })
        self._thread = threading.Thread(target=self._loop, name="edr-sender", daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        retry_budget = self.max_retries * (self.timeout + 10) + self.flush_interval + 2
        self._thread.join(timeout=retry_budget)
        if self._thread.is_alive():
            log.error("Sender is still draining the durable spool; queued events remain on disk.")

    def enqueue(self, event):
        """Persist an event before returning, so the collector may safely advance its bookmark."""
        event["agent_id"] = self.agent_id
        line = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            current_size = self.queue_file.stat().st_size if self.queue_file.exists() else 0
            if current_size + len(line) > self.max_spool_bytes:
                raise OSError(
                    f"EDR spool limit reached ({self.max_spool_bytes} bytes); "
                    "event was not acknowledged to the collector"
                )
            with self.queue_file.open("ab") as spool:
                spool.write(line)
                spool.flush()
                os.fsync(spool.fileno())

    def _loop(self):
        while not self._stop.wait(self.flush_interval):
            self._drain_spool()
        # Final best-effort attempt; failures stay on disk for the next start.
        self._drain_spool()

    def _post(self, batch):
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._session.post(self.url, json=batch, timeout=self.timeout)
                if 200 <= response.status_code < 300:
                    return True
                log.warning("XDR returned HTTP %s (attempt %s/%s)",
                            response.status_code, attempt, self.max_retries)
            except requests.RequestException as exc:
                log.warning("XDR connection failed (attempt %s/%s): %s",
                            attempt, self.max_retries, exc)
            if attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 10))
        return False

    def _replace_spool(self, events):
        """Atomically replace the queue after successful batches have been acknowledged."""
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.queue_file.parent,
                prefix=f"{self.queue_file.name}.", suffix=".tmp", delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                for event in events:
                    temp_file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.queue_file)
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def _drain_spool(self):
        # Keep the lock through send + atomic rewrite so concurrent appends cannot be lost.
        with self._lock:
            if not self.queue_file.exists() or self.queue_file.stat().st_size == 0:
                return
            try:
                with self.queue_file.open("r", encoding="utf-8") as spool:
                    events = [json.loads(line) for line in spool if line.strip()]
            except (OSError, json.JSONDecodeError) as exc:
                log.error("Cannot read EDR spool; preserving it for recovery: %s", exc)
                return

            remaining = []
            sent = 0
            for offset in range(0, len(events), self.batch_size):
                batch = events[offset:offset + self.batch_size]
                if self._post(batch):
                    sent += len(batch)
                else:
                    remaining.extend(batch)
            try:
                self._replace_spool(remaining)
            except OSError:
                # If the rewrite fails, the original spool is still intact unless replace completed.
                log.exception("Could not update EDR spool after sending")
                return
            if sent:
                log.info("XDR acknowledged %s queued events; %s remain", sent, len(remaining))
