"""
sender.py — Gửi event lên XDR server qua HTTP API, có xử lý lỗi kết nối.

Cơ chế:
- Gom event theo lô (batch) rồi POST JSON.
- Nếu gửi thất bại (server sập/mạng lỗi): thử lại max_retries lần, vẫn hỏng thì
  cất lô vào hàng đợi đĩa (spool.jsonl). Mỗi chu kỳ flush sẽ thử gửi lại hàng đợi.
=> Không mất dữ liệu khi XDR server tạm thời không truy cập được (yêu cầu Tuần 3).
"""
import json
import logging
import os
import threading
import time

import requests

log = logging.getLogger("edr.sender")


class Sender:
    def __init__(self, url, agent_id, agent_key, queue_file,
                 batch_size=20, flush_interval=3, max_retries=3, timeout=5):
        self.url = url
        self.agent_id = agent_id
        self.agent_key = agent_key
        self.queue_file = queue_file
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.timeout = timeout

        self._buffer = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-Agent-Id": agent_id,
            "X-Agent-Key": agent_key,
        })
        self._thread = threading.Thread(target=self._loop, daemon=True)

    # ---- API công khai ----
    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=self.flush_interval + self.timeout)
        self._flush()  # cố gắng gửi nốt trước khi thoát

    def enqueue(self, event):
        """Gắn metadata agent rồi đưa event vào buffer."""
        event["agent_id"] = self.agent_id
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self.batch_size:
                batch, self._buffer = self._buffer, []
                self._send_or_spool(batch)

    # ---- Nội bộ ----
    def _loop(self):
        while not self._stop.is_set():
            time.sleep(self.flush_interval)
            self._flush()
            self._drain_spool()

    def _flush(self):
        with self._lock:
            if not self._buffer:
                return
            batch, self._buffer = self._buffer, []
        self._send_or_spool(batch)

    def _post(self, batch):
        """Trả True nếu server nhận thành công."""
        for attempt in range(1, self.max_retries + 1):
            try:
                r = self._session.post(self.url, data=json.dumps(batch),
                                       timeout=self.timeout)
                if 200 <= r.status_code < 300:
                    return True
                log.warning("Server trả %s (lần %s)", r.status_code, attempt)
            except requests.RequestException as ex:
                log.warning("Lỗi kết nối XDR (lần %s/%s): %s",
                            attempt, self.max_retries, ex)
            time.sleep(min(2 ** attempt, 10))  # backoff
        return False

    def _send_or_spool(self, batch):
        if not batch:
            return
        if self._post(batch):
            log.info("Đã gửi %s event tới XDR.", len(batch))
        else:
            self._spool(batch)
            log.error("Không gửi được, đã cất %s event vào hàng đợi đĩa.", len(batch))

    def _spool(self, batch):
        with open(self.queue_file, "a", encoding="utf-8") as f:
            for ev in batch:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def _drain_spool(self):
        """Thử gửi lại các event đang nằm trong hàng đợi đĩa."""
        if not os.path.exists(self.queue_file) or os.path.getsize(self.queue_file) == 0:
            return
        with open(self.queue_file, "r", encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        if not lines:
            return
        events = [json.loads(l) for l in lines]
        # gửi theo lô
        remaining = []
        for i in range(0, len(events), self.batch_size):
            batch = events[i:i + self.batch_size]
            if not self._post(batch):
                remaining.extend(batch)  # còn hỏng -> giữ lại
        # ghi lại phần chưa gửi được (rỗng nếu đã sạch hàng đợi)
        with open(self.queue_file, "w", encoding="utf-8") as f:
            for ev in remaining:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        if not remaining:
            log.info("Đã gửi hết hàng đợi đĩa, XDR đã nhận lại dữ liệu tồn.")
