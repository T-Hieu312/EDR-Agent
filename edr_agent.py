"""
edr_agent.py — Điểm chạy chính của EDR Agent (TV1 - Nhóm A19).

Luồng: Sysmon Event Log --(collector)--> chuẩn hóa JSON --(sender)--> XDR server.
Chạy liên tục, chịu được lỗi kết nối, resume sau khi restart nhờ bookmark.

Chạy:  python edr_agent.py --config config.yaml
"""
import argparse
import logging
import os
import platform
import signal
import socket
import sys

import yaml

from sender import Sender
from sysmon_collector import SysmonCollector
from event_filter import EventFilter


def setup_logging(cfg):
    level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    if cfg.get("file"):
        handlers.append(logging.FileHandler(cfg["file"], encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description="EDR Agent - Nhóm A19")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    setup_logging(cfg.get("logging", {}))
    log = logging.getLogger("edr.main")

    if platform.system() != "Windows":
        log.error("EDR Agent chỉ chạy trên Windows (cần Sysmon + Event Log).")
        sys.exit(1)

    agent_id = cfg["agent"].get("agent_id") or socket.gethostname()
    log.info("Khởi động EDR Agent | agent_id=%s", agent_id)

    s = cfg["sender"]
    st = cfg["storage"]
    agent_key = os.environ.get("XDR_AGENT_KEY") or cfg["agent"].get("agent_key")
    if not agent_key:
        log.error("Set XDR_AGENT_KEY or configure agent.agent_key before starting.")
        sys.exit(1)

    sender = Sender(
        url=s["url"], agent_id=agent_id, agent_key=agent_key,
        queue_file=st["queue_file"], batch_size=s["batch_size"],
        flush_interval=s["flush_interval"], max_retries=s["max_retries"],
        timeout=s["timeout"],
    )
    sender.start()

    c = cfg["collector"]
    event_filter = EventFilter(cfg.get("filters", {}))
    collector = SysmonCollector(
        channel=c["channel"], event_ids=c["event_ids"],
        bookmark_file=st["bookmark_file"], poll_interval=c["poll_interval"],
    )

    # Thoát êm khi Ctrl+C
    def _graceful(_sig, _frm):
        log.info("Nhận tín hiệu dừng, flush dữ liệu còn lại...")
        sender.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, _graceful)
    signal.signal(signal.SIGTERM, _graceful)

    count = 0
    filtered = 0
    try:
        for event in collector.stream():
            if not event_filter.should_send(event):
                filtered += 1
                if filtered % 100 == 0:
                    log.info("ÄÃ£ loáº¡i %s event theo filter.", filtered)
                continue
            sender.enqueue(event)
            count += 1
            if count % 50 == 0:
                log.info("Đã thu thập %s sự kiện.", count)
    except Exception as ex:
        log.exception("Collector dừng bất thường: %s", ex)
        sender.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
