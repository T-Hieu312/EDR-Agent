"""Poll XDR for approved commands and report endpoint execution results."""
import logging
import threading
import time
from urllib.parse import urlparse

import requests

from response_executor import execute

log = logging.getLogger("edr.response")


class ResponseWorker:
    def __init__(self, ingest_url: str, agent_id: str, agent_key: str, host_id: str, interval: float = 5):
        parsed = urlparse(ingest_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.xdr_host = parsed.hostname or "127.0.0.1"
        self.agent_id, self.agent_key, self.host_id = agent_id, agent_key, host_id
        self.interval = max(2.0, float(interval))
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.session.headers.update({
            "X-Agent-Id": agent_id,
            "X-Agent-Key": agent_key,
            "X-Host-Id": host_id,
        })
        self.thread = threading.Thread(target=self._run, name="edr-response", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=10)
        self.session.close()

    def _run(self) -> None:
        commands_url = self.base_url + "/api/agent/commands"
        result_url = commands_url + "/result"
        while not self.stop_event.is_set():
            try:
                response = self.session.get(commands_url, timeout=10)
                response.raise_for_status()
                for command in response.json().get("commands", []):
                    try:
                        detail = execute(command, self.xdr_host)
                        success = True
                    except Exception as error:
                        detail = f"{type(error).__name__}: {error}"
                        success = False
                        log.exception("Response command %s failed", command.get("request_id"))
                    report = self.session.post(
                        result_url,
                        json={"request_id": command["request_id"], "success": success, "result": detail},
                        timeout=10,
                    )
                    report.raise_for_status()
                    log.info("Response command %s: %s", command["request_id"], detail)
            except requests.RequestException as error:
                log.warning("Could not poll/report XDR response commands: %s", error)
            self.stop_event.wait(self.interval)
