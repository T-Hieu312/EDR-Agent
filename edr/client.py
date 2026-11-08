import os
import platform
import time
from typing import Any, Dict, List

import requests

from .collector import collect_snapshot
from .ioc import detect_ioc


class EDRClient:
    def __init__(self, agent_id: str | None = None, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id or f"{platform.node()}-{os.getpid()}"

    def _analyze_snapshot(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for process in snapshot.get("processes", []):
            name = process.get("name") or "unknown"
            cmdline = process.get("cmdline") or ""
            parent_name = ""
            parent_pid = process.get("ppid")
            if parent_pid:
                for candidate in snapshot.get("processes", []):
                    if candidate.get("pid") == parent_pid:
                        parent_name = candidate.get("name") or ""
                        break

            result = detect_ioc(
                process_name=name,
                command_line=cmdline,
                parent_name=parent_name,
                network_connections=snapshot.get("network", []),
                event_data=snapshot.get("windows_events", []),
            )
            if result["suspicious"]:
                findings.append(
                    {
                        "pid": process.get("pid"),
                        "process_name": name,
                        "risk_score": result["risk_score"],
                        "matched_iocs": result["matched_iocs"],
                    }
                )
        return findings

    def send_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "timestamp": snapshot.get("timestamp"),
            "platform": snapshot.get("platform"),
            "processes": snapshot.get("processes", []),
            "network": snapshot.get("network", []),
            "windows_events": snapshot.get("windows_events", []),
            "findings": self._analyze_snapshot(snapshot),
        }
        response = requests.post(f"{self.server_url}/ingest", json=payload, timeout=10)
        response.raise_for_status()
        return response.json()

    def receive_commands(self) -> List[Dict[str, Any]]:
        response = requests.get(f"{self.server_url}/commands/{self.agent_id}", timeout=10)
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json().get("commands", [])

    def run_once(self) -> Dict[str, Any]:
        snapshot = collect_snapshot()
        server_response = self.send_snapshot(snapshot)
        commands = self.receive_commands()
        return {"snapshot": snapshot, "server_response": server_response, "commands": commands}

    def run_loop(self, interval: int = 30, max_cycles: int | None = None):
        cycle = 0
        while max_cycles is None or cycle < max_cycles:
            try:
                result = self.run_once()
                print(f"[EDR] cycle={cycle} findings={len(result['snapshot'].get('processes', []))} commands={len(result['commands'])}")
                if result["commands"]:
                    print("[EDR] received commands:", result["commands"])
            except Exception as exc:
                print(f"[EDR] error: {exc}")
            cycle += 1
            time.sleep(interval)


if __name__ == "__main__":
    client = EDRClient(server_url="http://127.0.0.1:8000")
    client.run_loop(interval=10, max_cycles=3)
