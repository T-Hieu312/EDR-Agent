from collections import defaultdict, deque
from typing import Any, Deque, Dict, List

from fastapi import FastAPI

app = FastAPI(title="XDR Server Prototype")
agent_data: Dict[str, Dict[str, Any]] = {}
command_queues: Dict[str, Deque[Dict[str, Any]]] = defaultdict(deque)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/ingest")
def ingest(payload: dict) -> dict:
    agent_id = payload.get("agent_id", "unknown")
    agent_data[agent_id] = payload
    return {"status": "accepted", "agent_id": agent_id}


@app.get("/agents")
def list_agents() -> dict:
    return {"agents": list(agent_data.keys())}


@app.get("/agent/{agent_id}")
def get_agent(agent_id: str) -> dict:
    return agent_data.get(agent_id, {"status": "not_found"})


@app.post("/commands/{agent_id}")
def enqueue_command(agent_id: str, command: dict) -> dict:
    command_queues[agent_id].append(command)
    return {"status": "queued", "agent_id": agent_id}


@app.get("/commands/{agent_id}")
def get_commands(agent_id: str) -> dict:
    commands = list(command_queues.get(agent_id, deque()))
    command_queues[agent_id].clear()
    return {"agent_id": agent_id, "commands": commands}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("edr.server:app", host="0.0.0.0", port=8000, reload=False)
