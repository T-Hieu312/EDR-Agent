import json

import pytest

from sender import Sender


def make_sender(queue_file, max_spool_mb=1):
    return Sender(
        url="http://127.0.0.1:8000/api/events/batch",
        agent_id="agent-01",
        agent_key="test-key",
        queue_file=queue_file,
        max_spool_mb=max_spool_mb,
    )


def test_enqueue_persists_event_and_drain_removes_acknowledged_spool(tmp_path) -> None:
    queue_file = tmp_path / "queue" / "spool.jsonl"
    sender = make_sender(queue_file)
    event = {"record_id": "123", "data": {"Image": "notepad.exe"}}
    sender._post = lambda batch: batch == [{**event, "agent_id": "agent-01"}]

    sender.enqueue(event)
    assert json.loads(queue_file.read_text(encoding="utf-8")) == {
        **event,
        "agent_id": "agent-01",
    }

    sender._drain_spool()

    assert queue_file.read_text(encoding="utf-8") == ""


def test_failed_send_keeps_event_in_spool(tmp_path) -> None:
    queue_file = tmp_path / "spool.jsonl"
    sender = make_sender(queue_file)
    sender._post = lambda _batch: False
    sender.enqueue({"record_id": "123"})

    sender._drain_spool()

    assert len(queue_file.read_text(encoding="utf-8").splitlines()) == 1


def test_spool_limit_rejects_event_without_dropping_existing_data(tmp_path) -> None:
    queue_file = tmp_path / "spool.jsonl"
    sender = make_sender(queue_file, max_spool_mb=0.00005)
    sender.enqueue({"data": "x"})
    existing = queue_file.read_bytes()

    with pytest.raises(OSError, match="spool limit reached"):
        sender.enqueue({"data": "y" * 100})

    assert queue_file.read_bytes() == existing
