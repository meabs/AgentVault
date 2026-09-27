from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from pav.domain.audit import verify_audit_chain
from pav.domain.models import AuditEvent
from pav.domain.types import AuditEventType
from pav.persistence import InMemoryStorage, SQLiteStorage


def _event(label: str) -> AuditEvent:
    return AuditEvent(
        id=f"event-{label}",
        event_type=AuditEventType.TASK_CREATED,
        timestamp=datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc),
        task_id=f"task-{label}",
        metadata={"label": label},
    )


def _append_three(storage: InMemoryStorage | SQLiteStorage) -> None:
    for label in ("one", "two", "three"):
        storage.append_audit_event(_event(label))


def test_untampered_event_sequence_verifies_as_ok() -> None:
    storage = InMemoryStorage()
    _append_three(storage)

    events = storage.load_audit_events()
    result = verify_audit_chain(events)

    assert result.ok is True
    assert result.status == "ok"
    assert result.valid_prefix_length == 3
    assert [event.sequence for event in events] == [1, 2, 3]
    assert all(event.hash for event in events)


def test_mutating_stored_event_reports_the_first_tampered_sequence() -> None:
    storage = InMemoryStorage()
    _append_three(storage)
    original_hash = storage.audit_events[1].hash

    storage.audit_events[1].metadata["label"] = "tampered"

    result = verify_audit_chain(storage.load_audit_events())

    assert result.ok is False
    assert result.status == "broken"
    assert result.first_break_sequence == 2
    assert result.valid_prefix_length == 1
    assert result.expected_hash != result.actual_hash
    assert result.actual_hash == original_hash


def test_deleting_middle_event_reports_the_sequence_gap() -> None:
    storage = InMemoryStorage()
    _append_three(storage)

    del storage.audit_events[1]

    result = verify_audit_chain(storage.load_audit_events())

    assert result.ok is False
    assert result.first_break_sequence == 3
    assert result.valid_prefix_length == 1
    assert result.reason == "sequence_gap"


def test_sqlite_and_in_memory_storage_produce_equivalent_valid_chains(tmp_path) -> None:
    in_memory = InMemoryStorage()
    sqlite = SQLiteStorage(tmp_path / "audit.sqlite3")
    try:
        events = [_event(label) for label in ("one", "two", "three")]
        for event in events:
            in_memory.append_audit_event(event)
            sqlite.append_audit_event(event)

        in_memory_events = in_memory.load_audit_events()
        sqlite_events = sqlite.load_audit_events()

        assert [(event.sequence, event.hash) for event in in_memory_events] == [
            (event.sequence, event.hash) for event in sqlite_events
        ]
        assert verify_audit_chain(in_memory_events).ok is True
        assert verify_audit_chain(sqlite_events).ok is True
    finally:
        sqlite.close()


def test_sqlite_payload_tampering_is_detected_at_the_changed_sequence(tmp_path) -> None:
    database = tmp_path / "audit.sqlite3"
    storage = SQLiteStorage(database)
    try:
        _append_three(storage)
    finally:
        storage.close()

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT payload FROM audit_events WHERE sequence = 2"
        ).fetchone()
        assert row is not None
        payload = json.loads(row[0])
        payload["metadata"]["label"] = "tampered"
        connection.execute(
            "UPDATE audit_events SET payload = ? WHERE sequence = 2",
            (json.dumps(payload),),
        )

    reopened = SQLiteStorage(database)
    try:
        result = verify_audit_chain(reopened.load_audit_events())
    finally:
        reopened.close()

    assert result.ok is False
    assert result.first_break_sequence == 2
    assert result.valid_prefix_length == 1


def test_deleting_middle_sqlite_event_is_detected_as_a_sequence_gap(tmp_path) -> None:
    database = tmp_path / "audit.sqlite3"
    storage = SQLiteStorage(database)
    try:
        _append_three(storage)
    finally:
        storage.close()

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM audit_events WHERE sequence = 2")

    reopened = SQLiteStorage(database)
    try:
        result = verify_audit_chain(reopened.load_audit_events())
    finally:
        reopened.close()

    assert result.ok is False
    assert result.first_break_sequence == 3
    assert result.valid_prefix_length == 1
    assert result.reason == "sequence_gap"
