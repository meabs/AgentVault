from __future__ import annotations

from collections.abc import Iterable

from .models import AuditEvent


class AuditLog:
    """Append-only in-memory audit log for the Phase 0 spike."""

    def __init__(self, events: Iterable[AuditEvent] = ()) -> None:
        self._events: list[AuditEvent] = list(events)

    def append(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    def all(self) -> list[AuditEvent]:
        return list(self._events)

    def for_task(self, task_id: str) -> list[AuditEvent]:
        return [event for event in self._events if event.task_id == task_id]

    def extend(self, events: Iterable[AuditEvent]) -> None:
        self._events.extend(events)
