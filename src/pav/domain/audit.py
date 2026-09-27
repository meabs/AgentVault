from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import json

from .models import AuditEvent


GENESIS_SEED = "PAV-AUDIT-CHAIN-GENESIS-V1"


@dataclass(frozen=True)
class ChainVerificationResult:
    """Independent result of recomputing an audit event hash chain."""

    ok: bool
    checked_events: int
    valid_prefix_length: int
    first_break_sequence: int | None = None
    expected_hash: str | None = None
    actual_hash: str | None = None
    reason: str | None = None

    @property
    def status(self) -> str:
        return "ok" if self.ok else "broken"


def _canonical_event_payload(event: AuditEvent, sequence: int, previous_hash: str) -> str:
    content = event.model_dump(mode="json", exclude={"sequence", "hash"})
    return json.dumps(
        {
            "event": content,
            "previous_hash": previous_hash,
            "sequence": sequence,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def compute_audit_event_hash(
    event: AuditEvent, *, sequence: int, previous_hash: str
) -> str:
    """Compute an event hash from metadata, position, and its chain predecessor."""

    canonical = _canonical_event_payload(event, sequence, previous_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def seal_audit_event(
    event: AuditEvent, *, sequence: int, previous_hash: str
) -> AuditEvent:
    return event.model_copy(
        update={
            "sequence": sequence,
            "hash": compute_audit_event_hash(
                event, sequence=sequence, previous_hash=previous_hash
            ),
        }
    )


def seal_next_audit_event(event: AuditEvent, events: Iterable[AuditEvent]) -> AuditEvent:
    existing = list(events)
    if not existing:
        return seal_audit_event(event, sequence=1, previous_hash=GENESIS_SEED)

    previous = existing[-1]
    sequence = (previous.sequence if previous.sequence is not None else len(existing)) + 1
    previous_hash = previous.hash or GENESIS_SEED
    return seal_audit_event(event, sequence=sequence, previous_hash=previous_hash)


def verify_audit_chain(events: Iterable[AuditEvent]) -> ChainVerificationResult:
    """Recompute a stored audit chain and return its first independently found break."""

    previous_hash = GENESIS_SEED
    expected_sequence = 1
    valid_prefix_length = 0

    for index, event in enumerate(events):
        actual_sequence = event.sequence
        if actual_sequence != expected_sequence:
            expected_hash = compute_audit_event_hash(
                event,
                sequence=expected_sequence,
                previous_hash=previous_hash,
            )
            return ChainVerificationResult(
                ok=False,
                checked_events=index + 1,
                valid_prefix_length=valid_prefix_length,
                first_break_sequence=(
                    actual_sequence if actual_sequence is not None else expected_sequence
                ),
                expected_hash=expected_hash,
                actual_hash=event.hash,
                reason="sequence_gap",
            )

        expected_hash = compute_audit_event_hash(
            event,
            sequence=actual_sequence,
            previous_hash=previous_hash,
        )
        if event.hash != expected_hash:
            return ChainVerificationResult(
                ok=False,
                checked_events=index + 1,
                valid_prefix_length=valid_prefix_length,
                first_break_sequence=actual_sequence,
                expected_hash=expected_hash,
                actual_hash=event.hash,
                reason="hash_mismatch",
            )

        previous_hash = event.hash
        expected_sequence += 1
        valid_prefix_length += 1

    return ChainVerificationResult(
        ok=True,
        checked_events=valid_prefix_length,
        valid_prefix_length=valid_prefix_length,
    )


class AuditLog:
    """Append-only in-memory audit log with a per-log hash chain."""

    def __init__(self, events: Iterable[AuditEvent] = ()) -> None:
        self._events: list[AuditEvent] = list(events)

    def append(self, event: AuditEvent) -> AuditEvent:
        sealed = seal_next_audit_event(event, self._events)
        self._events.append(sealed)
        return sealed

    def all(self) -> list[AuditEvent]:
        return list(self._events)

    def for_task(self, task_id: str) -> list[AuditEvent]:
        return [event for event in self._events if event.task_id == task_id]

    def extend(self, events: Iterable[AuditEvent]) -> None:
        for event in events:
            self.append(event)
