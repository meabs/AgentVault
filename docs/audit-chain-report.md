# Audit chain report

Personal Authority Vault now makes every persisted audit event tamper-evident
with a per-store SHA-256 hash chain. This implements PRD §SR7 while retaining
the metadata-only event payload required by §SR8.

## Construction

Each `AuditEvent` carries two additional fields when it is written:

- `sequence`: a one-based, monotonic sequence number within that store;
- `hash`: the lowercase SHA-256 digest for that event.

The first event uses the documented genesis seed
`PAV-AUDIT-CHAIN-GENESIS-V1` as its previous hash. Every subsequent event uses
the stored hash of the preceding event. The digest input is canonical JSON
with sorted keys and compact separators:

```json
{
  "event": "the event's existing metadata-only fields",
  "previous_hash": "the prior event hash or the genesis seed",
  "sequence": 1
}
```

The `event` value includes the event's existing `id`, type, timestamp, task,
agent, request, grant, purpose, resource, mode, destination, and metadata
fields. It explicitly excludes `sequence` and `hash` themselves. No secret or
new sensitive value is added to the event or to the hash input.

The in-memory adapter seals events before appending them to its event list.
SQLite stores the sealed event payload, sequence, and hash in the
`audit_events` table. SQLite also keeps the hash in a dedicated `event_hash`
column alongside its existing sequence column, so loading uses the persisted
chain fields rather than trusting only the serialized model payload.

## Verification and localization

`verify_audit_chain(events)` independently recomputes every digest from the
loaded event content. It does not rely on a write-time validity flag.

Verification begins at the genesis seed and expected sequence 1. It stops at
the first mismatch and returns:

- `status`: `ok` or `broken`;
- `first_break_sequence`;
- `expected_hash` and `actual_hash`;
- `valid_prefix_length`, the number of events verified before the break;
- `reason`, either `hash_mismatch` or `sequence_gap`.

Therefore, changing event 2 reports event 2 as the first break while events
before it remain a valid prefix. Deleting event 2 leaves event 3 with a
sequence gap and its old predecessor hash, so the verifier reports sequence 3
as the first break.

The task audit page verifies the complete persisted chain, not only the
task-filtered timeline, and shows either “Audit chain verified” or “Audit
chain broken” with the first affected sequence number.

## Why this design

This is the smallest mechanism that gives an offline auditor useful evidence
of silent changes without adding a cloud dependency, blockchain, or user-key
signing flow. The sequence makes omissions and reordering visible, while the
predecessor hash makes content changes propagate to the next link. It is
tamper-evident rather than an access-control boundary: an attacker who can
rewrite every event and every successor hash could construct a new internally
consistent chain, which is outside this MVP's threat mitigation.

## Manual SQLite tampering demonstration

The demonstration created a fresh SQLite store, wrote three events through a
normal `Authority` session (`TASK_CREATED`, `ACCESS_REQUESTED`, and
`POLICY_DENIED`), and verified the reopened persisted log. The payload for
sequence 2 was then edited directly with `sqlite3` to add
`tampered_by_manual_demo`, bypassing `Authority` and the normal write path.

Output from the run:

```text
database=/tmp/pav-audit-demo.rs3NVQ/vault.sqlite3
before_tampering status=ok events=3
after_tampering status=broken
first_break_sequence=2
valid_prefix_length=1
expected_hash=b8c9c9ca29caad4a8cdd931f5bd17bf00561d584bfa4378ea7d70ddc34e8ef25
actual_hash=1c831080e1279c60c963858d411a2b24441972c90e09a6ccefa9a9d1774f2a14
```

The differing expected and actual hashes demonstrate that the changed stored
content was detected and localized without distributed immutable storage or
user-key cryptographic signing.

## Verification

`uv run pytest` passes with 56 tests and 0 failures, including untampered
chains, direct in-memory and SQLite content mutation, SQLite middle-event
deletion, backend equivalence, and the audit-page status.
