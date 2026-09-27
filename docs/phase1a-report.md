# Phase 1A report

Phase 1A adds encrypted local persistence and a REST adapter while keeping the
Phase 0 authority lifecycle as the only place where policy, approval, grant,
and enforcement decisions are made.

## Storage interface

`AuthorityStorage` is the seam between `Authority` and state storage. It has
load/save operations for attributes, claim definitions, external handles,
agents, tasks, requests/decisions, grants, and append-only audit events.
`InMemoryStorage` is the default adapter, so the Phase 0 tests continue to run
without changes. `SQLiteStorage` loads the same Pydantic domain models and
persists lifecycle mutations, including grant use counts and expiry/revocation
state. Requests and decisions are stored as well because REST status and
approval are separate calls.

Policies remain runtime configuration, matching Phase 0: the current model has
no policy-management operation, and policy evaluation stays inside
`Authority`.

Claim evaluator callables are trusted application code rather than data. Claim
metadata and source attribute names are persisted; a reconnecting application
can provide the evaluator again when it constructs `Authority`. This avoids
serializing executable code into the vault.

## Encryption key and encrypted values

`SQLiteStorage` encrypts every attribute value before writing it to SQLite with
Fernet from `cryptography`. The key is resolved in this order:

1. explicit `key=` (useful for tests and embedding);
2. `PAV_ENCRYPTION_KEY`; or
3. a separately stored key file from `PAV_KEY_FILE`, defaulting to the SQLite
   path with `.key` appended.

The generated key file is created with mode `0600`. The default REST app uses
the separate key-file path, not a key stored in the database. Fernet is an
authenticated, well-known construction provided by the library; PAV does not
implement cryptography itself. Attribute values are encoded with small type
tags so dates and datetimes retain their Python types after reconnecting.

Audit rows contain identifiers, operation metadata, and destinations, never
raw attribute values or external secret material. The persistence test reads
the SQLite file bytes directly and proves a sensitive attribute value is not
present.

## REST adapter

`pav.adapters.rest.app` exposes task creation, access requests and status,
direct approval, reveal, prove, use, revoke, grant inspection, and audit
inspection. The routes only translate HTTP models/statuses and orchestrate the
existing `Authority` calls; policy and enforcement logic is not duplicated in
the adapter. `GET /health` provides a simple startup probe.

The approval endpoint is intentionally a direct Phase-1 stand-in for the later
approval UI. Domain decisions from Phase 0 are retained: a request with no
matching policy requires approval, and `max_uses` meters `use` only, not
`reveal` or `prove`.

