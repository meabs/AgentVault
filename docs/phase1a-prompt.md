You're continuing Personal Authority Vault (PAV). Phase 0 (domain model +
in-memory authority lifecycle, `src/pav/authority/service.py`) is built and
tested — read it, and `docs/PRD.md`, before writing anything. Also read
`docs/phase0-report.md` for the two judgment calls already made (approval
required when no policy matches; `max_uses` meters `use` only, not
`reveal`/`prove`) — keep those decisions, don't relitigate them.

## Scope for this step: persistence + REST API only

This is the first half of PRD §27 Phase 1. Build:

1. **Encrypted local persistence** (PRD §14, §FR1, SR5/SR6): a SQLite-backed
   store for attributes, claim definitions, external handles, agents, tasks,
   grants, and the audit log, replacing the current pure in-memory
   dictionaries in `Authority`. Sensitive attribute *values* must be encrypted
   at rest (application-level encryption, e.g. `cryptography`'s Fernet over a
   key that is NOT stored in the same SQLite file — read it from an
   environment variable or a separate key file, your call, but document
   which). Keep the in-memory backend available too (Phase 0's tests must
   still pass unmodified against it) — introduce a storage interface/protocol
   so `Authority` can run against either backend. Do not invent your own
   cryptographic primitives; use a well-known library.
2. **REST API** (PRD §FR14, §29): FastAPI app exposing the same operations as
   the Python API boundary — create task, request access, get request/decision
   status, approve (for now, a direct "approve" endpoint standing in for the
   Phase-1-D approval UI, which is a later step), reveal, prove, use, revoke,
   list/get grants, audit trail. PRD §FR14 is explicit: "MCP should act as an
   adapter over the same domain services rather than contain independent
   business logic" — so FastAPI route handlers should be thin, calling into
   `Authority`, not reimplementing policy/enforcement logic. Use Pydantic
   request/response models matching the domain types already defined.

## Do NOT build in this step

No MCP server yet (that's the next step). No web UI yet. No real external
secret-provider integration yet (Phase 2) — keep the mock provider. Don't
touch the demonstrator scripts yet.

## Tests required

- Every existing Phase 0 test must still pass unmodified.
- New tests under `tests/integration/` using FastAPI's `TestClient`:
  covering the same lifecycle + adversarial scenarios as Phase 0's 14 tests,
  but exercised through HTTP instead of the Python API directly — at minimum:
  full lifecycle happy path (create task → auto-allow reveal → approval-
  required booking → approve → reveal/prove/use → audit), plus 3-4 of the
  adversarial cases (expired grant, wrong task, max-uses exhaustion, secret
  reveal always denied) re-proven over HTTP.
- New tests under `tests/unit/` (or `tests/persistence/`) proving: data
  written through the SQLite backend survives a fresh `Authority` instance
  reconnecting to the same store; the raw attribute value is NOT present
  anywhere in the raw SQLite file bytes for at least one sensitive attribute
  (read the file directly in the test and assert the plaintext isn't a
  substring — this is the actual proof encryption-at-rest is real, not just
  configured).

## Definition of done

- `uv run pytest` passes, 0 failures, including everything from Phase 0.
- `uv run uvicorn pav.adapters.rest.app:app` (or wherever you put it) starts
  and serves the API — confirm this yourself by starting it and hitting one
  endpoint with `curl` before finishing, then stop the server.
- Add fastapi/uvicorn/cryptography (and a SQLite driver if needed beyond the
  stdlib) to `pyproject.toml` dependencies.
- Update `docs/phase0-report.md` or add `docs/phase1a-report.md` (your call)
  documenting: the storage interface design, where the encryption key comes
  from and why, and any judgment calls.
- Commit when done. No remote is configured; don't add one.
