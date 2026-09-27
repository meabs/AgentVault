You're building tamper-evidence for Personal Authority Vault's audit log —
PRD §23's "Should" item, §SR7: "Audit events must be tamper-evident or
otherwise designed so silent alteration is detectable. For MVP this may use
chained event hashes rather than distributed immutable storage." Read
`docs/PRD.md` §19 (SR7, SR8) and §FR11 again, plus `src/pav/domain/audit.py`
and however `AuditEvent`s are persisted in `src/pav/persistence/store.py`,
before writing anything.

## What to build

1. **Hash-chain every audit event.** Each `AuditEvent`, at the moment it's
   written, gets a `sequence` number (monotonic, per-store) and a `hash`
   computed over a canonical serialization of (its own content, its
   `sequence`, and the *previous* event's `hash` — genesis event chains from
   a fixed, documented seed value). This makes it so altering, deleting, or
   reordering any past event breaks the chain from that point forward, the
   same property PRD §SR7 asks for. Store the hash alongside the event (both
   in-memory and SQLite backends — check both, don't just do one).
2. **A verification function**, `verify_audit_chain(events) -> ChainVerificationResult`
   (or similar), that walks a sequence of events, recomputes each hash, and
   reports either `ok` or the exact point of the first break (sequence
   number, expected hash vs. actual). This needs to be genuinely independent
   of the write path — don't just check a boolean flag set at write time;
   recompute from the actual stored content, the same way an auditor
   verifying the log after the fact would.
3. **Wire verification into the audit UI** (`/ui/tasks/{task_id}/audit`
   from Phase 1c): show the chain's verification status. It should be
   trivially demonstrable that tampering is detected — you'll prove this in
   a test by directly mutating a stored event's content (bypassing the
   normal write path, simulating an attacker with DB access) and showing
   `verify_audit_chain` catches it.
4. Keep PRD §SR8 in mind while you're in this code: audit events already
   should not carry raw sensitive values (Phase 0 established this) — don't
   let the hash-chaining work incidentally start hashing/storing something
   that reveals more than the event already did. The hash is computed over
   the event's existing metadata-only content, nothing new gets added to
   what's stored.

## What NOT to build

No external/distributed immutable storage (blockchain, append-only cloud
log, etc.) — PRD §SR7 explicitly says chained hashes are sufficient for MVP.
No cryptographic signing with a user keypair — that's a heavier mechanism
than this phase needs; a hash chain alone satisfies "silent alteration is
detectable," which is the actual requirement.

## Tests required

- Every existing test must still pass unmodified — this is an additive
  change to how audit events are stored/verified, not a change to when
  they're emitted or what they contain.
- A test proving a genuine, untampered event sequence verifies as `ok`.
- A test proving that directly mutating one stored event's content (via the
  persistence layer, not through `Authority`) causes `verify_audit_chain` to
  report a break starting at that exact sequence number, and that everything
  before it still reports as fine (the chain properly localizes where
  tampering happened, it doesn't just fail everything globally).
- A test proving deleting an event from the middle of a persisted sequence
  is also detected (the sequence numbers/chain will show a gap or a broken
  link — whichever your design produces, assert it).
- A test proving the SQLite-backed store and the in-memory store both
  produce chains that verify correctly for the same sequence of operations.
- A UI test confirming the audit page surfaces the verification status.

## Definition of done

- `uv run pytest` passes, 0 failures.
- Manually demonstrate tampering detection outside the test suite too:
  write a few real audit events through a normal `Authority` session,
  directly edit one in the SQLite file, run verification, show it catching
  the break. Include this in your report.
- Write `docs/audit-chain-report.md`: the hash construction (what's included
  in each event's hash, the genesis seed, why this design), how
  verification localizes a break, and the manual tampering demonstration.
- Commit when done, locally only — don't push.
