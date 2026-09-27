You're building Phase 0 of Personal Authority Vault (PAV), a user-owned
authorization and context broker for AI agents. The full product requirements
document is at `docs/PRD.md` in this repo — read it now, in full, before writing
any code. This prompt tells you exactly what to build from it; do not build
beyond this scope.

## Scope: Phase 0 architecture spike only

Per PRD §27 (Delivery Phases) and §35 (Recommended First Technical Spike):

> Build the authority lifecycle before building the vault UI... No UI polish.
> Done when: unit tests demonstrate the complete authority lifecycle.

Build ONLY:
- The domain model (§15 of the PRD): Attribute, ClaimDefinition, ExternalHandle,
  Agent, Task, AccessRequest, AccessRequestItem, Grant, GrantPermission, Policy,
  AuditEvent.
- The authority lifecycle (§12, §16, §29): policy evaluation, approval, grant
  issuance, grant validation/enforcement, revocation, expiry, the grant state
  machine.
- The three access modes (§9): reveal, prove, use — with a mock `SecretProvider`
  for `use` (§FR15), since there is no real external credential provider yet.
- An in-memory audit log (§FR11) — no persistence layer yet.

Do NOT build in this pass: the MCP server, the REST API, any UI, real
encryption/persistence, or a real external secret provider integration. Those
are later phases (§27 Phase 1+). If you find yourself writing FastAPI routes,
an MCP tool, or a database migration, stop — that's out of scope for Phase 0.

## Language, structure, tooling

Python 3.12+, using the repo structure already sketched in PRD §28 (only the
parts this phase needs):

```
personal-authority-vault/
├── pyproject.toml
├── src/pav/
│   ├── domain/          # Attribute, Agent, Task, AccessRequest, Grant, AuditEvent, etc.
│   └── authority/       # policy.py, approvals.py, disclosure.py, proofs.py, capabilities.py
└── tests/
    ├── unit/
    └── security/
```

Use Pydantic v2 for the domain models (per PRD §14's suggested stack). Use
`pytest` for tests. Set up `pyproject.toml` with `uv` (or plain `pip`, your
call) so `uv run pytest` (or `pytest` in a venv) runs the suite. No web
framework dependency is needed for this phase — don't add FastAPI yet, there
are no HTTP routes in Phase 0.

## The concrete API boundary to implement (PRD §29, §35)

```python
task = authority.create_task(...)
request = authority.request_access(task=task, purpose=..., items=[...])
decision = authority.evaluate(request)          # ALLOW | DENY | APPROVAL_REQUIRED
grant = authority.authorize(decision)             # or approve() then issue_grant()
value = authority.reveal(grant=grant, resource=...)
proof = authority.prove(grant=grant, claim=...)
result = authority.use(grant=grant, capability=..., destination=...)
authority.revoke(grant=grant)                       # or revoke by agent/task
events = authority.audit(task=...)                   # or however you expose the trail
```

Match this shape; the exact function names/module layout are your call, but
keep the four-operation developer story from PRD §7R7/§32 intact: task,
request, grant, use.

## The fixture data to build the tests against (PRD §35's exact spike scope)

- **5 attributes**: `identity.full_name`, `identity.email`,
  `identity.date_of_birth`, `preferences.travel.airport`,
  `preferences.hotel.quiet_room`.
- **1 derived claim**: `identity.age_over_18`, derived from
  `identity.date_of_birth` via `age(dob) >= 18` (PRD §FR2). `prove()` must
  never return `identity.date_of_birth` itself.
- **1 external handle**: `credentials.booking_site` →
  `secret://mock/booking-site`, resolved through a mock `SecretProvider`
  (PRD §FR15) whose `execute()` returns an opaque execution handle, never the
  underlying secret value.
- **2 agents**: e.g. `travel-agent`, `research-agent`.
- **2 tasks**: one travel-booking task (mirrors PRD §10 Journey A/B — search
  then booking) and a second, unrelated task, used specifically to prove grants
  don't cross tasks.
- **3 policies** (PRD §FR16's exact examples are a good starting point):
  1. low-risk travel preferences (`purpose: travel.*`, `mode: reveal`,
     `sensitivity: low`) → `ALLOW`, short max TTL.
  2. `mode: use` → `APPROVAL_REQUIRED`, short max TTL, max_uses 1.
  3. raw secret resources with `mode: reveal` → `DENY`, always (this is what
     makes SR4 structurally true, not just conventionally true).

## Required test coverage — this is the actual deliverable

Write `pytest` tests, organized under `tests/unit/` (lifecycle/domain
correctness) and `tests/security/` (adversarial), that demonstrate:

**Full lifecycle (PRD §33's Definition of Done, scaled to Phase 0):**
1. Create a task, request low-risk `reveal` access → auto-`ALLOW` per policy,
   grant issued without an approval step.
2. Request `reveal` of identity fields + `prove` of `identity.age_over_18` +
   `use` of the booking credential → `APPROVAL_REQUIRED`; simulate approval;
   grant issued.
3. `reveal()` returns the exact approved value for an approved resource.
4. `prove()` returns only the boolean/derived result — assert the source
   attribute (`identity.date_of_birth`) is not present anywhere in the
   response.
5. `use()` returns an execution handle/result — assert the raw secret value
   from the mock provider is never present anywhere in the response.
6. Every one of the above emits the correct `AuditEvent` type(s) from PRD
   §FR11's list, and audit events for `use`/`prove` do not contain the
   underlying sensitive value.

**Security/adversarial (PRD §20 threat model, §26 Experiment 3) — each of
these must fail deterministically, not silently succeed:**
7. Reveal request for an attribute not on the grant's allow-list → denied.
8. A grant issued for task A cannot authorize an operation under task B
   (cross-task reuse).
9. An expired grant cannot be used (simulate/mock time, or use a very short
   TTL and sleep/advance a clock).
10. A grant cannot be reused past its `max_uses` (exhaustion).
11. A `use` operation is denied when the destination doesn't match the
    grant's `destination` constraint (destination substitution).
12. A revoked grant cannot be used for any further operation, even before its
    natural expiry.
13. A resource classified as `secret` can never be returned via `reveal`,
    regardless of policy configuration attempted (SR4 as a structural
    guarantee, not just the default policy rule — try to construct a policy
    that would allow it and confirm the enforcement layer still refuses).
14. Grant state transitions match PRD §16 exactly: a terminal-state grant
    (`REVOKED`/`EXPIRED`/`EXHAUSTED`) can never transition back to `ACTIVE`.

## Definition of done

- `uv run pytest` (or equivalent) passes, 0 failures, covering all 14 items
  above at minimum — each as its own named test, not folded into one giant
  test function.
- No FastAPI/MCP/HTTP/database code exists anywhere in the diff.
- No real secret value (the mock provider's underlying value) appears in any
  `reveal`/`prove`/`use` response or `AuditEvent` in the test assertions —
  add an explicit assertion for this in the `use` and `prove` tests, don't
  just rely on it happening to be true.
- Write a short `docs/phase0-report.md` (a few paragraphs, not a essay)
  summarizing: what you built, how to run the tests, any PRD ambiguities you
  had to make a judgment call on and what you decided, and anything you
  deliberately left out because it's out of Phase 0's scope.
- Commit your work with `git add`/`git commit` when done, with a clear commit
  message. Do not push anywhere — there is no remote configured, and none
  should be added.

Work through `docs/PRD.md` and this prompt carefully before writing code. This
is a security-sensitive authorization model — get the enforcement logic
right, not just the happy path.
