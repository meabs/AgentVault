# Phase 1C report

Phase 1C completes the local MVP surface around the existing Authority, REST,
and MCP adapters. The implementation keeps policy and lifecycle decisions in
the domain layer: the web UI is a server-rendered FastAPI adapter, and the
demonstrators use the official MCP Python client against the existing MCP
tools.

## What was built

- A local approval UI at `/` and `/approvals/{request_id}`. The home page shows
  pending-request, active-grant, and known-agent counts plus recent activity.
  The approval page answers who, what, why, where, and for how long, with
  explicit REVEAL, PROVE, and USE sections. It states, for example, that date
  of birth is not shared for the age-over-18 proof and that a booking
  credential is not shared for USE.
- A domain-level `Authority.deny()` path that persists the denied decision and
  writes `APPROVAL_DENIED`. The approval UI's approve and deny forms use the
  domain approve/deny paths. The temporary `vault.approve_request` MCP tool
  remains unchanged, as requested.
- Grant inspection at `/ui/grants` and `/ui/grants/{grant_id}`, including agent,
  purpose, task, permissions, destinations, expiry, use count, grant timeline,
  and revocation. The UI includes the limitation that already revealed values
  cannot be recalled from an external agent.
- Narrative audit views at `/ui/tasks` and
  `/ui/tasks/{task_id}/audit`. Operations are rendered as stories such as
  “Age-over-18 proved — date of birth NOT disclosed” and “Booking credential
  used — credential NOT disclosed”, rather than raw event dumps.
- Three runnable MCP demonstrators:
  - `uv run python examples/travel/low_risk_context.py`
  - `uv run python examples/travel/progressive_disclosure.py`
  - `uv run python examples/shopping/zero_exposure.py`

  The agent actions in each demo use MCP tools. The progressive-disclosure and
  zero-exposure demos represent the user's independent action with the real
  approval HTTP route, then continue through MCP. The zero-exposure demo
  asserts and prints that the mock secret is absent from the `vault.use`
  response.

## Verification

The full test suite passes:

```text
uv run pytest
31 passed in 0.64s
```

This includes the unmodified Phase 0/1a/1b tests, UI `TestClient` coverage for
approval rendering and approve/deny state transitions, and runnable tests for
all three demonstrators.

I also ran the demos directly and ran the UI detector. The detector reported no
findings:

```text
node /Users/garry/.codex/skills/impeccable/scripts/detect.mjs --json \
  src/pav/adapters/rest/app.py \
  examples/travel/low_risk_context.py \
  examples/travel/progressive_disclosure.py \
  examples/shopping/zero_exposure.py
[]
```

For the required live check, I started uvicorn with a seeded demo authority,
loaded `/` with `curl`, created a pending request through `POST /tasks/...`,
and loaded its approval URL over HTTP. The home response rendered the
“Overview · Personal Authority Vault” page. The approval response rendered all
five questions, `REVEAL`, `PROVE`, `USE`, “Date of birth will not be shared.”,
and “credential value will not be shared”. The server health response was
`{"status":"ok"}`.

## Phase 1 done-when assessment

Yes — I consider the §27 Phase 1 “done when” bar met for the local MVP. A real
MCP SDK client can create the search task, receive an automatically issued
low-risk task grant, request progressive booking authority, wait for the user
approval UI to issue the second task grant, then use MCP `reveal`, `prove`, and
`use` operations. The audit UI reconstructs the task story, and the
zero-exposure demo verifies that the credential value does not enter the MCP
caller response.

The temporary `vault.approve_request` stand-in is intentionally still present
because Phase 1b required it and the prompt explicitly asked not to change it.
The intended approval path is now the local UI; the stand-in should be removed
or separately protected in a future phase.
