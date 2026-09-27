You're finishing PRD §27 Phase 1 ("Local MVP") for Personal Authority Vault
(PAV). Domain + lifecycle (Phase 0), encrypted persistence + REST API
(Phase 1a), and the MCP server (Phase 1b, including the temporary
`vault.approve_request` stand-in — read its caveat in
`docs/phase1b-report.md`) are built and tested. Read `docs/PRD.md` in full
again, plus all three prior phase reports, before writing anything.

## Scope for this step: approval UI, audit timeline, and the three demonstrators

This is the rest of PRD §27 Phase 1. Phase 1 is "done when: a real MCP client
can complete the demo workflow using task grants" (§27) — that's the bar for
this step.

### 1. Approval UI (PRD §18.1, §18.2, §FR7)

"A small local web UI is sufficient for MVP" (§14). Build a minimal local web
UI, served by the existing FastAPI app (new routes returning server-rendered
HTML is fine — do not add a separate frontend framework/build step for this),
covering:

- **Home** (§18.1): pending-requests count, active-grants count, known-agents
  count, recent activity.
- **Approval screen** (§18.2): for a pending request, answer the five
  questions PRD §18.2 requires to be immediate: who is asking, what they
  want, why, where it'll be used, for how long — with explicit REVEAL / PROVE
  / USE sections, each stating exactly what is and isn't disclosed (mirror
  the PRD's own example copy in §18.2, e.g. "Date of birth will not be
  shared" under a PROVE item). Approve / Deny actions actually call the
  domain's approve/deny path — this replaces the `vault.approve_request` MCP
  stand-in as the real approval mechanism going forward; leave that MCP tool
  in place for now (don't touch Phase 1b), but this UI is the intended real
  path per the PRD.

### 2. Audit timeline (PRD §18.3, §FR12)

A view of a task's audit trail, in the narrative style PRD §18.3 shows —
"Age-over-18 proved — date of birth NOT disclosed" — not a raw event dump.
Also a simple active-grants list/detail view (§FR12): agent, purpose, task,
data/capabilities granted, expiry, use count.

### 3. The three demonstrators (PRD §24)

Runnable scripts or documented walkthroughs under `examples/` (per the repo
layout in §28: `examples/travel/`, plus one more — `forms/` or `shopping/`,
your call) that drive the system end-to-end through the MCP tools (Phase 1b),
not by calling `Authority` directly, since the point is to demonstrate real
agent integration:

- **Demo 1 — Low-risk automatic context** (§24): travel search, auto-allowed,
  no approval needed.
- **Demo 2 — Progressive disclosure** (§24): search then booking, second
  request needs identity + age proof, triggers approval.
- **Demo 3 — Zero-exposure capability** (§24): booking credential used via
  `vault.use`, never revealed to the caller.

Each demo should print/log what it did clearly enough that running it is
itself a readable proof of the property being demonstrated (e.g. print the
`vault.reveal` response next to an assertion that the credential value isn't
in it).

## Tests required

- Everything from Phases 0/1a/1b must still pass unmodified.
- New tests for the UI routes (FastAPI `TestClient` again) covering: the
  approval screen renders the correct reveal/prove/use breakdown for a real
  pending request, and clicking approve/deny actually transitions the
  request/grant state (check via the domain layer afterward, not just the
  HTTP 200).
- Each of the three demonstrator scripts should be runnable as a test too
  (e.g. `tests/examples/test_demonstrators.py` invoking each demo's main
  function/entrypoint and asserting it completes without raising, and that
  the zero-exposure demo's captured output/return value doesn't contain the
  mock secret value).

## Definition of done

- `uv run pytest` passes, 0 failures.
- Start the server yourself and actually load the home page and an approval
  screen (curl or a headless check is fine — you don't need a browser) to
  confirm the UI genuinely renders before finishing, the same way you
  verified uvicorn and the MCP server in the last two steps.
- Update `docs/PRD.md`'s §27 status informally isn't required, but do write
  `docs/phase1c-report.md` covering what you built, how you verified the UI
  renders, and confirm explicitly whether you think Phase 1's "done when" bar
  (§27) is actually met — if it isn't fully met, say so plainly rather than
  claiming it is.
- Commit when done. No remote is configured; don't add one.
