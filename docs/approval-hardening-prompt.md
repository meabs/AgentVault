You're hardening Personal Authority Vault's approval channel. This is not a
PRD-numbered phase — it's a fix for a structural weakness discovered after
Phase 1b shipped a temporary stand-in. Read `docs/PRD.md`, and specifically
re-read `docs/phase1b-report.md`'s caveat about `vault.approve_request`,
before writing anything.

## The problem (read this carefully, it's two problems, not one)

1. `vault.approve_request` is an MCP tool in the same tool surface as
   `vault.request_access`. Any MCP client can call both in sequence — an
   agent can approve its own request. This directly violates PRD principle
   P5: "Agents may request authority. They do not create their own
   authority."
2. Even without that tool, the approval flow returns an `approval_url`
   directly to the requesting agent (PRD §17's example response includes
   `"approval_url": "..."`). Nothing today stops that same agent from
   issuing the approval POST itself via plain HTTP, bypassing any human
   entirely, for any agent that can reach the local server (a co-located
   local agent/MCP client — not a remote cloud agent, which can't reach
   `localhost` on this machine at all, so that case is already fine).

## What to build

1. **Remove `vault.approve_request` from the MCP server** (`src/pav/adapters/mcp/server.py`).
   The web UI (Phase 1c) is now the only approval path. Update
   `docs/phase1b-report.md`'s caveat to note this tool has been removed and
   why (don't rewrite history, add a short dated note). Any existing test
   that exercised the MCP approve tool needs to be removed or rewritten to
   go through the real path instead — check Phase 1b/1c tests for this.

2. **Require a human-presence code on the REST approval endpoint.** When a
   request transitions to `APPROVAL_REQUIRED`:
   - Generate a short, high-entropy, single-use code (not the same as the
     approval URL/request id — a separate secret).
   - Deliver it through a channel the requesting process cannot read: fire a
     macOS desktop notification (`osascript -e 'display notification ...'`)
     containing the code and a link to the approval page. Wrap this in a
     `Notifier` interface with the macOS implementation as one backend and
     a no-op/log backend for environments without `osascript` (e.g. CI, or
     non-macOS) — don't hard-fail if notifications aren't available, but do
     make it obvious in logs/tests when the no-op backend is in use.
   - The approval page itself should display the code has been sent (not
     the code — it went to the notification, not the page) and require the
     human to enter it before the Approve button actually submits.
   - The REST `POST /approvals/{request_id}/approve` endpoint must reject
     the request unless the correct code is supplied as a form field. Wrong
     code, missing code, or a code reused after a successful approval must
     all fail with a clear error, and each failed attempt should still
     produce an audit event so repeated guessing is visible in the timeline
     (don't let failed attempts go unlogged).
   - Codes should expire (a few minutes is reasonable) independently of the
     grant's own TTL, so a stale, unused code can't be brute-forced at
     leisure.
   - Deny should NOT require the code — denying access should always be
     easy and low-friction; only approval (granting authority) needs the
     human-presence proof.

## Tests required

- Everything from prior phases must still pass, minus whatever
  `vault.approve_request`-specific tests you had to remove/rewrite (call
  those out explicitly in your report, don't silently delete coverage
  without saying so).
- A test proving an MCP client (or a plain HTTP client acting like one) that
  has ONLY the request id / approval URL — the same information an agent
  actually receives today — cannot successfully approve a request without
  also having the code (assert the POST fails, and that no grant is issued).
- A test proving the approval succeeds when the correct code is supplied.
- A test proving a wrong code fails and is audited.
- A test proving an expired code fails even if it was originally correct.
- A test proving a code cannot be reused after a successful approval.
- A test proving deny works without any code.
- A test for the notifier abstraction itself: given the no-op/log backend,
  confirm the code is captured (so tests don't depend on real macOS
  notification delivery) and confirm the real `osascript` backend is only
  invoked when explicitly selected, not by default in the test suite.

## Definition of done

- `uv run pytest` passes, 0 failures.
- Manually demonstrate the end-to-end flow once outside the test suite:
  trigger an approval-required request, show the notification firing (or
  its logged equivalent if run headlessly), and show that approving with
  the wrong code fails while the right code succeeds. Include this in your
  report.
- Write `docs/approval-hardening-report.md`: what changed, the notifier
  design, code expiry/reuse rules, and an honest assessment of what this
  does and doesn't protect against (e.g. it does not protect against a
  human being tricked into reading a legitimate code to a malicious
  process — that's a social-engineering problem, not what this fix
  addresses; be explicit about the boundary of what's actually solved).
- Update the README's "Known open problem" section to reflect the new state
  (or remove it if you believe it's now fully resolved — say which, and
  why).
- Commit when done. A remote (`origin` -> the public GitHub repo) is now
  configured, but do not push — commit locally only, I'll review and push
  myself.
