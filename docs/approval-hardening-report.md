# Approval channel hardening report

Date: 27 September 2026

## What changed

- Removed `vault.approve_request` from the MCP server. MCP clients can request
  authority and inspect request status, but cannot issue grants.
- Removed the old direct REST approve route at
  `/access-requests/{request_id}/approve`; grant approval is now available
  only through `/approvals/{request_id}/approve`.
- Added a persisted approval challenge per approval-required request. The
  code is a separate 10-character base32-style secret, generated with
  `secrets.choice`, and only its SHA-256 digest is stored.
- Added `Notifier`, `LogNotifier`, and `MacOSNotifier` adapters. The logged
  backend captures notifications for CI/headless runs. The macOS backend
  invokes `osascript` only when explicitly selected with
  `PAV_NOTIFIER=macos`; unavailable or failing `osascript` falls back to the
  logged backend without failing the request.
- The approval page says the code was sent, never renders the code, and asks
  the human to enter it. Deny remains code-free.
- Failed code attempts create `APPROVAL_CODE_REJECTED` audit events with a
  non-secret reason (`missing`, `incorrect`, `expired`, or `already_used`).

## Expiry and reuse rules

Approval codes expire five minutes after challenge creation, independently of
the requested grant TTL. A successful code submission consumes the code and
persists its consumption timestamp before grant issuance. Missing, incorrect,
expired, and already-consumed codes are rejected and audited. The approval
URL and request ID are not codes and cannot substitute for one.

## Verification

`uv run pytest` passes with 46 tests and zero failures. The tests cover:

- MCP tool discovery without `vault.approve_request` and an approval-required
  MCP response that contains only the request metadata and approval URL;
- approval without a code, correct approval, wrong code, expired code, code
  reuse, and deny without a code;
- audit visibility for failed guesses;
- notifier capture through the logged backend and explicit-only `osascript`
  selection;
- the existing Phase 0 through Phase 1c lifecycle and demonstrator tests.

The Phase 1b MCP lifecycle test was intentionally rewritten: it no longer
calls the removed `vault.approve_request` tool and now verifies that MCP stops
at `approval_required`. The REST lifecycle tests that used the old direct
`/access-requests/{request_id}/approve` route were likewise rewritten to use
the real approval page with the captured test notification code. This is a
deliberate security-coverage change, not silently deleted coverage.

## Manual end-to-end demonstration

Outside pytest, I ran the approval flow with a seeded Authority, a
`LogNotifier` (the headless equivalent of the desktop notification), and the
real REST routes. The notification captured the code and approval link; a
POST with the wrong code returned `403` and left the request ungranted; a POST
with the captured code returned `303` and issued one active grant.

Representative output:

```text
notification: request_id=req_... code=7KQ4... approval_url=http://127.0.0.1:8000/approvals/req_...
wrong code: status=403 detail=approval code is incorrect grant_issued=False
correct code: status=303 grant_state=active
```

## Security boundary

This closes the local confused-approval path where a co-located MCP client or
plain HTTP client has only the request ID and approval URL. It also removes
the same-process MCP self-approval tool. A remote cloud agent cannot reach
this machine's localhost service in the first place.

It does not authenticate the human's intent or protect against a human being
tricked into reading a legitimate notification code to a malicious process.
That is a social-engineering boundary, not something this channel proof can
solve. It also assumes the local machine's notification and application
runtime are not already compromised; a process with equivalent access to the
desktop, logs, or memory can defeat this mechanism.
