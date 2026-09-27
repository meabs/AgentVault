You're making two small, independent hardening fixes to Personal Authority
Vault. Read `docs/PRD.md`, `docs/phase2-report.md`, and
`docs/approval-hardening-report.md` before writing anything — both fixes
build directly on those two phases.

## Fix 1 — the zero-exposure demo proves the claim with a mock, not the real thing

`examples/shopping/zero_exposure.py` currently uses `MockSecretProvider`, not
the real `MacOSKeychainSecretProvider` built in Phase 2. The demo that's
supposed to be the flagship proof of "the credential never enters the agent's
context" isn't actually exercising a real secure store. Fix:

- Rewire `examples/shopping/zero_exposure.py` to set up a demo Keychain
  credential (same pattern as `tests/security/test_keychain_provider.py`:
  add it, use it, clean it up afterward — don't leave permanent keychain
  clutter) and drive the `use` operation through the real
  `MacOSKeychainSecretProvider`, not the mock.
- Keep printing the same kind of side-by-side proof Phase 2's report used:
  the actual Keychain value on one line, the opaque `vault.use` response on
  the next, so running the demo is itself readable evidence nothing leaked.
- If a demo run needs to work even where Keychain access might behave
  differently (e.g. CI), fall back gracefully to the mock with a clearly
  printed note saying why — don't make the demo fail hard in an environment
  where Keychain isn't available, but the default local run on this machine
  should use the real provider.
- Update `tests/examples/test_demonstrators.py` accordingly, and add
  cleanup/teardown so re-running the test suite doesn't accumulate keychain
  entries.

## Fix 2 — approval codes have no attempt lockout

The approval-code system (from `docs/approval-hardening-report.md`) audits
wrong/expired/reused attempts but never locks anything. Fix:

- After a small number of consecutive wrong-code attempts for one request
  (5 is a reasonable default — make it a named constant, not a magic
  number), invalidate the current code entirely. The request should remain
  `APPROVAL_REQUIRED` (don't deny the underlying request itself — that's a
  human decision), but the specific code is dead: no further attempts
  against it should succeed even if someone later guesses the original
  value.
- Emit a distinct audit event (or an existing event type with a clear
  `metadata["reason"] = "locked_out"`, your call — but it must be
  distinguishable from a single wrong-code event in the audit timeline) when
  lockout triggers.
- Provide a way to issue a fresh code for the same still-pending request
  after lockout (e.g. a "resend code" action on the approval page, which
  re-fires the notifier) — the human shouldn't be permanently stuck; the
  point is to stop a guessing script, not to break the legitimate approval
  path.
- The lockout counter should reset once a fresh code is issued.

## Tests required

- Everything from prior phases/hardening must still pass unmodified.
- New tests: N wrong attempts trigger lockout and the (N+1)th attempt fails
  even with the eventually-correct code; lockout is audited distinctly;
  requesting a fresh code resets the counter and the new code works.
- New/updated tests for the demo rewire proving it runs against the real
  Keychain provider (independent-oracle pattern from Phase 2: read the
  keychain value via a separate path, assert it's absent from the demo's
  captured output).

## Definition of done

- `uv run pytest` passes, 0 failures.
- Run `examples/shopping/zero_exposure.py` yourself and show its output in
  your report — it should now show a real Keychain value being fetched, not
  a mock string.
- Write `docs/hardening2-report.md` covering both fixes, the lockout
  threshold you chose and why, and confirm the demo genuinely exercises the
  real provider (not just claims to).
- Commit when done, locally only — don't push.
