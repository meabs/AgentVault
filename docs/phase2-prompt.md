You're starting PRD §27 Phase 2 ("Real capability mediation") for Personal
Authority Vault. Phase 0/1a/1b/1c are built and tested — read `docs/PRD.md`
again plus all four prior phase reports before writing anything.

## Scope for this step: one real external secret-provider adapter

PRD §27 Phase 2: "Add one external secret-provider adapter. Done when: an
agent can complete an authenticated action without receiving the underlying
credential." PRD §FR15 defines the interface:

```python
class SecretProvider:
    def can_use(self, handle, destination): ...
    def execute(self, handle, operation, destination): ...
```

The current `MockSecretProvider` (Phase 0) satisfies this interface but holds
its secret value in memory in the test process — it is not a real external
system. Build a second, real implementation backed by the **macOS Keychain**
via the `security` CLI (already available on this machine, no new
credentials or third-party signup needed — a genuinely separate, real secure
system, which is what this phase calls for).

Design constraints:

- Add the demo credential to the keychain yourself as part of setup (a
  clearly-namespaced demo entry, e.g. service name
  `pav-demo-booking-credential`, account `pav-demo` — do not touch or
  overwrite any other keychain entry). Use `security add-generic-password`
  with an access-control flag that permits the `security` CLI to read it back
  **non-interactively** (research the right flag — you want this to work in
  a headless/non-interactive session without a GUI "Allow" prompt; if you
  cannot get non-interactive read access working reliably in this
  environment after a genuine attempt, STOP trying that approach, document
  exactly what you tried and why it didn't work headlessly, and fall back to
  a still-real (not mock) alternative instead: a local
  application-encrypted secret file, using the `cryptography`/Fernet
  approach already in `src/pav/persistence/store.py` from Phase 1a, stored
  outside of PAV's own SQLite database and outside version control, read
  only by this new provider's `execute()`. Either choice is acceptable —
  what matters is that it's a real, separate secure store, not another
  in-memory mock, and that reading it never hangs the process waiting on
  human interaction.
- `can_use(handle, destination)` checks the handle references this provider
  and the destination is one the credential is scoped to use for (you decide
  how destination scoping is recorded — e.g. as metadata alongside the
  external handle).
- `execute(handle, operation, destination)` retrieves the real secret
  internally, performs a deterministic stand-in "use" (since there's no real
  booking site to call — e.g. compute and return a fingerprint/hash of the
  credential plus a fixed "authorized" status, or a fabricated confirmation
  code), and returns only that result. **The raw secret value must never be
  returned, logged, or included in any `AuditEvent` anywhere in the code
  path** — this is the one property that matters most in this whole phase.
- Wire this new provider into `Authority` as an available/selectable
  provider (keep `MockSecretProvider` available too — don't delete Phase 0's
  provider or its tests). Update the demo/example wiring in `examples/` only
  if needed for a demonstrator to use it; don't rewire the existing three
  Phase 1c demonstrators away from the mock provider unless you have a good
  reason to.

## Tests required

- Everything from Phases 0/1a/1b/1c must still pass unmodified.
- New tests proving:
  - the real provider's `execute()` returns an opaque result, never the raw
    secret value — read the actual keychain (or encrypted file) value
    independently in the test via a different code path than the provider
    itself uses, so the test has an independent oracle for what the real
    secret is, then assert it's absent from every response and audit event
    (same pattern as Phase 0's `secret_value not in repr(result)` checks,
    but against the real credential this time, not the mock's).
  - `can_use()` correctly rejects a destination the credential isn't scoped
    for.
  - setup/teardown cleanly adds and removes the demo credential (a test run
    should not leave permanent keychain/file clutter behind — clean up in a
    fixture teardown).
- If you go the encrypted-file route instead of Keychain, add a test proving
  the raw secret bytes are not present in the encrypted file on disk (same
  proof pattern as Phase 1a's SQLite encryption test).

## Definition of done

- `uv run pytest` passes, 0 failures.
- Manually demonstrate the new provider once outside the test suite too (a
  short script or a REPL-style check is fine) and show the output in your
  report — the actual secret value on one side, the opaque execution result
  on the other, side by side, so it's visually obvious nothing leaked.
- Write `docs/phase2-report.md`: which approach you used (Keychain or
  encrypted file) and why, exactly what you tried if Keychain access turned
  out to be non-interactive-hostile, how cleanup works, and confirm whether
  you consider Phase 2's "done when" bar (§27) met.
- Commit when done. No remote is configured; don't add one.
