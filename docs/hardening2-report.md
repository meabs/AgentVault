# Hardening 2 report

Date: 27 September 2026

## Zero-exposure demonstrator

`examples/shopping/zero_exposure.py` now creates a UUID-namespaced generic
Keychain item with `/usr/bin/security`, reads it independently, configures the
handle as `provider="macos-keychain"`, and runs the complete MCP → REST
approval → `vault.use` path through `MacOSKeychainSecretProvider`.

The raw value is printed on the independent proof stream so the comparison is
visible when stdout and stderr are combined. The MCP response is printed on
stdout and contains only the opaque Keychain execution fingerprint. The test
reads the same item through its own direct `security find-generic-password`
call and asserts that the raw value is absent from the captured MCP output.

The demo deletes the exact service/account pair in a `finally` block and
verifies that it is no longer readable. If Keychain setup or use is
unavailable, it prints the reason and completes with the existing mock provider
instead.

Manual run:

```text
$ uv run python examples/shopping/zero_exposure.py 2>&1
credential provider: MacOSKeychainSecretProvider
...
actual Keychain value: pav-demo-booking-secret-2026
3. vault.use returns an opaque execution handle
{
  "execution_handle": "keychain-exec-901d554c3783a05b",
  "status": "authorized"
}
ASSERTION: credential value is absent from the MCP response and never enters caller context.
```

The `keychain-exec-...` prefix and the non-`exec_...` result confirm that this
run used the real provider rather than `MockSecretProvider`.

## Approval-code lockout

Approval challenges now track failed attempts and a lock timestamp. The named
constant `APPROVAL_CODE_MAX_FAILED_ATTEMPTS` is set to 5. Five is a small
enough bound to stop a guessing script quickly while allowing for ordinary
human entry mistakes; it is not intended to make the approval decision itself.

On the fifth incorrect code, the current digest is invalidated and the
challenge is marked locked. The request and its decision remain
`APPROVAL_REQUIRED`, so lockout does not silently deny the underlying request.
Subsequent submissions, including the originally correct code, fail with a
distinct `locked_out` reason. The lockout is recorded as an
`APPROVAL_CODE_REJECTED` audit event with `metadata["reason"] == "locked_out"`.

The approval page now offers “Send a fresh code”. This replaces the challenge,
resets the failed-attempt counter, persists the new challenge, and re-fires the
configured notifier. The fresh code can approve the same still-pending
request; completed or denied requests cannot receive one.

## Verification

New coverage proves that:

- five wrong attempts lock the current code and a later correct attempt fails;
- lockout remains approval-required and is audited distinctly;
- resend creates a new working code and resets the counter;
- the demonstrator uses the real Keychain provider, keeps the independent raw
  value out of MCP output, and cleans up its test item.

```text
uv run pytest
49 passed in 1.36s
```
