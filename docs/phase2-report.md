# Phase 2 report

Phase 2 adds a real macOS Keychain-backed secret provider. The provider is
`MacOSKeychainSecretProvider` in `pav.authority.capabilities`; it implements
the existing `SecretProvider` interface and is selected by an external
handle's `provider="macos-keychain"` metadata. Legacy handles continue to use
`MockSecretProvider`, and `Authority` now keeps both providers available in
its provider registry.

## Approach

I used the macOS Keychain through `/usr/bin/security`, rather than the
encrypted-file fallback, because this machine provides a separate operating
system credential store without adding an application-owned secret database or
new credentials.

Keychain handles contain only the Keychain coordinates in an opaque URI, such
as `keychain://pav-demo-booking-credential/pav-demo`, plus an explicit set of
allowed destinations. The handle's provider and destination metadata are
persisted by SQLite, including a migration for databases created before these
fields existed.

The setup command was equivalent to:

```text
security add-generic-password -a pav-demo -s pav-demo-booking-credential \
  -T /usr/bin/security -w
```

The service/account pair was checked to be absent before setup, and the demo
password was supplied twice through stdin because `security` prompts for
confirmation when `-w` is the final option. I deliberately did not use `-U`,
so setup could not overwrite an existing item.

The local `security` man page documents `-A` as allowing any application and
labels it insecure. It documents `-T appPath` as granting access to a named
application, so I used the narrower `-T /usr/bin/security`. A closed-stdin
`find-generic-password -w` read completed successfully within a five-second
timeout, without a GUI prompt or human interaction. Keychain access was
therefore not headless-hostile in this environment and no fallback was needed.

`execute()` reads the password only inside the provider subprocess boundary,
hashes it, and returns a deterministic `keychain-exec-<fingerprint>` token.
Neither the raw bytes nor command output are logged or copied into an
`AuditEvent`; the Authority response contains only `status` and the opaque
execution token.

## Cleanup and tests

The new tests create a UUID-namespaced Keychain service, read the credential
independently with their own direct `security find-generic-password` call,
and delete the exact service/account pair in fixture teardown. Teardown also
verifies that the item is no longer readable. The manual demo used the fixed
`pav-demo` namespaced item and deleted it after the demonstration.

The complete suite passes, including all unmodified Phase 0–1c tests:

```text
34 passed in 0.98s
```

The new tests cover independent raw-secret comparison, opaque provider output,
Authority provider selection, absence of the secret from the Authority
response and audit events, destination rejection, and Keychain cleanup.

## Manual demonstration

Outside pytest, I completed the full Authority task/request/approval/grant/use
path against the Keychain item. The output was:

```text
actual Keychain value:     pav-demo-booking-secret-2026
opaque Authority response: {"execution_handle": "keychain-exec-901d554c3783a05b", "status": "authorized"}
raw secret in response:    False
raw secret in audit:        False
manual demo Keychain cleanup returncode: 0
```

## Phase 2 done-when assessment

Yes. I consider the §27 Phase 2 bar met: an agent can complete an
authenticated, destination-scoped action through `Authority.use()` while the
underlying Keychain credential remains outside the agent response and audit
history.
