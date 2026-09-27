# Phase 0 report

Phase 0 now contains a Pydantic v2 domain model for attributes, derived claims,
external handles, agents, tasks, access requests, grants, policies, and audit
events. The in-memory `Authority` implements deterministic policy evaluation,
approval and grant issuance, task/agent/purpose/resource enforcement, expiry,
revocation, max-use exhaustion, and the reveal/prove/use operations. A mock
secret provider returns only opaque execution handles. The audit log is
append-only in memory and records resource metadata rather than values.

Run the suite with `uv run pytest`. It contains 14 separately named lifecycle
and adversarial tests. An injectable clock makes expiry deterministic; the
tests also assert that the derived claim source and mock secret do not occur in
proof/use responses or audit events.

Two Phase 0 judgments are explicit in the implementation. Resources with no
automatic allow policy require approval rather than being silently allowed,
which permits the identity/proof/credential booking flow while retaining
default-deny behavior. Grant `max_uses` counts capability executions (`use`),
not read-only reveal/prove operations, so a single booking grant can provide
the approved context and exercise its credential once. Terminal grant states
cannot transition back to active.

Persistence, encryption, audit tamper evidence, approval UI, MCP, REST, real
secret-provider integrations, and all other later-phase adapters are
deliberately omitted.
