# Phase 3 report — PDP interoperability seam

Phase 3 is intentionally scoped to the policy decision point seam and one
experimental AuthZEN-shaped adapter. Transaction tokens, verifiable or
selective-disclosure credentials, approval-profile mapping, and all Phase 4
portable-context work remain out of scope.

## PolicyDecisionPoint interface

`pav.authority.policy.PolicyDecisionPoint` is a Python `Protocol` with this
interface:

```python
def evaluate(
    self,
    request: AccessRequest,
    resources: Mapping[str, PolicyResource],
) -> PolicyDecision: ...
```

`PolicyResource` contains only the resource name, resource type, and
sensitivity needed for policy evaluation. `Authority` remains the Policy
Enforcement Point: it validates the request's task/agent binding, resolves
resource metadata, persists the returned decision, writes the policy audit
event, and continues into approval, grant, and enforcement flows.

`EmbeddedPolicyDecisionPoint` contains the former `Authority.evaluate()`
policy logic unchanged in substance. `Authority` constructs it by default
from the existing `policies` argument, so the Phase 0–2 callers retain their
original behavior. A caller can replace it with any implementation satisfying
the protocol through the new `policy_decision_point=` constructor argument.

## Experimental AuthZEN-shaped adapter

`pav.authority.authzen.AuthZENPolicyDecisionPoint` is an in-process adapter.
For each PAV access-request item it constructs an AuthZEN-shaped evaluation
request:

```json
{
  "subject": {"type": "agent", "id": "travel-agent"},
  "resource": {
    "type": "attribute",
    "id": "preferences.travel.airport",
    "properties": {"sensitivity": "low"}
  },
  "action": {"name": "reveal"},
  "context": {
    "task_id": "task_...",
    "purpose": "travel.hotel_search",
    "destination": null,
    "requested_ttl_seconds": 900.0,
    "requested_max_uses": null
  }
}
```

The subject is the requesting PAV agent; the PAV resource identifier and
non-sensitive resource metadata become the AuthZEN resource; the PAV access
mode becomes the action name; and task, purpose, destination, and request
limits are carried as PAV-specific context attributes.

The adapter's in-process `reference_authzen_decision()` function applies the
three example policies from PRD §FR16. It returns an AuthZEN-shaped response
with a boolean `decision` and an optional `context`. AuthZEN has two wire-level
decision values, so `ALLOW` maps to `true` and both `DENY` and
`APPROVAL_REQUIRED` map to `false`; the latter is disambiguated by the
adapter's explicit `context.pav_outcome` extension. The adapter also carries
matched policy names, TTL/use caps, and safe decision reasons through that
response context before reconstructing PAV's `PolicyDecision`.

## AuthZEN specification basis

The request member names are based on the OpenID [Authorization API 1.0 Final
Specification](https://openid.net/specs/authorization-api-1_0-final.html):

- §5.1–§5.4 define the `subject`, `resource`, `action`, and `context`
  information model members and their required/optional shapes.
- §6.1 defines the Access Evaluation API request as `subject`, `action`, and
  `resource`, with optional `context`.
- §5.5 defines the response `decision` as a required boolean and `context` as
  optional decision information.

This implementation is deliberately only shaped like that exchange. It has
no remote transport, HTTPS binding, PDP authentication, metadata discovery,
or conformance claim. The adapter module is labeled experimental in its
docstring: it proves that PAV's PDP seam is real and swappable; it is not a
production-ready or certified AuthZEN client.

## Verification

The new tests prove:

- AuthZEN request translation uses the expected request shape.
- The same three PRD §FR16 policies produce the same `ALLOW`, `DENY`, and
  `APPROVAL_REQUIRED` outcomes, policy matches, TTL caps, and use caps through
  the embedded and AuthZEN-shaped PDPs.
- A complete low-risk task → request → evaluate → authorize → reveal lifecycle
  succeeds through an injected AuthZEN-shaped adapter.

The complete suite passes:

```text
uv run pytest
39 passed
```

The 34 pre-existing Phase 0–2 tests were left unmodified and run against the
default embedded PDP.

Per the PRD, the remaining Phase 3 interoperability items and Phase 4 are
stopped here. Phase 4 is gated on a product decision that the core
authorization model has demonstrated value.
