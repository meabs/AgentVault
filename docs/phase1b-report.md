# Phase 1B report

Phase 1B adds the MCP protocol adapter using the current official MCP Python
SDK v2 (`mcp[cli]>=2,<3`, resolved to 2.2.0). The adapter is in
`pav.adapters.mcp.server` and exposes:

- `vault.list_available_context`
- `vault.request_access`
- `vault.get_request_status`
- `vault.reveal`
- `vault.prove`
- `vault.use`
- `vault.get_grant`
- `vault.revoke_grant`

## Adapter boundary

`create_server(authority)` registers MCP tools over the supplied `Authority`
instance. The tools only translate MCP arguments/results and delegate task
creation, request creation, policy evaluation, approval, grant issuance,
enforcement, disclosure, proof, capability use, and revocation to `Authority`.
The default module-level `mcp` instance constructs an `Authority` over the
same configured SQLite database and encryption-key setup as the REST adapter;
applications embedding both adapters can pass one exact `Authority` instance
to both factories.

`vault.list_available_context` returns only resource names, resource kind,
one-line generic descriptions, access modes, and sensitivity. It never reads
or serializes attribute values, claim results, external secret material, or
secret-provider output. `vault.get_grant` and request status likewise return
metadata and permissions only. Expected authority failures are surfaced as
MCP tool errors while preserving the domain error message; unexpected failures
remain sanitized by the SDK.

When `task_id` is omitted, `vault.request_access` creates a task from the
provided agent identity and objective, then creates and evaluates the access
request. An existing task can be reused by passing its ID. TTL is expressed
as MCP-friendly seconds and converted to the domain `timedelta`.

## Approval stand-in caveat

`vault.approve_request` is intentionally present only because Phase 1 has no
approval UI yet. It lets the MCP demo complete end to end, but allowing the
same MCP client to approve its own request defeats the purpose of independent
user approval in the long-term design. This tool should be removed, protected
by a separate trusted principal, or otherwise gated once a real approval UI or
approval channel exists. It must not be treated as the final approval model.

**Update — 27 September 2026:** the Phase 1b stand-in has now been removed
from the MCP server. It was removed because an MCP client could approve its
own request, violating PAV principle P5. The Phase 1c web UI is now the only
approval path, and the approval-hardening work adds a separate human-presence
code delivered outside the requesting process.

## Verification

The new tests use the SDK's official in-process `Client(server)` pattern and
cover the complete search/request/approval/reveal/prove/use/revoke lifecycle,
metadata-only discovery, secret reveal denial, and expired-grant rejection.
The existing Phase 0 and Phase 1a tests were left unmodified.

```text
uv run pytest
24 passed
```

I also verified the actual server startup and introspection, not just the
in-process tests:

```text
uv run mcp run src/pav/adapters/mcp/server.py:mcp --transport streamable-http
```

An official `mcp.Client("http://127.0.0.1:8000/mcp")` connected to the running
server, negotiated protocol `2026-07-28`, and listed all nine `vault.*` tools.
The server was then stopped cleanly.
