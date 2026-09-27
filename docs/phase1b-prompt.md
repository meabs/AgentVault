You're continuing Personal Authority Vault (PAV). Phase 0 (domain + in-memory
lifecycle) and Phase 1a (encrypted SQLite persistence + REST API at
`src/pav/adapters/rest/app.py`) are built and tested — read `docs/PRD.md`,
`docs/phase0-report.md`, and `docs/phase1a-report.md` before writing anything.

## Scope for this step: MCP server only

PRD §FR13 is explicit: expose an MCP server, and "MCP should act as an
adapter over the same domain services rather than contain independent
business logic" (§FR14) — same principle already applied to the REST adapter
in Phase 1a. The MCP tools should call into the same `Authority` instance the
REST API uses (or an equivalent one wired to the same persistence backend),
not reimplement policy/enforcement.

Implement these tools from PRD §FR13, using the current official MCP Python
SDK:

- `vault.list_available_context` — list attributes/claims/capabilities the
  calling agent could plausibly request (names + one-line descriptions +
  sensitivity), WITHOUT revealing any values. This is a discovery tool, not a
  disclosure tool — read PRD §FR13's warning again: "Tool descriptions must
  not reveal values the caller is not already permitted to access."
- `vault.request_access` — wraps `create_task` (if needed) +
  `request_access` + `evaluate`, returning either a grant (if auto-allowed)
  or an `approval_required` status with a request id.
- `vault.get_request_status` — poll a pending request's decision/approval
  state.
- `vault.reveal`, `vault.prove`, `vault.use` — the three access modes, taking
  a grant id.
- `vault.get_grant` — grant metadata (state, expiry, uses, permissions) —
  never the underlying attribute/secret values.
- `vault.revoke_grant`.

Since there's no approval UI yet (that's the next step), also expose a
`vault.approve_request` tool for now so the MCP demo path is end-to-end
testable — note in your report that this tool is a stand-in and should
probably be removed or gated once a real approval UI exists, since letting
the same MCP client approve its own requests defeats the purpose long-term.
Flag this honestly rather than quietly shipping it as if it were the final
design.

## Tests required

- Existing tests (Phase 0 + Phase 1a) must still pass unmodified.
- New tests under `tests/mcp/` (or wherever fits your existing layout)
  exercising the MCP tools directly (via the SDK's in-process test/client
  pattern — no need to spawn a real subprocess/stdio transport for tests
  unless that's genuinely easier), covering:
  - The full lifecycle through MCP tools end to end (mirrors the REST
    integration test from Phase 1a).
  - `vault.list_available_context` never includes attribute *values*, only
    names/descriptions/sensitivity — assert this explicitly.
  - At least two adversarial cases re-proven through the MCP layer (e.g.
    secret-reveal-always-denied, expired-grant-rejected) — MCP is another
    entry point into the same enforcement, it needs the same proof REST got.

## Definition of done

- `uv run pytest` passes, 0 failures.
- Confirm the MCP server actually starts and can be introspected (list its
  tools) — do this yourself before finishing, the way you verified uvicorn
  startup last time, and mention how you checked it in your report.
- Add the MCP SDK dependency to `pyproject.toml`.
- Write `docs/phase1b-report.md`: what you built, how you verified it starts,
  the `vault.approve_request` stand-in caveat above, and any other judgment
  calls.
- Commit when done. No remote is configured; don't add one.
