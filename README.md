# AgentVault (Personal Authority Vault)

A user-owned authorization and context broker for AI agents. Instead of
giving an agent broad, standing access to your personal information,
accounts, or secrets, AgentVault lets an agent request the minimum
information or capability required for a specific task — and you (or a
policy) grant it for a bounded purpose, time period, use count, and
destination.

> **What may this agent know or do about me for this task?**

Full product requirements: [`docs/PRD.md`](docs/PRD.md).

## Three forms of access, not one

- **Reveal** — disclose an approved value to the agent.
- **Prove** — return a derived assertion without disclosing the underlying
  value (e.g. "over 18", never the date of birth).
- **Use** — let a deterministic component exercise a credential on the
  agent's behalf without the credential ever entering the agent's context.

## What's built so far

| Phase | Delivers | Report |
|---|---|---|
| 0 | Domain model + in-memory authority lifecycle (reveal/prove/use, policy evaluation, grants) | [`docs/phase0-report.md`](docs/phase0-report.md) |
| 1a | Encrypted SQLite persistence + REST API | [`docs/phase1a-report.md`](docs/phase1a-report.md) |
| 1b | MCP server (8 tools) | [`docs/phase1b-report.md`](docs/phase1b-report.md) |
| 1c | Approval UI, narrative audit timeline, 3 runnable demonstrators | [`docs/phase1c-report.md`](docs/phase1c-report.md) |
| 2 | Real macOS Keychain secret provider (credential never leaves the process) | [`docs/phase2-report.md`](docs/phase2-report.md) |
| 3 | Formal PDP/PEP boundary + experimental AuthZEN-shaped adapter | [`docs/phase3-report.md`](docs/phase3-report.md) |

Each phase was built by an AI coding agent (`codex exec`, `gpt-5.6-luna`)
against a scoped prompt derived from the PRD, and independently re-verified
(tests re-run, code read, servers booted and hit with real requests) before
being accepted — not taken on the agent's own word.

## Running it

```bash
uv sync
uv run pytest                                    # full suite (46 tests)
uv run uvicorn pav.adapters.rest.app:app --reload # REST API + local web UI at http://127.0.0.1:8000/
uv run python examples/travel/low_risk_context.py       # demo 1: auto-allowed low-risk context
uv run python examples/travel/progressive_disclosure.py # demo 2: search -> booking, approval required
uv run python examples/shopping/zero_exposure.py         # demo 3: credential used, never revealed
```

## Approval channel status

The approval channel is hardened: `vault.approve_request` is no longer an MCP
tool, and the web approval page is the only grant-issuing path. Approval
requires a short-lived, single-use code delivered through the configured
notifier (`PAV_NOTIFIER=macos` for macOS desktop notifications; the default
logged backend is suitable for CI/headless runs). Wrong, missing, expired, and
reused codes are audited. This prevents an agent that only has the request ID
and approval URL from approving its own request.

It does not prevent social engineering: a human can still be tricked into
reading a legitimate notification code to a malicious process.

## License

MIT — see [`LICENSE`](LICENSE).
