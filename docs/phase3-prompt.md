You're starting PRD §27 Phase 3 ("Interoperability") for Personal Authority
Vault — scoped down deliberately. Phases 0 through 2 are built and tested;
read `docs/PRD.md` again plus all prior phase reports before writing
anything.

## Scope for this step: formalize the PDP boundary + one experimental AuthZEN-shaped adapter

PRD §27 Phase 3 lists four items and explicitly says: "Treat standards still
in draft as experimental adapters rather than core dependencies." Build only
the most standards-mature one:

- PRD §12: "The implementation should keep Policy Decision Point and Policy
  Enforcement Point concerns separate... The initial implementation may use
  an embedded policy engine, but APIs should allow replacement by an external
  PDP later."
- PRD §30 OQ4: "Do not make this choice a product dependency. Define the
  authorization interface first. Evaluate embedded Python rules, OPA/Rego,
  Cedar and AuthZEN-compatible PDPs against that contract."
- PRD §21: OpenID AuthZEN Authorization API 1.0 became a Final Specification
  in January 2026 — the most standards-mature of the four Phase 3 items.

Do this:

1. **Extract a `PolicyDecisionPoint` interface** (a `Protocol` or ABC) that
   `Authority.evaluate()`'s current embedded policy logic already
   satisfies — formalize the boundary that's implicitly there today, without
   changing its behavior. `Authority` should take a `PolicyDecisionPoint`
   implementation as a constructor argument (defaulting to the existing
   embedded engine, so nothing breaks), the same pattern already used for
   `SecretProvider` in Phase 2.
2. **Build one alternative `PolicyDecisionPoint` implementation that speaks
   the AuthZEN wire shape** — an in-process adapter that translates a PAV
   access-request item into an AuthZEN-shaped decision request (`subject`,
   `resource`, `action`, `context` per the AuthZEN Authorization API), and
   translates an AuthZEN-shaped decision response back into PAV's
   `ALLOW`/`DENY`/`APPROVAL_REQUIRED` outcome. You do not have a live
   external AuthZEN server to call — that's fine and expected. Implement the
   translation layer plus a small in-process reference decision function
   that exercises the same three example policies from PRD §FR16, so the
   adapter's request/response shape is provably correct even without a real
   remote PDP. Fetch the actual AuthZEN spec if you need the exact field
   names (`https://openid.net/specs/authorization-api-1_0-final.html` or
   search for it) rather than guessing the shape.
3. **Label this clearly as experimental** in code (module docstring) and in
   your report — this adapter exists to prove the boundary is real and
   swappable, not as a production-ready AuthZEN client. Do not touch
   transaction tokens, verifiable credentials, or approval-profile mapping —
   those stay out of scope for this step.

## Tests required

- Everything from Phases 0-2 must still pass unmodified, run against the
  **default embedded PDP** (confirm `Authority`'s default behavior is
  unchanged by this refactor).
- New tests proving the SAME three PRD §FR16 policies, evaluated through the
  **AuthZEN-shaped adapter**, produce the same ALLOW/DENY/APPROVAL_REQUIRED
  outcomes as the embedded engine for equivalent inputs — this is the actual
  proof that the interface is swappable and the adapter is faithful, not
  just that it returns *something*.
- A test constructing `Authority` with the AuthZEN adapter and running one
  full lifecycle scenario (e.g. the low-risk auto-allow case) end to end
  through it.

## Definition of done

- `uv run pytest` passes, 0 failures.
- Write `docs/phase3-report.md`: the `PolicyDecisionPoint` interface you
  extracted, how the AuthZEN translation works, which real spec section you
  based the field names on (cite it), and an explicit statement that this is
  an experimental adapter proving the architecture, not a certified AuthZEN
  implementation.
- Commit when done. No remote is configured; don't add one.

After this step, PRD §27's remaining Phase 3 items (transaction tokens,
verifiable credentials, approval-profile mapping) and all of Phase 4
("portable personal context") are explicitly out of scope — Phase 4 in
particular is gated in the PRD itself behind "only proceed if the core
authorization model has demonstrated value," which is a product decision,
not an engineering one, so stop after this report rather than continuing
into either.
