# Personal Authority Vault (PAV) — Product Requirements Document

Status: Draft v0.1
Date: 27 September 2026
Working name: Personal Authority Vault (PAV)
Product type: User-owned agent authorization and personal context broker
Primary interface: MCP + REST API
Initial deployment: Local/self-hosted single-user application

---

## 1. Executive Summary

Personal Authority Vault (PAV) is a user-controlled authorization and context layer for AI agents.

Instead of giving an agent broad access to a user's personal information, accounts or secrets, PAV allows an agent to request the minimum information or capability required for a specific task. The user or policy engine can then grant access for a bounded purpose, time period, number of uses and destination.

The central product question is:

> **What may this agent know or do about me for this task?**

PAV deliberately separates three forms of access:

1. Reveal — disclose an approved value to the agent.
2. Prove — return a derived assertion without disclosing the underlying value.
3. Use — allow a deterministic component to use a sensitive value or credential without exposing it to the agent.

Example:

An agent booking a hotel may be allowed to:

- reveal the user's name, email and travel preferences;
- prove that the user is over 18 without revealing their date of birth;
- use a booking credential through an external secret provider without the credential entering model context.

PAV is not primarily a personal database. Its differentiator is task-scoped delegation, data minimisation, capability mediation and auditable authority for agents.

---

## 2. Problem

AI agents increasingly need personal context to perform useful tasks.

Today this context is normally handled through one or more of the following:

- copied into prompts;
- stored independently by each AI provider;
- retrieved from connected applications;
- exposed through broad OAuth scopes;
- embedded in agent memory;
- passed through MCP tools;
- manually entered by the user each time.

These approaches create several problems.

### 2.1 Excessive disclosure

An agent frequently receives the underlying personal value even when it only needs an assertion or capability.

For example, an agent may need to know that the user is over 18, not their full date of birth.

### 2.2 Standing access

Connected applications and agents can retain permissions beyond the task for which access was originally required.

### 2.3 Fragmented personal context

Different agents maintain their own incomplete and potentially contradictory representation of the user.

### 2.4 Weak purpose binding

Conventional access control tends to answer:

> Can application X read resource Y?

Agentic systems increasingly need to answer:

> Can agent X use attribute Y for purpose Z as part of task T, right now?

### 2.5 Secret exposure

Credentials, tokens or payment information may enter LLM context even though the model does not need to interpret those values.

### 2.6 Poor auditability

Users have limited visibility into:

- what an agent requested;
- why it requested it;
- what was actually disclosed;
- what capability was exercised;
- where information was sent;
- whether permission remains active.

---

## 3. Product Vision

PAV becomes the user's personal policy boundary between their data and autonomous software.

```
                  ┌─────────────────────┐
                  │      User Data      │
                  │                     │
                  │ facts               │
                  │ preferences         │
                  │ documents           │
                  │ external handles    │
                  └──────────┬──────────┘
                             │
                  ┌──────────▼──────────┐
                  │ Personal Authority  │
                  │       Vault         │
                  │                     │
                  │ policies            │
                  │ consent             │
                  │ derived claims      │
                  │ delegation grants   │
                  │ audit               │
                  └──────────┬──────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
        ChatGPT            Claude           Local Agent
           │                 │                 │
           └────────── MCP / API / A2A ──────┘
```

The user's personal context is maintained independently of any single agent provider.

Agents receive only authorised projections or capabilities.

---

## 4. Product Principles

- **P1. Task-scoped rather than application-scoped** — Permissions should normally belong to a task, not indefinitely to an application.
- **P2. Minimum disclosure** — Give the agent the least information required to complete the task.
- **P3. Prefer proof over disclosure** — If an assertion is sufficient, do not reveal the underlying attribute.
- **P4. Prefer execution over secret disclosure** — If a sensitive value can be injected or exercised deterministically, do not expose it to the model.
- **P5. User remains the authority** — Agents may request authority. They do not create their own authority.
- **P6. Explicit purpose** — Every grant must contain a machine-readable purpose.
- **P7. Expiry by default** — Every task grant expires. Permanent grants must be exceptional and deliberately configured.
- **P8. Auditable decisions** — Every request, decision, use, denial and revocation must be observable.
- **P9. Revocation stops future use** — Revocation cannot make an external system forget already disclosed information. The product must make this limitation explicit and minimise disclosure accordingly.
- **P10. Deterministic enforcement** — Authorization, disclosure and secret use must occur outside the probabilistic reasoning path of the LLM.
- **P11. Progressive trust** — Start with low-risk context and increase authority only when required by the task.
- **P12. Provider independence** — The user's personal context must not depend on one LLM vendor, agent runtime or protocol.

---

## 5. Goals

PAV v0.1 shall:

1. Store structured personal facts and preferences locally.
2. Allow an agent to request specific attributes or capabilities.
3. Evaluate each request against policy.
4. Support interactive user approval where policy alone cannot authorize the request.
5. Issue short-lived task grants.
6. Support reveal, prove and use semantics.
7. Expose approved functionality through MCP and REST.
8. Maintain an append-only audit history.
9. Allow grants to be viewed and revoked.
10. Support external secret providers through opaque references.
11. Prevent raw external secrets from entering the model context when using use mode.
12. Demonstrate the model with at least three realistic agent workflows.

---

## 6. Non-Goals for v0.1

PAV v0.1 will not attempt to:

- become a password manager;
- become a payment wallet;
- replace OAuth or OpenID Connect;
- become a general identity provider;
- replace operating-system keychains;
- replace existing credential stores;
- store bank account or payment card credentials directly;
- provide autonomous financial transactions;
- implement a distributed personal-data ecosystem;
- synchronize arbitrary personal data from every SaaS provider;
- guarantee deletion of data previously disclosed to an external agent;
- solve enterprise workforce authorization;
- become a full policy-language standard;
- support multi-user household delegation.

---

## 7. Target Users

- **7.1 Primary: Agent power user** — uses several AI assistants/agents, wants reusable personal context, wants to understand and control agent permissions.
- **7.2 Secondary: Agent developer** — building an agent that needs personal context but doesn't want to own the underlying store.
- **7.3 Future: Privacy-conscious consumer**
- **7.4 Future: Enterprise / regulated environment** — architectural model may later support this; not an MVP requirement.

---

## 8. Core Concepts

### 8.1 Attribute

A structured fact about the user. Examples: `identity.full_name`, `identity.date_of_birth`, `address.home.country`, `preferences.travel.airport`, `preferences.hotel.quiet_room`, `employment.occupation`.

Each attribute has: identifier; value; schema/type; sensitivity classification; provenance; verification state; created timestamp; last-updated timestamp.

### 8.2 Derived Claim

A fact calculated from one or more source attributes. Example: `identity.age_over_18` derived from `identity.date_of_birth`. The agent receives the derived result but not necessarily its source.

### 8.3 External Handle

An opaque reference to information owned by another secure system. Example: `secret://1password/item/booking-account` or `credential://os-keychain/travel-site`. PAV stores metadata and access policy, not necessarily the underlying secret.

### 8.4 Agent

An authenticated software actor requesting data or capabilities. Identity should include where available: client identifier; runtime/provider; declared name; signing identity; calling application; protocol; trust metadata.

### 8.5 Task

A bounded unit of user intent, e.g.:

```yaml
task:
  id: trip-edinburgh-2026-10
  objective: Book a hotel near Edinburgh Waverley
```

The task is the primary scope for delegated authority.

### 8.6 Purpose

A machine-readable description of why access is required, e.g. `travel.hotel_search`, `travel.hotel_booking`, `shopping.delivery`, `form.application_completion`. Purpose is separate from the agent identity.

### 8.7 Grant

A short-lived delegation permitting an agent to perform specified operations:

```yaml
grant:
  id: grant_01J...
  principal: garry
  agent: travel-agent
  task: trip-edinburgh-2026-10
  purpose: travel.hotel_booking

  allow:
    reveal:
      - identity.full_name
      - identity.email
      - preferences.hotel.*

    prove:
      - identity.age_over_18

    use:
      - credentials.booking_site

  constraints:
    expires_in: 30m
    max_uses: 1
    destination:
      - booking.example
```

---

## 9. Access Modes

### 9.1 Reveal

Returns the underlying approved value. Example request/response:

```json
{ "mode": "reveal", "attribute": "preferences.travel.airport" }
```

```json
{ "attribute": "preferences.travel.airport", "value": "MAN" }
```

Use for relatively low-risk information where the agent genuinely needs the actual value.

### 9.2 Prove

Returns a derived assertion without the source value:

```json
{ "mode": "prove", "claim": "identity.age_over_18" }
```

```json
{ "claim": "identity.age_over_18", "result": true }
```

The agent should not receive `identity.date_of_birth`. The initial implementation can use deterministic local rules. Verifiable credentials and cryptographic selective disclosure are later extensions, not MVP dependencies.

### 9.3 Use

Allows an operation to use protected material without revealing the value to the agent:

```json
{ "mode": "use", "capability": "credentials.booking_site", "destination": "booking.example" }
```

The response contains an execution handle or completion result, not the credential:

```json
{ "status": "authorized", "execution_handle": "exec_01J..." }
```

Actual credential injection occurs through a deterministic trusted component or external credential-provider integration.

---

## 10. Example User Journeys

### 10.1 Journey A — Travel search

User: "Find hotels near Edinburgh Waverley next Saturday under £180."

Agent requests `reveal: [preferences.hotel, preferences.travel, address.home.country]`, purpose `travel.hotel_search`, ttl 15m. Policy recognizes this as low sensitivity and permits it automatically. The audit log records the disclosure. No identity or credential information is exposed because it is not yet required.

### 10.2 Journey B — Hotel booking

After the user chooses a hotel, the agent requests `reveal: [identity.full_name, identity.email]`, `prove: [identity.age_over_18]`, `use: [credentials.booking_site]`, purpose `travel.hotel_booking`, ttl 10m, max_uses 1.

PAV determines that booking credentials require explicit user approval. The user sees exactly what will be revealed, proved (without the source), and used (without disclosure), the purpose, and the expiry. User approves; a task grant is issued.

### 10.3 Journey C — Form completion

User: "Fill in this insurance quotation form." Agent requests `reveal: [identity.full_name, address.home, employment.occupation]`, `prove: [identity.age_band]`, purpose `form.insurance_quote`. Policy requires approval because the destination is new. The user may deselect individual fields before approval.

### 10.4 Journey D — Request escalation

An agent originally receives `preferences.travel.*`. It later needs the user's passport number. The original grant cannot satisfy this request — the agent must create a new access request. This prevents authority from silently expanding during planning.

---

## 11. Functional Requirements

**FR1 — Personal attribute store.** Store structured personal attributes: hierarchical keys; typed values; sensitivity labels; provenance; verification metadata; timestamps; update and deletion.

**FR2 — Derived claims.** Support deterministic derived claims, e.g. `identity.age_over_18` from `identity.date_of_birth` via `age(dob) >= 18`. A claim response must not expose source values unless separately authorized.

**FR3 — Agent registration and identity.** Each requesting agent must have a distinguishable identity (agent/client ID, display name, protocol, authenticated principal where supported). Anonymous agents must be denied access to protected personal data by default.

**FR4 — Task creation.** A task contains: task identifier; objective; initiating user; requesting agent; created time; optional expiry.

**FR5 — Access request.** An agent must be able to request: access mode; exact attributes/claims/capabilities; task ID; purpose; requested TTL; requested number of uses; target/destination where relevant. Wildcard requests must be supported only where explicitly permitted by policy.

**FR6 — Policy evaluation.** Every access request must pass through deterministic policy evaluation. Inputs: principal, agent, task, purpose, resource, operation, destination, sensitivity, time, requested TTL, requested use count, existing grant. Outcomes: `ALLOW`, `DENY`, `APPROVAL_REQUIRED`.

**FR7 — Human approval.** Requests requiring user interaction must produce an approval request containing: requesting agent; task; purpose; exact information requested; mode for each item; expiry; use count; destination; reason approval is required. The user can approve, deny, reduce requested scope, reduce TTL, reduce number of uses.

**FR8 — Task grants.** Approved requests result in a signed or cryptographically protected grant containing: grant ID; principal; agent; task; purpose; resources; modes; issued time; expiry; usage constraints; destination constraints.

**FR9 — Grant enforcement.** Every protected operation must re-evaluate grant validity. A grant is invalid if: expired; revoked; wrong agent; wrong task; wrong purpose; wrong resource; wrong access mode; wrong destination; maximum use count exceeded.

**FR10 — Revocation.** Users must be able to revoke: a grant; all grants for an agent; all grants for a task. Revocation prevents future operations. The UI must state that previously revealed values cannot be technically recalled from external systems.

**FR11 — Audit log.** Append-only logical audit trail. Event types: `TASK_CREATED`, `ACCESS_REQUESTED`, `POLICY_ALLOWED`, `POLICY_DENIED`, `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `GRANT_ISSUED`, `ATTRIBUTE_REVEALED`, `CLAIM_PROVED`, `CAPABILITY_USED`, `GRANT_REVOKED`, `GRANT_EXPIRED`. Audit events must capture sufficient information to reconstruct why an operation occurred without unnecessarily copying sensitive values into the log.

**FR12 — Grant inspection.** The user must be able to view: active grants; historical grants; agent; purpose; task; data/capabilities granted; expiry; use count; audit history.

**FR13 — MCP interface.** Expose an MCP server for agent integration. Initial tool candidates: `vault.list_available_context`, `vault.request_access`, `vault.get_request_status`, `vault.reveal`, `vault.prove`, `vault.use`, `vault.get_grant`, `vault.revoke_grant`. Tool descriptions must not reveal values the caller is not already permitted to access.

**FR14 — REST API.** All core functionality must also be available through a protocol-neutral REST API. MCP should act as an adapter over the same domain services rather than contain independent business logic.

**FR15 — External secret adapter.** Provide an adapter interface for external credential providers:

```python
class SecretProvider:
    def can_use(self, handle, destination): ...
    def execute(self, handle, operation, destination): ...
```

The MVP may initially implement a local mock provider and one real provider integration. PAV should not persist the underlying external secret.

**FR16 — Policy configuration.** Users must be able to define rules such as:

```yaml
rules:
  - name: low-risk-travel-preferences
    when:
      purpose: travel.*
      mode: reveal
      sensitivity: low
    decision: allow
    max_ttl: 30m

  - name: secrets-require-approval
    when:
      mode: use
    decision: approval_required
    max_ttl: 10m
    max_uses: 1

  - name: raw-secrets-never-reveal
    when:
      resource_type: secret
      mode: reveal
    decision: deny
```

---

## 12. Policy Model

```
Decision =
    f(
        principal,
        agent,
        task,
        purpose,
        action,
        resource,
        destination,
        environment,
        existing authority
    )
```

The implementation should keep Policy Decision Point and Policy Enforcement Point concerns separate:

```
Agent
  │
  ▼
PEP / Vault API
  │
  ├────────► PDP / Policy Engine
  │                 │
  │                 ▼
  │          Allow / Deny / Request
  │
  ▼
Grant / Approval flow
```

The initial implementation may use an embedded policy engine, but APIs should allow replacement by an external PDP later.

---

## 13. Proposed Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         Agent                                │
│          ChatGPT / Claude / Gemini / Local Agent             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                    MCP / REST │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Protocol Adapters                         │
│       MCP Adapter                    REST Adapter            │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Authority Service                         │
│  task service / access-request service / grant service       │
│  disclosure service / claim service / capability service     │
└──────────────┬─────────────────────┬─────────────────────────┘
               │                     │
               ▼                     ▼
┌────────────────────────┐  ┌──────────────────────────────────┐
│     Policy Engine      │  │        Approval Service          │
│ ALLOW / DENY /         │  │ user interaction / biometric      │
│ APPROVAL_REQUIRED      │  │ later / scope reduction           │
└────────────────────────┘  └──────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│                       Vault Core                             │
│ personal attributes / derived-claim definitions /             │
│ external handles / policy configuration / task grants        │
└──────────────────────────────┬───────────────────────────────┘
                               │
             ┌─────────────────┼──────────────────┐
             ▼                 ▼                  ▼
       Encrypted DB       Audit Store       Secret Adapters
                                           (1Password / Keychain / future)
```

---

## 14. Suggested Technology Stack (indicative, not prescriptive)

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLite for local MVP, PostgreSQL for later multi-device/server deployment.
- **Authorization:** deterministic Python policy evaluation or OPA/Cedar-style embedded policy layer initially; signed short-lived grants; OAuth/OIDC for remote deployments later; AuthZEN-compatible PDP integration and transaction-token experimentation later.
- **Cryptography:** application-level encryption for sensitive vault values; encryption key held outside the database; OS keychain / platform secure storage for local root key where practical. Do not invent custom cryptographic primitives.
- **MCP:** official/current MCP SDK; stateless protocol adapter where possible; authenticated remote MCP only where deployment requires it.
- **Front end:** a small local web UI is sufficient for MVP (vault data, pending approvals, active grants, audit timeline, policies).

---

## 15. Data Model

Entities: `User`, `Attribute`, `ClaimDefinition`, `ExternalHandle`, `Agent`, `Task`, `AccessRequest`, `AccessRequestItem`, `Approval`, `Grant`, `GrantPermission`, `Policy`, `AuditEvent`, `Destination`.

```
User
 ├── Attribute*
 ├── Policy*
 └── Task*
       ├── AccessRequest*
       │     ├── AccessRequestItem*
       │     └── Approval?
       │
       └── Grant*
             └── GrantPermission*

Agent ── requests ──► AccessRequest
Grant ── authorizes ─► Disclosure / Proof / Use
Everything ─────────► AuditEvent
```

---

## 16. Grant State Model

```
REQUESTED
    │
    ├──────────── DENIED
    │
    ▼
APPROVAL_REQUIRED
    │
    ├──────────── DENIED
    │
    ▼
APPROVED
    │
    ▼
ACTIVE
    │
    ├──────────── REVOKED
    ├──────────── EXPIRED
    └──────────── EXHAUSTED
```

A grant can never transition back to `ACTIVE` from a terminal state. A new grant must be issued instead.

---

## 17. Example MCP Interaction

Agent calls:

```json
{
  "tool": "vault.request_access",
  "arguments": {
    "task_id": "trip-8472",
    "purpose": "travel.hotel_booking",
    "items": [
      { "mode": "reveal", "resource": "identity.full_name" },
      { "mode": "prove", "resource": "identity.age_over_18" },
      { "mode": "use", "resource": "credentials.booking_site", "destination": "booking.example" }
    ],
    "ttl_seconds": 600
  }
}
```

Response:

```json
{ "request_id": "req_01J...", "status": "approval_required", "approval_url": "http://localhost:7878/approvals/req_01J..." }
```

After approval:

```json
{ "request_id": "req_01J...", "status": "approved", "grant_id": "grant_01J...", "expires_at": "2026-09-27T12:40:00Z" }
```

The agent must present `grant_id` when performing subsequent protected operations.

---

## 18. User Experience

### 18.1 Home

Shows: pending requests count, active grants count, known agents count, and a recent-activity feed.

### 18.2 Approval screen

The approval experience is a critical product surface. It must answer five questions immediately: Who is asking? What do they want? Why do they want it? Where will it be used? For how long? — with explicit REVEAL / PROVE / USE sections, each stating exactly what is and isn't disclosed, plus destination and access (uses/expiry).

### 18.3 Audit timeline

The audit UI should tell the story of the task rather than merely dump security events (e.g. "Age-over-18 proved — date of birth NOT disclosed"; "Booking credential used — credential NOT disclosed"). This is both a security feature and a product differentiator.

---

## 19. Security Requirements

- **SR1 — Default deny.** No protected resource is accessible without policy authorization or an active grant.
- **SR2 — Grant binding.** Grants must be bound to the requesting agent and task.
- **SR3 — Short lifetime.** Default grant lifetimes should be measured in minutes, not days.
- **SR4 — No secret in model context.** Resources classified as secret must never support reveal.
- **SR5 — Encryption at rest.** Sensitive local data must be encrypted at rest.
- **SR6 — Root-key separation.** The database and root encryption key should not be stored in the same unprotected location.
- **SR7 — Audit integrity.** Audit events must be tamper-evident or otherwise designed so silent alteration is detectable. For MVP this may use chained event hashes rather than distributed immutable storage.
- **SR8 — No sensitive audit payloads.** Audit events record resource identifiers and actions, not raw personal values unless strictly necessary.
- **SR9 — Destination binding.** `use` capabilities should be restricted to approved destinations where technically possible.
- **SR10 — Request integrity.** The operation actually executed must match the operation the user approved.
- **SR11 — No silent scope expansion.** An agent requiring additional authority must submit a new request.
- **SR12 — Explicit trust boundary.** MCP tool output must be treated as disclosure. Anything returned to an external agent must be considered potentially copied permanently.

---

## 20. Threat Model

| Threat | Example | Primary mitigation |
|---|---|---|
| Over-broad request | Agent asks for `identity.*` | Policy + explicit scopes |
| Prompt-induced escalation | Web page tells agent to retrieve passport | Purpose/task binding + approval |
| Grant theft | Another process obtains grant ID | Agent binding + signed/unguessable grants |
| Grant replay | Agent reuses grant later | TTL + max-use counter |
| Cross-task use | Shopping agent uses travel grant | Task binding |
| Destination substitution | Credential approved for A used at B | Destination binding |
| Model secret exposure | Credential returned through MCP | Use mode only |
| Audit leakage | Logs contain DOB/password | Metadata-only audit |
| Policy bypass | Tool directly reads DB | PEP enforced below protocol adapter |
| User approval fatigue | Repeated low-risk prompts | Policy-based auto-approval for bounded cases |
| Confused deputy | Trusted agent acts for malicious content | Principal/task/purpose propagation |
| Revoked grant use | Agent keeps executing | Enforcement on every protected operation |

The MVP must explicitly test at least these threats.

---

## 21. Standards Alignment (context, not MVP dependencies)

PAV should align with existing standards where they solve part of the problem rather than invent replacement protocols:

- **MCP** — use as an agent-facing protocol adapter, not as the internal authorization model. (Model Context Protocol, 2026-07-28 release.)
- **OpenID AuthZEN** — AuthZEN Authorization API 1.0 (Final Spec, Jan 2026). PAV should model its architecture so an AuthZEN-compatible PDP could replace/augment the embedded policy engine later.
- **OAuth Transaction Tokens** — useful architectural input for propagating identity/authorization context through a call chain; still draft, not a settled standard.
- **W3C Digital Credentials** — selective disclosure as a data-minimisation technique; PAV's `prove` abstraction should remain implementation-neutral initially but leave space for verifiable/selectively-disclosed credentials later.

---

## 22. Market Validation / Adjacent Products

The product should not claim that agent-accessible personal vaults are novel. 1Password's July 2026 agent credential access for Claude (per-task approval, zero-exposure model) validates the `use` pattern. Solid and emerging personal-AI vault projects validate the broader user-owned-data concept. PAV's differentiation is the combination: data store + task identity + purpose + policy + approval + delegation + reveal/prove/use + audit. **The authorization and delegation layer is the product.**

---

## 23. MVP Scope

**Must:** local single-user vault; encrypted structured attribute storage; attributes and preferences; derived claims; agent identity; task creation; access requests; deterministic policy evaluation; ALLOW/DENY/APPROVAL_REQUIRED; local approval UI; short-lived task grants; reveal; prove; mock/use adapter; MCP server; REST API; active-grant view; revocation; audit timeline.

**Should:** one real external credential provider; hashed/chained audit events; policy editor; destination restrictions; import/export of user-owned vault data.

**Could:** biometric/platform approval; AuthZEN external PDP adapter; transaction-token prototype; verifiable-credential proof; browser-extension capability injector.

**Won't in MVP:** cloud sync; multi-user; mobile applications; direct payment-card storage; autonomous purchasing; arbitrary document RAG; email/calendar ingestion; social graph; health-record integration.

---

## 24. MVP Demonstrators

1. **Low-risk automatic context** (travel search) — reusable user context, automatic low-risk policy, task-scoped grant, audit.
2. **Progressive disclosure** (search → booking) — incremental authority, purpose transition, reveal, prove, explicit approval.
3. **Zero-exposure capability** (booking credential) — use mode, deterministic execution boundary, max-use capability, destination binding, audit.

---

## 25. Success Metrics

**Functional:** 100% of protected access passes through policy enforcement; expired/revoked grants cannot be reused; a grant cannot be reused across tasks; a grant cannot authorize undeclared attributes; `prove` never returns the source attribute; `use` never returns the protected secret to MCP/API callers.

**User value:** user enters personal data once; an agent can dynamically request what it needs; the user can understand an approval request without reading security terminology; the agent receives materially less personal data than a naïve full-profile approach.

**Developer value:** a third-party agent should be able to integrate using only `create task → request access → wait for decision → use grant`, without knowledge of how the underlying personal data is stored.

---

## 26. Validation Experiments

1. **Disclosure reduction** — compare conventional full-profile context vs. PAV access; measure attributes exposed, sensitive values exposed, context/token overhead, successful task completion. Target: PAV materially reduces exposed attributes without materially reducing task success.
2. **Approval comprehension** — users must correctly identify who is requesting, what will be revealed vs. only proved vs. used without disclosure, and expiry.
3. **Agent misbehaviour** — out-of-scope request, cross-task grant reuse, expired-grant reuse, destination substitution, repeated capability use, purpose change, prompt-injection-induced escalation. All must fail deterministically or require fresh approval.

---

## 27. Delivery Phases

- **Phase 0 — Architecture spike.** Build: attribute schema; tasks; request model; grants; policy evaluation; reveal/prove/use interfaces. No UI polish. **Done when:** unit tests demonstrate the complete authority lifecycle.
- **Phase 1 — Local MVP.** Add encrypted local persistence, MCP server, REST API, approval UI, audit timeline, travel demonstrators. Done when a real MCP client can complete the demo workflow using task grants.
- **Phase 2 — Real capability mediation.** Add one external secret-provider adapter. Done when an agent can complete an authenticated action without receiving the underlying credential.
- **Phase 3 — Interoperability.** AuthZEN PDP adapter, approval-profile mapping, transaction-token propagation, verifiable/selective-disclosure credentials — experimental adapters, not core dependencies.
- **Phase 4 — Portable personal context.** Vault import/export, multiple agent providers, encrypted sync, personal data connectors, delegated household authority — only if the core model has demonstrated value.

---

## 28. Suggested Repository Structure

```
personal-authority-vault/
├── README.md
├── AGENTS.md
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── policy-model.md
│   └── protocol.md
├── src/
│   └── pav/
│       ├── domain/
│       │   ├── attributes.py
│       │   ├── agents.py
│       │   ├── tasks.py
│       │   ├── requests.py
│       │   ├── grants.py
│       │   └── audit.py
│       ├── authority/
│       │   ├── policy.py
│       │   ├── approvals.py
│       │   ├── disclosure.py
│       │   ├── proofs.py
│       │   └── capabilities.py
│       ├── adapters/
│       │   ├── mcp/
│       │   ├── rest/
│       │   └── secrets/
│       ├── persistence/
│       └── ui/
├── policies/
│   └── default.yaml
├── examples/
│   ├── travel/
│   ├── forms/
│   └── shopping/
└── tests/
    ├── unit/
    ├── integration/
    ├── security/
    └── agent/
```

The domain model should remain independent of MCP. This allows PAV to support future protocols without turning the MCP adapter into the accidental architecture.

---

## 29. Key API Boundary

```python
task = authority.create_task(...)

request = authority.request_access(
    task=task,
    purpose='travel.hotel_booking',
    items=[...],
)

decision = authority.evaluate(request)

grant = authority.authorize(decision)

value = authority.reveal(grant=grant, resource='identity.full_name')

proof = authority.prove(grant=grant, claim='identity.age_over_18')

result = authority.use(
    grant=grant,
    capability='credentials.booking_site',
    destination='booking.example',
)
```

The simplicity of this boundary is important. The internal implementation can evolve significantly without forcing every agent integration to understand policy engines, storage systems or credential providers.

---

## 30. Open Product Decisions

- **OQ1 — Purpose: free text or controlled vocabulary?** Recommendation: controlled identifiers plus optional human-readable explanation.
- **OQ2 — How strongly do we authenticate agent identity?** MVP: registered clients plus transport authentication. Later: signed workload identity.
- **OQ3 — Should a grant itself be passed to the agent?** Options: opaque grant ID; signed JWT/capability; server-side session reference. For a local MVP, opaque high-entropy IDs backed by server-side state are simpler and easier to revoke.
- **OQ4 — Which policy technology?** Don't make this a product dependency — define the authorization interface first, then evaluate embedded Python rules, OPA/Rego, Cedar, and AuthZEN-compatible PDPs against that contract.
- **OQ5 — Is PAV a vault or an authorization broker?** Architecturally it should be a broker that happens to contain some personal data, to avoid becoming another monolithic personal-data warehouse.

---

## 31. Major Risks

- **R1 — Building a vault rather than an authority layer.** Mitigation: every roadmap feature must improve delegation, minimisation, policy, capability mediation or audit.
- **R2 — Consent fatigue.** Mitigation: risk-based policies, low-risk auto-approval, sensible TTLs, progressive escalation.
- **R3 — False sense of revocation.** Mitigation: clear distinction between reveal and use in the UI.
- **R4 — Agent identity ambiguity.** Mitigation: authenticated client identities, provenance, explicit trust metadata.
- **R5 — Scope explosion.** Mitigation: keep MVP centred on the authorization lifecycle.
- **R6 — Standards churn.** Mitigation: keep domain model protocol-neutral, implement standards through adapters.
- **R7 — Poor developer ergonomics.** Mitigation: keep integration model to four operations — task, request, grant, use.

---

## 32. Product Positioning

Avoid: "A secure personal database for AI." Prefer: **"Give AI agents exactly what they need about you, only for the task they are doing."**

Technical positioning: **"A user-owned authorization and context broker that provides agents with task-scoped, purpose-bound access to personal data and capabilities."**

Developer positioning: **"OAuth tells an agent what application it may access. PAV helps decide what this agent may know or do about this user for this task."**

---

## 33. Definition of MVP Done

The MVP is complete when this scenario works end-to-end: user creates a local vault → adds identity and travel preferences → configures a credential as an external handle → an MCP agent creates a hotel-search task → receives low-risk travel preferences automatically → selects a hotel → requests additional authority for booking → PAV asks the user to approve name/email disclosure, age proof and credential use → user approves → agent receives name/email → agent receives only the boolean age assertion → the credential is exercised without entering model context → the grant becomes exhausted or expires → the audit timeline reconstructs every step → attempts to replay the grant, change task, request undeclared resources, or use the capability at another destination all fail.

---

## 34. Immediate Build Backlog

**Epic A — Domain:** Attribute model; Sensitivity model; Agent model; Task model; Purpose model; Access request model; Grant model; Audit event model.

**Epic B — Authority:** Policy decision interface; Default-deny policy; Request evaluator; Approval workflow; Grant issuance; Grant validation; Grant revocation; Grant expiry; Usage limits.

**Epic C — Data minimisation:** Reveal operation; Derived claim registry; Prove operation; Use operation; External-handle abstraction.

**Epic D — Interfaces:** REST API; MCP adapter; Approval UI; Active grants UI; Audit timeline.

**Epic E — Security:** Local encryption; Key management; Audit-event chaining; Agent authentication; Destination validation; Security tests.

**Epic F — Demonstrators:** Travel-search scenario; Progressive hotel-booking scenario; Zero-exposure credential scenario.

---

## 35. Recommended First Technical Spike

Build the authority lifecycle before building the vault UI. The spike should contain only:

- 5 personal attributes
- 1 derived claim
- 1 external secret handle
- 2 agents
- 2 tasks
- 3 policies
- `request_access()`
- `approve()`
- `issue_grant()`
- `reveal()`
- `prove()`
- `use()`
- `revoke()`
- `audit()`

Run it entirely through automated tests first.

The key question is not whether encrypted CRUD can be built. It can. The key question is whether the delegation model remains understandable, enforceable and pleasant enough that agents and users will actually use it. That is the product hypothesis worth proving.
