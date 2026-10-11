# Implementation gates — current demo and historical foundation

This is an execution checklist, not a replacement for the collaboratively authored PRD. Keycloak is selected. Payments and custom identity simulators are out of scope. Every containment action requires analyst approval.

## Current implementation — 2026-10-01

- [x] Four investigator roles: Lead, Identity, SaaS and Cloud; one shared MCP service with eight scoped read-only tools.
- [x] Validated requests, evidence and reports; per-role tool access; persisted queue, run trace, audit and response proposals.
- [x] Five isolated replay scenarios including legitimate-anomaly and normal controls; graph view, rules and synthetic logistic baseline.
- [x] Dashboard sign-in, case launch, report inspection and analyst approval/rejection.
- [x] Real, approved Keycloak single-session revocation measured at a protected HTTP endpoint: 200 → 401; four other sessions still returned 200 in the recorded drill.
- [x] Cancellation during pending work, deadlines/budgets, malformed calls/reports, MCP failures, expired-worker leases and interrupted-action recovery checks.
- [x] Startup, presentation, verification and recovery runbook: [demo guide](demo-runbook.md).
- [ ] Configure and evaluate a real model. Deferred priority 1; scripted Responses tests are not real AI execution.
- [ ] Connect real SaaS/cloud providers. Current replay coverage must not be presented as live integrations.
- [ ] Production deployment and hardening. Local-demo completion does not satisfy the production requirements.

Verification this pass: TypeScript and the webpack production build; 54 automated unit/contract tests; 15 runtime/fault checks; five complete replay scenario checks; HTTP authorization checks; a real live-containment drill with dashboard approval. Worker interruption is covered through persisted lease-expiry injection, not OS process-kill chaos testing. Synthetic-model metrics are generator-based smoke evaluation only.

Browser walkthrough: analyst sign-in/reauthentication; launch through the scenario UI; read evidence/graph/report; reject a replay action and observe its audit; approve the live Keycloak drill and observe VERIFIED; launch the legitimate-anomaly control with no response proposal; inspect Agent workspace and Evaluation. The narrow desktop-panel layout had no horizontal overflow in the measured evaluation view. Test cases and the live drill are retained for inspection; one demo-charlie session was revoked, and re-login can create a replacement.

The sections below preserve the original phased plan and foundation verification. “Next” in those historical sections does not override the current implementation checklist above.

“Yesterday” and “today” refer to the foundation and integration work packages, not a claim that the remaining schedule is guaranteed.

## Foundation: yesterday's pending work

- [x] Initialise the TypeScript / Next.js repository and test commands.
- [x] Run pinned local Keycloak, PostgreSQL and Redis containers.
- [x] Import a dedicated project realm, distinct Alice / analyst identities and a read-only service account.
- [x] Enable user and admin event recording; exclude complete admin request representations.
- [x] Create the application's evidence, collection-state and console-session tables.
- [x] Generate local secrets without committing or printing them.

Exit gate: the realm is real, persistent, queryable and separate from Keycloak's master administration realm.

## Integration: today's work

- [x] Integrate analyst sign-in through Keycloak Authorization Code + PKCE.
- [x] Enforce the analyst role independently of successful employee authentication.
- [x] Query identity inventory, sessions, roles and both event feeds.
- [x] Collect selected evidence into PostgreSQL with stable IDs, overlap and retry.
- [x] Show actual provider sessions, evidence and stale-source status in the console.
- [x] Unit tests, TypeScript check, production build and live reader checks.
- [x] Complete and record browser permission / sign-out verification.
- [x] Test collector recovery and duplicate delivery against the running environment.

Exit gate: a real login appears in the analyst console; employee authentication does not grant SOC access; ingestion persists across reconnects.

### Verification recorded on 2026-09-22

- Nine automated tests passed; TypeScript checking and the production build passed.
- Live browser checks: analyst login reaches inventory/evidence; Alice authenticates but is refused SOC access; explicit console sign-out returns to sign-in.
- HTTP checks: anonymous inventory access returns 401; cross-origin sign-out returns 403; a callback without a valid login transaction is rejected.
- Repeated live collection: second pass inserted zero events, preserved earlier evidence, and both source cursors remained healthy.
- Worker restart: a read-only provider login occurred while the collector was stopped; the restarted worker collected the pending events (two new events, including its own connector authentication).
- This verifies foundation behaviour only. No identity-containment action was executed or claimed as verified.

## Identity investigation: next 1–2 working days

- [x] Part 1: Identity Agent request/scope, shared-MCP tool contracts, evidence, state and report validation with unit tests. See [contract walkthrough](identity-agent-contracts.md).
- [x] Part 2: Five scoped read-only evidence handlers, opaque run/query-bound pagination and provider/PostgreSQL integration checks. See [handler walkthrough](identity-agent-handlers.md). Execution and MCP transport were added in the subsequent demo milestone above.
- Define observable Keycloak signals and at least one legitimate-anomaly counterexample.
- Add the incident lifecycle and evidence references before LLM integration.
- Expose the identity tool group through one shared MCP server using the working reader adapter; enforce agent/run-specific permissions.
- Implement the Lead Investigator and Identity Agent with validated outputs and call/time budgets.
- Add action-specific approval, policy enforcement, an independently scoped executor and audit records.
- Test one approved target-session action against a protected client; separately measure outstanding access tokens and unrelated sessions.

Exit gate: real event → incident → agent evidence → analyst-approved action → verified access result. A successful logout API response alone is insufficient.

## SaaS and cloud coverage: following 1–2 working days

- Confirm available accounts, audit feeds, identity mappings and supported containment operations.
- Select one SaaS target and one small AWS sandbox. No account provisioning or cloud spending is authorised by this document.
- Implement the SaaS and Cloud agents and their scoped tool groups on the same shared MCP server.
- Add evidence-backed graph relationships; distinguish observed edges from hypotheses.
- Run one cross-domain scenario and preserve missing-telemetry indicators.

Exit gate: four agent roles and three tool domains on one shared MCP server work on evidence actually provided by the selected integrations. Replay fixtures are labelled as replay, never presented as live containment.

## Evaluation and hardening: final 1–2 working days

- Add a small synthetic-data model only after the observed feature contract stabilises.
- Keep scenario labels out of agent evidence; split train/test scenarios by run and identity where appropriate.
- Evaluate detection, cited evidence, uncertainty, prohibited actions, approval scope and verification outcomes.
- Compare rules-only results with model-assisted results.
- Deploy the selected demo configuration, test dependency failures and rehearse the investigation.

## Keycloak capability map

| Capability | Current use | Subsequent work |
| --- | --- | --- |
| Built-in login / Account / Admin consoles | Reused directly | Configure MFA testing and additional test identities as needed |
| Users and roles | Reader adapter and access checks | Groups and permission context in evidence |
| Active sessions | Live read-only inventory | Scoped approved revocation and connected-client verification |
| User/admin events | Enabled and persisted | Detection, investigation and higher-fidelity streaming if needed |
| OIDC token introspection | Console access validation | Verify revocation behaviour for selected protected applications |
| OAuth grants / consents / offline sessions | Provider features available, not yet surfaced | Choose and validate exact tools before adding them |
| Brute-force protection / authentication configuration | Not altered or claimed as implemented | Read-only configuration inventory where useful |
| Health / metrics | Container availability; Keycloak internal metrics enabled | Structured service monitoring |
| Administrative mutation APIs | Kept outside application reader | Separate approval-controlled adapter, never a generic admin proxy |

The platform will expose selected security evidence and approved operations; it will not blindly forward every Keycloak API to an agent.
