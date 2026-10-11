# Identity Agent — Part 1 contracts

Historical milestone walkthrough. Subsequent runtime, shared MCP and approval work is recorded in the [current checklist](delivery-plan.md) and [demo runbook](demo-runbook.md).

Implemented: provider-neutral TypeScript/Zod schemas and pure validation helpers.
At this milestone, runtime, MCP transport, persistence and containment were deliberately excluded. They have since been added. Part 2 documents the underlying [evidence handlers](identity-agent-handlers.md).

## Architecture decision

There will be **one shared MCP server** for all agents, with domain-prefixed tools and server-enforced permissions per authenticated caller/run. No dedicated MCP server per agent. The identity contract registry is the first domain's tool surface, not a running server. A tool appearing in a registry does not authorize it.

## Read the code in this order

1. `src/lib/agents/contracts.ts`: analyst request versus trusted run scope; version, timestamps and limits.
2. `src/lib/mcp/identity-contracts.ts`: the shared server's five identity tool contracts, evidence/error envelopes and scoped validation.
3. `src/lib/agents/identity-contracts.ts`: goal, model report, checkpoint state, provenance checks and delivered report.
4. `tests/identity-contracts.test.ts`: valid fixtures and rejected boundary violations. Fixtures are not actual investigations or attack determinations.

Schemas use strict objects: unknown authority fields are rejected, not silently accepted. TypeScript types are inferred from Zod to avoid two separate definitions.

## Input and authority

The analyst submits identity ID, question, fixed historical time range and optional initial event IDs. The backend must authenticate the analyst, authorize the target, validate starting-event ownership, and create the trusted run with IDs, realm, tool allowlist, versions, model configuration and budgets. Those authentication/storage lookups are later work; parsing a run object never proves its authority.

Initial policy: historical windows span at most seven days (aligned with local provider retention, NOT a coverage guarantee). The end cannot be after run creation. Maximums/defaults are eight model turns, twelve tool attempts, ninety seconds and ten seconds per tool; one retry defaults, two maximum. `maxTokens` must be explicitly set by deployment policy once the provider is chosen. No provider, model or API key is selected here. Actual timers, budget reservations and cancellation enforcement belong to the future runtime.

## Shared MCP tools

| Tool | Model arguments | Source |
| --- | --- | --- |
| `identity_get_profile` | Empty object | Targeted Keycloak lookup, implemented in Part 2 |
| `identity_get_roles` | Empty object | Existing Keycloak reader |
| `identity_get_sessions` | Empty object | Existing Keycloak reader |
| `identity_search_events` | Source, event types, actor/target relation, narrower window, page size, cursor | Scoped PostgreSQL query, implemented in Part 2 |
| `identity_get_event` | Event ID | Scoped PostgreSQL lookup, implemented in Part 2 |

Snapshot tools derive identity/realm from trusted context. Search pages default to 25 and cap at 100. Handlers must bind pagination cursors to run/query scope and enforce row ownership before returning data. Event lookup must not rely on knowing an ID as authorization. `affectedIdentityId` must come from validated resource mapping, not username/IP inference. Raw provider fields are adapted to bounded, allowlisted DTOs; missing fields use null. Unknown actors remain unknown.

Evidence responses carry run/target identifiers, a generated evidence reference, source, retrieval time, temporal basis, coverage warnings, truncation and pagination. Historical responses also carry their queried range. Snapshots are current observations, not historical proof. Missing data/errors must not become successful empty responses. Only transient errors can be retried.

## State and report

State stores the trusted run, execution counters/timestamps, pending calls, completed tool attempts with snapshots, a bounded normalized interaction transcript, optional working notes, runtime coverage warnings and nullable final report. It is a serializable contract only; no migration or persistence adapter is added. The transcript is not a provider-specific replay format; the model adapter will need to handle provider continuation data separately. No hidden reasoning or credentials are required.

Use `validateIdentityState` for full cross-field checkpoint validation, not just `identityStateSchema.parse`. The model may propose calls and reports; it must never supply the authoritative state/evidence arrays. A future repository must make scope immutable and protect checkpoints with concurrency control. Retry call IDs retain arguments and attempt numbers; refreshes of live state are separate observations.

Reports distinguish observation from inference and support suspicious / no suspicious evidence observed / insufficient evidence. Findings require references; references must exist in this run. A revocation proposal must cite a current session observation containing the exact target session. This establishes attribution, NOT sufficient justification to revoke. Semantic correctness still requires evaluations and analyst review.

`deliverIdentityReport` accepts completed validated state only, attaches runtime IDs and scope, and merges runtime/tool warnings even if the model omitted them. It always sets `containmentExecuted: false`; revocation proposals require analyst approval. Failed/cancelled/limit-reached runs retain partial evidence but cannot deliver a completed report. No approval token or execution capability exists in Part 1. Schema validation cannot detect every unsupported natural-language claim or secret embedded in a string.

## Validation and next boundary

Run `npm test` and `npm run typecheck`. If the environment blocks the tsx CLI's IPC pipe, use `node --import tsx --test tests/*.test.ts` for the same suite without that CLI pipe.

Part 2 implements scoped evidence handlers and their provider/database integration tests. Next, add the single shared MCP server around those handlers, including authenticated caller/run resolution. Model/runtime implementation remains separate.

The separation of application context from model context and structured output follows the [official agent-definition guidance](https://developers.openai.com/api/docs/guides/agents/define-agents); the domain contracts and policy defaults above are this project's design, not SDK guarantees.
