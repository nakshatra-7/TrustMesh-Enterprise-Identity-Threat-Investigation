# Identity Agent — Part 2 evidence handlers

Historical milestone walkthrough. The shared MCP transport and four-role runtime have since been added; see [the current checklist](delivery-plan.md) and [demo runbook](demo-runbook.md). Live SaaS/cloud connectors and real-model evaluation remain unimplemented/unverified, respectively.

Part 1 defined what tools accept and return. Part 2 implemented the five reads; this milestone itself did not add a model loop, MCP server, public endpoint, migration or containment action.

## Implementation and reading order

1. `src/lib/mcp/identity-handlers.ts`: `createIdentityHandlers(trustedRun, dependencies)` returns `execute(call, signal?)`. It clones/validates trusted scope, rejects invalid arguments and disallowed tools, runs the read with a deadline, maps selected data into the Part 1 evidence contract, and returns sanitized errors. `identityHandlersForRun` wires existing configuration, Keycloak and PostgreSQL for server-side use.
2. `src/lib/keycloak.ts`: new targeted `user(id, signal?)` avoids the first-100-users limitation. Profile, roles and session reads propagate abort signals through token acquisition and retry; existing callers remain compatible. Keycloak 26.7.4 session start/access timestamps are epoch milliseconds, confirmed in the [provider implementation](https://github.com/keycloak/keycloak/blob/26.7.4/server-spi-private/src/main/java/org/keycloak/models/utils/ModelToRepresentation.java).
3. `src/lib/mcp/identity-store.ts`: parameterized historical queries always constrain realm, time and actor/target. Reads use a read-only transaction and server-side statement timeout. Active SQL isn't instantly cancelled by AbortSignal; the statement timeout bounds it, and cleanup rolls back/releases the connection. The existing pool bounds connection acquisition.
4. `src/lib/mcp/identity-cursor.ts`: opaque AES-GCM cursors bind run ID, requesting analyst, identity/realm, filters, window and page size. They expire after 15 minutes and carry a fixed ingestion cutoff plus the last event's timestamp/ID. The server derives a purpose-specific key from COOKIE_SECRET; the model never receives it.

## Scope and evidence semantics

Only trusted application code may create a handler from an authorized run. A parsed run is not authentication. Part 3 must authenticate MCP callers and load/authorize their runs server-side, not accept model-authored run objects. The future shared server will register these handlers alongside other domains with per-run permissions. No separate identity MCP server is introduced.

Actions **by** a user match `actor_id` exactly. Actions **on** a user match the exact identity segment of `users/<id>[/...]` on admin events. Percent-encoded and dot-segment identities are conservatively excluded from target inference. No IP/username guessing or LIKE wildcards are used. Knowing an event ID does not grant access: lookup reuses realm/identity/time constraints and returns the same NOT_FOUND result for absent and out-of-scope rows. This is a selected resource mapping, not coverage of every Keycloak admin resource.

User/role/session responses describe current state. Session ownership comes from the scoped provider endpoint; an explicitly conflicting returned userId fails validation. Historical results come from retained normalized events, not live provider history. Unknown values remain null. Explicit credentials and raw provider representations are not included; allowed string values still require untrusted-data treatment by the future runtime.

Results cap at 100 records and 64 KiB serialized output, with explicit truncation. Large historical pages return a continuation cursor; capped roles/sessions have no continuation in this slice. Session/role arrays are currently fetched from Keycloak before output capping; this is not a network-response memory bound for enterprise-scale providers.

Historical ordering uses `(occurred_at, id)` keyset pagination with C collation. Cursor timestamps retain PostgreSQL microseconds even though displayed evidence timestamps use JavaScript millisecond precision. An ingestion cutoff excludes ordinarily later-arriving rows across pages, but is not a database snapshot across requests: concurrent uncommitted/backdated writes and evidence mutations can still affect results. Current evidence IDs are assumed stable under the append-only application collection behavior; the database is not tamper-proof.

Every historical response warns that polling and identity attribution may be incomplete. Connector freshness is reported separately and never treated as proof of complete historical coverage. Empty search, missing event, provider outage and malformed evidence have distinct outcomes. Evidence references are generated per observation; persisting those responses remains runtime work in a later part. Retries/budgets across multiple tool calls remain runtime responsibilities.

## Verification

- Unit suite: `node --import tsx --test tests/*.test.ts` (avoids the tsx CLI IPC restriction in some sandboxes).
- Type check: `npm run typecheck`.
- Integration: `npm run check:identity-handlers`, requiring the existing Keycloak/PostgreSQL containers and migrated foundation schema.

The integration check creates **session-local TEMP tables only**, tests actual PostgreSQL scope filters, actor versus target, SQL parameterization, missing events, ingestion cutoff and microsecond/tied timestamp pagination. Destroying that test connection discards its fixtures; no persistent application rows are inserted or deleted. It then uses the real read-only Keycloak service account for profile/role/session reads and queries existing stored evidence. Token acquisition may itself generate normal provider authentication events. No account/session changes are requested. Output contains check results, not tokens or evidence contents.

Next: Part 3 wires these tested handlers into the **one shared MCP server**, including caller authentication and trusted run resolution. The handlers should not be exposed directly before that boundary exists.
