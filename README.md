# TrustMesh — enterprise identity threat hunter

A local end-to-end demonstration: real **Keycloak 26.7.4** identity infrastructure, a **Next.js / TypeScript** analyst console, four investigator roles, one shared MCP evidence service, and analyst-approved session containment. No payment system or custom employee portal.

**Current engine: deterministic rehearsal.** The model-driven Responses adapter exists, but a real model has not been configured or evaluated. SaaS/cloud evidence is replay-only. This is not a production-ready security product.

Start with the [demo and recovery runbook](docs/demo-runbook.md), or see the [current delivery checklist](docs/delivery-plan.md).

## Run locally

Prerequisites: Node.js 22.13+, npm, Docker Desktop with its engine running. These instructions use the local ports 3000, 8080, 55432 and 56379.

```sh
npm ci
npm run setup
npm run infra:up
```

Wait for Keycloak to finish its first realm import. Then:

```sh
npm run db:migrate
npm run check:identity
npm run demo:seed
```

Start the web app, collector and investigation worker together in one foreground terminal:

```sh
npm run demo
```

Alternatively, use three separate terminals: `npm run dev`, `npm run worker`, and `npm run worker:agents`. Do not run both options at the same time.

- SOC console: http://localhost:3000 — sign in as `analyst`.
- Employee account console: http://localhost:8080/realms/trustmesh/account/ — sign in as `alice` in a separate browser profile.
- Keycloak administration: http://localhost:8080/admin/ — username `bootstrap-admin`.

Passwords are generated into the gitignored `.env`: `ANALYST_PASSWORD`, `EMPLOYEE_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`. Open that file locally; do not paste credentials into chat or commit them. The setup script never overwrites an existing `.env`.

Use `localhost`, not `127.0.0.1`, in browser URLs: the OIDC issuer and callback are registered with that hostname. The services themselves bind to loopback.

## What works

- Persistent Keycloak realm, distinct employee / analyst roles, and read-only service-account permissions.
- Authorization Code + PKCE + state + nonce login; server-side analyst-role checks.
- Opaque console cookie with a hashed database lookup; the short-lived provider access token is encrypted at rest and not returned to the browser by our console.
- Provider introspection and current role lookup on protected console requests. Dependency errors fail closed.
- Read-only identity APIs: users, roles, active user sessions, user events and admin events.
- BullMQ collection every five seconds; source-specific cursors, ten-minute overlap, retry and database deduplication.
- Database-persisted evidence, source timestamps, event inspection, live sessions and collection freshness indicators.
- Lead, Identity, SaaS and Cloud investigator roles on one stdio MCP service with eight read-only tools and run/role-bound capabilities.
- Five isolated scenarios, per-case graph views, deterministic rules and a tiny synthetic-data logistic regression baseline with explicitly limited evaluation results.
- Validated evidence citations, persisted reports/tool traces, model/tool/time/token limits, cancellation and expired-worker recovery.
- Analyst approval/rejection, single-observed-session policy, action audit and verification. No containment tool is available to an agent.
- Replay actions change only that case's session snapshot. Live actions are limited to explicitly seeded `demo-*` users in the local realm.
- Live verification makes an actual HTTP request to `/api/demo/protected` before and after revocation; it also checks introspection and unrelated session preservation.

`demo:seed` creates four marked identities and a lab-only password-grant probe client. Analyst login still uses Authorization Code + PKCE. Demo sessions are real Keycloak sessions; scenario evidence is separate replay data.

The collector uses Redis/BullMQ. Investigations use a PostgreSQL queue with leases; the agent worker owns the shared MCP child process. The approval executor lives outside MCP. There is no independent MCP server per agent.

The console session lasts up to five minutes in this foundation. Sign in again when it expires. **Sign out of console** deletes only the console session; it is not global Keycloak logout or containment.

## Evidence coverage

User and admin event recording are enabled with seven-day provider retention. Admin request representations are deliberately disabled. The collector stores selected event fields and a small details allowlist, not complete request bodies.

On first collection, the previous 24 hours are imported. Subsequent polls replay a ten-minute overlap. Date filters use UTC day boundaries with precise timestamp filtering locally. A per-source 10,000-event scan limit fails visibly without advancing its cursor; this is suitable for a small lab, not a production event-stream design. Offset-based source pagination is not a transactional snapshot. Reconcile a wider time window or use an event-listener integration before relying on it at enterprise scale.

Some provider admin events have no event ID. Their identity uses a deterministic fingerprint; truly identical events at the same millisecond can collapse. Normal user events retain the provider ID. Missing actor/session information stays missing.

The dashboard displays the first 100 provider identities and the latest 100 collected events. Device/IP values are provider observations; Docker may report a bridge IP. There is no device fingerprinting or impossible-travel claim.

## Verification

```sh
npm test
npm run typecheck
npm run build
npm run check:identity
npm run collect
npx tsx scripts/check-collection.ts
npx tsx scripts/check-http.ts
npm run check:demo
npm run check:runtime
```

The first three checks validate code and configuration. Integration checks require running containers and a migrated/seeded database; HTTP checks also require the web app. Stop the investigation worker before `check:demo`, `check:runtime` or `demo:live-check`: these scripts claim their own isolated cases. They retain labeled test records for inspection. `check:runtime` uses scripted model responses, makes no paid API calls and changes no live identities. `npx tsx scripts/check-console-session.ts` checks the most recent console session using boolean outcomes and non-secret metadata.

For the real approved-session drill, follow the runbook. `npm run demo:live-check` generates bounded activity on **demo-charlie only** and leaves a proposal pending; it does not approve it. After dashboard approval, `npm run demo:live-check -- CASE_ID` verifies actual denied access and unaffected sessions.

Do not print raw OIDC/JOSE exception objects: some include claims or credentials. Development request logging excludes authentication callback URLs for this reason.

## Operations and limitations

`npm run infra:stop` stops containers without deleting data. Realm import runs only when the realm is absent; editing import JSON does not update an existing realm. Changes to an existing realm must be made through explicit, scoped maintenance. `scripts/sync-console-audience.ts` adds only the console audience mapper to the local test realm when upgrading an initial setup that lacked it.

Keycloak is running in development mode. PostgreSQL databases are separate but share one local database role. Redis is loopback-bound and unauthenticated. TLS, service-specific database accounts, secret management, protected private networking, a durable event-stream integration and operational hardening are prerequisites for deployment beyond this lab. Keycloak's internal metrics endpoint is enabled but not published; metrics are not yet ingested into the console.

The local executor uses the bootstrap administrator credential behind fixed-path code and seeded-user checks. It is **not** a production least-privilege executor. MCP credentials are filtered in its environment, but the child process shares the filesystem and database authority; capabilities are application controls, not an OS sandbox. Production requires separate service identities, storage permissions and network/process isolation.

Revocation invalidates this demo's introspection-protected endpoint. An application performing only offline JWT signature checks may continue accepting an outstanding token until expiry. We do not claim instant revocation across arbitrary enterprise applications.

## Next steps

Live-model configuration and evaluation remain separate follow-up work. Real SaaS/cloud integrations, streaming detection triggers, checkpoint-resumable agents, operational monitoring and production deployment are not included in the current demo. Investigations are explicitly launched by an analyst, not automatically created from every collected event.

[Identity Agent Part 1](docs/identity-agent-contracts.md) explains the input, state, evidence and report contracts. [Part 2](docs/identity-agent-handlers.md) explains the five scoped read-only handlers. Their milestone descriptions are historical; the current runtime is described in the runbook and delivery checklist.

## References

- [Keycloak Docker setup](https://www.keycloak.org/getting-started/getting-started-docker)
- [Keycloak administration and event recording](https://www.keycloak.org/docs/latest/server_admin/)
- [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- [OIDC endpoints and introspection](https://www.keycloak.org/securing-apps/oidc-layers)
- [OpenID Client](https://github.com/panva/openid-client)
