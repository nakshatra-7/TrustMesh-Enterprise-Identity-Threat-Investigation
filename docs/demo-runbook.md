# TrustMesh demonstration and recovery guide

## What to say first

“Authentication tells us who a request belongs to. TrustMesh investigates whether that identity's session and permission use looks suspicious, gathers evidence through a shared read-only MCP layer, and proposes a controlled response. An analyst must approve containment.”

Be precise about the implementation: Keycloak and session revocation are real; repository/cloud scenarios are simulated. Four investigator roles run end-to-end in deterministic rehearsal today. The LLM adapter exists but has not been tested against a real model. Scripted Responses tests validate orchestration, not AI reasoning quality.

## Start a prepared workspace

Prerequisites: Node 22.13+, Docker Desktop running, dependencies installed. Keep `.env` private.

```sh
npm run infra:up
npm run db:migrate
npm run demo:seed
npm run demo
```

For a fresh clone, run `npm ci` and `npm run setup` first. Setup preserves existing secrets. Do not delete Docker volumes to resolve a startup problem.

The foreground supervisor starts Next on port 3000, the read-only collector, and the investigation worker (with its shared MCP child). PostgreSQL is on 55432, Redis 56379 and Keycloak 8080. Use **http://localhost:3000**, not a LAN hostname. Do not start duplicate workers or a second web process.

Sign in as `analyst`; retrieve `ANALYST_PASSWORD` from `.env` locally. Do not share it in screenshots, terminal output or chat. Console access expires after at most five minutes: reauthenticate before the main demonstration. A login transaction also expires after five minutes. Start a fresh sign-in after an expired or failed callback; do not replay the callback URL.

## Five-minute presentation

1. **Identity inventory:** show real users, active sessions, retained events and healthy collection. Explain that this reuses Keycloak rather than implementing another employee IAM system.
2. **Scenario lab → Identity → repository → cloud:** select deterministic rehearsal and launch. The worker runs Lead → Identity/SaaS/Cloud → shared evidence tools → cited report. The case must be labeled SIMULATED and NO LLM.
3. **Case workspace:** expand a tool event; show its scoped arguments, evidence reference and coverage warning. Show the relationship view, observations, legitimate alternatives and limitations. The graph is a scoped evidence-linked view, not an enterprise graph database.
4. **Approval:** inspect the exact identity and target session. Approve the replay proposal; show VERIFIED and the approval/audit records. This changes only the selected case's replay store. Launch privilege expansion and reject its proposal to show the alternative path.
5. **Legitimate anomaly:** launch it and show NO SUSPICIOUS EVIDENCE OBSERVED, without a revocation proposal. This is bounded evidence, not proof an account is safe.
6. **Evaluation / Agent workspace:** show the four roles, eight tools and synthetic model evaluation. The 300 training / 120 held-out vectors share a generator, so these are smoke-test metrics, not bank-grade accuracy or LLM quality results.

If demonstrating real containment, use the separate drill below rather than pretending replay has changed Keycloak.

## Real Keycloak containment drill

Use separate terminals (`npm run dev`, `npm run worker`) and **stop the investigation worker** for the preparation command. Leave the web app and containers running.

```sh
npm run demo:seed
npm run demo:live-check
```

The preparation script validates the marker and registry for `demo-charlie`, opens two real probe sessions, and generates six invalid-password requests on that one owned local identity. It does not disable brute-force protection; if protection is enabled, it stops for review. It collects real events and runs the investigators in rehearsal against live Keycloak evidence. SaaS/cloud return unavailable coverage rather than invented live results.

The script returns a case ID and leaves its action **PENDING**. It grants no role, changes no password and approves nothing. Open **LIVE KEYCLOAK · controlled containment drill** in the dashboard, inspect the observed evidence and target, and approve the single session. Within the 15-minute proposal validity period, verify:

```sh
npm run demo:live-check -- CASE_ID
```

Expected: actual HTTP 200 before, HTTP 401 after, inactive introspection token, target absent and unrelated sessions still HTTP 200. `/api/demo/protected` is a non-sensitive local resource that checks token introspection, probe client and demo registry; the token is never exposed to the browser. The command prints only verification outcomes.

Revocation cannot restore that session; the demo user can sign in again. Existing employee/analyst sessions must remain untouched. Re-running preparation adds sessions and events, so avoid repeated runs unnecessarily. Probe tokens are encrypted and expire; the seed script replenishes missing active probes. Historical case/audit records remain as evidence.

Restart `npm run worker:agents` afterwards. Do not claim that every existing application will instantly reject offline-validated JWTs: the measured result applies to the online-introspection endpoint.

## Automated verification

With the investigation worker stopped, containers up, database migrated and demo identities seeded:

```sh
npm test
npm run typecheck
npm run build -- --webpack
npm run check:demo
npm run check:runtime
node --import tsx scripts/check-http.ts
```

HTTP checks additionally need the web app. `check:demo` covers all five replay scenarios and approve/reject/duplicate decisions. `check:runtime` covers provider failure, malformed arguments, out-of-role calls, fabricated citations, call/token/turn/time limits, in-flight cancellation, four-role Responses routing, MCP disconnect/timeout, expired leases, concurrent approval and interrupted-executor recovery. It uses test doubles with no real model or live identity mutations. Its deliberately failed cases are labeled TEST DOUBLE and retained, not unexplained production failures.

Worker interruption is tested by expiring the persisted lease; recovery marks the run failed rather than replaying an uncertain operation. This is not a claim of process-kill chaos testing, resumable checkpoints or exactly-once delivery across external providers.

## Recovery checklist

| Symptom | Safe recovery |
| --- | --- |
| Docker unavailable | Start Docker Desktop, then `npm run infra:up`; wait for Keycloak startup. Preserve volumes. |
| Port 3000 occupied | Check your existing demo terminal. Stop only that owned process or reuse it; do not kill arbitrary processes. |
| Analyst sign-in fails | Use localhost; restart sign-in and complete it promptly. Check Keycloak and reader availability. Logs show a safe stage/code, not credentials. |
| Sign-in required after a few minutes | Reauthenticate; this is the current short-lived console policy. |
| Runtime unavailable / launch disabled | Start `npm run worker:agents`; it should register eight MCP tools. Health becomes stale after 30 seconds without a heartbeat. |
| Collector stale | Start `npm run worker`; check Docker/Redis/Postgres and reader permissions. The collector retries with overlap and deduplication. |
| Case stuck after a crash | Restart the agent worker. After the seven-minute lease expires it marks the run FAILED (or CANCELLED if requested). Start a new case; no automatic resume. |
| Model unavailable | Use deterministic rehearsal for the demo. There is no silent fallback pretending to be AI. Priority-1 model setup remains separate. |
| Approval expired | Reinvestigate the current sessions. Do not extend an old proposal or bypass approval. |
| Live verification fails | Inspect current Keycloak session state before retrying. A FAILED response may have already changed the provider. No automatic execution retry is allowed. |
| Executor crashed while EXECUTING | Worker recovery marks it FAILED after two minutes with outcome uncertain. Inspect provider state; never assume rollback. |
| Probe expired / target already absent | Reseed and reinvestigate. Do not reuse an expired proposal or print bearer tokens to troubleshoot. |

Stop the foreground supervisor with Ctrl+C. `npm run infra:stop` stops containers without deleting data.

## Remaining production work

Real-model evaluation; real SaaS/cloud connectors and mappings; automatic detection-to-case triggers; durable streaming/reconciliation; independently credentialed least-privilege executor; service/database/process isolation; managed secrets and TLS; telemetry/alerting; retention policy and audit tamper resistance; larger realistic datasets and calibration; robust crash recovery and deployment operations. The current local bootstrap-admin adapter, common filesystem/database authority and synthetic model are deliberate demo limitations.
