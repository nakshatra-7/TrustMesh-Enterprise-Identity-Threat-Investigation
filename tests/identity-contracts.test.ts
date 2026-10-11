import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONTRACT_VERSION, identityRunSchema, identityToolNameSchema, investigationRequestSchema, timeRangeSchema
} from "../src/lib/agents/contracts";
import {
  identityEvidenceSchema, identityToolContracts, identityToolResultSchema,
  validateIdentityEvidence, validateIdentityToolCall
} from "../src/lib/mcp/identity-contracts";
import {
  deliverIdentityReport, identityReportSchema, identityStateSchema,
  validateIdentityReport, validateIdentityState
} from "../src/lib/agents/identity-contracts";

const timeRange = { from: "2026-09-28T08:00:00Z", to: "2026-09-28T10:00:00Z" };
function run() {
  return identityRunSchema.parse({
    contractVersion: CONTRACT_VERSION, agentId: "identity-investigator",
    runId: "d243f3ee-a143-45a1-8991-53f622e385b1", requestedBy: "analyst-id",
    createdAt: "2026-09-28T10:00:00Z", question: "Investigate Alice's login activity.",
    scope: { realm: "trustmesh", identityId: "alice-id", timeRange }, initialEventIds: [],
    allowedTools: identityToolNameSchema.options, limits: { maxTokens: 12000 },
    promptVersion: "identity.v1", modelConfiguration: { provider: "test", model: "fixture" }
  });
}
function evidence() {
  return identityEvidenceSchema.parse({
    status: "ok", runId: run().runId, evidenceRef: "evidence-sessions-1", tool: "identity_get_sessions",
    realm: "trustmesh", identityId: "alice-id", retrievedAt: "2026-09-28T10:00:02Z",
    source: "keycloak", temporalBasis: "current_snapshot", coverageWarnings: [], truncated: false, nextCursor: null,
    data: { sessions: [{ id: "session-1", identityId: "alice-id", ipAddress: null, startedAt: null, lastAccessAt: null, applications: [] }] }
  });
}
function report() {
  return identityReportSchema.parse({
    assessment: "SUSPICIOUS_ACTIVITY", summary: "Fixture assessment for contract tests, not a real security conclusion.",
    findings: [{ claim: "The target has a reported active session.", kind: "observation", evidenceRefs: ["evidence-sessions-1"] }],
    alternativeExplanations: [{ explanation: "The session may be legitimate.", supportingEvidenceRefs: [], contradictingEvidenceRefs: [], unknowns: ["User confirmation unavailable."] }],
    limitations: [], recommendation: { type: "ANALYST_REVIEW", reason: "Review the evidence.", evidenceRefs: ["evidence-sessions-1"] }
  });
}
function state() {
  return identityStateSchema.parse({
    run: run(), execution: {
      status: "COMPLETED", step: 2, checkpointVersion: 2, modelCalls: 2, toolCalls: 1, tokensUsed: 100,
      retryCount: 0, startedAt: "2026-09-28T10:00:00Z", finishedAt: "2026-09-28T10:00:03Z",
      deadlineAt: "2026-09-28T10:01:30Z", cancellationRequested: false, lastError: null, pendingCalls: []
    },
    toolHistory: [{ callId: "call-1", attempt: 1, startedAt: "2026-09-28T10:00:01Z", finishedAt: "2026-09-28T10:00:02Z",
      call: { name: "identity_get_sessions", arguments: {} }, result: evidence() }],
    history: [{ kind: "tool_result", callId: "call-1", attempt: 1 }], workingNotes: [], coverageWarnings: [], report: report()
  });
}

test("analyst request accepts a bounded question but no forged runtime authority", () => {
  const input = { identityId: "alice-id", question: " Investigate login activity. ", timeRange };
  assert.equal(investigationRequestSchema.parse(input).question, "Investigate login activity.");
  for (const extra of [{ allowedTools: [] }, { requestedBy: "admin" }, { scope: {} }, { approved: true }]) {
    assert.equal(investigationRequestSchema.safeParse({ ...input, ...extra }).success, false);
  }
  for (const invalid of [{ ...input, question: " " }, { ...input, question: "x".repeat(2001) },
    { ...input, initialEventIds: ["e1", "e1"] }, { ...input, identityId: "\n" }]) {
    assert.equal(investigationRequestSchema.safeParse(invalid).success, false);
  }
});

test("timestamps require an offset, increasing order, and a nonfuture historical run window", () => {
  for (const invalid of [
    { from: timeRange.to, to: timeRange.from }, { from: timeRange.from, to: timeRange.from },
    { from: "2026-09-28T08:00:00", to: timeRange.to }, { from: "2026-02-30T08:00:00Z", to: timeRange.to },
    { from: "2026-09-01T08:00:00Z", to: timeRange.to }
  ]) assert.equal(timeRangeSchema.safeParse(invalid).success, false);
  assert.equal(identityRunSchema.safeParse({ ...run(), createdAt: timeRange.from }).success, false);
});

test("trusted run schema records explicit limits without allowing unknown tools or credentials", () => {
  assert.equal(run().limits.maxToolCalls, 12);
  assert.equal(identityRunSchema.safeParse({ ...run(), allowedTools: ["cloud_delete_key"] }).success, false);
  assert.equal(identityRunSchema.safeParse({ ...run(), allowedTools: ["identity_get_roles", "identity_get_roles"] }).success, false);
  assert.equal(identityRunSchema.safeParse({ ...run(), apiKey: "not-a-real-key" }).success, false);
  assert.equal(identityRunSchema.safeParse({ ...run(), limits: { ...run().limits, maxModelTurns: 9 } }).success, false);
});

test("shared MCP identity contracts register exactly five reads with target-free snapshot arguments", () => {
  assert.equal(Object.keys(identityToolContracts).length, 5);
  for (const name of ["identity_get_profile", "identity_get_roles", "identity_get_sessions"]) {
    assert.doesNotThrow(() => validateIdentityToolCall(run(), { name, arguments: {} }));
    assert.throws(() => validateIdentityToolCall(run(), { name, arguments: { identityId: "bob" } }));
    assert.throws(() => validateIdentityToolCall(run(), { name, arguments: { approved: true } }));
  }
  assert.throws(() => validateIdentityToolCall(run(), { name: "identity_revoke_session", arguments: {} }));
  assert.throws(() => validateIdentityToolCall({ ...run(), allowedTools: ["identity_get_profile"] }, { name: "identity_get_roles", arguments: {} }));
});

test("event search limits filters and prevents widening the authorized historical window", () => {
  const call = validateIdentityToolCall(run(), { name: "identity_search_events", arguments: {} });
  assert.equal(call.name === "identity_search_events" && call.arguments.pageSize, 25);
  assert.doesNotThrow(() => validateIdentityToolCall(run(), { name: "identity_search_events", arguments: {
    timeRange: { from: "2026-09-28T09:00:00Z", to: timeRange.to }, pageSize: 100, relationship: "target"
  } }));
  for (const args of [{ pageSize: 101 }, { pageSize: 1.5 }, { sql: "SELECT *" }, { source: "cloud" },
    { timeRange: { from: "2026-09-27T08:00:00Z", to: timeRange.to } }]) {
    assert.throws(() => validateIdentityToolCall(run(), { name: "identity_search_events", arguments: args }));
  }
});

test("evidence validates run, realm, target and nested session ownership", () => {
  assert.doesNotThrow(() => validateIdentityEvidence(run(), evidence()));
  for (const changes of [{ runId: "440e8ea8-a8cc-4cb8-b6cb-b5f692f01419" }, { realm: "other" },
    { identityId: "bob" }, { retrievedAt: "2026-09-28T09:00:00Z" },
    { data: { sessions: [{ id: "s", identityId: "bob", ipAddress: null, startedAt: null, lastAccessAt: null, applications: [] }] } }]) {
    assert.throws(() => validateIdentityEvidence(run(), { ...evidence(), ...changes }));
  }
});

function eventEvidence() {
  return {
    ...evidence(), evidenceRef: "event-result", tool: "identity_get_event", source: "identity_events",
    temporalBasis: "historical_events", queriedTimeRange: timeRange,
    data: { event: {
      id: "e1", source: "keycloak.admin", realm: "trustmesh", eventType: "UPDATE:USER",
      occurredAt: "2026-09-28T09:00:00Z", actorId: "administrator", affectedIdentityId: "alice-id",
      sessionId: null, clientId: null, ipAddress: null, resource: "users/alice-id", outcome: "success", details: {}
    } }
  };
}

test("historical evidence accepts actions on the target but rejects unrelated and out-of-window events", () => {
  const input = eventEvidence();
  assert.doesNotThrow(() => validateIdentityEvidence(run(), input));
  for (const changes of [{ affectedIdentityId: "bob" }, { occurredAt: "2026-09-28T07:00:00Z" },
    { realm: "other" }, { details: { access_token: "must-not-pass" } }]) {
    assert.throws(() => validateIdentityEvidence(run(), { ...input, data: { event: { ...input.data.event, ...changes } } }));
  }
});

test("tool failures cannot masquerade as successful empty results or retry authorization errors", () => {
  assert.equal(identityToolResultSchema.safeParse({ status: "error", code: "TIMEOUT", retryable: true, safeMessage: "Provider timed out." }).success, true);
  assert.equal(identityToolResultSchema.safeParse({ status: "error", code: "OUT_OF_SCOPE", retryable: true, safeMessage: "Denied." }).success, false);
  assert.equal(identityToolResultSchema.safeParse({ status: "ok", data: [] }).success, false);
  assert.equal(identityToolResultSchema.safeParse({ ...evidence(), nextCursor: "next", truncated: false }).success, false);
});

test("model reports cannot supply authority or invent citations", () => {
  assert.doesNotThrow(() => validateIdentityReport(run(), report(), [evidence()]));
  for (const extra of [{ approved: true }, { containmentExecuted: true }, { runId: run().runId }, { confidence: 0.99 }]) {
    assert.equal(identityReportSchema.safeParse({ ...report(), ...extra }).success, false);
  }
  assert.throws(() => validateIdentityReport(run(), { ...report(), findings: [{ claim: "Invented", kind: "observation", evidenceRefs: ["missing"] }] }, [evidence()]));
  assert.throws(() => validateIdentityReport(run(), report(), [evidence(), evidence()]));
});

test("revocation is only a proposal and must cite a current scoped session observation", () => {
  const proposal = { ...report(), recommendation: { type: "PROPOSE_SESSION_REVOCATION", sessionId: "session-1", reason: "Analyst must assess this proposal.", evidenceRefs: ["evidence-sessions-1"] } };
  assert.doesNotThrow(() => validateIdentityReport(run(), proposal, [evidence()]));
  assert.throws(() => validateIdentityReport(run(), { ...proposal, recommendation: { ...proposal.recommendation, sessionId: "other-session" } }, [evidence()]));
  assert.equal(identityReportSchema.safeParse({ ...proposal, assessment: "INSUFFICIENT_EVIDENCE" }).success, false);
});

test("inconclusive investigations can complete without pretending an identity is safe", () => {
  const inconclusive = { ...report(), assessment: "INSUFFICIENT_EVIDENCE", findings: [], recommendation: { type: "ANALYST_REVIEW", reason: "Telemetry missing.", evidenceRefs: [] } };
  assert.doesNotThrow(() => validateIdentityReport(run(), inconclusive, []));
  assert.equal(identityReportSchema.safeParse({ ...inconclusive, assessment: "SAFE" }).success, false);
  assert.equal(identityReportSchema.safeParse({ ...inconclusive, recommendation: { type: "NO_ACTION_RECOMMENDED", reason: "No evidence", evidenceRefs: [] } }).success, false);
});

test("delivered reports preserve runtime warnings and tool failures omitted by the model", () => {
  const input = state();
  input.coverageWarnings = ["Historical coverage has not been established."];
  const first = input.toolHistory[0].result;
  if (first.status === "ok") { first.truncated = true; first.coverageWarnings = ["Provider result capped."]; }
  input.toolHistory.push({ callId: "call-2", attempt: 1, startedAt: "2026-09-28T10:00:01Z", finishedAt: "2026-09-28T10:00:02Z",
    call: { name: "identity_get_roles", arguments: {} }, result: { status: "error", code: "UNAVAILABLE", retryable: true, safeMessage: "Provider unavailable." } });
  input.execution.toolCalls = 2;
  const delivered = deliverIdentityReport(input);
  assert.ok(delivered.limitations.includes(input.coverageWarnings[0]));
  assert.ok(delivered.limitations.includes("Provider result capped."));
  assert.ok(delivered.limitations.some(w => w.includes("truncated")));
  assert.ok(delivered.limitations.some(w => w.includes("UNAVAILABLE")));
  assert.equal(delivered.containmentExecuted, false);
});

test("completed states cannot be cancelled, over budget, late, or missing a report", () => {
  assert.doesNotThrow(() => validateIdentityState(state()));
  for (const changes of [{ cancellationRequested: true }, { modelCalls: 9 }, { toolCalls: 13 },
    { tokensUsed: 12001 }, { finishedAt: "2026-09-28T10:02:00Z" }, { deadlineAt: "2026-09-28T11:00:00Z" }]) {
    const input = state(); Object.assign(input.execution, changes);
    assert.throws(() => validateIdentityState(input));
  }
  assert.throws(() => validateIdentityState({ ...state(), report: null }));
});

test("limit-reached states preserve partial evidence but cannot deliver a final report", () => {
  const input = state(); input.execution.status = "LIMIT_REACHED"; input.report = null;
  assert.doesNotThrow(() => validateIdentityState(input));
  assert.throws(() => deliverIdentityReport(input));
});

test("checkpoints reject mismatched calls, duplicate attempts, and fabricated working-note references", () => {
  const duplicate = state(); duplicate.toolHistory.push(duplicate.toolHistory[0]); duplicate.execution.toolCalls = 2;
  assert.throws(() => validateIdentityState(duplicate));
  const mismatch = state(); mismatch.toolHistory[0].call = { name: "identity_get_roles", arguments: {} };
  assert.throws(() => validateIdentityState(mismatch));
  const notes = state(); notes.workingNotes = [{ hypothesis: "Possible legitimate retries", evidenceRefs: ["invented"], openQuestions: [] }];
  assert.throws(() => validateIdentityState(notes));
  const idMismatch = state(); idMismatch.toolHistory[0].call = { name: "identity_get_event", arguments: { eventId: "wrong-id" } };
  idMismatch.toolHistory[0].result = identityEvidenceSchema.parse(eventEvidence());
  assert.throws(() => validateIdentityState(idMismatch));
});

test("search responses must match the requested filters and narrower window", () => {
  const input = state();
  const historical = eventEvidence();
  input.toolHistory[0].call = validateIdentityToolCall(run(), { name: "identity_search_events", arguments: { relationship: "target" } });
  input.toolHistory[0].result = identityEvidenceSchema.parse({ ...historical, evidenceRef: "evidence-sessions-1", tool: "identity_search_events", data: { events: [historical.data.event] } });
  assert.doesNotThrow(() => validateIdentityState(input));
  input.toolHistory[0].call = validateIdentityToolCall(run(), { name: "identity_search_events", arguments: { relationship: "actor" } });
  assert.throws(() => validateIdentityState(input));
  input.toolHistory[0].call = validateIdentityToolCall(run(), { name: "identity_search_events", arguments: { source: "user" } });
  assert.throws(() => validateIdentityState(input));
  input.toolHistory[0].call = validateIdentityToolCall(run(), { name: "identity_search_events", arguments: { timeRange: { from: "2026-09-28T09:00:00Z", to: timeRange.to } } });
  assert.throws(() => validateIdentityState(input));
});

test("retries are ordered, bounded and only follow retryable failures", () => {
  const invalid = state(); invalid.toolHistory[0].attempt = 2;
  assert.throws(() => validateIdentityState(invalid));
  const input = state();
  const success = structuredClone(input.toolHistory[0]); success.attempt = 2;
  input.toolHistory[0].result = { status: "error", code: "TIMEOUT", retryable: true, safeMessage: "Timed out." };
  input.toolHistory.push(success); input.execution.toolCalls = 2; input.execution.retryCount = 1;
  assert.doesNotThrow(() => validateIdentityState(input));
  input.toolHistory[0].result = { status: "error", code: "OUT_OF_SCOPE", retryable: false, safeMessage: "Denied." };
  assert.throws(() => validateIdentityState(input));
});

test("delivering a revocation proposal never marks it approved or executed", () => {
  const input = state();
  input.report!.recommendation = { type: "PROPOSE_SESSION_REVOCATION", sessionId: "session-1", reason: "Review required.", evidenceRefs: ["evidence-sessions-1"] };
  const delivered = deliverIdentityReport(input);
  assert.equal(delivered.analystApprovalRequired, true);
  assert.equal(delivered.containmentExecuted, false);
  assert.equal("approved" in delivered, false);
});
