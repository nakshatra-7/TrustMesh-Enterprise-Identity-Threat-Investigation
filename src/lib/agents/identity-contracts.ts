import { z } from "zod";
import {
  ContractError, idSchema, identityRunSchema, noteSchema, timestampSchema
} from "./contracts";
import {
  identityToolCallSchema, toolAttemptSchema, validateIdentityEvidence, validateIdentityToolCall,
  type IdentityEvidence
} from "../mcp/identity-contracts";

export const IDENTITY_AGENT_GOAL = "Investigate one identity's authentication, session and role-related activity within authorized scope. Cite evidence, consider legitimate explanations and missing telemetry, and recommend next steps without modifying identity systems.";

const evidenceRefsSchema = z.array(idSchema).max(24).refine(refs => new Set(refs).size === refs.length, "Duplicate evidence references");
const supportedRefsSchema = evidenceRefsSchema.refine(refs => refs.length > 0, "Evidence is required");
const recommendationSchema = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("NO_ACTION_RECOMMENDED"), reason: noteSchema, evidenceRefs: supportedRefsSchema }),
  z.strictObject({ type: z.literal("ANALYST_REVIEW"), reason: noteSchema, evidenceRefs: evidenceRefsSchema }),
  z.strictObject({ type: z.literal("PROPOSE_SESSION_REVOCATION"), reason: noteSchema, sessionId: idSchema, evidenceRefs: supportedRefsSchema })
]);

// Only the model-authored report. Authoritative IDs/status/approval are not accepted here.
export const identityReportSchema = z.strictObject({
  assessment: z.enum(["SUSPICIOUS_ACTIVITY", "NO_SUSPICIOUS_EVIDENCE_OBSERVED", "INSUFFICIENT_EVIDENCE"]),
  summary: noteSchema,
  findings: z.array(z.strictObject({
    claim: noteSchema, kind: z.enum(["observation", "inference"]), evidenceRefs: supportedRefsSchema
  })).max(20),
  alternativeExplanations: z.array(z.strictObject({
    explanation: noteSchema, supportingEvidenceRefs: evidenceRefsSchema,
    contradictingEvidenceRefs: evidenceRefsSchema, unknowns: z.array(noteSchema).max(10)
  })).max(5),
  limitations: z.array(noteSchema).max(20),
  recommendation: recommendationSchema
}).superRefine((report, ctx) => {
  if (report.assessment !== "INSUFFICIENT_EVIDENCE" && report.findings.length === 0) {
    ctx.addIssue({ code: "custom", path: ["findings"], message: "A substantive assessment requires findings" });
  }
  if (report.assessment === "INSUFFICIENT_EVIDENCE" && report.recommendation.type !== "ANALYST_REVIEW") {
    ctx.addIssue({ code: "custom", path: ["recommendation"], message: "Insufficient evidence requires analyst review" });
  }
  if (report.recommendation.type === "PROPOSE_SESSION_REVOCATION" && report.assessment !== "SUSPICIOUS_ACTIVITY") {
    ctx.addIssue({ code: "custom", path: ["recommendation"], message: "Revocation proposals require a suspicious assessment" });
  }
});
export type IdentityReport = z.infer<typeof identityReportSchema>;

export const runStatusSchema = z.enum(["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "LIMIT_REACHED"]);

// Normalized application transcript, NOT a provider-specific SDK replay format or hidden reasoning.
const historyItemSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("message"), role: z.enum(["user", "assistant"]), content: z.string().max(12000) }),
  z.strictObject({ kind: z.literal("tool_call"), callId: idSchema, call: identityToolCallSchema }),
  z.strictObject({ kind: z.literal("tool_result"), callId: idSchema, attempt: z.number().int().positive() })
]);

export const identityStateSchema = z.strictObject({
  run: identityRunSchema,
  execution: z.strictObject({
    status: runStatusSchema, step: z.number().int().nonnegative(), checkpointVersion: z.number().int().nonnegative(),
    modelCalls: z.number().int().nonnegative(), toolCalls: z.number().int().nonnegative(),
    tokensUsed: z.number().int().nonnegative(), retryCount: z.number().int().nonnegative(),
    startedAt: timestampSchema.nullable(), finishedAt: timestampSchema.nullable(), deadlineAt: timestampSchema.nullable(),
    cancellationRequested: z.boolean(), lastError: noteSchema.nullable(),
    pendingCalls: z.array(z.strictObject({ callId: idSchema, call: identityToolCallSchema })).max(12)
  }),
  toolHistory: z.array(toolAttemptSchema).max(36),
  history: z.array(historyItemSchema).max(100),
  workingNotes: z.array(z.strictObject({ hypothesis: noteSchema, evidenceRefs: evidenceRefsSchema, openQuestions: z.array(noteSchema).max(10) })).max(10),
  // Runtime-maintained; model report omissions cannot delete this list.
  coverageWarnings: z.array(noteSchema).max(100),
  report: identityReportSchema.nullable()
}).superRefine((state, ctx) => {
  const e = state.execution;
  const issue = (message: string) => ctx.addIssue({ code: "custom", message });
  const terminal = !["QUEUED", "RUNNING"].includes(e.status);
  if (terminal !== (e.finishedAt !== null)) issue("Only terminal runs have a finishedAt timestamp");
  if ((e.status === "COMPLETED") !== (state.report !== null)) issue("Only completed runs have a final report");
  if (terminal && e.pendingCalls.length) issue("Terminal runs cannot have pending calls");
  if ((e.startedAt === null) !== (e.deadlineAt === null)) issue("Start and deadline must be set together");
  if (["RUNNING", "COMPLETED", "LIMIT_REACHED"].includes(e.status) && !e.startedAt) issue("Run must have started");
  if (e.status === "QUEUED" && (e.startedAt || e.modelCalls || e.toolCalls || e.pendingCalls.length || state.toolHistory.length || e.tokensUsed)) issue("Queued run cannot contain execution");
  if (e.startedAt && (Date.parse(e.startedAt) < Date.parse(state.run.createdAt) ||
      Date.parse(e.deadlineAt!) !== Date.parse(e.startedAt) + state.run.limits.maxDurationMs)) issue("Invalid runtime timestamps");
  if (e.finishedAt && Date.parse(e.finishedAt) < Date.parse(e.startedAt ?? state.run.createdAt)) issue("Finish precedes run start");
  if (e.status === "COMPLETED" && (e.cancellationRequested || e.modelCalls > state.run.limits.maxModelTurns ||
      e.toolCalls > state.run.limits.maxToolCalls || e.tokensUsed > state.run.limits.maxTokens ||
      Date.parse(e.finishedAt!) > Date.parse(e.deadlineAt!))) issue("Completed run exceeds limits or was cancelled");
  if (new Set(e.pendingCalls.map(c => c.callId)).size !== e.pendingCalls.length) issue("Duplicate pending call IDs");
});
export type IdentityState = z.infer<typeof identityStateSchema>;

/** Validate references against TRUSTED, stored tool observations, not model-supplied evidence. */
export function validateIdentityReport(runInput: unknown, reportInput: unknown, observations: readonly unknown[]): IdentityReport {
  const run = identityRunSchema.parse(runInput);
  const report = identityReportSchema.parse(reportInput);
  const evidence = observations.map(item => validateIdentityEvidence(run, item));
  const byRef = new Map(evidence.map(item => [item.evidenceRef, item]));
  if (byRef.size !== evidence.length) throw new ContractError("INVALID_EVIDENCE");
  const refs = [
    ...report.findings.flatMap(f => f.evidenceRefs),
    ...report.alternativeExplanations.flatMap(a => [...a.supportingEvidenceRefs, ...a.contradictingEvidenceRefs]),
    ...report.recommendation.evidenceRefs
  ];
  if (refs.some(ref => !byRef.has(ref))) throw new ContractError("INVALID_REPORT");
  if (report.recommendation.type === "PROPOSE_SESSION_REVOCATION") {
    const recommendation = report.recommendation;
    const observed = recommendation.evidenceRefs.some(ref => {
      const item = byRef.get(ref)!;
      return item.tool === "identity_get_sessions" && item.data.sessions.some(s => s.id === recommendation.sessionId);
    });
    if (!observed) throw new ContractError("INVALID_REPORT");
  }
  // Existence of a citation is not semantic proof. Analyst review/evals remain necessary.
  return report;
}

/** Cross-field checks for a checkpoint loaded by the runtime. This does not authenticate its author. */
export function validateIdentityState(input: unknown): IdentityState {
  const state = identityStateSchema.parse(input);
  const evidence: IdentityEvidence[] = [];
  const attempts = new Set<string>();
  const calls = new Map<string, string>();
  const lastAttempts = new Map<string, number>();
  const retryableCalls = new Set<string>();
  for (const item of state.toolHistory) {
    validateIdentityToolCall(state.run, item.call);
    if (item.attempt > state.run.limits.maxRetries + 1) throw new ContractError("INVALID_STATE");
    const key = `${item.callId}:${item.attempt}`;
    const signature = JSON.stringify(item.call);
    if (attempts.has(key) || (calls.has(item.callId) && calls.get(item.callId) !== signature)) throw new ContractError("INVALID_STATE");
    if (item.attempt !== (lastAttempts.get(item.callId) ?? 0) + 1 ||
        (lastAttempts.has(item.callId) && !retryableCalls.has(item.callId))) throw new ContractError("INVALID_STATE");
    lastAttempts.set(item.callId, item.attempt);
    retryableCalls.delete(item.callId);
    if (item.result.status === "error" && item.result.retryable) retryableCalls.add(item.callId);
    if (!state.execution.startedAt || Date.parse(item.startedAt) < Date.parse(state.execution.startedAt) ||
        (state.execution.finishedAt && Date.parse(item.finishedAt) > Date.parse(state.execution.finishedAt))) throw new ContractError("INVALID_STATE");
    attempts.add(key); calls.set(item.callId, signature);
    if (item.result.status === "ok") {
      const result = validateIdentityEvidence(state.run, item.result);
      if (Date.parse(result.retrievedAt) > Date.parse(item.finishedAt) || Date.parse(result.retrievedAt) < Date.parse(item.startedAt)) throw new ContractError("INVALID_EVIDENCE");
      if (item.call.name === "identity_get_event" && result.tool === "identity_get_event" &&
          item.call.arguments.eventId !== result.data.event.id) throw new ContractError("INVALID_EVIDENCE");
      if (item.call.name === "identity_search_events" && result.tool === "identity_search_events") {
        const args = item.call.arguments;
        const range = args.timeRange ?? state.run.scope.timeRange;
        if (Date.parse(range.from) !== Date.parse(result.queriedTimeRange.from) || Date.parse(range.to) !== Date.parse(result.queriedTimeRange.to) ||
            result.data.events.length > args.pageSize || result.data.events.some(event =>
              (args.source !== "both" && event.source !== `keycloak.${args.source}`) ||
              (args.eventTypes.length > 0 && !args.eventTypes.includes(event.eventType)) ||
              (args.relationship === "actor" && event.actorId !== state.run.scope.identityId) ||
              (args.relationship === "target" && event.affectedIdentityId !== state.run.scope.identityId))) throw new ContractError("INVALID_EVIDENCE");
      }
      evidence.push(result);
    }
  }
  for (const pending of state.execution.pendingCalls) {
    validateIdentityToolCall(state.run, pending.call);
    if (calls.has(pending.callId) && (!retryableCalls.has(pending.callId) || calls.get(pending.callId) !== JSON.stringify(pending.call))) throw new ContractError("INVALID_STATE");
  }
  if (state.execution.toolCalls < state.toolHistory.length + state.execution.pendingCalls.length) throw new ContractError("INVALID_STATE");
  if (state.execution.retryCount < state.toolHistory.filter(item => item.attempt > 1).length) throw new ContractError("INVALID_STATE");
  const refs = new Set(evidence.map(e => e.evidenceRef));
  if (refs.size !== evidence.length || state.workingNotes.some(n => n.evidenceRefs.some(ref => !refs.has(ref)))) throw new ContractError("INVALID_EVIDENCE");
  for (const item of state.history) {
    if (item.kind === "tool_call") {
      validateIdentityToolCall(state.run, item.call);
      const expected = calls.get(item.callId) ?? state.execution.pendingCalls.find(c => c.callId === item.callId)?.call;
      if (!expected || (typeof expected === "string" ? expected : JSON.stringify(expected)) !== JSON.stringify(item.call)) throw new ContractError("INVALID_STATE");
    }
    if (item.kind === "tool_result" && !attempts.has(`${item.callId}:${item.attempt}`)) throw new ContractError("INVALID_STATE");
  }
  if (state.report) validateIdentityReport(state.run, state.report, evidence);
  return state;
}

/** Build the delivered view from trusted state so coverage warnings survive model omissions. */
export function deliverIdentityReport(input: unknown) {
  const state = validateIdentityState(input);
  if (state.execution.status !== "COMPLETED" || !state.report) throw new ContractError("INVALID_STATE");
  const warnings = state.toolHistory.flatMap(item => item.result.status === "error"
    ? [`${item.call.name}: ${item.result.code}. Evidence may be unavailable.`]
    : [...item.result.coverageWarnings, ...(item.result.truncated ? [`${item.result.evidenceRef}: results were truncated.`] : [])]);
  return {
    contractVersion: state.run.contractVersion,
    runId: state.run.runId, scope: state.run.scope, completedAt: state.execution.finishedAt!,
    ...state.report,
    limitations: [...new Set([...state.report.limitations, ...state.coverageWarnings, ...warnings])],
    // Set by code, never accepted as model-authored approval or execution state.
    containmentExecuted: false as const,
    analystApprovalRequired: state.report.recommendation.type === "PROPOSE_SESSION_REVOCATION"
  };
}
