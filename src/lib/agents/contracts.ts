import { z } from "zod";

// Provider-neutral, JSON-serializable contracts. No credentials belong in these objects.
export const CONTRACT_VERSION = "identity.v1" as const;
// Initial lab policy, aligned with configured provider retention; not a coverage guarantee.
export const MAX_HISTORY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
export const idSchema = z.string().min(1).max(512).refine(value => value.trim() === value && !/[\u0000-\u001f]/.test(value), "Invalid identifier");
export const timestampSchema = z.iso.datetime({ offset: true });
export const noteSchema = z.string().trim().min(1).max(2000);
export const timeRangeSchema = z.strictObject({
  from: timestampSchema,
  to: timestampSchema
}).refine(value => Date.parse(value.from) < Date.parse(value.to), "Time range must be increasing")
  .refine(value => Date.parse(value.to) - Date.parse(value.from) <= MAX_HISTORY_WINDOW_MS, "Historical window exceeds seven days");
export type TimeRange = z.infer<typeof timeRangeSchema>;

export function rangeContains(outer: TimeRange, inner: TimeRange): boolean {
  return Date.parse(inner.from) >= Date.parse(outer.from) && Date.parse(inner.to) <= Date.parse(outer.to);
}

export const identityToolNameSchema = z.enum([
  "identity_get_profile", "identity_get_roles", "identity_get_sessions",
  "identity_search_events", "identity_get_event"
]);
export type IdentityToolName = z.infer<typeof identityToolNameSchema>;

export const investigationRequestSchema = z.strictObject({
  identityId: idSchema,
  question: z.string().trim().min(1).max(2000),
  timeRange: timeRangeSchema,
  initialEventIds: z.array(idSchema).max(20).default([])
}).refine(value => new Set(value.initialEventIds).size === value.initialEventIds.length, "Duplicate initial event IDs");

export const scopeSchema = z.strictObject({
  realm: z.string().regex(/^[a-zA-Z0-9_-]+$/).max(128),
  identityId: idSchema,
  timeRange: timeRangeSchema
});

export const runLimitsSchema = z.strictObject({
  maxModelTurns: z.number().int().positive().max(8).default(8),
  maxToolCalls: z.number().int().positive().max(12).default(12),
  maxDurationMs: z.number().int().positive().max(90000).default(90000),
  toolTimeoutMs: z.number().int().positive().max(10000).default(10000),
  maxRetries: z.number().int().min(0).max(2).default(1),
  // Required from deployment policy when a provider is selected, not guessed by the model.
  maxTokens: z.number().int().positive().max(100000)
});

export const identityRunSchema = z.strictObject({
  contractVersion: z.literal(CONTRACT_VERSION),
  agentId: z.literal("identity-investigator"),
  runId: z.uuid(),
  requestedBy: idSchema,
  createdAt: timestampSchema,
  question: noteSchema,
  scope: scopeSchema,
  initialEventIds: z.array(idSchema).max(20),
  allowedTools: z.array(identityToolNameSchema).min(1).max(5),
  limits: runLimitsSchema,
  promptVersion: idSchema,
  modelConfiguration: z.strictObject({ provider: idSchema, model: idSchema })
}).superRefine((run, ctx) => {
  if (new Set(run.allowedTools).size !== run.allowedTools.length) {
    ctx.addIssue({ code: "custom", path: ["allowedTools"], message: "Duplicate tools" });
  }
  if (new Set(run.initialEventIds).size !== run.initialEventIds.length) {
    ctx.addIssue({ code: "custom", path: ["initialEventIds"], message: "Duplicate initial event IDs" });
  }
  if (Date.parse(run.scope.timeRange.to) > Date.parse(run.createdAt)) {
    ctx.addIssue({ code: "custom", path: ["scope", "timeRange"], message: "Historical window cannot end in the future" });
  }
  if (run.limits.toolTimeoutMs > run.limits.maxDurationMs) {
    ctx.addIssue({ code: "custom", path: ["limits"], message: "Tool timeout exceeds run duration" });
  }
});
export type IdentityRun = z.infer<typeof identityRunSchema>;

export class ContractError extends Error {
  constructor(public readonly code: "OUT_OF_SCOPE" | "INVALID_EVIDENCE" | "INVALID_REPORT" | "INVALID_STATE") {
    super(code);
    this.name = "ContractError";
  }
}
