import { z } from "zod";
import {
  ContractError, idSchema, identityRunSchema, identityToolNameSchema,
  noteSchema, rangeContains, timeRangeSchema, timestampSchema
} from "../agents/contracts";

const emptyArgs = z.strictObject({});
const searchArgs = z.strictObject({
  source: z.enum(["user", "admin", "both"]).default("both"),
  eventTypes: z.array(z.string().min(1).max(128)).max(20).default([]),
  relationship: z.enum(["actor", "target", "either"]).default("either"),
  timeRange: timeRangeSchema.optional(),
  pageSize: z.number().int().min(1).max(100).default(25),
  cursor: z.string().min(1).max(2048).optional()
});

// Registry for the ONE shared MCP server. No transport, handlers or permissions are installed here.
export const identityToolContracts = {
  identity_get_profile: { description: "Read the scoped identity's current profile, not historical account state.", inputSchema: emptyArgs },
  identity_get_roles: { description: "Read current effective realm roles, not roles held at an earlier event time.", inputSchema: emptyArgs },
  identity_get_sessions: { description: "Read current active sessions; absence does not establish historical absence.", inputSchema: emptyArgs },
  identity_search_events: { description: "Search retained events in scope; distinguish actions by the identity from actions on it.", inputSchema: searchArgs },
  identity_get_event: { description: "Read one retained event, subject to the same identity, realm and time scope.", inputSchema: z.strictObject({ eventId: idSchema }) }
} as const;

export const identityToolCallSchema = z.discriminatedUnion("name", [
  z.strictObject({ name: z.literal("identity_get_profile"), arguments: emptyArgs }),
  z.strictObject({ name: z.literal("identity_get_roles"), arguments: emptyArgs }),
  z.strictObject({ name: z.literal("identity_get_sessions"), arguments: emptyArgs }),
  z.strictObject({ name: z.literal("identity_search_events"), arguments: searchArgs }),
  z.strictObject({ name: z.literal("identity_get_event"), arguments: identityToolContracts.identity_get_event.inputSchema })
]);
export type IdentityToolCall = z.infer<typeof identityToolCallSchema>;

// Call only with a run loaded by trusted application code. Parsing is NOT authentication.
export function validateIdentityToolCall(runInput: unknown, input: unknown): IdentityToolCall {
  const run = identityRunSchema.parse(runInput);
  const call = identityToolCallSchema.parse(input);
  if (!run.allowedTools.includes(call.name)) throw new ContractError("OUT_OF_SCOPE");
  if (call.name === "identity_search_events" && call.arguments.timeRange &&
      !rangeContains(run.scope.timeRange, call.arguments.timeRange)) throw new ContractError("OUT_OF_SCOPE");
  // Cursor binding and event ownership require storage/provider lookups in future handlers.
  return call;
}

const eventSchema = z.strictObject({
  id: idSchema,
  source: z.enum(["keycloak.user", "keycloak.admin"]),
  realm: idSchema,
  eventType: z.string().min(1).max(128),
  occurredAt: timestampSchema,
  actorId: idSchema.nullable(),
  // Handler-derived from validated provider resource mapping, never guessed by the model.
  affectedIdentityId: idSchema.nullable(),
  sessionId: idSchema.nullable(),
  clientId: idSchema.nullable(),
  ipAddress: z.string().max(128).nullable(),
  resource: z.string().max(1024).nullable(),
  outcome: z.enum(["success", "failure"]),
  details: z.strictObject({
    auth_method: z.string().max(200).optional(), auth_type: z.string().max(200).optional(),
    grant_type: z.string().max(200).optional(), credential_type: z.string().max(200).optional(),
    reason: z.string().max(200).optional(), error: z.string().max(200).optional()
  })
});
const sessionSchema = z.strictObject({
  id: idSchema, identityId: idSchema,
  ipAddress: z.string().max(128).nullable(),
  startedAt: timestampSchema.nullable(), lastAccessAt: timestampSchema.nullable(),
  applications: z.array(z.string().max(256)).max(100)
});

const envelope = {
  status: z.literal("ok"), runId: z.uuid(), evidenceRef: idSchema,
  realm: idSchema, identityId: idSchema, retrievedAt: timestampSchema,
  coverageWarnings: z.array(noteSchema).max(20),
  truncated: z.boolean(), nextCursor: z.string().min(1).max(2048).nullable()
};
const current = { ...envelope, source: z.literal("keycloak"), temporalBasis: z.literal("current_snapshot") };
const historical = {
  ...envelope, source: z.literal("identity_events"), temporalBasis: z.literal("historical_events"),
  queriedTimeRange: timeRangeSchema
};

export const identityEvidenceSchema = z.discriminatedUnion("tool", [
  z.strictObject({ ...current, tool: z.literal("identity_get_profile"), data: z.strictObject({ id: idSchema, username: z.string().min(1).max(256), enabled: z.boolean().nullable() }) }),
  z.strictObject({ ...current, tool: z.literal("identity_get_roles"), data: z.strictObject({ roles: z.array(z.string().min(1).max(256)).max(100) }) }),
  z.strictObject({ ...current, tool: z.literal("identity_get_sessions"), data: z.strictObject({ sessions: z.array(sessionSchema).max(100) }) }),
  z.strictObject({ ...historical, tool: z.literal("identity_search_events"), data: z.strictObject({ events: z.array(eventSchema).max(100) }) }),
  z.strictObject({ ...historical, tool: z.literal("identity_get_event"), data: z.strictObject({ event: eventSchema }) })
]).refine(value => value.truncated || value.nextCursor === null, "A pagination cursor requires truncated=true");
export type IdentityEvidence = z.infer<typeof identityEvidenceSchema>;

export const identityToolErrorSchema = z.strictObject({
  status: z.literal("error"),
  code: z.enum(["INVALID_ARGUMENT", "OUT_OF_SCOPE", "UNAVAILABLE", "TIMEOUT", "NOT_FOUND"]),
  retryable: z.boolean(), safeMessage: noteSchema
}).refine(value => !value.retryable || ["UNAVAILABLE", "TIMEOUT"].includes(value.code), "Only transient errors may be retried");
export const identityToolResultSchema = z.union([identityEvidenceSchema, identityToolErrorSchema]);

export function validateIdentityEvidence(runInput: unknown, input: unknown): IdentityEvidence {
  const run = identityRunSchema.parse(runInput);
  const evidence = identityEvidenceSchema.parse(input);
  if (evidence.runId !== run.runId || evidence.realm !== run.scope.realm ||
      evidence.identityId !== run.scope.identityId || !run.allowedTools.includes(evidence.tool) ||
      Date.parse(evidence.retrievedAt) < Date.parse(run.createdAt)) throw new ContractError("INVALID_EVIDENCE");
  if (evidence.tool === "identity_get_profile" && evidence.data.id !== run.scope.identityId) {
    throw new ContractError("INVALID_EVIDENCE");
  }
  if (evidence.tool === "identity_get_sessions" && evidence.data.sessions.some(s => s.identityId !== run.scope.identityId)) {
    throw new ContractError("INVALID_EVIDENCE");
  }
  if (evidence.temporalBasis === "historical_events") {
    if (!rangeContains(run.scope.timeRange, evidence.queriedTimeRange)) throw new ContractError("INVALID_EVIDENCE");
    const events = evidence.tool === "identity_get_event" ? [evidence.data.event] : evidence.data.events;
    for (const event of events) {
      if (event.realm !== run.scope.realm ||
          (event.actorId !== run.scope.identityId && event.affectedIdentityId !== run.scope.identityId) ||
          Date.parse(event.occurredAt) < Date.parse(evidence.queriedTimeRange.from) ||
          Date.parse(event.occurredAt) > Date.parse(evidence.queriedTimeRange.to)) {
        throw new ContractError("INVALID_EVIDENCE");
      }
    }
  }
  return evidence;
}

export const toolAttemptSchema = z.strictObject({
  callId: idSchema, attempt: z.number().int().min(1).max(3),
  startedAt: timestampSchema, finishedAt: timestampSchema,
  call: identityToolCallSchema, result: identityToolResultSchema
}).superRefine((value, ctx) => {
  if (Date.parse(value.finishedAt) < Date.parse(value.startedAt)) {
    ctx.addIssue({ code: "custom", message: "Attempt timestamps are reversed" });
  }
  if (value.result.status === "ok" && value.result.tool !== value.call.name) {
    ctx.addIssue({ code: "custom", message: "Tool result does not match call" });
  }
});
export const sharedMcpIdentityPolicy = {
  agentId: "identity-investigator",
  mode: "read-only",
  tools: identityToolNameSchema.options
} as const;
