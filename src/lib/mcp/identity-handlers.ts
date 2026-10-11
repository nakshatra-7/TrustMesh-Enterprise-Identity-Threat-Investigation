import { createHmac, randomUUID } from "node:crypto";
import { z } from "zod";
import { ContractError, identityRunSchema } from "../agents/contracts";
import { config } from "../config";
import { db } from "../db";
import { identityReader, KeycloakError, type KeycloakReader } from "../keycloak";
import { identityToolResultSchema, validateIdentityEvidence, validateIdentityToolCall, type IdentityEvidence } from "./identity-contracts";
import { createIdentityCursorCodec, InvalidCursorError, type IdentityCursorCodec } from "./identity-cursor";
import { createIdentityEvidenceStore, type EventQuery, type EventRow, type IdentityEvidenceStore } from "./identity-store";

type ToolResult = z.infer<typeof identityToolResultSchema>;
type ErrorCode = Extract<ToolResult, { status: "error" }>["code"];
type Dependencies = {
  realm: string;
  reader: Pick<KeycloakReader, "user" | "roles" | "sessions">;
  store: IdentityEvidenceStore;
  cursors: IdentityCursorCodec;
  now?: () => Date;
};
const MAX_RESULT_BYTES = 65536;
const PAGE_DATA_BYTES = 56000; // Reserve room for envelope, coverage and cursor.
const failure = (code: ErrorCode, safeMessage: string, retryable = false): ToolResult => ({ status: "error", code, retryable, safeMessage });

// Only unambiguous users/<exact-id>[/...] admin paths are interpreted. No IP/name inference.
export function affectedIdentityId(source: string, resource: string | null): string | null {
  if (source !== "keycloak.admin" || !resource) return null;
  const segment = /^users\/([^/]+)(?:\/|$)/.exec(resource)?.[1];
  // Reject ambiguous encoded/dot segments instead of decoding them into an identity.
  return segment && !segment.includes("%") && segment !== "." && segment !== ".." ? segment : null;
}

function eventDto(row: EventRow) {
  const details: Record<string, string> = {};
  for (const key of ["auth_method", "auth_type", "grant_type", "credential_type", "reason", "error"]) {
    if (typeof row.details?.[key] === "string") details[key] = row.details[key].slice(0, 200);
  }
  return {
    id: row.id, source: row.source, realm: row.realm, eventType: row.event_type,
    occurredAt: row.occurred_at.toISOString(), actorId: row.actor_id,
    affectedIdentityId: affectedIdentityId(row.source, row.resource), sessionId: row.session_id,
    clientId: row.client_id, ipAddress: row.ip_address, resource: row.resource,
    outcome: row.outcome, details
  };
}

function capped<T>(items: T[], max = 100): { items: T[]; truncated: boolean } {
  const selected: T[] = [];
  let bytes = 2;
  for (const item of items.slice(0, max)) {
    const size = Buffer.byteLength(JSON.stringify(item)) + 1;
    if (bytes + size > PAGE_DATA_BYTES) break;
    selected.push(item); bytes += size;
  }
  if (items.length && !selected.length) throw new Error("Evidence item exceeds response budget");
  return { items: selected, truncated: selected.length < items.length };
}

/** Internal API only: trustedRun must be loaded/authorized by application code, NOT an HTTP/MCP argument. */
export function createIdentityHandlers(trustedRun: unknown, dependencies: Dependencies) {
  const run = identityRunSchema.parse(trustedRun); // Parse clones caller data; no mutable model-owned scope retained.
  const now = dependencies.now ?? (() => new Date());
  if (run.scope.realm !== dependencies.realm) throw new ContractError("OUT_OF_SCOPE");

  async function execute(input: unknown, callerSignal?: AbortSignal): Promise<ToolResult> {
    let call;
    try { call = validateIdentityToolCall(run, input); }
    catch (error) {
      return error instanceof ContractError ? failure("OUT_OF_SCOPE", "Tool or range is outside this investigation.")
        : failure("INVALID_ARGUMENT", "Tool arguments do not match the allowed contract.");
    }
    if (Date.parse(run.createdAt) > now().getTime()) return failure("INVALID_ARGUMENT", "Run creation timestamp is in the future.");
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (callerSignal?.aborted) abort();
    callerSignal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, run.limits.toolTimeoutMs);
    const signal = controller.signal;
    let rejectAbort: () => void = () => {};
    try {
      const aborted = new Promise<never>((_, reject) => {
        rejectAbort = () => reject(new DOMException("Tool interrupted", "AbortError"));
        signal.addEventListener("abort", rejectAbort, { once: true });
        if (signal.aborted) rejectAbort();
      });
      const operation = async (): Promise<IdentityEvidence> => {
        signal.throwIfAborted();
        const base = () => ({
          status: "ok", runId: run.runId, evidenceRef: randomUUID(), realm: run.scope.realm,
          identityId: run.scope.identityId, retrievedAt: now().toISOString(),
          truncated: false, nextCursor: null
        });
        let output: unknown;
        if (call.name === "identity_get_profile") {
          const user = await dependencies.reader.user(run.scope.identityId, signal);
          output = { ...base(), tool: call.name, source: "keycloak", temporalBasis: "current_snapshot",
            coverageWarnings: ["Profile is current state, not historical account state."],
            data: { id: user.id, username: user.username, enabled: user.enabled ?? null } };
        } else if (call.name === "identity_get_roles") {
          const roles = capped((await dependencies.reader.roles(run.scope.identityId, signal)).map(r => r.name));
          output = { ...base(), tool: call.name, source: "keycloak", temporalBasis: "current_snapshot",
            truncated: roles.truncated, coverageWarnings: ["Roles are current realm roles; historical assignments and client-specific permissions are not established."],
            data: { roles: roles.items } };
        } else if (call.name === "identity_get_sessions") {
          const raw = await dependencies.reader.sessions(run.scope.identityId, signal);
          if (raw.some(s => s.userId !== undefined && s.userId !== run.scope.identityId)) throw new ContractError("INVALID_EVIDENCE");
          let applicationsTruncated = false;
          const sessions = capped(raw.map(s => {
            const applications = Object.values(s.clients ?? {});
            applicationsTruncated ||= applications.length > 100;
            return {
              id: s.id, identityId: run.scope.identityId, ipAddress: s.ipAddress ?? null,
              // Keycloak 26.7.4 ModelToRepresentation returns epoch milliseconds.
              startedAt: s.start === undefined ? null : new Date(s.start).toISOString(),
              lastAccessAt: s.lastAccess === undefined ? null : new Date(s.lastAccess).toISOString(),
              applications: applications.slice(0, 100)
            };
          }));
          output = { ...base(), tool: call.name, source: "keycloak", temporalBasis: "current_snapshot",
            truncated: sessions.truncated || applicationsTruncated,
            coverageWarnings: ["Only current online sessions are queried; offline tokens and historical sessions are not covered."],
            data: { sessions: sessions.items } };
        } else {
          const args = call.name === "identity_search_events" ? call.arguments : null;
          const timeRange = args?.timeRange ?? run.scope.timeRange;
          const binding = {
            runId: run.runId, requestedBy: run.requestedBy, scope: run.scope, tool: call.name,
            source: args?.source ?? "both", relationship: args?.relationship ?? "either",
            eventTypes: [...new Set(args?.eventTypes ?? [])].sort(), timeRange, pageSize: args?.pageSize ?? 1
          };
          const cursor = args?.cursor ? dependencies.cursors.decode(args.cursor, binding, now().getTime()) : null;
          const asOf = cursor?.asOf ?? now().toISOString();
          const query: EventQuery = {
            scope: run.scope, timeRange, source: binding.source, relationship: binding.relationship,
            eventTypes: binding.eventTypes, pageSize: binding.pageSize, asOf,
            position: cursor?.position, eventId: call.name === "identity_get_event" ? call.arguments.eventId : undefined
          };
          const result = await dependencies.store.read(query, signal, run.limits.toolTimeoutMs);
          signal.throwIfAborted();
          if (call.name === "identity_get_event" && !result.rows.length) throw new KeycloakError(404);
          if (result.rows.some(row => (query.eventId && row.id !== query.eventId) ||
              (query.source !== "both" && row.source !== `keycloak.${query.source}`) ||
              (query.eventTypes.length && !query.eventTypes.includes(row.event_type)) ||
              (query.relationship === "actor" && row.actor_id !== run.scope.identityId) ||
              (query.relationship === "target" && affectedIdentityId(row.source, row.resource) !== run.scope.identityId))) {
            throw new ContractError("INVALID_EVIDENCE");
          }
          const rows = result.rows.slice(0, query.pageSize);
          const page = capped(rows.map(eventDto));
          const truncated = result.rows.length > page.items.length;
          const warnings = [
            "Polling history may be incomplete; a healthy collector does not prove historical coverage.",
            "Unattributed attempts and ambiguous resource paths cannot be assigned to this identity."
          ];
          const sources = query.source === "both" ? ["keycloak.user", "keycloak.admin"] : [`keycloak.${query.source}`];
          for (const source of sources) {
            const coverage = result.coverage.find(c => c.source === source);
            const age = coverage?.last_success_at ? now().getTime() - coverage.last_success_at.getTime() : Infinity;
            if (!coverage || coverage.status !== "healthy" || age < 0 || age >= 20000) warnings.push(`${source}: collector is stale, missing or unavailable.`);
          }
          const last = rows[page.items.length - 1];
          const nextCursor = truncated && last && args ? dependencies.cursors.encode(binding, asOf,
            { time: last.cursor_time, id: last.id }, cursor?.expiresAt ?? now().getTime() + 15 * 60000) : null;
          output = { ...base(), tool: call.name, source: "identity_events", temporalBasis: "historical_events",
            queriedTimeRange: timeRange, truncated, nextCursor, coverageWarnings: warnings,
            data: call.name === "identity_get_event" ? { event: page.items[0] } : { events: page.items } };
        }
        signal.throwIfAborted();
        const evidence = validateIdentityEvidence(run, output);
        if (Buffer.byteLength(JSON.stringify(evidence)) > MAX_RESULT_BYTES) throw new Error("Evidence exceeds response budget");
        return evidence;
      };
      return await Promise.race([aborted, operation()]);
    } catch (error) {
      if (error instanceof InvalidCursorError) return failure("INVALID_ARGUMENT", "Cursor is invalid, expired or does not match this run and query.");
      if (signal.aborted || (error instanceof Error && ["AbortError", "TimeoutError"].includes(error.name)) ||
          (typeof error === "object" && error !== null && "code" in error && error.code === "57014")) {
        return failure("TIMEOUT", "Evidence request timed out or was cancelled.", !callerSignal?.aborted);
      }
      if (error instanceof KeycloakError && error.status === 404) return failure("NOT_FOUND", "Evidence was not found within the authorized scope.");
      if (error instanceof KeycloakError && [401, 403].includes(error.status)) return failure("UNAVAILABLE", "Provider read permission is unavailable.");
      return failure("UNAVAILABLE", "Evidence could not be read or validated.", !(error instanceof ContractError || error instanceof z.ZodError));
    } finally {
      clearTimeout(timer); callerSignal?.removeEventListener("abort", abort); signal.removeEventListener("abort", rejectAbort);
    }
  }
  return { execute };
}

/** Server-side wiring, not a public route. Caller must authorize/load the run first. */
export function identityHandlersForRun(trustedRun: unknown) {
  const c = config();
  const cursorKey = createHmac("sha256", Buffer.from(c.COOKIE_SECRET, "hex")).update("trustmesh.identity.cursor.v1").digest();
  return createIdentityHandlers(trustedRun, {
    realm: c.KEYCLOAK_REALM, reader: identityReader, store: createIdentityEvidenceStore(db()),
    cursors: createIdentityCursorCodec(cursorKey)
  });
}
