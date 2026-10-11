import { createHash } from "node:crypto";
import { z } from "zod";

const eventSchema = z.object({
  id: z.string().optional(), time: z.number().int().nonnegative(), type: z.string().optional(),
  userId: z.string().optional(), sessionId: z.string().optional(), clientId: z.string().optional(),
  ipAddress: z.string().optional(), error: z.string().optional(), operationType: z.string().optional(),
  resourceType: z.string().optional(), resourcePath: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
  authDetails: z.object({ userId: z.string().optional(), clientId: z.string().optional(), ipAddress: z.string().optional() }).optional()
});
export type IdentityEvent = {
  id: string; source: "keycloak.user" | "keycloak.admin"; realm: string; type: string; occurredAt: Date;
  actorId?: string; sessionId?: string; clientId?: string; ipAddress?: string; resource?: string;
  outcome: "success" | "failure"; details: Record<string, string>;
};
export function normalizeEvent(input: unknown, source: "user" | "admin", realm: string): IdentityEvent {
  const e = eventSchema.parse(input);
  const type = source === "user" ? e.type : `${e.operationType ?? "UNKNOWN"}:${e.resourceType ?? "UNKNOWN"}`;
  if (!type) throw new Error("Missing Keycloak user event type");
  const details: Record<string, string> = {};
  // Deliberate allowlist. URLs, representation, passwords, token/code/session values are excluded.
  for (const key of ["auth_method", "auth_type", "grant_type", "credential_type", "reason"]) {
    const value = e.details?.[key];
    if (typeof value === "string") details[key] = value.slice(0, 200);
  }
  if (e.error) details.error = e.error.slice(0, 200);
  const actorId = e.userId ?? e.authDetails?.userId;
  const clientId = e.clientId ?? e.authDetails?.clientId;
  const ipAddress = e.ipAddress ?? e.authDetails?.ipAddress;
  // Some admin events have no provider ID. Fingerprint observable fields; identical same-ms events may collapse.
  const fingerprint = createHash("sha256").update(JSON.stringify([e.time, type, actorId, e.sessionId, clientId, ipAddress, e.resourcePath, details])).digest("hex");
  return {
    id: `${realm}:${source}:${e.id ?? fingerprint}`, source: `keycloak.${source}`, realm,
    type, occurredAt: new Date(e.time), actorId, sessionId: e.sessionId, clientId, ipAddress,
    resource: e.resourcePath, outcome: e.error || type.endsWith("_ERROR") ? "failure" : "success", details
  };
}
