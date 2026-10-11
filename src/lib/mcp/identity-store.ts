import type { Pool, PoolClient } from "pg";
import type { IdentityRun, TimeRange } from "../agents/contracts";
import type { EventPosition } from "./identity-cursor";

export type EventRow = {
  id: string; source: "keycloak.user" | "keycloak.admin"; realm: string; event_type: string;
  occurred_at: Date; cursor_time: string; actor_id: string | null; session_id: string | null;
  client_id: string | null; ip_address: string | null; resource: string | null;
  outcome: "success" | "failure"; details: Record<string, unknown>;
};
export type CoverageRow = { source: string; status: string; last_success_at: Date | null };
export type EventQuery = {
  scope: IdentityRun["scope"]; timeRange: TimeRange; source: "user" | "admin" | "both";
  eventTypes: string[]; relationship: "actor" | "target" | "either";
  pageSize: number; asOf: string; position?: EventPosition; eventId?: string;
};
export type IdentityEvidenceStore = {
  read(query: EventQuery, signal: AbortSignal, timeoutMs: number): Promise<{ rows: EventRow[]; coverage: CoverageRow[] }>;
};

// Exact segment match; NOT LIKE (IDs containing %/_ must not widen the query).
const targetPredicate = "(source='keycloak.admin' AND split_part(resource,'/',1)='users' AND split_part(resource,'/',2)=$2 AND split_part(resource,'/',2) NOT IN ('.','..') AND strpos(split_part(resource,'/',2),'%')=0)";
export function buildIdentityEventQuery(query: EventQuery) {
  const values: unknown[] = [query.scope.realm, query.scope.identityId, query.timeRange.from, query.timeRange.to, query.asOf];
  const clauses = ["realm=$1", "occurred_at >= $3::timestamptz", "occurred_at <= $4::timestamptz", "received_at <= $5::timestamptz"];
  clauses.push(query.relationship === "actor" ? "actor_id=$2" : query.relationship === "target" ? targetPredicate : `(actor_id=$2 OR ${targetPredicate})`);
  const parameter = (value: unknown) => { values.push(value); return `$${values.length}`; };
  if (query.source !== "both") clauses.push(`source=${parameter(`keycloak.${query.source}`)}`);
  if (query.eventTypes.length) clauses.push(`event_type=ANY(${parameter(query.eventTypes)}::text[])`);
  if (query.eventId) clauses.push(`id=${parameter(query.eventId)}`);
  if (query.position) clauses.push(`(occurred_at,id COLLATE "C") < (${parameter(query.position.time)}::timestamptz,${parameter(query.position.id)} COLLATE "C")`);
  const limit = parameter(query.eventId ? 1 : query.pageSize + 1);
  return {
    text: `SELECT id,source,realm,event_type,occurred_at,actor_id,session_id,client_id,ip_address,resource,outcome,details,
      to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_time
      FROM identity_events WHERE ${clauses.join(" AND ")}
      ORDER BY occurred_at DESC,id COLLATE "C" DESC LIMIT ${limit}`,
    values
  };
}

/** SQL reads run in a read-only transaction with a server-side statement timeout. */
export function createIdentityEvidenceStore(pool: Pick<Pool, "connect">): IdentityEvidenceStore {
  return {
    async read(query, signal, timeoutMs) {
      signal.throwIfAborted();
      const client: PoolClient = await pool.connect();
      let destroy = false;
      try {
        signal.throwIfAborted();
        await client.query("BEGIN READ ONLY");
        await client.query("SELECT set_config('statement_timeout',$1,true)", [String(Math.max(1, Math.min(timeoutMs, 10000)))]);
        signal.throwIfAborted();
        const result = await client.query<EventRow>(buildIdentityEventQuery(query));
        signal.throwIfAborted();
        const sources = query.source === "both" ? ["keycloak.user", "keycloak.admin"] : [`keycloak.${query.source}`];
        const coverage = await client.query<CoverageRow>("SELECT source,status,last_success_at FROM connector_state WHERE source=ANY($1::text[])", [sources]);
        signal.throwIfAborted();
        await client.query("COMMIT");
        return { rows: result.rows, coverage: coverage.rows };
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch { destroy = true; }
        throw error;
      } finally { client.release(destroy); }
    }
  };
}
