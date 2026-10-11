import { config } from "./config";
import { db } from "./db";
import { normalizeEvent } from "./events";
import { identityReader } from "./keycloak";

export async function collectIdentityEvents() {
  let inserted = 0;
  for (const source of ["user", "admin"] as const) {
    const key = `keycloak.${source}`;
    const started = new Date();
    const stored = await db().query("SELECT cursor_at FROM connector_state WHERE source=$1", [key]);
    const since = new Date(stored.rows[0] ? new Date(stored.rows[0].cursor_at).getTime() - 600000 : started.getTime() - 86400000);
    try {
      const raw = await identityReader.events(source, since);
      const events = raw.map(e => normalizeEvent(e, source, config().KEYCLOAK_REALM)).filter(e => e.occurredAt >= since);
      const connection = await db().connect();
      try {
        await connection.query("BEGIN");
        for (const e of events) {
          const result = await connection.query(`INSERT INTO identity_events
            (id,source,realm,event_type,occurred_at,actor_id,session_id,client_id,ip_address,resource,outcome,details)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING`,
            [e.id,e.source,e.realm,e.type,e.occurredAt,e.actorId,e.sessionId,e.clientId,e.ipAddress,e.resource,e.outcome,JSON.stringify(e.details)]);
          inserted += result.rowCount ?? 0;
        }
        await connection.query(`INSERT INTO connector_state (source,cursor_at,last_success_at,status)
          VALUES ($1,$2,now(),'healthy') ON CONFLICT (source) DO UPDATE SET
          cursor_at=GREATEST(connector_state.cursor_at,EXCLUDED.cursor_at),last_success_at=now(),status='healthy',last_error=NULL`, [key, started]);
        await connection.query("COMMIT");
      } catch (error) { await connection.query("ROLLBACK"); throw error; }
      finally { connection.release(); }
    } catch (error) {
      await db().query(`INSERT INTO connector_state (source,cursor_at,status,last_error) VALUES ($1,$2,'error',$3)
        ON CONFLICT (source) DO UPDATE SET status='error',last_error=EXCLUDED.last_error`,
        [key, since, "Collection failed. Check provider availability, read permissions and worker logs."]);
      throw error;
    }
  }
  return inserted;
}
