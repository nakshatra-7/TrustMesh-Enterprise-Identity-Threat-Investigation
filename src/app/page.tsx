import { currentAnalyst } from "../lib/auth";
import { config } from "../lib/config";
import { db } from "../lib/db";
import { identityReader } from "../lib/keycloak";
import Refresh from "./refresh";
import LogoutButton from "./logout-button";
export const dynamic = "force-dynamic";
const time = (value: string | Date) => new Date(value).toLocaleString("en-GB", { timeZone: "UTC", hour12: false });
export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const params = await searchParams;
  let analyst: Awaited<ReturnType<typeof currentAnalyst>> = null;
  let unavailable = false;
  try { analyst = await currentAnalyst(); } catch { unavailable = true; }
  const errors: Record<string, string> = {
    "analyst-required": "This identity is authenticated, but does not have the SOC analyst role. Use a separate browser profile to sign in as the analyst.",
    "identity-unavailable": "Keycloak is unavailable. Start the local infrastructure and retry.",
    "login-failed": "Sign-in could not be completed. Retry with a fresh login."
  };
  if (!analyst) return <main className="welcome">
    <div className="brand"><span className="mark">T</span> TRUSTMESH <span className="badge">IDENTITY LAB</span></div>
    <div className="welcome-body"><p className="eyebrow">ENTERPRISE IDENTITY SECURITY</p><h1>Valid access.<br /><span className="accent">Visible behaviour.</span></h1>
    <p className="intro">A workspace for identity evidence, session activity and controlled investigation. Connected to a real Keycloak realm.</p>
    {(params.error || unavailable) && <p className="notice">{unavailable ? "An identity dependency is unavailable. Access remains closed until it recovers." : errors[params.error!] ?? "Unable to sign in."}</p>}
    <a className="button" href="/api/auth/login">Sign in as analyst <span>↗</span></a>
    <p className="muted">Employee accounts do not grant access to this console.</p></div>
    <footer>FOUNDATION / KEYCLOAK INTEGRATION <span>Containment requires analyst approval</span></footer>
  </main>;
  type Person = Awaited<ReturnType<typeof identityReader.users>>[number];
  type EventRow = { id: string; event_type: string; source: string; occurred_at: Date; actor_id?: string; client_id?: string; outcome: string; session_id?: string; ip_address?: string; resource?: string; details: Record<string,string> };
  let data: {
    people: Person[]; events: EventRow[];
    states: { source: string; status: string; last_success_at: Date }[];
    counts: { total: number; failures: number };
    sessions: { user: Person; sessions: Awaited<ReturnType<typeof identityReader.sessions>> }[];
  } | undefined;
  try {
    const [users, events, states, counts] = await Promise.all([
      identityReader.users(),
      db().query("SELECT * FROM identity_events ORDER BY occurred_at DESC LIMIT 100"),
      db().query("SELECT * FROM connector_state ORDER BY source"),
      db().query("SELECT count(*)::int AS total, count(*) FILTER (WHERE outcome='failure')::int AS failures FROM identity_events")
    ]);
    const people = users.filter(u => !u.username.startsWith("service-account-"));
    const sessions = (await Promise.all(people.map(async user => ({ user, sessions: await identityReader.sessions(user.id) }))));
    data = { people, events: events.rows, states: states.rows, counts: counts.rows[0], sessions };
  } catch { unavailable = true; }
  const c = config();
  return <main className="shell">
    <header><div className="brand"><span className="mark">T</span> TRUSTMESH</div><nav><span className="active">Identity overview</span><a href="/investigations">Investigations ↗</a><a href={`${c.KEYCLOAK_URL}/realms/${c.KEYCLOAK_REALM}/account/`} target="_blank" rel="noreferrer">Account console ↗</a></nav><div><span className="muted">{analyst.username}</span><LogoutButton /></div></header>
    <section className="heading"><div><p className="eyebrow">OPERATIONS / IDENTITY</p><h1>Know who has access.</h1><p className="muted">Real Keycloak activity. Read-only evidence. No automatic containment.</p></div><a className="button" href="/investigations">Open investigation workspace ↗</a></section>
    {unavailable || !data ? <div className="notice">Evidence is temporarily unavailable. This is a coverage gap, not evidence of safety. Check the database, provider and collector.</div> : <>
    <section className="metrics">
      <article><span>Employees & analysts</span><strong>{data.people.length}</strong><small>First 100 provider identities</small></article>
      <article><span>Active user sessions</span><strong>{data.sessions.reduce((n, u) => n + u.sessions.length, 0)}</strong><small>Live from Keycloak</small></article>
      <article><span>Collected events</span><strong>{data.counts.total}</strong><small>Persisted, deduplicated evidence</small></article>
      <article><span>Failed operations</span><strong>{data.counts.failures}</strong><small>Authentication and admin failures</small></article>
    </section>
    <section className="coverage"><span className="eyebrow">COLLECTOR COVERAGE</span>{data.states.length ? data.states.map(s => {
      const fresh = s.status === "healthy" && Date.now() - new Date(s.last_success_at).getTime() < 20000;
      return <span key={s.source} className={fresh ? "status good" : "status warn"}>{s.source} · {fresh ? "collecting" : "stale / unavailable"}</span>;
    }) : <span className="status warn">No collection recorded — start the worker</span>}<Refresh /></section>
    <section className="panel"><div className="panel-title"><h2>Session inventory</h2><span className="muted">Live provider state</span></div>
      <div className="table-wrap"><table><thead><tr><th>Identity</th><th>Session reference</th><th>Source IP</th><th>Applications</th></tr></thead><tbody>
        {data.sessions.flatMap(({ user, sessions }) => sessions.length ? sessions.map(s => <tr key={s.id}><td>{user.username}</td><td className="mono">{s.id}</td><td>{s.ipAddress ?? "Not reported"}</td><td>{Object.values(s.clients ?? {}).join(", ") || "Not reported"}</td></tr>) : [<tr key={user.id}><td>{user.username}</td><td colSpan={3} className="muted">No active session</td></tr>])}
      </tbody></table></div>
    </section>
    <section className="panel"><div className="panel-title"><h2>Identity evidence</h2><span className="muted">Latest 100 events · UTC</span></div>
      {!data.events.length ? <div className="empty">No evidence collected yet. Sign in as Alice through Keycloak’s Account Console, then start the identity worker.</div> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Client</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>
        {data.events.map(e => <tr key={e.id}><td className="mono">{time(e.occurred_at)}</td><td>{e.event_type}<small>{e.source}</small></td><td>{data.people.find(u => u.id === e.actor_id)?.username ?? e.actor_id ?? "Not reported"}</td><td>{e.client_id ?? "—"}</td><td><span className={`status ${e.outcome === "success" ? "good" : "warn"}`}>{e.outcome}</span></td><td><details><summary>Inspect</summary><dl><dt>ID</dt><dd>{e.id}</dd><dt>Session reference</dt><dd>{e.session_id ?? "Not reported"}</dd><dt>IP</dt><dd>{e.ip_address ?? "Not reported"}</dd><dt>Resource</dt><dd>{e.resource ?? "Not reported"}</dd><dt>Selected details</dt><dd><pre>{JSON.stringify(e.details, null, 2)}</pre></dd></dl></details></td></tr>)}
      </tbody></table></div>}
    </section></>}
    <footer>KEYCLOAK → EVIDENCE COLLECTOR → POSTGRESQL <span>Investigations and approval-controlled demo responses are available in the workspace.</span></footer>
  </main>;
}
