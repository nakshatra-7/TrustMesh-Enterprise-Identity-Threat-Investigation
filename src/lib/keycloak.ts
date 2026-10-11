import { z } from "zod";
import { config, issuer } from "./config";

export const userSchema = z.object({ id: z.string(), username: z.string(), enabled: z.boolean().optional() });
export const sessionSchema = z.object({
  id: z.string(), userId: z.string().optional(), username: z.string().optional(),
  ipAddress: z.string().optional(), start: z.number().optional(), lastAccess: z.number().optional(),
  clients: z.record(z.string(), z.string()).optional()
});
export class KeycloakError extends Error {
  constructor(public status: number) { super(`Keycloak request failed (${status})`); }
}
export class KeycloakReader {
  private token?: { value: string; expires: number };
  constructor(private request: typeof fetch = fetch) {}
  private async accessToken(signal?: AbortSignal): Promise<string> {
    signal?.throwIfAborted();
    if (this.token && this.token.expires > Date.now() + 15000) return this.token.value;
    const c = config();
    const response = await this.request(`${issuer()}/protocol/openid-connect/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: c.KEYCLOAK_READER_ID, client_secret: c.KEYCLOAK_READER_SECRET }),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000), cache: "no-store"
    });
    if (!response.ok) throw new KeycloakError(response.status);
    const body = z.object({ access_token: z.string(), expires_in: z.number().positive() }).parse(await response.json());
    this.token = { value: body.access_token, expires: Date.now() + body.expires_in * 1000 };
    return this.token.value;
  }
  private async get(path: string, query: Record<string, string> = {}, retry = true, signal?: AbortSignal): Promise<unknown> {
    signal?.throwIfAborted();
    const c = config();
    const url = new URL(`${c.KEYCLOAK_URL}/admin/realms/${c.KEYCLOAK_REALM}/${path}`);
    url.search = new URLSearchParams(query).toString();
    const response = await this.request(url, {
      headers: { Authorization: `Bearer ${await this.accessToken(signal)}` },
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000), cache: "no-store"
    });
    if (response.status === 401 && retry) { this.token = undefined; return this.get(path, query, false, signal); }
    if (!response.ok) throw new KeycloakError(response.status);
    return response.json();
  }
  async users() { return z.array(userSchema).parse(await this.get("users", { first: "0", max: "100", briefRepresentation: "true" })); }
  async user(userId: string, signal?: AbortSignal) { return userSchema.parse(await this.get(`users/${encodeURIComponent(userId)}`, {}, true, signal)); }
  async sessions(userId: string, signal?: AbortSignal) { return z.array(sessionSchema).parse(await this.get(`users/${encodeURIComponent(userId)}/sessions`, {}, true, signal)); }
  async roles(userId: string, signal?: AbortSignal) { return z.array(z.object({ name: z.string() })).parse(await this.get(`users/${encodeURIComponent(userId)}/role-mappings/realm/composite`, {}, true, signal)); }
  async events(source: "user" | "admin", since: Date): Promise<unknown[]> {
    const result: unknown[] = [];
    // Keycloak date filtering varies with versions. Use UTC start-of-day and filter precisely locally.
    for (let first = 0; first < 10000; first += 100) {
      const page = z.array(z.unknown()).parse(await this.get(source === "user" ? "events" : "admin-events", {
        dateFrom: since.toISOString().slice(0, 10), first: String(first), max: "100"
      }));
      result.push(...page);
      if (page.length < 100) return result;
    }
    throw new Error("Keycloak event page limit reached; collection cursor has not advanced.");
  }
}
export const identityReader = new KeycloakReader();
