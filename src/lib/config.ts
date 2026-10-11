import { z } from "zod";
const schema = z.object({
  APP_URL: z.url(), KEYCLOAK_URL: z.url(), KEYCLOAK_REALM: z.string().regex(/^[a-zA-Z0-9_-]+$/),
  KEYCLOAK_CONSOLE_ID: z.string().min(1), KEYCLOAK_CONSOLE_SECRET: z.string().min(16),
  KEYCLOAK_READER_ID: z.string().min(1), KEYCLOAK_READER_SECRET: z.string().min(16),
  DATABASE_URL: z.string().min(1), REDIS_URL: z.url(), COOKIE_SECRET: z.string().regex(/^[0-9a-f]{64}$/)
});
export function config() {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) throw new Error(`Missing/invalid configuration: ${parsed.error.issues.map(i => i.path.join(".")).join(", ")}. Run npm run setup.`);
  return parsed.data;
}
export function issuer() { const c = config(); return `${c.KEYCLOAK_URL}/realms/${c.KEYCLOAK_REALM}`; }
