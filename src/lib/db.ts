import pg from "pg";
import { config } from "./config";
const globalDb = globalThis as unknown as { trustmeshPool?: pg.Pool };
export function db(): pg.Pool {
  globalDb.trustmeshPool ??= new pg.Pool({ connectionString: config().DATABASE_URL, max: 5, connectionTimeoutMillis: 5000 });
  return globalDb.trustmeshPool;
}
