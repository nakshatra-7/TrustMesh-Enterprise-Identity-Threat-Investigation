import "dotenv/config";
import { readFile, readdir } from "node:fs/promises";
import { db } from "../src/lib/db";
const pool = db();
const connection = await pool.connect();
try {
  await connection.query("BEGIN");
  await connection.query("SELECT pg_advisory_xact_lock(7829341)");
  await connection.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  for (const name of (await readdir(new URL('../infra/migrations/', import.meta.url))).filter(n => /^\d+_.*\.sql$/.test(n)).sort()) {
    const applied = await connection.query("SELECT name FROM schema_migrations WHERE name=$1", [name]);
    if (!applied.rowCount) {
      await connection.query(await readFile(new URL(`../infra/migrations/${name}`, import.meta.url), "utf8"));
      await connection.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
    }
  }
  await connection.query("COMMIT");
  console.log("Database migrations are current.");
} catch (error) {
  await connection.query("ROLLBACK");
  throw error;
} finally { connection.release(); await pool.end(); }
