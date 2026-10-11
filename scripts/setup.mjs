import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
const secret = () => randomBytes(32).toString("hex");
const dbPassword = secret();
const entries = {
  APP_URL: "http://localhost:3000", KEYCLOAK_URL: "http://localhost:8080",
  KEYCLOAK_REALM: "trustmesh", KEYCLOAK_CONSOLE_ID: "trustmesh-console",
  KEYCLOAK_READER_ID: "trustmesh-reader", KEYCLOAK_CONSOLE_SECRET: secret(),
  KEYCLOAK_READER_SECRET: secret(), KEYCLOAK_ADMIN_PASSWORD: secret(),
  ANALYST_PASSWORD: secret(), EMPLOYEE_PASSWORD: secret(), POSTGRES_PASSWORD: dbPassword,
  DATABASE_URL: `postgresql://trustmesh:${dbPassword}@localhost:55432/trustmesh`,
  REDIS_URL: "redis://localhost:56379", COOKIE_SECRET: secret()
};
try {
  writeFileSync(new URL("../.env", import.meta.url), Object.entries(entries).map(([k,v]) => `${k}=${v}`).join("\n") + "\n", { flag: "wx", mode: 0o600 });
  console.log("Created .env with random local credentials. Read credentials locally; never paste them into chat. Existing container realms are not overwritten by setup/import.");
} catch (error) {
  if (error.code !== "EEXIST") throw error;
  console.log(".env already exists; preserved all credentials.");
}
