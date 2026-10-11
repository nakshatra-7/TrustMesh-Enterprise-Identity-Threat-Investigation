import "dotenv/config";
import { identityReader } from "../src/lib/keycloak";
const users = await identityReader.users();
const alice = users.find(u => u.username === "alice");
if (!alice) throw new Error("Test employee Alice is missing.");
const analyst = users.find(u => u.username === "analyst");
if (!analyst) throw new Error("Test analyst is missing.");
const [employeeRoles, analystRoles, sessions, events] = await Promise.all([
  identityReader.roles(alice.id), identityReader.roles(analyst.id), identityReader.sessions(alice.id),
  identityReader.events("user", new Date(Date.now()-86400000))
]);
if (employeeRoles.some(r => r.name === "soc-analyst")) throw new Error("Employee must not have console access.");
if (!analystRoles.some(r => r.name === "soc-analyst")) throw new Error("Analyst role is missing.");
console.log(JSON.stringify({ readerConnected: true, employeeSeparatedFromAnalyst: true, userCount: users.length, employeeSessionCount: sessions.length, availableEvents: events.length }));
