export function isAnalyst(roles: unknown): boolean {
  return Array.isArray(roles) && roles.some(role => role === "soc-analyst");
}
export function allowsLocalHttp(url: URL): boolean {
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}
