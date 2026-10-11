import type { NextConfig } from "next";
const config: NextConfig = {
  poweredByHeader: false,
  // Authorization-code callback query strings must not enter development request logs.
  logging: { incomingRequests: { ignore: [/\/api\/auth\//] } },
  serverExternalPackages: ["pg"],
  async headers() {
    return [{ source: "/:path*", headers: [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Frame-Options", value: "DENY" }
    ] }];
  }
};
export default config;
