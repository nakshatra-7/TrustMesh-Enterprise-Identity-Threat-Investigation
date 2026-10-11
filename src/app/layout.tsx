import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "TrustMesh · Identity Operations", description: "Enterprise identity evidence and investigation console" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
