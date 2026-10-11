"use client";
import { useState } from "react";
export default function LogoutButton() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  async function signOut() {
    setBusy(true); setError(false);
    try {
      const response = await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
      if (!response.ok) throw new Error("Sign-out failed");
      // A full navigation discards previously rendered sensitive data and pending refreshes.
      window.location.replace("/");
    } catch { setError(true); setBusy(false); }
  }
  return <><button type="button" className="quiet" disabled={busy} onClick={signOut}>{busy ? "Signing out…" : "Sign out of console"}</button>{error && <span role="alert"> Sign-out failed. Please retry.</span>}</>;
}
