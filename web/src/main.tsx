import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, setCSRF } from "./api";
import type { Session } from "./model";
import { Brand, ErrorNotice } from "./ui";
import { Owner } from "./owner";
import { Organization } from "./organization";
import "./style.css";

function App() {
  const [session, setSession] = useState<Session | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    api<Session>("/auth/me")
      .then((result) => {
        if (live) {
          setSession(result);
          setCSRF(result.csrf_token);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (live) setLoading(false);
      });
    const expired = () => {
      setSession(null);
      setCSRF("");
    };
    window.addEventListener("cherry-session-expired", expired);
    return () => {
      live = false;
      window.removeEventListener("cherry-session-expired", expired);
    };
  }, []);
  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true);
    setError("");
    try {
      const result = await api<Session>("/auth/login", "POST", {
        email: data.get("email"),
        password: data.get("password"),
      });
      setCSRF(result.csrf_token);
      setSession(result);
      form.reset();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }
  async function logout() {
    setBusy(true);
    try {
      await api("/auth/logout", "POST", {});
      setCSRF("");
      setSession(null);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign out failed");
    } finally {
      setBusy(false);
    }
  }
  if (loading)
    return (
      <div className="loading" role="status">
        Connecting to CherrySecurity…
      </div>
    );
  if (!session)
    return (
      <main className="login-shell">
        <section className="login-story">
          <Brand />
          <div>
            <BadgeTitle />
            <h1>
              A clear view.
              <br />
              <em>A lighter footprint.</em>
            </h1>
            <p>
              Understand application activity and endpoint health across your
              organization.
            </p>
            <div className="story-line" />
            <small>EMPLOYEE ACTIVITY & ENDPOINT MONITORING</small>
          </div>
          <span className="pilot-note">
            M0 DEVELOPMENT PILOT · SIMULATED TELEMETRY
          </span>
        </section>
        <section className="login-form">
          <div className="eyebrow">CHERRYSECURITY CONSOLE</div>
          <h2>Welcome back</h2>
          <p>Sign in to your workspace.</p>
          <ErrorNotice message={error} />
          <form onSubmit={login}>
            <label>
              Email address
              <input
                name="email"
                type="email"
                autoComplete="username"
                required
                maxLength={254}
                placeholder="you@company.com"
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
                maxLength={72}
              />
            </label>
            <button className="primary" disabled={busy}>
              {busy ? "Signing in…" : "Sign in →"}
            </button>
          </form>
          <p className="form-note">
            Accounts are provisioned by your Product Owner.
            <br />
            There is no public signup.
          </p>
        </section>
      </main>
    );
  return (
    <>
      <ErrorNotice message={error} />
      {session.role === "product_owner" ? (
        <Owner onLogout={logout} busy={busy} />
      ) : (
        <Organization role={session.role} onLogout={logout} busy={busy} />
      )}
    </>
  );
}
function BadgeTitle() {
  return (
    <span className="story-badge">
      <span /> YOUR WORKSPACE, IN FOCUS
    </span>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
