import { useEffect, useRef, useState } from "react";
import type { FormEvent as SubmitEvent } from "react";
import { api } from "./api";
import { timestamp, timezones } from "./model";
import { Brand, Badge, Empty, Panel, ErrorNotice } from "./ui";
type Org = {
  id: string;
  name: string;
  timezone: string;
  created_at: string;
  admin_count: number;
  active_device_count: number;
  unused_key_count: number;
};
const zones = timezones();
export type KeyMetadata = {
  id: string;
  status: string;
  created_at: string;
  expires_at: string;
  device_id: string | null;
};
type IssuedKey = { id: string; secret: string; expires_at: string };
export function Owner({
  onLogout,
  busy,
}: {
  onLogout: () => void;
  busy: boolean;
}) {
  const [orgs, setOrgs] = useState<Org[]>([]),
    [selected, setSelected] = useState(""),
    [keys, setKeys] = useState<KeyMetadata[]>([]),
    [issued, setIssued] = useState<IssuedKey[]>([]),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [working, setWorking] = useState(false),
    [loading, setLoading] = useState(true),
    [query, setQuery] = useState("");
  // Keys issued during one-step creation survive the selection change that follows it.
  const freshKeys = useRef<{ org: string; keys: IssuedKey[] } | null>(null);
  async function refresh(search = query, signal?: AbortSignal) {
    const result = await api<{ organizations: Org[] }>(
      `/owner/organizations${search.trim() ? "?q=" + encodeURIComponent(search.trim()) : ""}`,
      "GET",
      undefined,
      signal,
    );
    setOrgs(result.organizations);
  }
  useEffect(() => {
    const abort = new AbortController();
    const timer = window.setTimeout(() => {
      refresh(query, abort.signal)
        .catch((err) => {
          if (err.name !== "AbortError") setError(err.message);
        })
        .finally(() => setLoading(false));
    }, 250);
    return () => {
      clearTimeout(timer);
      abort.abort();
    };
  }, [query]);
  useEffect(() => {
    const fresh = freshKeys.current;
    freshKeys.current = null;
    setKeys([]);
    setIssued(fresh && fresh.org === selected ? fresh.keys : []);
    if (!selected) return;
    const abort = new AbortController();
    api<{ keys: KeyMetadata[] }>(
      `/owner/organizations/${selected}/keys`,
      "GET",
      undefined,
      abort.signal,
    )
      .then((result) => setKeys(result.keys))
      .catch((err) => {
        if (err.name !== "AbortError") setError(err.message);
      });
    return () => abort.abort();
  }, [selected]);
  async function action(fn: () => Promise<void>) {
    setWorking(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setWorking(false);
    }
  }
  function createOrg(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget,
      data = new FormData(form),
      email = String(data.get("admin_email") || "").trim(),
      password = String(data.get("admin_password") || ""),
      keyCount = Number(data.get("key_count") || 0);
    if (Boolean(email) !== Boolean(password)) {
      setError("Enter both the first administrator's email and initial password, or neither.");
      return;
    }
    void action(async () => {
      const result = await api<{ id: string; admin_id?: string; keys?: IssuedKey[] }>(
        "/owner/organizations",
        "POST",
        {
          name: data.get("name"),
          timezone: data.get("timezone"),
          ...(email ? { admin: { email, password } } : {}),
          key_count: keyCount,
        },
      );
      freshKeys.current = { org: result.id, keys: result.keys || [] };
      setQuery("");
      await refresh("");
      setSelected(result.id);
      form.reset();
      setNotice(
        result.admin_id
          ? "Organization and its first administrator created. Hand off credentials and any keys through your approved secure channel."
          : "Organization created. Provision its administrator next.",
      );
    });
  }
  function createAdmin(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget,
      data = new FormData(form);
    void action(async () => {
      await api(`/owner/organizations/${selected}/admins`, "POST", {
        email: data.get("email"),
        password: data.get("password"),
      });
      form.reset();
      await refresh();
      setNotice(
        "Organization administrator created. Hand off credentials through your approved secure channel.",
      );
    });
  }
  function issue(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void action(async () => {
      const result = await api<{ keys: IssuedKey[] }>(
        `/owner/organizations/${selected}/keys`,
        "POST",
        { count: Number(data.get("count")) },
      );
      setIssued(result.keys);
      const list = await api<{ keys: KeyMetadata[] }>(
        `/owner/organizations/${selected}/keys`,
      );
      setKeys(list.keys);
      await refresh();
    });
  }
  function revoke(id: string) {
    if (!window.confirm("Revoke this unused enrollment key?")) return;
    void action(async () => {
      await api(`/owner/keys/${id}/revoke`, "POST", {});
      setKeys(
        (
          await api<{ keys: KeyMetadata[] }>(
            `/owner/organizations/${selected}/keys`,
          )
        ).keys,
      );
    });
  }
  const organization = orgs.find((org) => org.id === selected);
  return (
    <div className="app-shell">
      <aside>
        <Brand />
        <div className="sidebar-label">PLATFORM</div>
        <nav aria-label="Platform navigation">
          <button className="active">
            ◇ <span>Organizations</span>
            <span className="nav-count">{orgs.length}</span>
          </button>
        </nav>
        <div className="sidebar-bottom">
          <Badge tone="pilot">M0 PILOT</Badge>
          <p>
            Provisioning access only.
            <br />
            Employee activity stays private.
          </p>
          <button className="signout" onClick={onLogout} disabled={busy}>
            Sign out
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header>
          <span>
            Platform / <strong>Organizations</strong>
          </span>
          <Badge>Product Owner</Badge>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">PLATFORM MANAGEMENT</div>
              <h1>Organizations</h1>
              <p>
                Create customer workspaces and allocate endpoint enrollment
                keys.
              </p>
            </div>
            <span className="environment">
              <i /> Local development
            </span>
          </div>
          <ErrorNotice message={error} />
          {notice && (
            <div className="notice success" role="status">
              {notice}
            </div>
          )}
          <div className="stats-grid">
            <div className="stat">
              <span>Customer workspaces</span>
              <strong>{orgs.length}</strong>
              <small>Up to 100 shown</small>
            </div>
            <div className="stat">
              <span>Selected workspace</span>
              <strong className="small-value">
                {organization?.name || "None selected"}
              </strong>
              <small>
                {organization?.timezone || "Choose an organization below"}
              </small>
            </div>
            <div className="stat accent">
              <span>Enrollment policy</span>
              <strong className="small-value">One key. One endpoint.</strong>
              <small>24-hour expiry · Secrets shown once</small>
            </div>
          </div>
          <div className="owner-grid">
            <Panel
              title="Customer workspaces"
              description="Select a workspace to manage its access."
            >
              <label>
                Search organizations
                <input
                  type="search"
                  value={query}
                  maxLength={120}
                  placeholder="Name contains…"
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>
              <label className="sr-only" htmlFor="organization-select">
                Selected organization
              </label>
              <select
                id="organization-select"
                disabled={working}
                value={selected}
                onChange={(event) => setSelected(event.target.value)}
              >
                <option value="">Select an organization</option>
                {orgs.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name}
                  </option>
                ))}
              </select>
              {loading ? (
                <p role="status">Loading workspaces…</p>
              ) : !orgs.length ? (
                query.trim() ? (
                  <Empty title="No matching workspaces">
                    No organization name contains “{query.trim()}”.
                  </Empty>
                ) : (
                  <Empty title="Your first workspace starts here">
                    Create an organization to begin provisioning.
                  </Empty>
                )
              ) : (
                <div className="org-list">
                  {orgs.map((org) => (
                    <button
                      key={org.id}
                      disabled={working}
                      className={`org-item ${selected === org.id ? "selected" : ""}`}
                      onClick={() => setSelected(org.id)}
                    >
                      <span className="org-avatar">
                        {org.name.slice(0, 2).toUpperCase()}
                      </span>
                      <span>
                        <strong>{org.name}</strong>
                        <small>
                          {org.timezone} · {org.admin_count} admin
                          {org.admin_count === 1 ? "" : "s"} ·{" "}
                          {org.active_device_count} active device
                          {org.active_device_count === 1 ? "" : "s"} ·{" "}
                          {org.unused_key_count} unused key
                          {org.unused_key_count === 1 ? "" : "s"}
                        </small>
                      </span>
                      {org.admin_count === 0 ? (
                        <Badge tone="pilot">No administrator</Badge>
                      ) : (
                        <span>→</span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </Panel>
            <Panel
              title="Create organization"
              description="A separate data boundary for each customer. Add the first administrator and keys now, or later."
            >
              <form onSubmit={createOrg}>
                <label>
                  Organization name
                  <input
                    name="name"
                    required
                    maxLength={120}
                    placeholder="Acme Technologies"
                  />
                </label>
                <label>
                  Reporting timezone
                  <select
                    name="timezone"
                    required
                    defaultValue={zones.includes("Asia/Kolkata") ? "Asia/Kolkata" : "UTC"}
                  >
                    {zones.map((zone) => (
                      <option key={zone} value={zone}>
                        {zone}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  First admin email (optional)
                  <input
                    name="admin_email"
                    type="email"
                    autoComplete="off"
                    maxLength={254}
                  />
                </label>
                <label>
                  First admin password
                  <input
                    name="admin_password"
                    type="password"
                    minLength={14}
                    maxLength={72}
                    autoComplete="new-password"
                  />
                </label>
                <label>
                  Enrollment keys to issue now
                  <input
                    name="key_count"
                    type="number"
                    min={0}
                    max={100}
                    defaultValue={0}
                  />
                </label>
                <p className="muted">
                  Creation is all-or-nothing: if the administrator or keys
                  cannot be created, no organization is created. The timezone
                  cannot be changed later.
                </p>
                <button className="primary" disabled={working}>
                  Create organization
                </button>
              </form>
            </Panel>
          </div>
          {organization && (
            <>
              <div className="section-divider">
                <h2>{organization.name}</h2>
                <Badge>Workspace provisioning</Badge>
              </div>
              <div className="two-columns">
                <Panel
                  title="Provision administrator"
                  description="Administrators can manage this organization's devices."
                >
                  <form onSubmit={createAdmin}>
                    <label>
                      Administrator email
                      <input
                        name="email"
                        type="email"
                        required
                        autoComplete="off"
                        maxLength={254}
                      />
                    </label>
                    <label>
                      Initial password
                      <input
                        name="password"
                        type="password"
                        required
                        minLength={14}
                        maxLength={72}
                        autoComplete="new-password"
                      />
                    </label>
                    <button disabled={working} className="secondary">
                      Create administrator
                    </button>
                  </form>
                </Panel>
                <Panel
                  title="Allocate enrollment keys"
                  description="Each key can enroll one simulated endpoint during M0."
                >
                  <form onSubmit={issue}>
                    <label>
                      Number of keys
                      <input
                        name="count"
                        type="number"
                        min={1}
                        max={100}
                        required
                        defaultValue={1}
                      />
                    </label>
                    <p className="muted">
                      Keys expire after 24 hours. Used keys cannot be reused.
                    </p>
                    <button className="primary" disabled={working}>
                      Generate keys
                    </button>
                  </form>
                </Panel>
              </div>
              {issued.length > 0 && (
                <section
                  className="secret-panel"
                  aria-label="Enrollment key secrets"
                >
                  <h2>Save these keys now</h2>
                  <p>
                    Secrets appear only in this response. Hand them off securely
                    before dismissing.
                  </p>
                  {issued.map((key) => (
                    <label key={key.id}>
                      Enrollment key · expires {timestamp(key.expires_at)}
                      <input
                        readOnly
                        value={key.secret}
                        onFocus={(event) => event.currentTarget.select()}
                      />
                    </label>
                  ))}
                  <button className="secondary" onClick={() => setIssued([])}>
                    I have saved the keys — dismiss
                  </button>
                </section>
              )}
              <Panel
                title="Enrollment key inventory"
                description="Metadata only. Issued secrets cannot be retrieved."
              >
                {keys.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Key ID</th>
                          <th>Status</th>
                          <th>Expires</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {keys.map((key) => (
                          <tr key={key.id}>
                            <td>
                              <code title={key.id}>{key.id.slice(0, 12)}…</code>
                            </td>
                            <td>
                              <Badge
                                tone={
                                  key.status === "unused" ? "green" : "neutral"
                                }
                              >
                                {key.status}
                              </Badge>
                            </td>
                            <td>{timestamp(key.expires_at)}</td>
                            <td>
                              {key.status === "unused" ? (
                                <button
                                  className="text-button danger"
                                  disabled={working}
                                  onClick={() => revoke(key.id)}
                                >
                                  Revoke
                                </button>
                              ) : (
                                "—"
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="No keys allocated">
                    Generate enrollment keys for this organization.
                  </Empty>
                )}
              </Panel>
            </>
          )}
        </main>
        <footer>
          CherrySecurity Console{" "}
          <span>M0 · Provisioning & simulated telemetry</span>
        </footer>
      </div>
    </div>
  );
}
