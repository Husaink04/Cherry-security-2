import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "./api";
import { duration, reportDate, timestamp } from "./model";
import type { Role } from "./model";
import type { KeyMetadata } from "./owner";
import { Brand, Badge, Empty, Panel, ErrorNotice } from "./ui";

type Device = {
  id: string;
  hostname: string;
  employee_id: string;
  os: string;
  agent_version: string;
  simulated: boolean;
  last_contact: string | null;
  connectivity: string;
  helper_status: string;
  extension_status: string;
  revoked_at: string | null;
};
type Timeline = {
  event_id: string;
  kind: string;
  observed_at: string;
  payload: {
    app?: string;
    hostname?: string;
    service?: string;
    state?: string;
    start?: string;
    end?: string;
  };
};
type Service = {
  service: string;
  state: string;
  startup_type: string;
  observed_at: string;
};
type ReportItem = {
  device_id: string;
  hostname: string;
  simulated: boolean;
  kind: string;
  label: string;
  seconds: number;
};
type Report = {
  date: string;
  timezone: string;
  application_seconds: number;
  browser_seconds: number;
  idle_seconds: number;
  locked_seconds: number;
  gap_seconds: number;
  truncated: boolean;
  row_count: number;
  coverage: string;
  items: ReportItem[];
  updated_at: string;
};
type Settings = {
  name: string;
  timezone: string;
  idle_seconds: number;
  raw_retention_days: number;
  summary_retention_days: number;
  collection_schedule: {
    days: number[];
    start: string;
    end: string;
    unrestricted: boolean;
  };
};
const pages = [
  ["devices", "◈", "Devices"],
  ["reports", "▥", "Activity reports"],
  ["keys", "⌘", "Enrollment keys"],
  ["settings", "⚙", "Collection settings"],
];
export function Organization({
  role,
  onLogout,
  busy,
}: {
  role: Role;
  onLogout: () => void;
  busy: boolean;
}) {
  const [page, setPage] = useState("devices"),
    [devices, setDevices] = useState<Device[]>([]),
    [selected, setSelected] = useState(""),
    [detail, setDetail] = useState<{
      device: Device;
      timeline: Timeline[];
      sequence_gap_count: number;
    } | null>(null),
    [services, setServices] = useState<Service[]>([]),
    [report, setReport] = useState<Report | null>(null),
    [keys, setKeys] = useState<KeyMetadata[]>([]),
    [settings, setSettings] = useState<Settings | null>(null),
    [date, setDate] = useState(reportDate("UTC")),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [working, setWorking] = useState(false),
    [notice, setNotice] = useState(""),
    [updated, setUpdated] = useState<string | null>(null),
    [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    api<Settings>("/org/settings", "GET", undefined, controller.signal)
      .then((value) => {
        setSettings(value);
        setDate(reportDate(value.timezone));
      })
      .catch((err) => {
        if (err.name !== "AbortError") setError(err.message);
      });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setLoading(true);
    setError("");
    async function load() {
      try {
        if (page === "devices") {
          const result = await api<{ devices: Device[] }>(
            "/org/devices",
            "GET",
            undefined,
            controller.signal,
          );
          if (!live) return;
          setDevices(result.devices);
          if (selected) {
            const [deviceResult, serviceResult] = await Promise.all([
              api<{
                device: Device;
                timeline: Timeline[];
                sequence_gap_count: number;
              }>(
                `/org/devices/${selected}`,
                "GET",
                undefined,
                controller.signal,
              ),
              api<{ services: Service[] }>(
                `/org/devices/${selected}/services`,
                "GET",
                undefined,
                controller.signal,
              ),
            ]);
            if (!live) return;
            setDetail(deviceResult);
            setServices(serviceResult.services);
          }
        } else if (page === "reports") {
          const result = await api<Report>(
            `/org/reports/daily?date=${encodeURIComponent(date)}${selected ? "&device_id=" + encodeURIComponent(selected) : ""}`,
            "GET",
            undefined,
            controller.signal,
          );
          if (!live) return;
          setReport(result);
          const inventory = await api<{ devices: Device[] }>(
            "/org/devices",
            "GET",
            undefined,
            controller.signal,
          );
          if (live) setDevices(inventory.devices);
        } else if (page === "keys") {
          const result = await api<{ keys: KeyMetadata[] }>(
            "/org/keys",
            "GET",
            undefined,
            controller.signal,
          );
          if (live) setKeys(result.keys);
        }
        if (live) {
          setUpdated(new Date().toISOString());
          setError("");
        }
      } catch (err) {
        if (live && err instanceof Error && err.name !== "AbortError")
          setError(err.message);
      } finally {
        if (live) setLoading(false);
      }
    }
    void load();
    const timer =
      page === "devices" || page === "reports"
        ? window.setInterval(() => {
            if (document.visibilityState === "visible") void load();
          }, 30000)
        : undefined;
    return () => {
      live = false;
      controller.abort();
      if (timer) clearInterval(timer);
    };
  }, [page, selected, date, refresh]);
  function navigate(next: string) {
    setPage(next);
    setSelected("");
    setDetail(null);
    setNotice("");
  }
  async function revoke(device: Device) {
    if (
      !window.confirm(
        `Revoke ${device.hostname}? Future telemetry uploads will be rejected.`,
      )
    )
      return;
    setWorking(true);
    setError("");
    try {
      await api(`/org/devices/${device.id}/revoke`, "POST", {});
      setNotice("Device credentials revoked.");
      setRefresh((value) => value + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Revocation failed");
    } finally {
      setWorking(false);
    }
  }
  async function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!settings) return;
    setWorking(true);
    setNotice("");
    setError("");
    try {
      await api("/org/settings", "PUT", {
        idle_seconds: settings.idle_seconds,
        raw_retention_days: settings.raw_retention_days,
        summary_retention_days: settings.summary_retention_days,
        collection_schedule: settings.collection_schedule,
      });
      setNotice(
        "Collection settings saved. M0 uses fixtures; endpoint enforcement begins with the real agent.",
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Settings could not be saved",
      );
    } finally {
      setWorking(false);
    }
  }
  const title = pages.find((value) => value[0] === page)?.[2] || "Devices";
  const online = devices.filter(
    (value) => value.connectivity === "online",
  ).length;
  return (
    <div className="app-shell">
      <aside>
        <Brand />
        <div className="workspace-card">
          <div className="org-avatar">
            {settings?.name.slice(0, 2).toUpperCase() || "CS"}
          </div>
          <div>
            <strong>{settings?.name || "Organization"}</strong>
            <small>Organization workspace</small>
          </div>
        </div>
        <div className="sidebar-label">WORKSPACE</div>
        <nav aria-label="Organization navigation">
          {pages.map(([id, icon, label]) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              onClick={() => navigate(id)}
            >
              <span aria-hidden="true">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <Badge tone="pilot">M0 PILOT</Badge>
          <p>
            Simulated observations only.
            <br />
            Coverage is shown explicitly.
          </p>
          <button className="signout" onClick={onLogout} disabled={busy}>
            Sign out
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header>
          <span>
            Workspace / <strong>{title}</strong>
          </span>
          <Badge>{role === "org_admin" ? "Administrator" : "Viewer"}</Badge>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">YOUR WORKSPACE, IN FOCUS</div>
              <h1>{title}</h1>
              <p>
                {page === "devices"
                  ? "A clear picture of endpoint connectivity and collector health."
                  : page === "reports"
                    ? "Observed activity, with browser time shown as a separate breakdown."
                    : page === "keys"
                      ? "Enrollment keys allocated to your organization by the Product Owner."
                      : "Control collection boundaries and data retention."}
              </p>
            </div>
            <span className="environment">
              <i /> Local development
            </span>
          </div>
          <div className="notice pilot-banner">
            <Badge tone="pilot">SIMULATED</Badge>
            <span>
              This M0 workspace contains fixture telemetry. No employee
              monitoring agent is installed.
            </span>
          </div>
          <ErrorNotice message={error} />
          {notice && (
            <div className="notice success" role="status">
              {notice}
            </div>
          )}
          {loading && (
            <p className="muted" role="status">
              Updating workspace…
            </p>
          )}
          {page === "devices" && (
            <>
              <div className="stats-grid">
                <div className="stat">
                  <span>Registered endpoints</span>
                  <strong>{devices.length}</strong>
                  <small>Up to 100 most recent devices</small>
                </div>
                <div className="stat">
                  <span>Online now</span>
                  <strong>
                    {online}
                    <span className="stat-dot" />
                  </strong>
                  <small>Heartbeat within 3 minutes</small>
                </div>
                <div className="stat accent">
                  <span>Collection coverage</span>
                  <strong className="small-value">See each collector</strong>
                  <small>Connectivity and collection are separate</small>
                </div>
              </div>
              {!selected ? (
                <Panel
                  title="Endpoint inventory"
                  description="Select an endpoint to inspect its observations."
                  action={
                    <button
                      className="secondary compact"
                      onClick={() => setRefresh((value) => value + 1)}
                    >
                      ↻ Refresh
                    </button>
                  }
                >
                  {devices.length ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Endpoint</th>
                            <th>Connectivity</th>
                            <th>Helper / Extension</th>
                            <th>Last contact</th>
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {devices.map((device) => (
                            <tr key={device.id}>
                              <td>
                                <strong>{device.hostname}</strong>
                                <small className="cell-note">
                                  {device.os} ·{" "}
                                  <span className="simulated-label">
                                    SIMULATED
                                  </span>
                                </small>
                              </td>
                              <td>
                                <Badge
                                  tone={
                                    device.connectivity === "online"
                                      ? "green"
                                      : "neutral"
                                  }
                                >
                                  {device.connectivity.replaceAll("_", " ")}
                                </Badge>
                              </td>
                              <td>
                                {device.helper_status} /{" "}
                                {device.extension_status}
                              </td>
                              <td>{timestamp(device.last_contact)}</td>
                              <td>
                                <button
                                  className="text-button"
                                  onClick={() => {
                                    setDetail(null);
                                    setSelected(device.id);
                                  }}
                                >
                                  View →
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    !loading && (
                      <Empty title="No endpoints enrolled yet">
                        Ask your Product Owner for an enrollment key, then run
                        the M0 simulator in Kali.
                      </Empty>
                    )
                  )}
                </Panel>
              ) : (
                detail &&
                detail.device.id === selected && (
                  <>
                    <button
                      className="text-button back"
                      onClick={() => setSelected("")}
                    >
                      ← All endpoints
                    </button>
                    <Panel
                      title={detail.device.hostname}
                      description={`${detail.device.os} · Agent ${detail.device.agent_version}`}
                      action={<Badge tone="pilot">SIMULATED</Badge>}
                    >
                      <dl className="details">
                        <div>
                          <dt>Connectivity</dt>
                          <dd>{detail.device.connectivity}</dd>
                        </div>
                        <div>
                          <dt>Session helper</dt>
                          <dd>{detail.device.helper_status}</dd>
                        </div>
                        <div>
                          <dt>Browser extension</dt>
                          <dd>{detail.device.extension_status}</dd>
                        </div>
                        <div>
                          <dt>Last contact</dt>
                          <dd>{timestamp(detail.device.last_contact)}</dd>
                        </div>
                      </dl>
                      {detail.sequence_gap_count > 0 && (
                        <div className="notice pilot-banner" role="status">
                          Detected sequence gaps: {detail.sequence_gap_count}.
                          Observations may be missing.
                        </div>
                      )}
                      {role === "org_admin" && !detail.device.revoked_at && (
                        <button
                          className="secondary danger"
                          disabled={working}
                          onClick={() => revoke(detail.device)}
                        >
                          Revoke device credentials
                        </button>
                      )}
                    </Panel>
                    <Panel
                      title="Windows service observations"
                      description="Latest observed state per service; older arrivals do not replace newer states."
                    >
                      {services.length ? (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Service</th>
                                <th>State</th>
                                <th>Startup</th>
                                <th>Observed</th>
                              </tr>
                            </thead>
                            <tbody>
                              {services.map((service) => (
                                <tr key={service.service}>
                                  <td>{service.service}</td>
                                  <td>
                                    <Badge
                                      tone={
                                        service.state === "running"
                                          ? "green"
                                          : "neutral"
                                      }
                                    >
                                      {service.state}
                                    </Badge>
                                  </td>
                                  <td>{service.startup_type}</td>
                                  <td>{timestamp(service.observed_at)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <Empty title="No service observations">
                          Service state is unknown until reported.
                        </Empty>
                      )}
                    </Panel>
                    <Panel
                      title="Recent observation timeline"
                      description="Up to 100 observations. Missing periods are not assumed to be idle."
                    >
                      <div className="timeline">
                        {detail.timeline.map((event) => (
                          <div className="timeline-row" key={event.event_id}>
                            <span className="timeline-dot" />
                            <div>
                              <strong>
                                {event.payload.app ||
                                  event.payload.hostname ||
                                  event.payload.service ||
                                  event.kind}
                              </strong>
                              <small>
                                {event.kind}{" "}
                                {event.payload.state &&
                                  `· ${event.payload.state}`}
                              </small>
                            </div>
                            <time>{timestamp(event.observed_at)}</time>
                          </div>
                        ))}
                      </div>
                    </Panel>
                  </>
                )
              )}
            </>
          )}
          {page === "reports" && (
            <>
              <div className="filter-bar">
                <label>
                  Reporting date
                  <input
                    type="date"
                    value={date}
                    onChange={(event) => setDate(event.target.value)}
                    required
                  />
                </label>
                <label>
                  Endpoint
                  <select
                    value={selected}
                    onChange={(event) => setSelected(event.target.value)}
                  >
                    <option value="">All endpoints</option>
                    {devices.map((device) => (
                      <option key={device.id} value={device.id}>
                        {device.hostname}
                      </option>
                    ))}
                  </select>
                </label>
                <span className="muted">
                  Timezone: {settings?.timezone || "Loading"}
                </span>
              </div>
              {report && (
                <>
                  <div className="stats-grid">
                    <div className="stat">
                      <span>Foreground application time</span>
                      <strong>
                        {report.coverage === "no_data"
                          ? "Unknown"
                          : duration(report.application_seconds)}
                      </strong>
                      <small>Observed active intervals only</small>
                    </div>
                    <div className="stat">
                      <span>Browser breakdown</span>
                      <strong>
                        {report.coverage === "no_data"
                          ? "Unknown"
                          : duration(report.browser_seconds)}
                      </strong>
                      <small>Not added to application time</small>
                    </div>
                    <div className="stat accent">
                      <span>Observed idle time</span>
                      <strong>
                        {report.coverage === "no_data"
                          ? "Unknown"
                          : duration(report.idle_seconds)}
                      </strong>
                      <small>Gaps remain unknown</small>
                    </div>
                  </div>
                  <div className="two-columns">
                    {["application", "browser"].map((kind) => {
                      const items = report.items.filter(
                          (item) => item.kind === kind,
                        ),
                        max = Math.max(...items.map((item) => item.seconds), 1);
                      return (
                        <Panel
                          key={kind}
                          title={
                            kind === "application"
                              ? "Application usage"
                              : "Website domains"
                          }
                          description={
                            kind === "application"
                              ? "Foreground activity by application."
                              : "Hostname-only observations; no page content."
                          }
                        >
                          {items.length ? (
                            <div className="usage-list">
                              {items.map((item, index) => (
                                <div
                                  className="usage-row"
                                  key={`${item.device_id}-${item.label}`}
                                >
                                  <div className="usage-label">
                                    <strong>{item.label}</strong>
                                    <span>{duration(item.seconds)}</span>
                                  </div>
                                  <div className="usage-track">
                                    <div
                                      className={
                                        kind === "browser" ? "rose" : ""
                                      }
                                      style={{
                                        width: `${Math.max(2, Math.min(100, (item.seconds / max) * 100))}%`,
                                      }}
                                    />
                                  </div>
                                  <small>
                                    {item.hostname} · SIMULATED{" "}
                                    {index === 0 ? "· Most observed" : ""}
                                  </small>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <Empty title="No observations for this date">
                              Unknown coverage does not mean zero usage.
                            </Empty>
                          )}
                        </Panel>
                      );
                    })}
                  </div>
                  <p className="muted">
                    Coverage: {report.coverage.replaceAll("_", " ")} · Report
                    date {report.date} · {report.timezone} · Updated{" "}
                    {timestamp(report.updated_at)}
                  </p>
                  {report.truncated && (
                    <p className="muted">
                      Showing the first 1,000 of {report.row_count} breakdown
                      rows. Totals include all matching observations.
                    </p>
                  )}
                </>
              )}
            </>
          )}
          {page === "keys" && (
            <Panel
              title="Allocated enrollment keys"
              description="Only the Product Owner can issue keys. Request replacement if a secret was lost."
            >
              {keys.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Key ID</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Expires</th>
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
                          <td>{timestamp(key.created_at)}</td>
                          <td>{timestamp(key.expires_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty title="No keys allocated">
                  Contact your Product Owner to allocate endpoint keys.
                </Empty>
              )}
            </Panel>
          )}
          {page === "settings" && settings && (
            <Panel
              title="Collection boundaries"
              description={`Reporting timezone: ${settings.timezone}. Set when the organization is created.`}
            >
              <form onSubmit={saveSettings}>
                <fieldset disabled={role !== "org_admin" || working}>
                  <div className="two-columns">
                    <label>
                      Idle threshold (seconds)
                      <input
                        type="number"
                        min={60}
                        max={3600}
                        value={settings.idle_seconds}
                        onChange={(event) =>
                          setSettings({
                            ...settings,
                            idle_seconds: Number(event.target.value),
                          })
                        }
                      />
                    </label>
                    <label>
                      Raw observations retained (days)
                      <input
                        type="number"
                        min={1}
                        max={90}
                        value={settings.raw_retention_days}
                        onChange={(event) =>
                          setSettings({
                            ...settings,
                            raw_retention_days: Number(event.target.value),
                          })
                        }
                      />
                    </label>
                    <label>
                      Daily summaries retained (days)
                      <input
                        type="number"
                        min={settings.raw_retention_days}
                        max={365}
                        value={settings.summary_retention_days}
                        onChange={(event) =>
                          setSettings({
                            ...settings,
                            summary_retention_days: Number(event.target.value),
                          })
                        }
                      />
                    </label>
                  </div>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={settings.collection_schedule.unrestricted}
                      onChange={(event) =>
                        setSettings({
                          ...settings,
                          collection_schedule: {
                            ...settings.collection_schedule,
                            unrestricted: event.target.checked,
                          },
                        })
                      }
                    />
                    Explicitly allow an unrestricted collection schedule
                  </label>
                  {!settings.collection_schedule.unrestricted && (
                    <>
                      <div className="weekdays">
                        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map(
                          (day, index) => (
                            <label className="check" key={day}>
                              <input
                                type="checkbox"
                                checked={settings.collection_schedule.days.includes(
                                  index,
                                )}
                                onChange={(event) =>
                                  setSettings({
                                    ...settings,
                                    collection_schedule: {
                                      ...settings.collection_schedule,
                                      days: event.target.checked
                                        ? [
                                            ...settings.collection_schedule
                                              .days,
                                            index,
                                          ]
                                        : settings.collection_schedule.days.filter(
                                            (value) => value !== index,
                                          ),
                                    },
                                  })
                                }
                              />
                              {day}
                            </label>
                          ),
                        )}
                      </div>
                      <div className="two-columns">
                        <label>
                          Collection starts
                          <input
                            type="time"
                            value={settings.collection_schedule.start}
                            onChange={(event) =>
                              setSettings({
                                ...settings,
                                collection_schedule: {
                                  ...settings.collection_schedule,
                                  start: event.target.value,
                                },
                              })
                            }
                          />
                        </label>
                        <label>
                          Collection ends
                          <input
                            type="time"
                            value={settings.collection_schedule.end}
                            onChange={(event) =>
                              setSettings({
                                ...settings,
                                collection_schedule: {
                                  ...settings.collection_schedule,
                                  end: event.target.value,
                                },
                              })
                            }
                          />
                        </label>
                      </div>
                    </>
                  )}
                  {role === "org_admin" && (
                    <button className="primary" disabled={working}>
                      Save collection settings
                    </button>
                  )}
                </fieldset>
              </form>
              <p className="muted">
                M0 stores policy settings; fixtures do not represent schedule
                enforcement. Real endpoint enforcement is verified in M1. Audit
                records are retained for 90 days.
              </p>
            </Panel>
          )}
          <div className="update-line">
            {updated &&
              `Last refreshed ${timestamp(updated)} · Device/report views refresh every 30 seconds while visible.`}
          </div>
        </main>
        <footer>
          CherrySecurity Console{" "}
          <span>Observed activity · No productivity scoring</span>
        </footer>
      </div>
    </div>
  );
}
