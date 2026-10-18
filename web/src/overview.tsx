import { connectivitySummary, duration, needsAttention, topLabels } from "./model";
import type { Device, Report } from "./organization";
import { Badge, Empty, Panel } from "./ui";

export function Overview({
  devices,
  report,
  timezone,
  onOpenDevice,
}: {
  devices: Device[];
  report: Report | null;
  timezone: string;
  onOpenDevice: (id: string) => void;
}) {
  const counts = connectivitySummary(devices),
    attention = needsAttention(devices),
    known = report !== null && report.coverage !== "no_data",
    show = (seconds: number) => (known ? duration(seconds) : "Unknown");
  return (
    <>
      <div className="stats-grid">
        <div className="stat">
          <span>Registered endpoints</span>
          <strong>{counts.total}</strong>
          <small>
            {counts.revoked} revoked · {counts.never_seen} never seen
          </small>
        </div>
        <div className="stat">
          <span>Online now</span>
          <strong>
            {counts.online}
            <span className="stat-dot" />
          </strong>
          <small>
            {counts.stale} stale · {counts.offline} offline
          </small>
        </div>
        <div className="stat accent">
          <span>Needs attention</span>
          <strong>{attention.length}</strong>
          <small>Connectivity or collector problems</small>
        </div>
      </div>
      <div className="stats-grid">
        <div className="stat">
          <span>Foreground application time today</span>
          <strong>{show(report?.application_seconds ?? 0)}</strong>
          <small>Observed active intervals only</small>
        </div>
        <div className="stat">
          <span>Browser breakdown today</span>
          <strong>{show(report?.browser_seconds ?? 0)}</strong>
          <small>Not added to application time</small>
        </div>
        <div className="stat accent">
          <span>Observed idle time today</span>
          <strong>{show(report?.idle_seconds ?? 0)}</strong>
          <small>Gaps remain unknown</small>
        </div>
      </div>
      <Panel
        title="Endpoints needing attention"
        description="Offline, stale, never-seen, or helper problems. Revoked endpoints are excluded."
      >
        {attention.length ? (
          <ul className="attention-list">
            {attention.map((device) => (
              <li key={device.id}>
                <strong>{device.hostname}</strong>
                <span>
                  {device.reasons.map((reason) => (
                    <Badge key={reason}>{reason}</Badge>
                  ))}
                </span>
                <button
                  className="text-button"
                  onClick={() => onOpenDevice(device.id)}
                >
                  View →
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="No endpoint problems detected">
            Every active endpoint is online with a healthy or simulated helper.
          </Empty>
        )}
      </Panel>
      <div className="two-columns">
        {(["application", "browser"] as const).map((kind) => {
          const top = topLabels(report?.items ?? [], kind);
          return (
            <Panel
              key={kind}
              title={kind === "application" ? "Top applications today" : "Top domains today"}
              description={`Combined across endpoints · ${timezone}`}
            >
              {top.length ? (
                <div className="usage-list">
                  {top.map((item) => (
                    <div className="usage-label" key={item.label}>
                      <strong>{item.label}</strong>
                      <span>{duration(item.seconds)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty title="No observations today">
                  Unknown coverage does not mean zero usage.
                </Empty>
              )}
            </Panel>
          );
        })}
      </div>
      {report?.truncated && (
        <p className="muted">
          Top lists use the first 1,000 of {report.row_count} breakdown rows.
          Totals include all matching observations.
        </p>
      )}
    </>
  );
}
