import { timestamp } from "./model";
import { Badge } from "./ui";

export type NativeHealth = {
  schema_version?: number;
  helper?: string;
  extension?: string;
  collection_state?: string;
  policy_version?: string;
  policy_age_seconds?: number;
  queue_events?: number;
  queue_bytes?: number;
  lost_events?: number;
  loss_epoch?: string;
  last_error?: string;
};

export function DeviceHealth({
  simulated,
  connectivity,
  health,
  receivedAt,
}: {
  simulated: boolean;
  connectivity: string;
  health: NativeHealth | null;
  receivedAt: string | null;
}) {
  if (simulated)
    return <p className="muted">Simulator data; no Windows agent is installed.</p>;
  if (health?.schema_version !== 2)
    return <p className="muted">No native collection health report yet.</p>;
  return (
    <div className="device-health">
      <p>
        <Badge tone={connectivity === "online" && health.collection_state === "collecting" ? "green" : "neutral"}>
          {health.collection_state?.replaceAll("_", " ") || "Unknown collection state"}
        </Badge>{" "}
        Last reported {timestamp(receivedAt)}
      </p>
      <dl className="details">
        <div><dt>Session helper</dt><dd>{health.helper || "Unknown"}</dd></div>
        <div><dt>Browser-domain coverage</dt><dd>Not installed in M1</dd></div>
        <div><dt>Pending events</dt><dd>{health.queue_events ?? 0}</dd></div>
        <div><dt>Queue storage</dt><dd>{health.queue_bytes ?? 0} bytes</dd></div>
        <div><dt>Lost events</dt><dd>{health.lost_events ?? 0}</dd></div>
        <div><dt>Loss counter epoch</dt><dd>{health.loss_epoch?.slice(0, 12) || "Unknown"}</dd></div>
        <div><dt>Policy age</dt><dd>{health.policy_version ? `${health.policy_age_seconds ?? 0} seconds (last reported)` : "Unavailable"}</dd></div>
      </dl>
      {health.last_error && health.last_error !== "none" && <p role="status">Agent error: {health.last_error.replaceAll("_", " ")}</p>}
      <p className="muted">The Windows agent reports application basenames and service metadata. It does not collect window titles, input contents, or browser domains.</p>
      <p className="muted">Connectivity and collection status are separate. Missing intervals count as gaps, not activity.</p>
    </div>
  );
}
