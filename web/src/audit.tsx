import { timestamp } from "./model";
import { Empty, Panel } from "./ui";

export type AuditEvent = {
  id: string;
  action: string;
  actor: string;
  target: string;
  target_id: string;
  created_at: string;
};
export const auditActions: [string, string][] = [
  ["login", "Signed in"],
  ["login_failed", "Failed sign-in"],
  ["settings_updated", "Settings changed"],
  ["device_revoked", "Device revoked"],
  ["device_employee_assigned", "Employee assigned"],
  ["enrollment_key_issued", "Key issued"],
  ["enrollment_key_revoked", "Key revoked"],
  ["enrollment_key_redeemed", "Key redeemed"],
  ["administrator_created", "Administrator created"],
  ["organization_created", "Organization created"],
];
const label = (action: string) =>
  auditActions.find(([value]) => value === action)?.[1] || action;

export function AuditLog({
  events,
  action,
  hasMore,
  loading,
  onFilter,
  onMore,
}: {
  events: AuditEvent[];
  action: string;
  hasMore: boolean;
  loading: boolean;
  onFilter: (action: string) => void;
  onMore: () => void;
}) {
  return (
    <>
      <div className="filter-bar">
        <label>
          Action
          <select value={action} onChange={(event) => onFilter(event.target.value)}>
            <option value="">All actions</option>
            {auditActions.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
        </label>
        <span className="muted">Newest first · retained for 90 days</span>
      </div>
      <Panel
        title="Audit events"
        description="Security-relevant actions in this organization. Submitted passwords and key secrets are never recorded."
      >
        {events.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>{timestamp(event.created_at)}</td>
                    <td>
                      <strong>{label(event.action)}</strong>
                    </td>
                    <td>{event.actor}</td>
                    <td>
                      {event.target || (
                        <code title={event.target_id}>
                          {event.target_id ? `${event.target_id.slice(0, 12)}…` : "—"}
                        </code>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          !loading && (
            <Empty title="No audit events">
              No matching events within the retention period.
            </Empty>
          )
        )}
        {hasMore && (
          <button className="secondary compact" onClick={onMore} disabled={loading}>
            Load older events
          </button>
        )}
      </Panel>
    </>
  );
}
