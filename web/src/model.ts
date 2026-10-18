export type Role = "product_owner" | "org_admin" | "org_viewer";
export type Session = {
  role: Role;
  organization_id: string;
  csrf_token: string;
};
export function duration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "Unknown";
  const minutes = Math.floor(seconds / 60);
  return minutes >= 60
    ? `${Math.floor(minutes / 60)}h ${minutes % 60}m`
    : `${minutes}m`;
}
export function reportDate(timezone: string, now = new Date()): string {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(now);
  const part = (name: string) =>
    parts.find((value) => value.type === name)?.value;
  return `${part("year")}-${part("month")}-${part("day")}`;
}
export type Page =
  | "organizations"
  | "overview"
  | "devices"
  | "reports"
  | "keys"
  | "settings"
  | "audit";
export function navigationFor(role: Role): Page[] {
  if (role === "product_owner") return ["organizations"];
  const shared: Page[] = ["overview", "devices", "reports"];
  return role === "org_admin" ? [...shared, "keys", "settings", "audit"] : shared;
}
export type Action =
  | "revoke_device"
  | "assign_employee"
  | "edit_settings"
  | "view_keys"
  | "view_audit";
// The API enforces every permission; this only hides controls a role cannot use.
export function can(role: Role, action: Action): boolean {
  const adminActions: Action[] = [
    "revoke_device",
    "assign_employee",
    "edit_settings",
    "view_keys",
    "view_audit",
  ];
  return role === "org_admin" && adminActions.includes(action);
}
type DeviceState = {
  id: string;
  hostname: string;
  simulated: boolean;
  connectivity: string;
  helper_status: string;
  revoked_at: string | null;
};
export function connectivitySummary(devices: DeviceState[]) {
  const count = (state: string) =>
    devices.filter((device) => device.connectivity === state).length;
  return {
    total: devices.length,
    online: count("online"),
    stale: count("stale"),
    offline: count("offline"),
    never_seen: count("never_seen"),
    revoked: count("revoked"),
  };
}
export function needsAttention(devices: DeviceState[]) {
  return devices
    .filter((device) => !device.revoked_at)
    .map((device) => {
      const reasons: string[] = [];
      if (device.connectivity !== "online")
        reasons.push(device.connectivity.replaceAll("_", " "));
      if (!device.simulated && device.helper_status !== "healthy")
        reasons.push(`helper ${device.helper_status}`);
      return { id: device.id, hostname: device.hostname, reasons };
    })
    .filter((device) => device.reasons.length > 0);
}
export function topLabels(
  items: { kind: string; label: string; seconds: number }[],
  kind: string,
  limit = 5,
) {
  const totals = new Map<string, number>();
  for (const item of items)
    if (item.kind === kind)
      totals.set(item.label, (totals.get(item.label) || 0) + item.seconds);
  return [...totals]
    .map(([label, seconds]) => ({ label, seconds }))
    .sort((a, b) => b.seconds - a.seconds || a.label.localeCompare(b.label))
    .slice(0, limit);
}
const fallbackTimezones = ["UTC", "Asia/Kolkata", "Europe/London", "America/New_York"];
// Some engines still report pre-rename IANA links; offer the current names instead.
const renamedZones: Record<string, string> = {
  "Asia/Calcutta": "Asia/Kolkata",
  "Asia/Katmandu": "Asia/Kathmandu",
  "Asia/Saigon": "Asia/Ho_Chi_Minh",
  "Asia/Rangoon": "Asia/Yangon",
  "Europe/Kiev": "Europe/Kyiv",
  "America/Godthab": "America/Nuuk",
  "Atlantic/Faeroe": "Atlantic/Faroe",
  "Pacific/Ponape": "Pacific/Pohnpei",
  "Pacific/Truk": "Pacific/Chuuk",
  "Pacific/Enderbury": "Pacific/Kanton",
};
// The browser's IANA list keeps typos out; the API validates the chosen zone again.
export function timezones(): string[] {
  const supported =
    typeof Intl.supportedValuesOf === "function"
      ? Intl.supportedValuesOf("timeZone")
      : fallbackTimezones;
  const current = supported.map((zone) => renamedZones[zone] || zone);
  return [...new Set(["UTC", ...current])].sort((a, b) =>
    a === "UTC" ? -1 : b === "UTC" ? 1 : a.localeCompare(b),
  );
}
export function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not observed";
}
