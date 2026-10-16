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
export function allowedPages(role: Role): string[] {
  return role === "product_owner"
    ? ["organizations"]
    : ["devices", "reports", "keys", "settings"];
}
export function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not observed";
}
