import { describe, it, expect } from "vitest";
import {
  can,
  connectivitySummary,
  duration,
  navigationFor,
  needsAttention,
  reportDate,
  timezones,
  topLabels,
} from "./model";
describe("organization timezone choices", () => {
  it("offers valid IANA zones with UTC first and no duplicates", () => {
    const zones = timezones();
    expect(zones[0]).toBe("UTC");
    expect(zones).toContain("Asia/Kolkata");
    expect(zones).not.toContain("Asia/Calcutta");
    expect(zones).toContain("Europe/Kyiv");
    expect(new Set(zones).size).toBe(zones.length);
    for (const zone of zones.slice(0, 25))
      expect(() => new Intl.DateTimeFormat("en-US", { timeZone: zone })).not.toThrow();
  });
});
describe("report presentation boundaries", () => {
  it("formats observed durations without adding browser and application time", () => {
    expect(duration(900)).toBe("15m");
    expect(duration(300)).toBe("5m");
    expect(duration(0)).toBe("0m");
    expect(duration(3660)).toBe("1h 1m");
    expect(duration(Number.NaN)).toBe("Unknown");
  });
  it("uses organization timezone near midnight", () => {
    expect(reportDate("Asia/Kolkata", new Date("2026-10-15T18:35:00Z"))).toBe(
      "2026-10-16",
    );
  });
  it("keeps owner navigation separate from employee reports", () => {
    expect(navigationFor("product_owner")).toEqual(["organizations"]);
    expect(navigationFor("org_viewer")).not.toContain("organizations");
    expect(navigationFor("org_admin")).toContain("devices");
  });
});
describe("organization role boundaries", () => {
  it("shows viewers only read-only pages", () => {
    expect(navigationFor("org_viewer")).toEqual(["overview", "devices", "reports"]);
    for (const page of ["keys", "settings", "audit"] as const)
      expect(navigationFor("org_viewer")).not.toContain(page);
    expect(navigationFor("org_admin")).toEqual([
      "overview",
      "devices",
      "reports",
      "keys",
      "settings",
      "audit",
    ]);
  });
  it("grants administrative actions to administrators only", () => {
    for (const action of [
      "revoke_device",
      "assign_employee",
      "edit_settings",
      "view_keys",
      "view_audit",
    ] as const) {
      expect(can("org_admin", action)).toBe(true);
      expect(can("org_viewer", action)).toBe(false);
      expect(can("product_owner", action)).toBe(false);
    }
  });
});
describe("overview summaries", () => {
  const device = (
    id: string,
    connectivity: string,
    helper_status = "healthy",
    simulated = false,
    revoked_at: string | null = null,
  ) => ({ id, hostname: id, connectivity, helper_status, simulated, revoked_at });
  it("counts connectivity states", () => {
    expect(
      connectivitySummary([
        device("a", "online"),
        device("b", "stale"),
        device("c", "offline"),
        device("d", "never_seen"),
        device("e", "revoked", "healthy", false, "2026-10-18T00:00:00Z"),
      ]),
    ).toEqual({ total: 5, online: 1, stale: 1, offline: 1, never_seen: 1, revoked: 1 });
  });
  it("flags connectivity and helper problems but not revoked or simulated helpers", () => {
    const flagged = needsAttention([
      device("healthy", "online"),
      device("simulated", "online", "simulated", true),
      device("helper", "online", "missing"),
      device("stale", "stale"),
      device("revoked", "revoked", "missing", false, "2026-10-18T00:00:00Z"),
    ]);
    expect(flagged.map((item) => item.id)).toEqual(["helper", "stale"]);
    expect(flagged[0].reasons).toEqual(["helper missing"]);
  });
  it("combines labels across devices and keeps kinds separate", () => {
    const items = [
      { kind: "application", label: "chrome.exe", seconds: 300 },
      { kind: "application", label: "Code.exe", seconds: 400 },
      { kind: "application", label: "chrome.exe", seconds: 200 },
      { kind: "browser", label: "docs.example.com", seconds: 900 },
    ];
    expect(topLabels(items, "application")).toEqual([
      { label: "chrome.exe", seconds: 500 },
      { label: "Code.exe", seconds: 400 },
    ]);
    expect(topLabels(items, "browser", 1)).toEqual([
      { label: "docs.example.com", seconds: 900 },
    ]);
  });
});
