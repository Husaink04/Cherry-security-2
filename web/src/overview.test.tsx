import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Overview } from "./overview";
import type { Device, Report } from "./organization";

const device = (id: string, connectivity: string, helper_status = "healthy"): Device => ({
  id,
  hostname: id,
  employee_id: "",
  os: "Windows",
  agent_version: "m1",
  simulated: false,
  last_contact: null,
  connectivity,
  helper_status,
  extension_status: "missing",
  revoked_at: null,
  health: null,
  health_received_at: null,
});
const report = (coverage: string, items: Report["items"] = []): Report => ({
  date: "2026-10-18",
  timezone: "UTC",
  application_seconds: 900,
  browser_seconds: 300,
  idle_seconds: 120,
  locked_seconds: 0,
  gap_seconds: 0,
  truncated: false,
  row_count: items.length,
  coverage,
  items,
  updated_at: "2026-10-18T12:00:00Z",
});

describe("organization overview", () => {
  it("labels missing coverage as unknown instead of zero", () => {
    const html = renderToStaticMarkup(
      <Overview devices={[]} report={report("no_data")} timezone="UTC" onOpenDevice={() => {}} />,
    );
    expect(html).toContain("Unknown");
    expect(html).not.toContain("15m");
    expect(html).toContain("No observations today");
  });

  it("lists endpoints needing attention and combined top labels", () => {
    const html = renderToStaticMarkup(
      <Overview
        devices={[device("HEALTHY-PC", "online"), device("STALE-PC", "stale"), device("HELPER-PC", "online", "missing")]}
        report={report("partial_observations", [
          { device_id: "a", hostname: "HEALTHY-PC", simulated: false, kind: "application", label: "Code.exe", seconds: 600 },
          { device_id: "b", hostname: "STALE-PC", simulated: false, kind: "application", label: "Code.exe", seconds: 300 },
          { device_id: "a", hostname: "HEALTHY-PC", simulated: false, kind: "browser", label: "docs.example.com", seconds: 300 },
        ])}
        timezone="UTC"
        onOpenDevice={() => {}}
      />,
    );
    expect(html).toContain("STALE-PC");
    expect(html).toContain("helper missing");
    expect(html).not.toMatch(/<li>(?:(?!<\/li>).)*HEALTHY-PC/);
    expect(html).toContain("15m");
    expect(html).toContain("docs.example.com");
  });
});
