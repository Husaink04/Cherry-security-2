import { describe, it, expect } from "vitest";
import { duration, reportDate, allowedPages } from "./model";
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
    expect(allowedPages("product_owner")).toEqual(["organizations"]);
    expect(allowedPages("org_viewer")).not.toContain("organizations");
    expect(allowedPages("org_admin")).toContain("devices");
  });
});
