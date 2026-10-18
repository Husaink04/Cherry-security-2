import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DeviceHealth } from "./device-health";

describe("native device coverage", () => {
  it("does not claim collection from connectivity alone", () => {
    const html = renderToStaticMarkup(
      <DeviceHealth simulated={false} connectivity="online" health={null} receivedAt={null} />,
    );
    expect(html).toContain("No native collection health report yet");
    expect(html).not.toContain("collecting");
  });

  it("shows a reported gap and bounded loss without calling it activity", () => {
    const html = renderToStaticMarkup(
      <DeviceHealth
        simulated={false}
        connectivity="online"
        receivedAt="2026-10-17T10:00:00Z"
        health={{ schema_version: 2, helper: "missing", extension: "missing", collection_state: "helper_missing", policy_version: "policy-1", policy_age_seconds: 123, lost_events: 3, loss_epoch: "epoch-123456789", queue_events: 2, queue_bytes: 240, last_error: "helper" }}
      />,
    );
    expect(html).toContain("helper missing");
    expect(html).toContain("Lost events");
    expect(html).toContain("3");
    expect(html).toContain("Agent error: helper");
    expect(html).toContain("123 seconds");
    expect(html).toContain("epoch-123456");
    expect(html).toContain("gaps, not activity");
    expect(html).toContain("does not collect window titles");
  });
});
