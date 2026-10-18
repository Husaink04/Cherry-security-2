import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AuditLog } from "./audit";

describe("organization audit log", () => {
  it("renders recorded values as text, never markup", () => {
    const html = renderToStaticMarkup(
      <AuditLog
        events={[
          {
            id: "a".repeat(64),
            action: "login_failed",
            actor: "system",
            target: '<img src=x onerror="alert(1)">',
            target_id: "b".repeat(64),
            created_at: "2026-10-18T12:00:00Z",
          },
        ]}
        action=""
        hasMore
        loading={false}
        onFilter={() => {}}
        onMore={() => {}}
      />,
    );
    expect(html).toContain("Failed sign-in");
    expect(html).toContain("&lt;img");
    expect(html).not.toContain("<img");
    expect(html).toContain("Load older events");
  });

  it("explains an empty result without implying no activity was audited", () => {
    const html = renderToStaticMarkup(
      <AuditLog events={[]} action="device_revoked" hasMore={false} loading={false} onFilter={() => {}} onMore={() => {}} />,
    );
    expect(html).toContain("No matching events within the retention period");
    expect(html).not.toContain("Load older events");
  });
});
