import { test, expect } from "@playwright/test";
test("organization selection cannot change during a delayed key issuance", async ({
  page,
}) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    if (path === "/api/auth/me")
      return json({
        role: "product_owner",
        organization_id: "",
        csrf_token: "test-csrf",
      });
    if (path === "/api/owner/organizations")
      return json({
        organizations: [
          {
            id: "a",
            name: "Organization A",
            timezone: "UTC",
            created_at: "2026-10-16T00:00:00Z",
          },
          {
            id: "b",
            name: "Organization B",
            timezone: "UTC",
            created_at: "2026-10-16T00:00:00Z",
          },
        ],
      });
    if (
      path === "/api/owner/organizations/a/keys" &&
      route.request().method() === "POST"
    ) {
      await pending;
      return route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          keys: [
            {
              id: "key-a",
              secret: "test-secret-for-organization-a",
              expires_at: "2026-10-17T00:00:00Z",
            },
          ],
        }),
      });
    }
    if (path.endsWith("/keys")) return json({ keys: [] });
    return route.fulfill({
      status: 404,
      contentType: "application/json",
      body: '{"error":"not found"}',
    });
  });
  await page.goto("/");
  await page.getByLabel("Selected organization").selectOption("a");
  await page
    .getByRole("button", { name: "Generate keys", exact: true })
    .click();
  try {
    await expect(page.getByLabel("Selected organization")).toBeDisabled();
    await expect(
      page.getByRole("button", { name: /Organization B/ }),
    ).toBeDisabled();
  } finally {
    release();
  }
  await expect(
    page.getByRole("region", { name: "Enrollment key secrets" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Organization A", exact: true }),
  ).toBeVisible();
  await page.getByLabel("Selected organization").selectOption("b");
  await expect(
    page.getByRole("region", { name: "Enrollment key secrets" }),
  ).toHaveCount(0);
});

test("known missing event sequences are visible in endpoint coverage", async ({
  page,
}) => {
  const device = {
    id: "fixture-device",
    hostname: "SIMULATED-GAPS",
    os: "Windows fixture",
    agent_version: "m0",
    simulated: true,
    last_contact: null,
    connectivity: "never_seen",
    helper_status: "simulated",
    extension_status: "simulated",
    revoked_at: null,
    employee_id: "",
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let result: unknown = {};
    if (path === "/api/auth/me")
      result = {
        role: "org_admin",
        organization_id: "a",
        csrf_token: "test-csrf",
      };
    else if (path === "/api/org/settings")
      result = {
        name: "Coverage fixture",
        timezone: "UTC",
        idle_seconds: 300,
        raw_retention_days: 7,
        summary_retention_days: 30,
        collection_schedule: {
          days: [1],
          start: "09:00",
          end: "18:00",
          unrestricted: false,
        },
      };
    else if (path === "/api/org/devices") result = { devices: [device] };
    else if (path === "/api/org/devices/fixture-device")
      result = {
        device,
        timeline: [],
        sequence_gap_count: 2,
        coverage: "partial_observations",
      };
    else if (path.endsWith("/services")) result = { services: [] };
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(result),
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "View →", exact: true }).click();
  await expect(
    page.getByText("Detected sequence gaps: 2. Observations may be missing.", {
      exact: true,
    }),
  ).toBeVisible();
});
