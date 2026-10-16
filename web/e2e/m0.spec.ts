import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
const fixture = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "../../artifacts/browser-fixture.json"),
    "utf8",
  ),
);

test("owner provisions a tenant, enrollment replays safely, and administrator inspects simulated reports", async ({
  page,
}) => {
  const unique = Date.now().toString();
  const name = `M0 Browser Workspace ${unique}`;
  const adminEmail = `admin-${unique}@cherrysecurity.test`;
  const browserErrors: string[] = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
  await page.getByLabel("Email address").fill(fixture.email);
  await page.getByLabel("Password", { exact: true }).fill(fixture.password);
  await page.getByRole("button", { name: "Sign in →" }).click();
  await expect(
    page.getByRole("heading", { name: "Organizations", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Activity reports", exact: true }),
  ).toHaveCount(0);
  await page.getByLabel("Organization name").fill(name);
  await page.getByLabel("Reporting timezone").fill("Asia/Kolkata");
  await page
    .getByRole("button", { name: "Create organization", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Provision administrator" }),
  ).toBeVisible();
  await page.getByLabel("Administrator email").fill(adminEmail);
  await page.getByLabel("Initial password").fill(fixture.admin_password);
  await page
    .getByRole("button", { name: "Create administrator", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("administrator created");
  await page
    .getByRole("button", { name: "Generate keys", exact: true })
    .click();
  const keyPanel = page.getByRole("region", { name: "Enrollment key secrets" });
  await expect(keyPanel).toBeVisible();
  const secret = await keyPanel.locator("input").inputValue();
  expect(secret.length).toBe(64);
  await keyPanel
    .getByRole("button", { name: "I have saved the keys — dismiss" })
    .click();
  await expect(keyPanel).toHaveCount(0);
  const enrollment = {
    enrollment_key: secret,
    hostname: "SIMULATED-BROWSER-ENDPOINT",
    os: "Windows simulated fixture",
    agent_version: "m0-browser-test",
    simulated: true,
  };
  const enrolledResponse = await page.request.post("/api/agent/enroll", {
    data: enrollment,
  });
  expect(enrolledResponse.status()).toBe(201);
  const enrolled = await enrolledResponse.json();
  const replayEnrollment = await page.request.post("/api/agent/enroll", {
    data: enrollment,
  });
  expect(replayEnrollment.status()).toBe(401);
  const now = Date.now(),
    start = now - 3600000;
  function event(
    id: string,
    kind: string,
    sequence: number,
    offset: number,
    seconds: number,
    payload: Record<string, unknown>,
  ) {
    return {
      event_id: `${unique}-${id}`,
      session_id: unique,
      sequence,
      observed_at: new Date(start + (offset + seconds) * 1000).toISOString(),
      kind,
      payload:
        kind === "service"
          ? payload
          : {
              ...payload,
              start: new Date(start + offset * 1000).toISOString(),
              end: new Date(start + (offset + seconds) * 1000).toISOString(),
            },
    };
  }
  const batch = {
    schema_version: 1,
    events: [
      event("app", "application", 1, 0, 600, { app: "chrome.exe" }),
      event("web", "browser", 2, 0, 300, { hostname: "docs.example.com" }),
      event("editor", "application", 3, 600, 300, { app: "Code.exe" }),
      event("service", "service", 4, 900, 0, {
        service: "Spooler",
        state: "running",
        startup_type: "automatic",
      }),
    ],
  };
  const headers = { Authorization: `Bearer ${enrolled.device_token}` };
  expect(
    (
      await page.request.post("/api/agent/heartbeat", {
        headers,
        data: { helper: "simulated", extension: "simulated" },
      })
    ).status(),
  ).toBe(200);
  expect(
    (
      await page.request.post("/api/agent/events", { headers, data: batch })
    ).status(),
  ).toBe(200);
  expect(
    (
      await page.request.post("/api/agent/events", { headers, data: batch })
    ).status(),
  ).toBe(200);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByLabel("Email address").fill(adminEmail);
  await page
    .getByLabel("Password", { exact: true })
    .fill(fixture.admin_password);
  await page.getByRole("button", { name: "Sign in →" }).click();
  await expect(
    page.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("SIMULATED-BROWSER-ENDPOINT", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Organizations", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "View →", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Windows service observations" }),
  ).toBeVisible();
  await expect(
    page.getByRole("cell", { name: "Spooler", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Activity reports", exact: false })
    .click();
  await expect(
    page.getByRole("heading", { name: "Activity reports", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("15m", { exact: true })).toBeVisible();
  await expect(page.getByText("5m", { exact: true }).first()).toBeVisible();
  await expect(
    page.getByText("docs.example.com", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("chrome.exe", { exact: true })).toBeVisible();
  await expect(page.getByText("Code.exe", { exact: true })).toBeVisible();
  await page.screenshot({
    path: resolve(
      import.meta.dirname,
      "../../artifacts/console-report-desktop.png",
    ),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: resolve(
      import.meta.dirname,
      "../../artifacts/console-report-mobile.png",
    ),
    fullPage: true,
  });
  const session = await (await page.request.get("/api/auth/me")).json();
  expect(
    (
      await page.request.post(`/api/org/devices/${enrolled.device_id}/revoke`, {
        headers: {
          Origin: "http://127.0.0.1:8082",
          "X-CSRF-Token": session.csrf_token,
        },
        data: {},
      })
    ).status(),
  ).toBe(200);
  expect(
    (
      await page.request.post("/api/agent/heartbeat", {
        headers,
        data: { helper: "simulated", extension: "simulated" },
      })
    ).status(),
  ).toBe(401);
  expect(browserErrors).toEqual([]);
  // Deliberately public assertion only: the test must not print fixture credentials or tokens.
});

test("anonymous access and invalid credentials stay on the sign-in screen", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Email address").fill("unknown@example.test");
  await page
    .getByLabel("Password", { exact: true })
    .fill("Incorrect-password-2026");
  await page.getByRole("button", { name: "Sign in →" }).click();
  await expect(page.getByRole("alert")).toContainText("invalid credentials");
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
  expect((await page.request.get("/api/org/devices")).status()).toBe(401);
});
