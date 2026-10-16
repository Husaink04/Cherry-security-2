import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 60000,
  outputDir: "../artifacts/browser-results",
  use: {
    baseURL: process.env.CHERRY_TEST_URL || "http://127.0.0.1:8082",
    channel: "msedge",
    headless: true,
    trace: "off",
    screenshot: "only-on-failure",
  },
  reporter: [
    ["list"],
    ["json", { outputFile: "../artifacts/browser-results.json" }],
  ],
});
