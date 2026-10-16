import { afterEach, describe, expect, it, vi } from "vitest";
import { api, APIError, setCSRF } from "./api";
afterEach(() => {
  vi.unstubAllGlobals();
  setCSRF("");
});
describe("authenticated API transport", () => {
  it("uses same-origin cookies and explicit CSRF headers for writes", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ status: "saved" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetch);
    setCSRF("session-bound-csrf");
    await expect(
      api("/org/settings", "PUT", { idle_seconds: 300 }),
    ).resolves.toEqual({ status: "saved" });
    const options = fetch.mock.calls[0][1];
    expect(fetch.mock.calls[0][0]).toBe("/api/org/settings");
    expect(options.credentials).toBe("same-origin");
    expect(options.headers["X-CSRF-Token"]).toBe("session-bound-csrf");
  });
  it("rejects an HTML proxy failure without treating it as JSON data", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>bad gateway</html>", {
            status: 502,
            headers: { "Content-Type": "text/html" },
          }),
        ),
    );
    await expect(api("/org/devices")).rejects.toBeInstanceOf(APIError);
  });
  it("signals that expired sessions must leave authenticated screens", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ error: "session expired or revoked" }),
            { status: 401, headers: { "Content-Type": "application/json" } },
          ),
        ),
    );
    await expect(api("/auth/me")).rejects.toThrow("session expired or revoked");
    expect(dispatchEvent).toHaveBeenCalledOnce();
    expect(dispatchEvent.mock.calls[0][0].type).toBe("cherry-session-expired");
  });
});
