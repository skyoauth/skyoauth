import { describe, expect, it, vi } from "vitest";
import { SkyOAuthClient, SkyOAuthError } from "../src/index.js";

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), init);
}

describe("SkyOAuthClient", () => {
  it.each(["https://example.com/api/", "https://example.com/api"])(
    "fetches health from %s, keeping the path prefix",
    async (baseUrl) => {
      const fetch = vi.fn<typeof globalThis.fetch>(() =>
        Promise.resolve(jsonResponse({ status: "ok", version: "0.1.0" })),
      );
      const client = new SkyOAuthClient({ baseUrl, fetch });

      await expect(client.health()).resolves.toEqual({
        status: "ok",
        version: "0.1.0",
      });
      expect((fetch.mock.calls[0]?.[0] as URL).href).toBe(
        "https://example.com/api/healthz",
      );
    },
  );

  it("forwards the abort signal", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(jsonResponse({ status: "ok", version: "0.1.0" })),
    );
    const client = new SkyOAuthClient({
      baseUrl: "https://example.com",
      fetch,
    });
    const controller = new AbortController();

    await client.health(controller.signal);
    expect(fetch.mock.calls[0]?.[1]).toEqual({ signal: controller.signal });
  });

  it("throws SkyOAuthError on a non-2xx response", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response("boom", {
          status: 503,
          statusText: "Service Unavailable",
        }),
      ),
    );
    const client = new SkyOAuthClient({
      baseUrl: "https://example.com",
      fetch,
    });

    const error: unknown = await client.health().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SkyOAuthError);
    expect((error as SkyOAuthError).status).toBe(503);
  });

  it.each([
    ["resolves", () => Promise.resolve()],
    ["rejects", () => Promise.reject(new Error("cancel failed"))],
  ])(
    "cancels the error body before throwing when cancel %s",
    async (_name, cancel) => {
      const cancelSpy = vi.fn(cancel);
      const body = new ReadableStream<Uint8Array>({ cancel: cancelSpy });
      const fetch = vi.fn<typeof globalThis.fetch>(() =>
        Promise.resolve(new Response(body, { status: 503 })),
      );
      const client = new SkyOAuthClient({
        baseUrl: "https://example.com",
        fetch,
      });

      await expect(client.health()).rejects.toMatchObject({
        name: "SkyOAuthError",
        status: 503,
      });
      expect(cancelSpy).toHaveBeenCalledOnce();
    },
  );

  it("defaults to the global fetch", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ status: "ok", version: "0.1.0" }));
    await new SkyOAuthClient({ baseUrl: "https://example.com" }).health();
    expect(spy).toHaveBeenCalledOnce();
    spy.mockRestore();
  });
});
