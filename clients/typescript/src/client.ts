export interface Health {
  status: string;
  version: string;
}

export interface ClientOptions {
  /** Base URL of the skyoauth service, e.g. `https://auth.example.com`. */
  baseUrl: string | URL;
  /** Fetch implementation; defaults to the global `fetch`. */
  fetch?: typeof globalThis.fetch;
}

/** Thrown when the service answers with a non-2xx status. */
export class SkyOAuthError extends Error {
  readonly status: number;

  constructor(status: number, statusText: string) {
    super(`skyoauth request failed: ${String(status)} ${statusText}`);
    this.name = "SkyOAuthError";
    this.status = status;
  }
}

export class SkyOAuthClient {
  readonly #baseUrl: URL;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    const baseUrl = new URL(options.baseUrl);
    // A base path without a trailing slash would otherwise lose its last
    // segment when endpoint paths are resolved against it.
    if (!baseUrl.pathname.endsWith("/")) {
      baseUrl.pathname += "/";
    }
    this.#baseUrl = baseUrl;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Calls `GET /healthz`. */
  async health(signal?: AbortSignal): Promise<Health> {
    const response = await this.#fetch(
      new URL("healthz", this.#baseUrl),
      signal ? { signal } : {},
    );
    if (!response.ok) {
      // Release the connection; an unread body keeps it occupied.
      await response.body?.cancel().catch(() => undefined);
      throw new SkyOAuthError(response.status, response.statusText);
    }
    const health: Health = await response.json();
    return health;
  }
}
