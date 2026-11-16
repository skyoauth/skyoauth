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
    this.#baseUrl = new URL(options.baseUrl);
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Calls `GET /healthz`. */
  async health(signal?: AbortSignal): Promise<Health> {
    const response = await this.#fetch(
      new URL("healthz", this.#baseUrl),
      signal ? { signal } : {},
    );
    if (!response.ok) {
      throw new SkyOAuthError(response.status, response.statusText);
    }
    return (await response.json()) as Health;
  }
}
