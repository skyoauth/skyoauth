# ADR-001: Issuer and discovery

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.1 and T00.4 (inferred: tasks §2 names no ADR in
  either task; T00.1 freezes the public issuer/token/JWKS boundary and T00.4
  freezes the issuer). Implementation: T20.1, T20.2, T20.4, T51.10.
- **Baseline (tasks §11):** "One stable canonical HTTPS issuer independent of
  human providers".
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md)
  §2, [public-api.md](../contracts/public-api.md) §2,
  [token-profiles.md](../contracts/token-profiles.md) §4.

## Context

SkyOAuth is an identity bridge. It accepts upstream human and workload
identities and presents its own stable credentials to protected services
(design §1). The non-negotiable migration goal is that replacing the upstream
human IdP changes no client or protected service (design §1, §2 C04). That is
only possible if the issuer that protected services trust belongs to SkyOAuth,
not to the replaceable provider (design §1 "SkyOAuth owns its public
issuer/signing keys", §2 C01, C08). Design §5.5 states that Zitadel is "the
first human adapter, not the canonical API issuer".

Design §12 lists issuer and signer custody among the decisions that need ADR
ratification; tasks §11 records this baseline.

## Decision

1. **One canonical issuer.** SkyOAuth has one stable canonical HTTPS issuer,
   independent of every human provider (design §2 C01; tasks §11). Every
   credential carries exactly that `iss` (design §6).
2. **Distinct from upstream issuers.** The SkyOAuth issuer is distinct from
   upstream IdPs. Protected services need not trust GitHub, Kubernetes or
   Zitadel directly (design §2 C08). Upstream tokens are normalized to the
   SkyOAuth profile and never passed through as the default application
   credential (design §5.5).
3. **Issuer origin endpoints.** The issuer origin serves the public token and
   JWKS endpoints (public, TLS, rate limited) and the native authorization,
   upstream callback and confirmation endpoints. Browser auth routes are
   served on the registered application origin instead (design §3, §4 table).
4. **Discovery.** `GET /.well-known/oauth-authorization-server` returns stable
   metadata that advertises implemented grants and profiles only.
   `GET /.well-known/jwks.json` publishes the public access-token signer keys
   with rotation overlap, from M2 (tasks §2 "Endpoint matrix"; T20.1). The
   metadata carries explicit private token-profile information with no
   upstream-issued pretense and no implicit RFC 9068 claim (T20.1).
5. **Independence from provider changes.** A human-provider switch does not
   change the issuer, rotate signing keys or rotate issuer certificates
   (design §6 "Provider migration does not rotate keys"; T51.10). Issuer key
   rotation is an independent operation, never an implicit migration side
   effect (design §2 note under the table).
6. **Internal assertions use the same issuer value.** The separate internal
   assertion keys are published only at the private
   `/internal/v1/assertion-jwks`, never in the issuer JWKS (design §6.2). The
   key set, not `iss`, separates key purposes (lead decision recorded in
   token-profiles OQ-TP-2; see Consequences).

Signer custody, rotation and the internal signer group are ADR-002.

## Consequences and requirements

- Contract requirements that implement this decision: IR-001, IR-010, IR-011,
  IR-012, IR-013 (identity-registry §1–§2); TP-031 (exact `iss` for every
  profile, including internal assertions), TP-046 (`act.iss` equals the
  canonical issuer), TP-011 (the two key sets are non-interchangeable);
  API-001 (private listeners are never public routes); the public issuer
  endpoint table in public-api §2.
- IR-014: the audience a WIF proof is minted for at the external source (for
  example the issuer URL in the design §5.7 example) is distinct from the API
  audience in the issued token.
- Protected services configure one issuer and its JWKS; they need no per-IdP,
  per-cluster or per-CI trust (design §2 C08).
- The issuer and its metadata are part of the stable compatibility contract
  (design §2 C01, C02) and of the migration snapshot (design §8 step 1).
- Conformance rows that depend on this decision: A14 (same endpoints and
  configuration after a provider change), A19 (independent issuer-key
  rotation), A20 (WIF works while the human IdP is down), A55 (private types,
  no `at+jwt` or ID token).

## Alternatives considered

- **Using the upstream human IdP as the API issuer.** Rejected: Zitadel is the
  first human adapter, not the canonical API issuer (design §5.5), and C08
  requires the SkyOAuth issuer to be distinct from upstream IdPs.
- **Other issuers.** "Other gateways/issuers" are listed as conditional or
  later work, separately approved (design §11 roadmap).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-8** — metadata content: the fields and whether the private grant
  URI appears in `grant_types_supported` are not specified (open).
- **OQ-API-3** — no operator endpoint administers public issuer keys, although
  A19 requires independent issuer-key rotation. Decided (lead decision,
  2026-11-19) by [threat model](../threat-model.md) OQ-TM-10: an admin
  endpoint for public-key emergency disable and rotation is added, with a
  prepublished standby and a bounded JWKS cache max-age (ADR-002 item 4). The
  public-api contract now decides it: `/admin/v1/issuer-keys` (API-153), with
  a JWKS cache max-age of at most 300 s and immediate removal of a disabled
  key (API-042, API-043).
- **OQ-TP-2** — `iss` of internal assertions. Decided (lead decision,
  2026-11-19): the canonical issuer (TP-031).
- **OQ-TP-3** — the allowed JWS algorithm set is not fixed (open).

New questions raised by this ADR:

- **OQ-ADR001-1 — Changing the issuer URL.** Decided (lead decision,
  2026-11-19): the canonical issuer URL cannot change in v0.1; any issuer
  change procedure is deferred beyond v0.1. Original question: design §2 C01
  calls the issuer "stable", and T51.10 forbids issuer or certificate
  rotation only "solely for a human provider change". The sources did not say
  whether the canonical issuer URL itself may ever change (for example a
  domain change), or what procedure would apply.

## Tests

- A19 — issuer-key rotation through overlap without client or backend change.
- A14 and A15 — unchanged issuer, endpoints and configuration across a
  provider change and migration.
- A20 — valid WIF and operator recovery with the human IdP unavailable.
- A55 — only exact private type/profile/ingress pairs accepted.
- Task tests: T20.4 (verifier fixtures for issuer errors), T51.10 (no issuer or
  certificate rotation for a provider change), T52.1 (issuer/algorithm
  confusion corpus).
