# ADR-005: Workload identity federation adapters

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.11 and T00.12 (inferred: tasks §2 names no ADR
  in either task; T00.11 covers nonunique issuer strings and same-issuer
  cluster fixtures, T00.12 source-capability replay). Implementation:
  T11.1–T11.11, T22, T23, T24.
- **Baseline (tasks §11):** "Three source kinds, fixed source selector/cluster
  config and keyset parent; reusable projected tokens".
- **Contracts:** [public-api.md](../contracts/public-api.md) §2.1,
  [identity-registry.md](../contracts/identity-registry.md) §2, §4, §10,
  [token-profiles.md](../contracts/token-profiles.md) §2,
  [lifetimes.md](../contracts/lifetimes.md) §8.

## Context

The central workload outcome is secretless GitHub Actions to protected cluster
API access, without cloud STS, SPIRE or sidecars (tasks §0; design §1.1
goal 3). GitHub Actions to the project's k3s APIs is mandatory (design §1).
Workloads present external proofs: GitHub Actions OIDC tokens, projected
Kubernetes service-account tokens and registered external JWTs (design §1).
External proof is untrusted until verified by the selected registered source;
an `iss`, `kid`, source ID or grant ID is not authority to choose a verifier
URL, tenant or subject (design §3.1 boundary 1).

Source configurations are part of the compatibility contract: they survive a
human-provider migration without reset (design §2 C05).

## Decision

1. **Three source kinds** (design §5.4; tasks §3 `TrustSource`, T11.1):
   - `oidc_discovery`: exact issuer, explicitly approved discovery and JWKS
     egress, algorithm and audience allowlists, bounded refresh, cache and
     staleness; SSRF-safe metadata and JWKS fetches (T11.2). GitHub Actions
     uses this kind (design §5.7 example; T22.1).
   - `uploaded_jwks`: exact issuer, audiences and algorithms, and a stable
     tenant-owned `TrustKeyset` parent with public-only versioned keysets and
     explicit overlap. Several versions may be active; conflicting live
     kid/key combinations deny; private key parameters are rejected (T11.3,
     T11.9).
   - `kubernetes_token_review`: a stable cluster ID, configured expected
     issuer metadata, a fixed HTTPS API endpoint, a versioned CA/fingerprint,
     a narrowly scoped reviewer-credential reference, requested audiences and
     a timeout. A fixed private-egress profile permits only the approved
     endpoint with TLS hostname/CA verification and no redirects. Reviewer
     secrets are externally managed, never plaintext exports (design §5.4;
     T11.8).
   - For all three kinds, secret references (`ca_bundle_ref`,
     `reviewer_credential_ref`) resolve only within a per-tenant provisioned
     secret namespace, and discovery, JWKS and TokenReview egress
     destinations come from an allowlist approved by instance
     `security_admin`; tenant operators only choose from it (OQ-TM-13; before
     M1a, T11.8).
   - Kubernetes local JWT validation (item 7) is not a fourth kind
     (OQ-ADR005-1).
2. **Fixed source selector.** The required generated `skyoauth_trust_source`
   ID selects exactly one registered verifier. It is not proof of a tenant or
   cluster. No verifier is chosen by token content (`iss`, `kid`, `jku`,
   `x5u`, embedded keys), no cluster is probed, and no alternate verifier is
   tried after a denial (design §3.1, §5.4; T11.5, T11.7, T21.3).
3. **Fixed cluster configuration.** Each cluster's TokenReview configuration
   (endpoint, CA, reviewer reference, audiences, timeout) is fixed at
   enrollment. Clients cannot supply an endpoint, CA or credentials. Several
   clusters may share an issuer, so the issuer is not a lookup key (design
   §5.4). How clusters are disambiguated is ADR-011.
4. **TokenReview evidence.** TokenReview sends explicit `spec.audiences` and
   requires authenticated success, no error and compatible nonempty returned
   audiences. SkyOAuth binds the returned service-account identity/UID and
   supported bound-Pod evidence to the selected cluster and source.
   TokenReview returns authenticated user and audience evidence, not a general
   claim set or a verified `jti`; policies that require evidence the adapter
   cannot attest are rejected, and parsed token fields can narrow checks but
   never supply missing positive evidence (design §5.4; T23.3).
5. **Keyset parent.** `TrustKeyset` is a stable tenant-owned parent;
   `TrustKeysetVersion` rows carry public-only keys with explicit validity.
   Rotation overlap preserves parent, source, binding and grant IDs (design
   §5.4; T11.9, T24.2). Public JWKS and CA references resolve to validated
   versioned contents at enrollment, never to client-selected fetches (design
   §5.7).
6. **Reusable projected tokens.** Workloads use rotated, audience-bound
   projected service-account tokens and reread the file on renewal. Projected
   tokens, including TokenReview sources, use `reusable` replay in v0.1; a
   renewal may present the same still-valid token before kubelet rotation
   (design §5.3, §5.4; T23.1, T23.5). The replay rules themselves are
   ADR-016.
7. **Kubernetes local JWT validation** is a separately enrolled mode with
   explicit stale-object-revocation limits, never a fallback from a failed
   TokenReview (design §5.4; T23.6). It is enrolled as an `uploaded_jwks` or
   `oidc_discovery` source with the `projected_service_account` assertion
   profile and an explicit stale-revocation acknowledgment (OQ-ADR005-1).
8. **Common rejections.** Unregistered sources, token `jku`/`x5u`/embedded-key
   trust, `alg=none`, weak algorithm substitution, private-key uploads and
   arbitrary redirects are rejected. Input sizes, claim complexity, clocks and
   key refresh are bounded (design §5.4; T11.4, T24.3).
9. **Lifecycle independence.** Disable and rotation are audited and preserve
   source, binding and grant IDs; reviewer rotation and source changes are
   independent of human-provider changes (design §2 note, §5.4; T11.6, T23.7).
10. **Client adapters.** The Rust workload provider obtains a fresh on-demand
    GitHub assertion or rereads the projected token, caches only the SkyOAuth
    token in memory and never logs or persists workload tokens; WIF receives
    no refresh credential (design §5.3, §10.3; T21.9, T22.3, T23.5).

## Consequences and requirements

- Contract requirements: API-011 (generated selectors only), API-012 (source
  and grant loaded as untrusted same-tenant candidates), API-013 (verify only
  at the selected source, no fallback), IR-014 (proof audience versus API
  audience), IR-032 (issuer strings are not unique), IR-033 (WIF tenant comes
  from the selected source and grant), TP-015 (`jku`, `x5u`, `jwk` never
  locate keys), TP-044 (no WIF refresh credential), and the registry
  allowlists for `TrustSource.audiences` and `algorithms` (identity-registry
  §10). Lifetimes §8 lists the discovery cache and TokenReview timeout as
  configured bounds without values.
- A canceled job can leave an issued bearer credential valid until its
  expiry; critical operations use live checks (design §5.3, §6.1).
- TokenReview revocation follows the cluster's documented time and
  object-revocation behavior, not an instantaneous promise (design §5.4).
- Conformance rows: A03, A04, A05, A06, A07, A15, A28, A29, A54.

## Alternatives considered

- **Cloud STS, SPIRE/SPIFFE, sidecars or node agents.** Not required and not a
  dependency (design §1.1 goal 3, §1.2; tasks §0).
- **Kubernetes local JWT validation as a fallback** after a failed
  TokenReview. Rejected; it is only a separately enrolled mode with stated
  stale-revocation limits (design §5.4; T23.6).
- **Token-directed key or verifier discovery** (`jku`, `x5u`, embedded keys,
  issuer lookup). Rejected (design §1.2, §5.4).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-6** — export field names differ from the logical model (`issuer`
  versus `exact_issuer`, `api_server` versus `token_review_endpoint`,
  `keyset_id` versus `jwks_keyset_id`, `public_jwks_ref` versus
  `public_jwks`, `allowed_algs` versus `algorithms`) (open).
- **OQ-LT-11** — `oidc_discovery` refresh and staleness bounds are not given
  (open).
- **OQ-TP-3** — allowed algorithm set (open; the sources fix it only for
  SkyOAuth's own keys as "allowed", and per source as an allowlist).
- **OQ-TM-13** ([threat model](../threat-model.md) §6) — external secret
  references and egress approval. Decided (lead decision, 2026-11-19):
  per-tenant secret namespaces and a `security_admin`-approved egress
  allowlist (item 1); the amendment lands before M1a (T11.8).

New questions raised by this ADR:

- **OQ-ADR005-1 — Source kind of Kubernetes local JWT validation.** Decided
  (lead decision, 2026-11-19): no fourth kind. Local validation uses an
  `uploaded_jwks` or `oidc_discovery` source with the
  `projected_service_account` assertion profile plus an explicit
  stale-revocation acknowledgment; fixed before the M1a schema. Original
  question: the baseline names three source kinds, and design §5.4 calls Kubernetes local
  JWT validation "a separately enrolled mode". Whether that mode is an
  `oidc_discovery` or `uploaded_jwks` source with a projected-service-account
  assertion profile, or a fourth kind, is not stated.
- **OQ-ADR005-2 — Assertion profile values.** Decided (lead decision,
  2026-11-19): `assertion_profile` takes `on_demand_jwt`, `reusable_jwt` or
  `projected_service_account`. `single_use` replay is allowed only with
  `on_demand_jwt` on an `oidc_discovery` or `uploaded_jwks` source. The
  binding `profile` field is a separate template name, not an assertion
  profile. Original question: `TrustSource.assertion_profile` is a model
  field (tasks §3). The design §5.7 export shows `on_demand_jwt`,
  `reusable_jwt` and `projected_service_account`, and design §5.3 speaks of
  "an on-demand assertion profile" and "any projected-service-account
  assertion profile". The normative value set, and how it relates to the
  binding `profile` field (`github_production` in the example), are not
  stated. ADR-016 depends on this set.

## Tests

- A03 — selected source proof issuer, key or audience mismatch denies with no
  alternate verifier or key source.
- A04 — keyset rotation keeps parent, source, binding and grant IDs.
- A05 — private-key upload or token-directed key URL rejected.
- A06, A07 — TokenReview positive and negative cases, no fallback.
- A15 — migration keeps discovery, uploaded-key and two shared-issuer
  TokenReview configurations.
- A28, A29 — shared issuers across clusters and tenants.
- A54 — projected-token reuse before and after rotation.
- Task tests: T11.10, T22.5, T23.4, T24.3, T52.1, T52.2.
