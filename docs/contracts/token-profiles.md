# SkyOAuth credential profiles

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.3.
- **Derived from:** [design](../skyoauth-design.md) §1, §3, §3.1, §4, §4.1,
  §5.2, §5.2.2, §5.6, §5.7, §6, §6.1, §6.1.1, §6.2, §13 (RFC 8693, RFC 8725,
  RFC 9068); [tasks](../skyoauth-tasks.md) §0, §2 "Exchange selection and
  scope", §3 ("Policy revisions", "Key separation"), T20.1–T20.8, T32.2,
  T32.13, T40.13, §8 (A30, A44, A55, A61, A62), §11 (ADR-002, ADR-007,
  ADR-019).
- **Related contracts:** [identity-registry.md](identity-registry.md) (claim
  namespace, constraint schemas, scopes),
  [public-api.md](public-api.md) (where each profile is issued and accepted).

SkyOAuth issues a **private, versioned JWT profile**. It is not an RFC 9068
JWT access token and makes no RFC 9068 conformance claim. This document
freezes the protected types, the signed profile discriminator, the required
claim set of each profile and the rejection rules a verifier applies. Items
marked **Decided** under [Open questions](#open-questions) record lead
decisions that the normative text already reflects.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `TP-nnn`.

## 1. Profiles at a glance

| Signed `skyoauth_profile` | Protected `typ`         | Issued by                                          | Accepted on                                                                  | Signed with                                               | Source                       |
| ------------------------- | ----------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------- |
| `wif`                     | `skyoauth-access+jwt`   | `/oauth/token` WIF exchange (direct or delegation) | Bearer path                                                                  | Public access-token key (issuer JWKS)                     | design §6; tasks T20.3       |
| `human_cli`               | `skyoauth-access+jwt`   | `/oauth/token` native code exchange or refresh     | Bearer path                                                                  | Public access-token key (issuer JWKS)                     | design §6; tasks T40.13      |
| `human_session`           | `skyoauth-internal+jwt` | SkyOAuth gateway Check after a live session check  | Authenticated gateway-only header `X-SkyOAuth-Assertion` (decided, OQ-TP-11) | Internal signer-group key (`/internal/v1/assertion-jwks`) | design §6, §6.2; tasks T32.2 |

- **TP-001** `skyoauth-access+jwt` and `skyoauth-internal+jwt` are proposed
  private identifiers, not registered media types. They MUST be matched
  exactly. (design §6)
- **TP-002** SkyOAuth MUST NOT emit `typ=at+jwt` and MUST NOT accept `at+jwt`
  as a SkyOAuth profile. SkyOAuth MUST NOT advertise RFC 9068 compliance. RFC
  9068 requires `client_id`, which WIF does not invent from a source or actor.
  Future RFC 9068 support needs a separate complete conformance profile.
  (design §6; tasks T00.3, T20.8)
- **TP-003** Verifiers MUST reject OIDC ID tokens, including upstream ID tokens,
  as SkyOAuth credentials. (tasks T00.3, T20.8, A55)
- **TP-004** `skyoauth_profile_version` is `1` for every profile in this
  document. (design §6)

## 2. Protected header

| ID     | Parameter           | Rule                                                                                                                          | Source                         |
| ------ | ------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| TP-012 | `typ`               | Exactly `skyoauth-access+jwt` or `skyoauth-internal+jwt`; any other value or absence MUST be rejected                         | design §6                      |
| TP-013 | `alg`               | MUST be an allowed asymmetric algorithm for the selected trust set; `none` MUST be rejected (allowed set: OQ-TP-3)            | design §5.4, §6, §6.2          |
| TP-014 | `kid`               | MUST identify a key in the trust set already selected by profile and ingress. Public and internal kid namespaces are disjoint | design §6, §6.2                |
| TP-015 | `jku`, `x5u`, `jwk` | MUST NOT be used to locate or supply verification keys                                                                        | design §5.4, §6.2; tasks T11.5 |

- **TP-010** The verifier MUST select the trust set from the expected ingress
  and profile **before** looking up `kid`. Changing `typ` MUST NOT cross key
  purposes. (design §6.2)
- **TP-011** Access tokens MUST verify only against the public issuer JWKS.
  Internal assertions MUST verify only against the private internal assertion
  key set. The two sets are non-interchangeable. (design §3.1, §6.2)

## 3. Profile selection and ingress

The protected `typ`, the signed `skyoauth_profile` and the expected ingress
route jointly select the validation rules (design §6).

| `typ`                          | `skyoauth_profile`                                               | Ingress                                                                         | Result                         | Source                                                          |
| ------------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------ | --------------------------------------------------------------- |
| `skyoauth-access+jwt`          | `wif`                                                            | Bearer path, route allows `wif`                                                 | Validate as `wif`              | design §6                                                       |
| `skyoauth-access+jwt`          | `human_cli`                                                      | Bearer path, route allows `human_cli`                                           | Validate as `human_cli`        | design §6                                                       |
| `skyoauth-internal+jwt`        | `human_session`                                                  | Authenticated gateway-only `X-SkyOAuth-Assertion`, route allows `human_session` | Validate as `human_session`    | design §4, §6                                                   |
| `skyoauth-internal+jwt`        | any                                                              | Public bearer ingress                                                           | Reject                         | design §6 ("Public bearer ingress rejects internal assertions") |
| `skyoauth-access+jwt`          | `human_session`                                                  | Any                                                                             | Reject (type/profile mismatch) | design §6                                                       |
| `skyoauth-internal+jwt`        | `wif` or `human_cli`                                             | Any                                                                             | Reject (type/profile mismatch) | design §6                                                       |
| Any                            | Profile not allowed by the route or resource-server registration | Any                                                                             | Reject                         | design §4.1, §6                                                 |
| `at+jwt`, `JWT`, absent, other | Any                                                              | Any                                                                             | Reject                         | design §6; tasks A55                                            |

- **TP-020** A verifier MUST NOT infer a profile from a `usr_` prefix, a
  missing grant, the presence of `act` or an untrusted request header.
  (design §6)
- **TP-021** A verifier MUST reject unknown profile values, unknown
  `skyoauth_profile_version` values and contradictory claim sets. (design §6)
- **TP-022** Withdrawn as a duplicate. Mixed credentials (cookie plus bearer,
  or bearer plus internal assertion) follow
  [public-api.md API-062](public-api.md#4-private-gateway-endpoints), which is
  canonical.
- **TP-023** Bearer validation MUST NOT choose the expected audience from the
  token itself; the expected audience is pinned by gateway and backend
  configuration. (design §4.1)

## 4. Common claims

Every SkyOAuth credential carries these claims (design §6).

| Claim                      | Type                                  | Rule                                                                                           | Source                                 |
| -------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------- |
| `iss`                      | String                                | MUST equal the canonical SkyOAuth issuer exactly, for every profile (TP-031)                   | design §6; lead decision               |
| `sub`                      | String                                | Local principal ID per profile (§5). Never an upstream subject                                 | design §3.1, §6                        |
| `aud`                      | JSON string                           | Exactly one registered audience, as a string, equal to the verifier's own audience (TP-032)    | design §6, §5.7; lead decision         |
| `iat`                      | NumericDate                           | Required                                                                                       | design §6                              |
| `nbf`                      | NumericDate                           | Required                                                                                       | design §6                              |
| `exp`                      | NumericDate                           | Required; bounded TTL (§7) and bounded skew (OQ-TP-10)                                         | design §6                              |
| `jti`                      | String                                | Required; unique per issued credential, an issuer property (TP-033); not a verifier replay key | design §6; tasks T20.2                 |
| `scope`                    | Space-delimited string                | Required and explicit; canonical on issue, a set on verify (TP-034)                            | design §5.7, §6; lead decision         |
| `skyoauth_tenant`          | Tenant ID                             | Required; signed                                                                               | design §6                              |
| `skyoauth_profile`         | `wif`, `human_cli` or `human_session` | Required; signed                                                                               | design §6                              |
| `skyoauth_profile_version` | Integer `1`                           | Required; signed                                                                               | design §6                              |
| `skyoauth_policy_revision` | `PolicyRevision` ID                   | Required; the ID of the immutable policy decision snapshot (TP-035)                            | design §6; tasks §3 "Policy revisions" |
| `skyoauth_constraints`     | Object                                | Required; schema per profile in [identity-registry.md §8](identity-registry.md#8-constraints)  | design §6                              |

- **TP-030** A credential missing any common claim MUST be rejected. (design
  §6; tasks A30)
- **TP-031** `iss` MUST equal the one canonical SkyOAuth issuer exactly. This
  holds for `human_session` internal assertions too, even though they are
  signed with the separate internal key set; the trust set, not `iss`,
  separates key purposes (TP-010). (design §6; internal assertions: lead
  decision, OQ-TP-2)
- **TP-032** `aud` MUST be a single JSON string naming exactly one registered
  audience, equal to the verifier's own registered audience. An array,
  including a single-element array, MUST be rejected. (design §5.7, §6;
  encoding: lead decision, OQ-TP-4)
- **TP-033** The issuer MUST assign each issued credential a `jti` that is
  unique among the credentials it issues, including each new output of a
  reusable-proof exchange. Uniqueness is an issuer property, not a verifier
  check. (design §5.3, §6; tasks T20.2)
- **TP-034** Issuers MUST emit `scope` as the canonical scope string: unique
  scope tokens, bytewise ASCII-sorted, joined by single spaces
  ([identity-registry.md §6](identity-registry.md#6-scopes)). Verifiers MUST
  treat the value as a set of scope tokens; order carries no meaning. (lead
  decision, OQ-TP-8; canonical form from design §5.2.1)
- **TP-035** `skyoauth_policy_revision` MUST hold the ID of the immutable
  `PolicyRevision` record (for example `polrev_...`) for every profile. For
  human profiles that record references the `HumanAccessPolicy` and its
  revision among its dependencies; the claim does not carry the
  `HumanAccessPolicy` revision number. (design §6; tasks §3 "Policy
  revisions"; lead decision, OQ-TP-9)

## 5. Profile-specific claims

Legend: **R** required, **X** MUST NOT be present, **–** not part of the
profile and therefore rejected as an extra claim (TP-045).

| Claim                                | `wif` direct                            | `wif` delegation                                                       | `human_cli`                            | `human_session`                                                     | Source                 |
| ------------------------------------ | --------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------- | ---------------------- |
| `sub`                                | R: workload principal (grant actor)     | R: the grant's preapproved service principal                           | R: human principal                     | R: human principal                                                  | design §5.6, §6        |
| `act`                                | X (no target service)                   | R: object with `iss` = canonical issuer and `sub` = workload principal | X                                      | X                                                                   | design §5.6, §6        |
| `skyoauth_mode`                      | R: `direct`                             | R: `delegation`                                                        | X                                      | X                                                                   | design §6; tasks T20.3 |
| `skyoauth_grant`                     | R: grant ID                             | R: grant ID                                                            | X                                      | X                                                                   | design §6              |
| `client_id`                          | X (never invented from source or actor) | X                                                                      | R: actual registered OAuth `client_id` | X (no invented `client_id`)                                         | design §6; tasks T20.8 |
| `auth_time`                          | –                                       | –                                                                      | R                                      | R                                                                   | design §6              |
| `skyoauth_authentication`            | –                                       | –                                                                      | R: opaque authentication reference     | R: opaque authentication reference                                  | design §6              |
| `skyoauth_application_origin`        | –                                       | –                                                                      | –                                      | R: application-origin ID                                            | design §6              |
| `skyoauth_session`                   | –                                       | –                                                                      | –                                      | R: opaque internal session reference; never a cookie hash or ticket | design §6              |
| `skyoauth_route`                     | –                                       | –                                                                      | –                                      | R: `ApplicationRoute` ID (TP-047)                                   | design §4.1, §6        |
| `skyoauth_route_version`             | –                                       | –                                                                      | –                                      | R: pinned `ApplicationRouteVersion` ID (TP-047)                     | design §4.1, §6        |
| `skyoauth_request`                   | –                                       | –                                                                      | –                                      | R: request binding v1 (§6)                                          | design §4.1, §6        |
| `skyoauth_policy_revision` refers to | Binding-backed WIF `PolicyRevision`     | Binding-backed WIF `PolicyRevision`                                    | `PolicyRevision` (TP-035)              | `PolicyRevision` (TP-035)                                           | design §6              |
| `skyoauth_constraints.authorization` | `allowlist`                             | `allowlist`                                                            | `backend_rbac`                         | `backend_rbac`                                                      | design §6              |

- **TP-040** A `wif` credential MUST carry `skyoauth_mode`, `skyoauth_grant`, a
  binding-backed policy revision and `allowlist` constraints. A delegation
  credential MUST additionally carry `act` naming the workload. (design §6;
  tasks T20.3)
- **TP-041** A `human_cli` or `human_session` credential MUST NOT carry a WIF
  grant, mode or `act`. A `human_session` credential MUST NOT carry
  `client_id`. (design §6)
- **TP-042** A `wif` credential MUST NOT use `backend_rbac` and MUST NOT omit
  allowlists. A human credential MUST NOT masquerade as delegated WIF.
  (design §6; tasks A44)
- **TP-043** `act` MUST appear only in a `wif` delegation credential. Its
  presence MUST NOT itself select a profile (TP-020). (design §5.6, §6)
- **TP-044** A WIF exchange MUST NOT issue a refresh credential. WIF renewal
  uses a fresh or still-valid reusable proof according to the source's
  capability. (design §5.3, §5.7; tasks T20.5)
- **TP-045** Each profile has an exact top-level claim set: the common claims
  (§4) plus the claims marked R for that profile. A verifier MUST reject a
  credential that carries any other top-level claim, including a claim marked
  X or – for its profile and any unknown `skyoauth_*` claim. (lead decision,
  OQ-TP-6)
- **TP-046** In a delegation credential, `act.iss` MUST be present and MUST
  equal the canonical SkyOAuth issuer (the same value as `iss`). (design §6
  example; lead decision, OQ-TP-5)
- **TP-047** A `human_session` assertion MUST carry `skyoauth_route`, the
  stable `ApplicationRoute` ID, and the separate claim
  `skyoauth_route_version`, the ID of the `ApplicationRouteVersion` pinned by
  the active route bundle. (design §4.1 "skyoauth_route and its revision";
  claim shape: lead decision, OQ-TP-1)

## 6. Request binding (`human_session` only)

`skyoauth_request` is an object (design §4.1):

| Member          | Rule                                                                                                                              | Source      |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `version`       | `1`                                                                                                                               | design §4.1 |
| `method`        | Exact uppercase registered method                                                                                                 | design §4.1 |
| `scheme`        | `https`                                                                                                                           | design §4.1 |
| `authority`     | Registered lowercase ASCII/IDNA host, with a non-default port if present (443 omitted); no userinfo or trailing dot               | design §4.1 |
| `target_sha256` | Unpadded base64url of the full 32-byte SHA-256 of the exact ASCII origin-form target (path plus optional `?query`), 43 characters | design §4.1 |

- **TP-050** The tuple MUST describe the request after ingress validation and
  normalization and before ext_authz. The backend MUST recompute and compare
  method, scheme, authority and the raw-target digest before URL decoding.
  (design §4.1)
- **TP-051** The assertion MUST NOT contain the raw path or query. (design §4.1)
- **TP-052** Query order, duplicate parameters, percent-escape spelling, `+`
  versus `%20` and absent versus empty query MUST all be significant. (design
  §4.1)
- **TP-053** Fixture: target `/rpc/billing?item=1&item=2&q=a%20b` has
  `target_sha256=EqNKWsbu3kU-OFps9t2Cn28dZrhJcWZ1ApnVNevplu8`. A 4 KiB query
  MUST NOT enlarge the target claim. (design §4.1; tasks A61)
- **TP-054** Routes accepting `human_session` MUST NOT use path, host or query
  rewrites, post-auth routing-input mutation or route-cache rematching.
  Mismatch fails closed. (design §4.1)

## 7. Lifetimes

This table summarizes the credential maxima from design §5.2.2, §6 and §6.1.
The T00.6 lifetimes contract (`lifetimes.md`, PR #10) is authoritative for
lifetimes and their interactions.

| Credential                | Maximum lifetime                                                                     | Source                 |
| ------------------------- | ------------------------------------------------------------------------------------ | ---------------------- |
| `wif` access token        | 300 s; policy (grant `max_ttl`) may shorten                                          | design §5.7, §6.1      |
| `human_cli` access token  | 300 s; also bounded by the refresh family and authentication                         | design §5.2.2, §6.1    |
| `human_session` assertion | 30 s; never beyond session, authentication or applicable route-observation deadlines | design §6; tasks T32.2 |

- **TP-060** A verifier MUST reject a credential whose lifetime exceeds its
  profile maximum or whose time claims fall outside the bounded skew. (design
  §6)
- **TP-061** Retired public verification keys MUST be retained through the
  maximum issued TTL plus skew. Retired internal verification keys MUST be
  retained for the 30-second assertion lifetime plus skew. Compromised or
  disabled keys MUST be rejected. (design §6, §6.2)
- **TP-062** An expired `human_session` assertion MUST NOT be accepted as fresh
  evidence, including for stream admission. (design §6.1, §6.1.1)

## 8. Verifier obligations

Offline verification (backend or gateway):

- **TP-070** Verify signature, allowed algorithm and `kid` in the selected
  trust set; exact `iss` (TP-031); `aud` (TP-032); `iat`, `nbf`, `exp`; that
  `jti` is present as a string; explicit `scope`; the common signed claims;
  and the profile's exact claim set (TP-045). `jti` uniqueness is an issuer
  property (TP-033), not a verifier check: an access token is a bearer
  credential presented on every call within its lifetime, so a verifier MUST
  NOT reject a credential only because it has seen its `jti` before. The only
  per-`jti` one-use rules are continuation admission
  ([public-api.md API-080](public-api.md#5-private-policy-and-trust-endpoints))
  and the replay check on `single_use` external WIF proofs (design §5.3), which
  applies to the incoming proof's `jti`, not to a SkyOAuth credential. (design
  §5.3, §6, §6.1, §6.1.1)
- **TP-071** Reject a profile that the resource-server registration or the
  ingress route does not allow. (design §4.1, §6)
- **TP-072** Validate `skyoauth_constraints` against the profile's schema;
  unknown constraint fields or versions and the wrong authorization mode MUST
  deny. (design §6)
- **TP-073** After profile validation, the backend MUST resolve the resource's
  canonical SkyOAuth tenant, compare it with `skyoauth_tenant`, check scope and
  apply its own current RBAC. Backend RBAC is required for every profile; for
  `wif` the backend MUST additionally check every allowlist dimension, which
  is ANDed with tenant, audience, scope and RBAC. Credential validity alone
  MUST NOT authorize. (design §2 C09, §3.1, §6; see
  [identity-registry.md §9](identity-registry.md#9-backend-authorization-order))

Live verification (`/internal/v1/policy/check` and continuation rechecks):

- **TP-080** Live checks MUST verify the complete profile, audience and tenant
  assignment, current principal and the immutable decision dependencies in the
  policy revision. Superseded or invalidated revisions MUST deny; an old token
  MUST NOT be reinterpreted under broader policy. (design §6.1; tasks §3
  "Policy revisions")
- **TP-081** For `human_cli`, live checks MUST resolve the unique refresh family
  from the signed authentication reference, actual `client_id` and audience,
  and MUST deny if it is absent or revoked. (design §5.2.2)
- **TP-082** After verifying a signature, live checks, admission and rechecks
  MUST deny evidence whose signing key is still an unpromoted standby and MUST
  raise a rate-bounded compromise alert without token bytes. An invalid
  signature that merely names a standby kid MUST NOT raise that alert. Offline
  verification alone cannot enforce this. (design §6.2; tasks A62)

## 9. Conceptual payloads

These are the design's conceptual payloads (design §6). IDs are illustrative
generated values. No conceptual `human_session` payload is given in the
sources; its claims are those in §4–§6.

Delegated `wif`, protected `typ=skyoauth-access+jwt`:

```json
{
  "iss": "https://identity.example.com",
  "sub": "svc_43738ce105c748278cd73d1b30617fc8",
  "act": {
    "iss": "https://identity.example.com",
    "sub": "wld_206f380172eb482783d6dfbe9c0ae418"
  },
  "aud": "control-plane-api",
  "scope": "deployments.create workflows.read",
  "skyoauth_tenant": "ten_018f31a6d2094aa4b28c119be13b0472",
  "skyoauth_profile": "wif",
  "skyoauth_profile_version": 1,
  "skyoauth_mode": "delegation",
  "skyoauth_grant": "grant_d50e0a3bd52e4f26a3ad452017d64f09",
  "skyoauth_policy_revision": "polrev_8526ec2d468e4adc94c9343608ee873f",
  "skyoauth_constraints": {
    "version": 1,
    "authorization": "allowlist",
    "projects": ["platform-production"],
    "environments": ["production"]
  },
  "iat": 1794780000,
  "nbf": 1794780000,
  "exp": 1794780300,
  "jti": "jti_d8139a27124d4ea3a4835a4cd30a09de"
}
```

`human_cli`, protected `typ=skyoauth-access+jwt`:

```json
{
  "iss": "https://identity.example.com",
  "sub": "usr_f81b224cda9548b382541b16f823ac5e",
  "aud": "control-plane-api",
  "client_id": "client_6e94e21f46ba4eb1b8bd5bec24070f14",
  "scope": "workflows.read",
  "skyoauth_tenant": "ten_018f31a6d2094aa4b28c119be13b0472",
  "skyoauth_profile": "human_cli",
  "skyoauth_profile_version": 1,
  "skyoauth_authentication": "hauth_594948a2cc4b4ca19c5ca2d52bc7536d",
  "skyoauth_policy_revision": "polrev_97fc45cb6fe84d9d8df13c2981f9ca3e",
  "skyoauth_constraints": { "version": 1, "authorization": "backend_rbac" },
  "auth_time": 1794780000,
  "iat": 1794780000,
  "nbf": 1794780000,
  "exp": 1794780300,
  "jti": "jti_43ff5f1289c94db49dcb50d0e7a53375"
}
```

## Open questions

Items marked **Decided** record a lead decision; the normative text above
already reflects it, and the design and tasks documents still need the
follow-up. All other items are not resolved by this contract.

- **OQ-TP-1 — Route revision claim.** **Decided** (lead decision,
  2026-11-19): `skyoauth_route` carries the `ApplicationRoute` ID and a
  separate claim `skyoauth_route_version` carries the pinned
  `ApplicationRouteVersion` ID (TP-047). Follow-up: the design names only
  `skyoauth_route` and "its revision"; design §4.1, §6 and tasks T32.2 need the
  new claim name. Original question: whether the revision is a separate claim
  (and its name) or part of a structured `skyoauth_route` value.
- **OQ-TP-2 — `iss` of internal assertions.** **Decided** (lead decision,
  2026-11-19): internal assertions use the same canonical issuer as access
  tokens (TP-031). Original question: whether the `iss` of an assertion signed
  by the separate signer group is the canonical public issuer URL or another
  value.
- **OQ-TP-3 — Allowed algorithms.** Keys are asymmetric and verifiers check an
  "allowed algorithm", but the permitted JWS algorithm set for public and
  internal keys is not fixed.
- **OQ-TP-4 — `aud` encoding.** **Decided** (lead decision, 2026-11-19): a
  JSON string only; arrays, including single-element arrays, are rejected
  (TP-032). Original question: whether a single-element array is accepted.
- **OQ-TP-5 — `act.iss`.** **Decided** (lead decision, 2026-11-19): required
  and equal to the canonical issuer (TP-046). Original question: the
  delegation example includes `act.iss` but the profile table requires only
  the workload `act`.
- **OQ-TP-6 — Unexpected top-level claims.** **Decided** (lead decision,
  2026-11-19): each profile has an exact claim set and extra claims are
  rejected (TP-045). Original question: whether a verifier rejects or ignores
  unexpected claims such as `auth_time` in a `wif` token or an unknown
  `skyoauth_*` claim.
- **OQ-TP-7 — Version scope.** `skyoauth_profile_version=1` and the
  constraints `version: 1` are separate fields. Whether they version
  independently, and whether `skyoauth_request.version` ties to either, is not
  stated.
- **OQ-TP-8 — Scope claim ordering.** **Decided** (lead decision,
  2026-11-19): issuers emit the canonical sorted unique scope string;
  verifiers treat `scope` as a set (TP-034). Original question: whether the
  `scope` claim itself must be canonical.
- **OQ-TP-9 — Meaning of `skyoauth_policy_revision` for human profiles.**
  **Decided** (lead decision, 2026-11-19): the claim holds the
  `PolicyRevision` ID for every profile (TP-035). Follow-up: the design §6
  table's "HumanAccessPolicy revision" wording should say it is the
  `PolicyRevision` that snapshots the `HumanAccessPolicy`. Original question:
  whether the claim holds the `PolicyRevision` ID or the `HumanAccessPolicy`
  revision number.
- **OQ-TP-10 — Clock skew.** "Bounded TTL/skew" is required, but the maximum
  allowed clock skew is not given.
- **OQ-TP-11 — Assertion header.** **Decided** (lead decision, 2026-11-19):
  `X-SkyOAuth-Assertion` (same decision as OQ-API-10; see
  [public-api.md API-061](public-api.md#4-private-gateway-endpoints)).
