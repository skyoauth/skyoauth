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
claim set of each profile and the rejection rules a verifier applies.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `TP-nnn`.

## 1. Profiles at a glance

| Signed `skyoauth_profile` | Protected `typ`         | Issued by                                          | Accepted on                                            | Signed with                                               | Source                       |
| ------------------------- | ----------------------- | -------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------- | ---------------------------- |
| `wif`                     | `skyoauth-access+jwt`   | `/oauth/token` WIF exchange (direct or delegation) | Bearer path                                            | Public access-token key (issuer JWKS)                     | design §6; tasks T20.3       |
| `human_cli`               | `skyoauth-access+jwt`   | `/oauth/token` native code exchange or refresh     | Bearer path                                            | Public access-token key (issuer JWKS)                     | design §6; tasks T40.13      |
| `human_session`           | `skyoauth-internal+jwt` | SkyOAuth gateway Check after a live session check  | Authenticated gateway-only assertion header to backend | Internal signer-group key (`/internal/v1/assertion-jwks`) | design §6, §6.2; tasks T32.2 |

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

| Parameter           | Rule                                                                                                                          | Source                         |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `typ`               | Exactly `skyoauth-access+jwt` or `skyoauth-internal+jwt`; any other value or absence MUST be rejected                         | design §6                      |
| `alg`               | MUST be an allowed asymmetric algorithm for the selected trust set; `none` MUST be rejected (allowed set: OQ-TP-3)            | design §5.4, §6, §6.2          |
| `kid`               | MUST identify a key in the trust set already selected by profile and ingress. Public and internal kid namespaces are disjoint | design §6, §6.2                |
| `jku`, `x5u`, `jwk` | MUST NOT be used to locate or supply verification keys                                                                        | design §5.4, §6.2; tasks T11.5 |

- **TP-010** The verifier MUST select the trust set from the expected ingress
  and profile **before** looking up `kid`. Changing `typ` MUST NOT cross key
  purposes. (design §6.2)
- **TP-011** Access tokens MUST verify only against the public issuer JWKS.
  Internal assertions MUST verify only against the private internal assertion
  key set. The two sets are non-interchangeable. (design §3.1, §6.2)

## 3. Profile selection and ingress

The protected `typ`, the signed `skyoauth_profile` and the expected ingress
route jointly select the validation rules (design §6).

| `typ`                          | `skyoauth_profile`                                               | Ingress                                                                   | Result                         | Source                                                              |
| ------------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------- |
| `skyoauth-access+jwt`          | `wif`                                                            | Bearer path, route allows `wif`                                           | Validate as `wif`              | design §6                                                           |
| `skyoauth-access+jwt`          | `human_cli`                                                      | Bearer path, route allows `human_cli`                                     | Validate as `human_cli`        | design §6                                                           |
| `skyoauth-internal+jwt`        | `human_session`                                                  | Authenticated gateway-only assertion header, route allows `human_session` | Validate as `human_session`    | design §4, §6                                                       |
| `skyoauth-internal+jwt`        | any                                                              | Public bearer ingress                                                     | Reject                         | design §6.1.1 ("Public bearer ingress rejects internal assertions") |
| `skyoauth-access+jwt`          | `human_session`                                                  | Any                                                                       | Reject (type/profile mismatch) | design §6                                                           |
| `skyoauth-internal+jwt`        | `wif` or `human_cli`                                             | Any                                                                       | Reject (type/profile mismatch) | design §6                                                           |
| Any                            | Profile not allowed by the route or resource-server registration | Any                                                                       | Reject                         | design §4.1, §6                                                     |
| `at+jwt`, `JWT`, absent, other | Any                                                              | Any                                                                       | Reject                         | design §6; tasks A55                                                |

- **TP-020** A verifier MUST NOT infer a profile from a `usr_` prefix, a
  missing grant, the presence of `act` or an untrusted request header.
  (design §6)
- **TP-021** A verifier MUST reject unknown profile values, unknown
  `skyoauth_profile_version` values and contradictory claim sets. (design §6)
- **TP-022** A request that presents more than one credential (cookie plus
  bearer, or bearer plus internal assertion) MUST be rejected. (design §4, §6;
  tasks T31.4, A10)
- **TP-023** Bearer validation MUST NOT choose the expected audience from the
  token itself; the expected audience is pinned by gateway and backend
  configuration. (design §4.1)

## 4. Common claims

Every SkyOAuth credential carries these claims (design §6).

| Claim                      | Type                                  | Rule                                                                                                   | Source                                 |
| -------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------- |
| `iss`                      | String                                | MUST equal the canonical SkyOAuth issuer exactly (see OQ-TP-2 for internal assertions)                 | design §6                              |
| `sub`                      | String                                | Local principal ID per profile (§5). Never an upstream subject                                         | design §3.1, §6                        |
| `aud`                      | One registered audience               | MUST be exactly one registered audience, equal to the verifier's own registered audience (see OQ-TP-4) | design §6, §5.7                        |
| `iat`                      | NumericDate                           | Required                                                                                               | design §6                              |
| `nbf`                      | NumericDate                           | Required                                                                                               | design §6                              |
| `exp`                      | NumericDate                           | Required; bounded TTL (§7) and bounded skew (OQ-TP-10)                                                 | design §6                              |
| `jti`                      | String                                | Required; unique                                                                                       | design §6                              |
| `scope`                    | Space-delimited string                | Required and explicit; see [identity-registry.md §6](identity-registry.md#6-scopes)                    | design §5.7, §6                        |
| `skyoauth_tenant`          | Tenant ID                             | Required; signed                                                                                       | design §6                              |
| `skyoauth_profile`         | `wif`, `human_cli` or `human_session` | Required; signed                                                                                       | design §6                              |
| `skyoauth_profile_version` | Integer `1`                           | Required; signed                                                                                       | design §6                              |
| `skyoauth_policy_revision` | String                                | Required; references the immutable policy decision snapshot (§5)                                       | design §6; tasks §3 "Policy revisions" |
| `skyoauth_constraints`     | Object                                | Required; schema per profile in [identity-registry.md §8](identity-registry.md#8-constraints)          | design §6                              |

- **TP-030** A credential missing any common claim MUST be rejected. (design
  §6; tasks A30)

## 5. Profile-specific claims

Legend: **R** required, **X** MUST NOT be present, **–** not part of the
profile (see OQ-TP-6 for how a verifier treats an unexpected claim).

| Claim                                | `wif` direct                            | `wif` delegation                                                      | `human_cli`                            | `human_session`                                                     | Source                 |
| ------------------------------------ | --------------------------------------- | --------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------- | ---------------------- |
| `sub`                                | R: workload principal (grant actor)     | R: the grant's preapproved service principal                          | R: human principal                     | R: human principal                                                  | design §5.6, §6        |
| `act`                                | X (no target service)                   | R: object with `sub` = workload principal (see OQ-TP-5 for `act.iss`) | X                                      | X                                                                   | design §5.6, §6        |
| `skyoauth_mode`                      | R: `direct`                             | R: `delegation`                                                       | X                                      | X                                                                   | design §6; tasks T20.3 |
| `skyoauth_grant`                     | R: grant ID                             | R: grant ID                                                           | X                                      | X                                                                   | design §6              |
| `client_id`                          | X (never invented from source or actor) | X                                                                     | R: actual registered OAuth `client_id` | X (no invented `client_id`)                                         | design §6; tasks T20.8 |
| `auth_time`                          | –                                       | –                                                                     | R                                      | R                                                                   | design §6              |
| `skyoauth_authentication`            | –                                       | –                                                                     | R: opaque authentication reference     | R: opaque authentication reference                                  | design §6              |
| `skyoauth_application_origin`        | –                                       | –                                                                     | –                                      | R: application-origin ID                                            | design §6              |
| `skyoauth_session`                   | –                                       | –                                                                     | –                                      | R: opaque internal session reference; never a cookie hash or ticket | design §6              |
| `skyoauth_route` and route revision  | –                                       | –                                                                     | –                                      | R (claim shape: OQ-TP-1)                                            | design §4.1, §6        |
| `skyoauth_request`                   | –                                       | –                                                                     | –                                      | R: request binding v1 (§6)                                          | design §4.1, §6        |
| `skyoauth_policy_revision` refers to | Binding-backed WIF policy revision      | Binding-backed WIF policy revision                                    | `HumanAccessPolicy` revision (OQ-TP-9) | `HumanAccessPolicy` revision (OQ-TP-9)                              | design §6              |
| `skyoauth_constraints.authorization` | `allowlist`                             | `allowlist`                                                           | `backend_rbac`                         | `backend_rbac`                                                      | design §6              |

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
  trust set; exact `iss`; exactly one `aud` equal to the verifier's own
  registered audience; `iat`, `nbf`, `exp`; unique `jti`; explicit `scope`;
  the common signed claims; and the profile's required claims. (design §6)
- **TP-071** Reject a profile that the resource-server registration or the
  ingress route does not allow. (design §4.1, §6)
- **TP-072** Validate `skyoauth_constraints` against the profile's schema;
  unknown constraint fields or versions and the wrong authorization mode MUST
  deny. (design §6)
- **TP-073** After profile validation, the backend MUST resolve the resource's
  canonical SkyOAuth tenant, compare it with `skyoauth_tenant`, check scope and
  then apply allowlists (`wif`) or its own current RBAC (`backend_rbac`).
  Credential validity alone MUST NOT authorize. (design §2 C09, §6; see
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

- **OQ-TP-1 — Route revision claim.** Design §4.1 says the assertion "carries
  `skyoauth_route` and its revision" and §6 says "`skyoauth_route`/route
  revision". Whether the revision is a separate claim (and its name) or part of
  a structured `skyoauth_route` value is not specified.
- **OQ-TP-2 — `iss` of internal assertions.** All credentials require an exact
  issuer, but the internal assertion is signed by a separate signer group and
  verified against a private key set. Whether its `iss` is the canonical public
  issuer URL or another value is not stated.
- **OQ-TP-3 — Allowed algorithms.** Keys are asymmetric and verifiers check an
  "allowed algorithm", but the permitted JWS algorithm set for public and
  internal keys is not fixed.
- **OQ-TP-4 — `aud` encoding.** Credentials carry "one registered audience"
  and the examples use a JSON string. Whether a single-element array is
  accepted or rejected is not stated.
- **OQ-TP-5 — `act.iss`.** The delegation example includes `act.iss` equal to
  the SkyOAuth issuer; the profile table requires only the workload `act`.
  Whether `act.iss` is required, optional or fixed is not stated.
- **OQ-TP-6 — Unexpected top-level claims.** Contradictory claim sets must be
  rejected, but the treatment of other unexpected claims (for example
  `auth_time` or `skyoauth_authentication` in a `wif` token, or an unknown
  `skyoauth_*` claim) is not specified: reject or ignore.
- **OQ-TP-7 — Version scope.** `skyoauth_profile_version=1` and the
  constraints `version: 1` are separate fields. Whether they version
  independently, and whether `skyoauth_request.version` ties to either, is not
  stated.
- **OQ-TP-8 — Scope claim ordering.** Comparison v1 defines a canonical sorted
  scope string, and the examples are sorted, but whether the `scope` claim
  itself must be canonical (sorted, unique) is not stated.
- **OQ-TP-9 — Meaning of `skyoauth_policy_revision` for human profiles.** The
  design §6 table calls it the "HumanAccessPolicy revision", the example value
  is a `polrev_` ID and the tasks §3 model has a `PolicyRevision` record that
  references the `HumanAccessPolicy`. Whether the claim holds the
  `PolicyRevision` ID or the `HumanAccessPolicy` revision number is ambiguous.
- **OQ-TP-10 — Clock skew.** "Bounded TTL/skew" is required, but the maximum
  allowed clock skew is not given.
- **OQ-TP-11 — Assertion header.** The backend header carrying the
  `human_session` assertion is described as "private, overwritten" but not
  named (same as OQ-API-10).
