# SkyOAuth threat model

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Task covered:** T00.7 ([tasks](skyoauth-tasks.md) §2).
- **Derived from:** [design](skyoauth-design.md) §1.2, §2 (C04, C08, C09,
  C10), §3, §3.1, §4, §4.1, §4.2, §5.1, §5.1.1, §5.2, §5.2.1, §5.2.2, §5.3,
  §5.4, §5.6, §5.7, §6, §6.1, §6.1.1, §6.2, §7, §7.1, §7.2, §7.3, §7.4, §8,
  §9, §10.2, §10.3; [tasks](skyoauth-tasks.md) §0, §2 (T00.7, "Endpoint
  matrix", "Exchange selection and scope"), §3 ("Ownership", "One-time
  state", "Provider pointer/enrollment", "Stream state", "Key separation"),
  T10–T14, T20–T26, T30–T33, T40, T50–T52, §8 (conformance matrix), §11
  (ADR-002, ADR-007, ADR-008, ADR-011, ADR-013, ADR-014, ADR-016, ADR-020,
  ADR-021, ADR-023).
- **Related contracts (proposed on other branches, not yet on `main`):**
  public API (`API-`), errors and retry (`ERR-`), token profiles (`TP-`) and
  identity registry (`IR-`) on branch `claude/m0-public-contracts`; gateway
  containment (`GW-`) and lifetimes (`LT-`) on branch
  `claude/m0-gateway-containment`. They are cited by requirement ID only.

## Conventions

- Each threat has a stable ID `TM-nn`. Each open question has an ID
  `OQ-TM-n`. Neither adds behavior.
- **Mitigations** restate the design and tasks plan and cite the section and,
  where one exists, the contract requirement ID. This document invents no
  mitigation. Where the sources give none for a listed attack, the entry
  records a **Gap** and an open question.
- **Conformance references** are existing rows of the tasks §8 matrix. They
  are cited as references; this document defines no new test rows.
- **Residual risk** is what remains after the specified mitigations, including
  limits the design states itself (design §9).
- MUST, MUST NOT and similar words, where quoted, carry the meaning of the
  cited source.

## 1. Scope

This model covers exactly the threat list of T00.7:

| ID    | Threat                                |
| ----- | ------------------------------------- |
| TM-01 | Malicious CI                          |
| TM-02 | Issuer, cluster and key confusion     |
| TM-03 | Audience and tenant escalation        |
| TM-04 | Subject and resource-server confusion |
| TM-05 | Profile substitution                  |
| TM-06 | Replay                                |
| TM-07 | Login CSRF                            |
| TM-08 | OIDC callback abuse                   |
| TM-09 | Redirect URI confusion                |
| TM-10 | Identity-linking confusion            |
| TM-11 | Native-client impersonation           |
| TM-12 | Generic-provider-write bypass         |
| TM-13 | Cookie leakage to backends            |
| TM-14 | Shadow routes                         |
| TM-15 | Operator recovery                     |
| TM-16 | Runtime and database compromise       |

Design §9 also lists SSRF, XSS, header spoofing, session fixation,
credential resurrection and stale streams. They are not on the T00.7 list.
Where one of them is part of a listed threat (for example session fixation
under TM-07, header spoofing under TM-03 and TM-05, SSRF under TM-02) it is
covered there; otherwise it is out of scope here (OQ-TM-1).

Out of scope by design: device flow, active impersonation, upstream provider
exchange and vault, alternate gateway adapters and cloud STS (design §1.3,
§11). They appear only where the design requires them to stay disabled.

## 2. Assets

| Asset                                                                     | Held by                                                  | Source                    |
| ------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------- |
| Public access-token signing key                                           | Isolated public signer, optionally KMS/HSM               | Design §3.1, §6           |
| Internal assertion signer-group keys and eligible standby                 | Signer-group replicas; standby in separate custody       | Design §6.2               |
| Operator mTLS keys and offline recovery key                               | Operator workstation or hardware signer, never a pod     | Design §7.2               |
| TokenReview reviewer and upstream provider credentials                    | External secret references                               | Design §5.4, §7.3         |
| Trust, policy and authority records                                       | PostgreSQL                                               | Design §7                 |
| One-time state: consumed proofs, flows, codes, refresh families, sessions | PostgreSQL, as keyed hashes                              | Tasks §3 "One-time state" |
| Browser session, flow cookies and CSRF token                              | Browser (`__Host-` cookies), memory in the SPA library   | Design §4, §5.1, §10.2    |
| Access JWTs, refresh credentials, internal assertions                     | Clients, gateway channel, OS credential store            | Design §5.2.2, §6         |
| Continuation IDs                                                          | Checker backend and SkyOAuth only                        | Design §6.1.1             |
| Protected gateway configuration and route-bundle approvals                | Route controller, Kubernetes, PostgreSQL                 | Design §4.2               |
| Application resources                                                     | Backend, under its own canonical tenant mapping and RBAC | Design §3.1, §7.1         |

## 3. Trust boundaries

| Boundary                                 | Rule                                                                                                                                                                | Source                    |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| External proof to SkyOAuth               | Untrusted until verified by the selected registered source. `iss`, `kid`, source ID or grant ID never chooses a verifier URL, tenant or subject.                    | Design §3.1 (1)           |
| Upstream human IdP to SkyOAuth authority | SkyOAuth owns issuance, tenants, audiences and operator authority. OIDC claims and WIF never grant `adm_*` rights.                                                  | Design §1, §3.1 (2), §7.2 |
| Envoy to application                     | Envoy authenticates transport, not application permission. Protected routes fail closed; client identity headers are stripped; backends are not directly reachable. | Design §3.1 (3), §4       |
| Backend authorization                    | The backend checks the exact profile, its audience, the canonical resource tenant and then RBAC.                                                                    | Design §3.1 (4), §7.1     |
| Public versus private listeners          | Gateway, policy, internal-key and operator listeners are private and authenticated; external clients cannot reach them.                                             | Design §3, §4             |
| Operator plane                           | Independent `adm_*` mTLS identities; recovery crosses a deployment-local channel with an offline-signed challenge.                                                  | Design §7.2               |
| Infrastructure administrators            | Kubernetes and cluster administrators who can remove guards or replace the data plane are trusted and outside the route guarantee.                                  | Design §4.2               |
| Browser origin                           | HttpOnly limits token extraction, not actions by same-origin malicious JavaScript.                                                                                  | Design §4, §9             |
| Cloudflare Tunnel and other edges        | Connectivity only, not per-route authorization; `CF-*` and `X-Forwarded-*` are trusted only inside the configured proxy chain.                                      | Design §4                 |

## 4. Threat summary

| ID    | Primary specified mitigations                                                                          | Conformance references                 | Open questions    |
| ----- | ------------------------------------------------------------------------------------------------------ | -------------------------------------- | ----------------- |
| TM-01 | Push-only immutable-ID bindings, grant-directed evaluation, no WIF refresh, 300 s access cap           | A01, A02, A21, A25, A26, A36, A37, A50 | OQ-TM-2           |
| TM-02 | Source ID selects one verifier; fixed TokenReview endpoint; no token-directed keys                     | A03–A07, A19, A28, A29, A54            | —                 |
| TM-03 | Instance audience registry and assignments; signed tenant; backend canonical tenant check              | A13, A29, A43, A46, A48, A49           | —                 |
| TM-04 | Checker identity separate from token subject; one audience per credential                              | A25, A31, A44, A45, A56                | —                 |
| TM-05 | Private `typ` plus signed profile plus ingress; disjoint key sets                                      | A10, A18, A30, A44, A55, A62           | —                 |
| TM-06 | Atomic single-use consumption, one-time codes, refresh rotation, request-bound short assertions        | A23, A24, A32, A34, A35, A54, A57, A61 | OQ-TM-3           |
| TM-07 | Browser-bound flow cookie plus state; fresh session ticket; Origin plus CSRF                           | A08, A09, A33, A51, A52                | —                 |
| TM-08 | Transaction-bound provider, issuer, callback, epoch, nonce and PKCE; separate app and native callbacks | A33, A47, A51, A52, A60                | OQ-TM-4           |
| TM-09 | Registered origin, callback and relative return paths; exact loopback redirect binding                 | A27, A40, A41, A46, A51, A59           | OQ-TM-5           |
| TM-10 | Exact subject links, no email merge, enrollment hold, zero-privilege auto-create                       | A14, A22, A47, A51, A60                | OQ-TM-6, OQ-TM-7  |
| TM-11 | Mandatory explicit confirmation with comparison value; no silent SSO approval                          | A27, A34, A38, A41, A52, A57, A59      | —                 |
| TM-12 | Sole active-provider pointer; guarded switch; narrow credential-only rotation                          | A14, A17, A20, A42, A47, A63           | OQ-TM-7           |
| TM-13 | Route-level Cookie/CSRF and Set-Cookie removal on every non-SkyOAuth route                             | A08, A10, A18, A61                     | —                 |
| TM-14 | Fail-closed admission guard, sole-writer controller, protected-scope projection, observation           | A18, A36, A58, A61                     | OQ-TM-11          |
| TM-15 | Durably closed bootstrap; instance- and argument-bound single-use recovery challenge; offline key      | A20, A22, A32, A48, A64                | OQ-TM-8, OQ-TM-9  |
| TM-16 | Signer isolation, standby custody and tripwire, keyed hashes, fail-closed stores                       | A11, A19, A31, A35, A62                | OQ-TM-10–OQ-TM-12 |

## 5. Threats

### TM-01 — Malicious CI

**Attacker capability.** Controls code in a GitHub Actions job that can
request an OIDC assertion (`id-token: write`): a fork or pull-request author,
a contributor who can trigger `workflow_dispatch`, `issue_comment` or
`workflow_run`, a compromised third-party action or runner, or another
repository that shares the GitHub issuer. Can read anything the job can read,
including issued SkyOAuth tokens.

**Attacks.**

- Satisfy a production binding from a non-push event or a fork.
- Match name-based predicates from a renamed or recreated owner/repository.
- Exploit an omitted, deleted or wildcard predicate.
- Select a grant, actor or target service the workflow is not bound to, or
  override subject, target, tenant or mode.
- Obtain broader scope through omission, or another audience.
- Exfiltrate the GitHub assertion or the issued access token and use it
  outside the job, including after cancellation.
- Present GitHub's `actor` as a human login, or obtain a refresh credential
  for persistence.

**Specified mitigations.**

| Mitigation                                                                                                                                                       | Source                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Production bindings require immutable owner/repository IDs, explicit `event_name`, ref, environment and workflow identity, plus reusable-workflow identity       | Design §5.3; T12.2, T22.2                |
| The production example is push-only; `pull_request_target`, `workflow_dispatch`, `issue_comment` and `workflow_run` are denied                                   | Design §5.3; T22.5                       |
| Predicates are ANDed exact strings; a configured claim absent from evidence is a non-match; required predicates cannot be omitted; deletion is reviewed widening | Design §5.3; T12.2; ADR-008              |
| Generated source and grant selectors; evaluation only of bindings for the grant's actor and `allowed_binding_ids`; no subject/target/tenant/mode override        | Design §5.7; API-010–API-015             |
| Omitted scope uses only explicit nonempty defaults; scopes within assignment, grant and service ceilings                                                         | Design §5.7; API-016, IR-062, IR-063     |
| Signed allowlist constraints; backend canonical tenant and RBAC still required                                                                                   | Design §6; IR-120–IR-122, TP-040, TP-042 |
| No WIF refresh credential; access TTL at most 300 s; memory-only tokens, never logged                                                                            | Design §5.3, §5.7, §6.1; TP-044, LT-013  |
| GitHub `actor` is audit provenance only; delegation records the workload as `act`                                                                                | Design §5.3, §5.6; T12.4                 |
| Critical operations use the live check, so committed revocation denies new checks                                                                                | Design §5.3, §6.1; API-070–API-074       |
| Exchange is rate limited                                                                                                                                         | T50.5                                    |

**Conformance references.** A01, A02, A21, A25, A26, A36, A37, A50.

**Residual risk.**

- A run that legitimately satisfies the binding (malicious code merged to the
  bound ref through the repository's own review, a compromised action
  dependency, or a compromised runner during a push run) receives the grant's
  full authority. SkyOAuth cannot distinguish it.
- An exfiltrated access token is a bearer credential valid until expiry (at
  most 300 s); job cancellation does not revoke it (design §5.3).
- A `reusable` source permits repeated exchange of a stolen assertion until
  the assertion expires (TM-06).

**Gaps.**

- **Gap (OQ-TM-2):** the sources require an `environment` predicate but do
  not say whether the binding's meaning depends on GitHub-side controls
  (environment protection rules, branch protection) or whether self-hosted
  runners, which can be shared between repositories, are in scope.

### TM-02 — Issuer, cluster and key confusion

**Attacker capability.** Controls a registered JWT issuer or Kubernetes
cluster (possibly in another tenant), or one that shares an issuer string
with a registered source. Can mint validly signed tokens for its own issuer,
craft JWT headers (`kid`, `jku`, `x5u`, `jwk`, `alg`) and host URLs.

**Attacks.**

- Present a token from cluster B to the source for cluster A when both use
  the same issuer string.
- Have the verifier select a source by `iss` or `kid`, or probe clusters
  until one accepts.
- Use `jku`, `x5u`, an embedded `jwk`, `alg=none` or algorithm substitution.
- Upload a private key, or a conflicting `kid` in an overlapping keyset.
- Steer discovery or JWKS fetches to arbitrary URLs (SSRF).
- Reference another tenant's keyset.
- Supply a TokenReview endpoint, CA or credentials; invent a `jti` from
  decoded input; force a fallback from TokenReview to local validation.

**Specified mitigations.**

| Mitigation                                                                                                                                   | Source                                          |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| The source ID selects exactly one registered verifier; it is not proof of tenant or cluster; issuer is not a unique key; no probing          | Design §3.1, §5.4, §7.1; T11.7; API-013, IR-032 |
| TokenReview uses a fixed endpoint, versioned CA, reviewer reference, explicit `spec.audiences`, timeout and private egress without redirects | Design §5.4; T11.8, T23.2                       |
| Returned SA identity, UID and Pod evidence are bound to the selected cluster; no invented claims or `jti`                                    | Design §5.4; T23.3                              |
| No degradation from failed TokenReview to local validation; local JWT mode is a separate enrollment                                          | Design §5.4; T23.6                              |
| Reject `jku`, `x5u`, embedded keys, `alg=none`, weak substitution, private-key uploads and arbitrary redirects; bounded sizes and clocks     | Design §5.4; T11.5, T24.3                       |
| Uploaded keysets are public-only, same-tenant, with explicit overlap; conflicting live `kid`/key pairs deny                                  | Design §5.4; T11.3, T11.9                       |
| Discovery uses exact issuer, approved egress, algorithm/audience allowlists and bounded cache; no permissive fallback                        | Design §5.4; T11.2, T11.4                       |
| Composite tenant references prevent cross-tenant source or keyset use                                                                        | Design §7.1; IR-031                             |
| SkyOAuth's own keys: ingress and profile select the trust set before `kid` lookup                                                            | Design §6.2; TP-010, TP-011                     |

**Conformance references.** A03, A04, A05, A06, A07, A19, A28, A29, A54.

**Residual risk.**

- Clusters or issuers sharing one signing authority are not isolated from
  each other (design §5.4).
- Compromise of a registered external issuer's key lets the attacker mint
  proofs that match its bindings until an operator disables or rotates the
  source; that is an independent operator action (design §2).
- TokenReview revocation follows the cluster's documented semantics, not
  instantaneous revocation (design §5.4).

**Gaps.** None identified beyond OQ-TP-3 (allowed algorithms for SkyOAuth's
own tokens) in the token-profiles contract.

### TM-03 — Audience and tenant escalation

**Attacker capability.** A tenant-scoped operator (`trust_admin`,
`client_admin`, `provider_admin`) of tenant B, or a principal of tenant B
with valid credentials, who knows tenant A's audience strings, project names
and possibly object IDs. May control HTTP headers sent to the public ingress.

**Attacks.**

- Register or self-assign tenant A's audience, or reference it from a grant,
  client, origin or human policy.
- Use a shared audience to reach A-owned resources because project, scope or
  audience names match.
- Reference A's objects by ID, claim a missing global ID in an import, or
  probe for existence.
- Spoof `Host`, `Forwarded` or a `tenant` query parameter, or claim A's host
  as an application origin.
- Widen scope by omission, exceed ceilings, or exploit a store failure.

**Specified mitigations.**

| Mitigation                                                                                                                                                                | Source                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Instance `security_admin` owns a globally unique audience registry; tenants cannot self-assign or create competing ones                                                   | Design §7.1; T14.1; IR-070, IR-071                |
| References require an active same-tenant assignment, rechecked at issuance and every live check                                                                           | Design §7.1; T14.2; IR-080, IR-081                |
| Signed `skyoauth_tenant`; the backend maps each resource to its canonical tenant before scope and RBAC; missing mapping denies                                            | C09; design §6, §7.1; IR-082, TP-073              |
| Composite tenant/object references, generated IDs, no global ID claim on import, non-enumerating errors                                                                   | Design §7.1, §7.4; IR-020–IR-023, IR-031, ERR-020 |
| Origin ownership is enrolled by instance `security_admin`; tenant comes from the registered origin and trusted gateway chain, never a query or untrusted forwarded header | Design §4; T14.7; IR-033, API-050                 |
| Scopes lie within every applicable ceiling; browser headers cannot select scope or audience                                                                               | Design §4.1, §6; IR-062–IR-065                    |
| Store failure never expands privilege                                                                                                                                     | Design §7; IR-170                                 |
| No role inheritance; combined imports require every role                                                                                                                  | Design §7.2, §7.3; API-120, API-121               |

**Conformance references.** A13, A26, A29, A31, A43, A46, A48, A49.

**Residual risk.**

- For a shared multi-tenant audience, isolation depends on every backend
  mapping resources to the correct canonical tenant (design §7.1). SkyOAuth
  cannot verify that mapping.
- Human profiles use `backend_rbac`; human authorization correctness rests on
  backend RBAC (design §6).
- Instance `security_admin` can assign any audience to any tenant; it is a
  trusted instance role.

**Gaps.** None new. OQ-IR-7 (grants with several audiences) affects how
ceilings combine.

### TM-04 — Subject and resource-server confusion

**Attacker capability.** A workload or service principal with valid
credentials, or the operator of one resource server that receives tokens and
holds a checker identity.

**Attacks.**

- Treat a delegated service principal as the API receiver or checker because
  its `sub` or allowed audiences name that API (confused deputy).
- Use one resource server's checker identity to check tokens for another
  audience or tenant, or to recheck or close another checker's continuation.
- Treat `act.sub` or the token subject as the authorizing receiver.
- Forward a received bearer token to another endpoint.

**Specified mitigations.**

| Mitigation                                                                                                                 | Source                                   |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `ServiceIdentity` is a possible token subject, not the API receiver; checkers are registered per resource server           | Design §7.1; T14.3; IR-044, IR-090       |
| The live check authenticates a `ResourceServerChecker` bound to one audience and a tenant set, never the delegated subject | Design §6.1; T26.1; API-070              |
| A resource server cannot use another audience's checker identity                                                           | Design §6.1                              |
| Direct grants have a null target; delegation requires a same-tenant service and carries the workload in `act`              | Design §5.6; IR-045, TP-043              |
| One registered audience per credential; bearer validation never takes the expected audience from the token                 | Design §4.1, §6; IR-072, TP-023          |
| Continuations are bound to the checker identity, nonce and context; foreign recheck or close is non-enumerating            | Design §6.1.1; API-082, API-084, ERR-032 |

**Conformance references.** A25, A31, A44, A45, A56.

**Residual risk.** A backend that receives a bearer token can present it to
any other endpoint of the same audience until expiry; access tokens are not
sender-constrained. A compromised checker credential is limited to its own
resource server and tenant set.

**Gaps.** None identified.

### TM-05 — Profile substitution

**Attacker capability.** Holds a valid credential of one SkyOAuth profile, an
upstream ID token or an `at+jwt` token; can add request headers at the
public ingress.

**Attacks.**

- Present `human_cli` where a WIF allowlist is expected, or reshape a WIF
  token into human form to obtain `backend_rbac` treatment.
- Present a `human_session` assertion on bearer ingress, or an access token
  in the assertion header.
- Present an upstream ID token or `at+jwt`.
- Drop the profile discriminator and rely on a `usr_` prefix or on the
  absence of `act` or a grant.
- Use an unknown profile version or constraint field.
- Verify an access token against the internal key set or the reverse.
- Combine a cookie with a bearer token, or a bearer token with an assertion.

**Specified mitigations.**

| Mitigation                                                                                                                                   | Source                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Protected `typ`, signed profile and expected ingress jointly select rules; no inference from prefix, `act`, grant or header                  | Design §6; TP-010, TP-020                |
| Private types only; `at+jwt` and ID tokens rejected                                                                                          | Design §6; T20.8; TP-001–TP-003          |
| Profile-specific required claims; WIF cannot use `backend_rbac`; human profiles cannot carry WIF grant, mode or `act`; unknown versions deny | Design §6; TP-021, TP-040–TP-043, IR-140 |
| Distinct public and internal key pairs with disjoint `kid` namespaces and trust sets                                                         | Design §3.1, §6.2; TP-011                |
| Bearer ingress rejects internal assertions; Envoy strips client-supplied assertion headers; mixed credentials deny                           | Design §4, §6; API-062, TP-022           |
| Resource-server registration and route allowed profiles bound acceptance                                                                     | Design §4.1, §6; IR-110, TP-071          |

**Conformance references.** A10, A18, A30, A44, A55, A62.

**Residual risk.** A compromised internal signer can forge `human_session`
evidence within its trust boundary (design §6.2; TM-16). Each alternative
gateway adapter must preserve typed semantics and needs its own review
(design §4, §4.2).

**Gaps.** None new. OQ-TP-2 (internal assertion `iss`) and OQ-TP-11 /
OQ-API-10 (assertion header name) are open in the contracts.

### TM-06 — Replay

**Attacker capability.** Has captured a one-time or short-lived artifact: an
external proof, OIDC state or code, a native authorization code, a refresh
credential (possibly with its retry request ID), an access token, an internal
assertion on the gateway-to-backend path, a continuation ID, a signed
recovery response, a back-channel logout token, an old observation report,
or a database backup.

**Specified mitigations by artifact.**

| Artifact                   | Specified behavior                                                                                                                     | Source                                          |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `reusable` WIF proof       | Repeat exchange allowed within proof lifetime only after fresh policy evaluation and rate limits; new output `jti`                     | Design §5.3; T21.6                              |
| `single_use` WIF proof     | Atomic consumption of `(tenant, source, issuer, jti)` digest across replicas and grants; missing `jti`, replay or store failure denies | Design §5.3; T21.6; ERR-023                     |
| Projected Kubernetes token | `single_use` rejected at enrollment; no invented `jti`                                                                                 | Design §5.3, §5.4; T11.11                       |
| OIDC state and code        | One-time state, nonce and PKCE; transaction consumed atomically                                                                        | Design §5.1; API-052                            |
| Native authorization code  | Single use across replicas; bound to client, redirect, PKCE, audience, scopes and authentication                                       | Design §5.2; API-020                            |
| Refresh credential         | One-time rotation; consumed reuse revokes the family; optional 30 s exact retry; no switching paths by adding or removing the ID       | Design §5.2.2; API-022–API-025, ERR-021, LT-012 |
| Access JWT                 | Unique `jti`, TTL at most 300 s; live checks for critical actions                                                                      | Design §6, §6.1; LT-013                         |
| Internal assertion         | TTL at most 30 s; bound to method, scheme, authority and target digest; authenticated gateway channel; never returned to browser code  | Design §4.1, §6; TP-050–TP-053                  |
| Continuation admission     | One continuation per assertion `jti`; tombstone kept through assertion expiry plus skew                                                | Design §6.1.1; LT-080                           |
| Continuation ID            | Bound to checker identity, nonce and context; not a bearer capability                                                                  | Design §6.1.1; API-082                          |
| Recovery response          | Short-lived, single-use challenge bound to instance, operation, arguments and revision; durably consumed                               | Design §7.2; T13.5                              |
| Back-channel logout token  | Signature, issuer, audience, events, time and replay verification                                                                      | Design §5.1; T30.6                              |
| Route observation          | Owner epoch and increasing sequence; old epochs and replayed reports cannot reopen a gate                                              | Design §4.2; API-111                            |
| Database restore           | Preserve consumed and bootstrap-closed state, or quarantine issuance                                                                   | Design §7.2; T10.6; LT-100, LT-101              |

**Conformance references.** A23, A24, A32, A34, A35, A52, A54, A56, A57,
A61.

**Residual risk.**

- A stolen access token is usable until expiry (at most 300 s); there is no
  sender constraint.
- A stolen `reusable` proof can be exchanged until the proof expires.
- A stolen refresh credential together with its retry request ID can recover
  the same result within 30 s; the design states this trade-off explicitly
  (design §5.2.2).
- A crash can burn a single-use proof (availability only).

**Gaps.**

- **Gap (OQ-TM-3):** the internal assertion binds request metadata but not
  the body (design §4.1), and the sources require a unique `jti` without
  saying whether a backend must reject a second use of the same assertion
  for an ordinary (non-stream) request. Within its 30 s lifetime, a party on
  the gateway-to-backend path could resend it for the same target with a
  different body.

### TM-07 — Login CSRF

**Attacker capability.** A web attacker who can make the victim's browser
navigate (links, forms, frames, redirects) to application-origin or issuer
URLs, and who has an upstream account and can run their own login to obtain
a valid authorization response.

**Attacks.**

- Deliver the attacker's callback (code and state) to the victim's browser
  so the victim is logged in as the attacker.
- Force the victim to start a login, superseding a pending one.
- Plant a session cookie before login (fixation).
- Cross-site unsafe cookie calls, including logout.
- Have the victim's browser confirm a native transaction the attacker
  started.

**Specified mitigations.**

| Mitigation                                                                                                                                                 | Source                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Server-generated flow secret in host-only `__Host-skyoauth_login` (Secure, HttpOnly, SameSite=Lax); only its keyed hash is stored                          | Design §5.1; API-055; T30.2   |
| The transaction binds that hash, flow kind, origin, tenant, provider and epoch, exact callback and return path                                             | Design §5.1                   |
| The callback requires both one-time state and the matching flow cookie; a missing or wrong binding denies without creating, replacing or linking a session | Design §5.1; API-052; T30.7   |
| A fresh CSPRNG session ticket is issued at login and only its keyed hash stored; the transaction is consumed                                               | Design §5.1; T31.1            |
| Unsafe cookie calls, including Connect POST and logout, require exact `Origin` and `X-SkyOAuth-CSRF`                                                       | Design §5.1; API-053          |
| Native confirmation requires the rotated issuer flow binding, exact Origin, CSRF and anti-framing                                                          | Design §5.2; API-033, API-034 |
| Duplicate or ambiguous SkyOAuth cookies are rejected                                                                                                       | Design §4; API-056, GW-024    |

**Conformance references.** A08, A09, A33, A51, A52.

**Residual risk.**

- Forcing a navigation to `/_skyoauth/login` supersedes a pending login in the
  same cookie slot; the stale tab must restart (availability only).
- Login CSRF at the upstream IdP (the victim's browser holds the attacker's
  upstream session) makes the victim's own SkyOAuth login resolve to the
  attacker's identity. Defense depends on the upstream provider (design §9).
- Same-origin malicious JavaScript can act with the session (design §9).

**Gaps.** None new. Flow lifetimes are unspecified (OQ-LT-1).

### TM-08 — OIDC callback abuse

**Attacker capability.** Can send crafted requests to `/_skyoauth/callback`
or the issuer `/oauth/callback`, steal or inject authorization codes, control
an upstream IdP configured in another tenant or as an inactive candidate,
or send back-channel logout tokens.

**Attacks.**

- Inject a stolen code into the attacker's flow, or the attacker's code into
  the victim's flow.
- Mix-up: have a response from one provider redeemed or trusted as another.
- Present an ID token with wrong issuer, audience, nonce, time, signature or
  authentication context.
- Replay a callback, or deliver one after a provider switch.
- Cross flow kinds: app callback with a native transaction, or the reverse.
- Forge back-channel logout to end arbitrary sessions.
- Trigger principal creation during a migration hold.

**Specified mitigations.**

| Mitigation                                                                                                                                                                       | Source                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Fixed registered app callback per origin and a distinct issuer native callback; flow kinds and cookies are never interchangeable                                                 | Design §5.1, §5.2; API-032; T40.12             |
| The transaction stores expected issuer, callback, provider and epochs; ID-token issuer, audience, signature, nonce, time and authentication requirements are verified; PKCE S256 | Design §5.1; tasks §3 `OIDCTransaction`; T30.1 |
| Provider and tenant epochs invalidate flows across switch and rollback                                                                                                           | Design §5.1, §7.3, §8                          |
| One-time consumption; state alone is not browser authentication                                                                                                                  | Design §5.1                                    |
| Fixed upstream authorization endpoint; top-level GET callback baseline; another response mode needs a tested profile                                                             | Design §5.1                                    |
| Back-channel logout verification with indexed provider/subject/sid selection; no arbitrary claim lookup                                                                          | Design §5.1; T30.6                             |
| Enrollment policy and hold rechecked inside the callback's principal/link transaction                                                                                            | Design §5.1.1; tasks §3                        |
| SSRF-safe discovery; provider outage fails closed; upstream tokens discarded by default                                                                                          | Design §5.1; T30.3                             |

**Conformance references.** A33, A47, A51, A52, A60.

**Residual risk.** An attacker who controls the tenant's active provider can
authenticate as any linked user of that tenant (design §9).

**Gaps.**

- **Gap (OQ-TM-4):** design §5.1 names OIDC mix-up as a release threat, but
  the sources do not say whether the authorization-response `iss` parameter
  (RFC 9207) is required or checked. The specified defense is the
  transaction's single expected provider plus ID-token `iss` verification;
  the issuer `/oauth/callback` is shared by every tenant's provider.
- Login and callback availability while the route gate is closed is open
  (OQ-API-1).

### TM-09 — Redirect URI confusion

**Attacker capability.** Can craft login or authorize URLs with arbitrary
return paths or redirect URIs, register lookalike hosts, spoof `Host` or
`Forwarded`, or run a local process on the user's machine.

**Attacks.**

- Open redirect through the return path (`//evil`, backslashes, encoded
  traversal, prefix confusion such as `/app` versus `/application`).
- Native redirect to a non-loopback host, a different port or path than
  authorized, or a changed redirect at redemption.
- Make SkyOAuth build a callback or redirect for an attacker host.
- Make an authenticated API fetch follow a redirect off-origin with
  credentials.

**Specified mitigations.**

| Mitigation                                                                                                                                   | Source                               |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `ApplicationOrigin` binds one canonical HTTPS origin, callback URI and allowed relative return paths                                         | Design §4; T14.5                     |
| Return locations are normalized same-origin relative paths; protocol-relative URLs, backslashes, traversal and prefix confusion are rejected | Design §4; API-051                   |
| Unknown or ambiguous origins and spoofed `Host`/`Forwarded` deny before redirect; authority only from the trusted gateway chain              | Design §4; API-050                   |
| Native redirects are registered IP-loopback URIs; the exact chosen redirect must match at redemption; the code is bound to it                | Design §5.2, §10.3; API-020, API-031 |
| The comparison value includes the exact `redirect_uri`, and the page shows the loopback destination                                          | Design §5.2, §5.2.1; API-037         |
| Upstream callbacks are fixed on the provider and preserved by switch                                                                         | Design §4, §5.2, §7.3                |
| The SPA library rejects redirects for authenticated fetches; the Rust crate does not forward credentials across origins                      | Design §10.2, §10.3                  |
| Ingress rejects malformed targets                                                                                                            | Design §4.1; GW-002                  |

**Conformance references.** A27, A40, A41, A46, A51, A59.

**Residual risk.** A local process can bind its own loopback port and start
its own authorization with the public client ID (TM-11).

**Gaps.**

- **Gap (OQ-TM-5):** native redirect matching is not fully specified: whether
  registered `redirect_rules` fix the port or allow a per-request port
  (RFC 8252 §7.3), which loopback literals and paths are allowed, and whether
  `localhost` is rejected. Related: OQ-API-4.

### TM-10 — Identity-linking confusion

**Attacker capability.** Holds an upstream account, possibly with the same
email as the victim; controls subjects at a replacement provider; races
first logins during a migration; or is an insider `provider_admin`.

**Attacks.**

- Merge into the victim's principal by email.
- During migration, be auto-created as or matched to the victim.
- Reassign the account during the victim's linking callback.
- Create duplicate principals or bypass the hold with concurrent logins.
- Replace a disabled principal through auto-create.
- Promote upstream roles or groups to operator or backend privileges.
- As `provider_admin`, link an attacker subject to the victim's principal.

**Specified mitigations.**

| Mitigation                                                                                                                                    | Source                           |
| --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| Links are exact tenant, provider, issuer and subject; never email                                                                             | Design §2, §5.1.1; T12.1; IR-041 |
| `preprovisioned` default; explicit `auto_create` makes one fresh zero-privilege principal under a unique constraint; disabled identities deny | Design §5.1.1; T30.4; IR-042     |
| Switch and rollback set the enrollment hold; only an explicit audited resume bound to provider, generation and revision clears it             | Design §5.1.1; T30.8             |
| Linking requires an initiating-browser-bound transaction and explicit proof or approval; no callback account reassignment                     | Design §5.1; T30.4               |
| OIDC roles, groups and emails never grant operator authority                                                                                  | Design §7.2                      |

**Conformance references.** A14, A22, A47, A51, A60.

**Residual risk.**

- `provider_admin` is trusted to create verified links. A malicious or
  compromised `provider_admin` can link any upstream subject to any human
  principal of its tenant, which then inherits that principal's backend
  RBAC.
- A compromised active IdP can impersonate any linked user (design §9).

**Gaps.**

- **Gap (OQ-TM-6):** the verified-linking ceremony is not specified: what
  proof the existing identity supplies, how a browser-bound linking
  transaction starts and is approved, and how it relates to the
  `provider_admin` `/human-links` endpoint and
  `HumanSubjectLink.verified_by` / `verification_operation_id`. See also
  contradiction 2 in §7.
- **Gap (OQ-TM-7):** no second approval or separation of duty is specified
  for link creation (see also TM-12).

### TM-11 — Native-client impersonation

**Attacker capability.** Runs a malicious program on the user's machine, or
persuades the user to run one; knows the public `client_id`; can open the
system browser; may race the legitimate CLI.

**Attacks.**

- Start an authorization with the legitimate `client_id`, its own PKCE and
  loopback listener, and rely on existing SSO for a silent code.
- Get the user to approve the attacker's concurrent request.
- Use a superseded tab, or frame the confirmation page.
- Steal refresh credentials from storage.
- Phish through device flow, if shipped.

**Specified mitigations.**

| Mitigation                                                                                                         | Source                             |
| ------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| `client_id` identifies configuration, not a local program; the page warns of this                                  | Design §5.2                        |
| Every new loopback authorization requires explicit approval; prior consent or SSO never auto-approves              | Design §5.2; T40.2, T40.4; API-035 |
| Server-derived comparison value v1 and exact port shown; the user acknowledges "matches my CLI"                    | Design §5.2.1; T40.14; API-037     |
| Confirmation requires exact Origin, CSRF, anti-framing, rotated flow binding and request digest                    | Design §5.2; API-034               |
| A new start supersedes the old slot with an explicit error, never a silent redirect                                | Design §5.2; API-036               |
| The code is single use and bound to client, redirect, PKCE, audience, scopes and authentication                    | Design §5.2; API-020               |
| Refresh credentials in the OS credential store or explicit memory-only session; rotation, family limits and revoke | Design §5.2.2; T40.5               |
| Device flow is conditional and needs equivalent explicit approval                                                  | Design §5.2; T40.6                 |
| Native confirmation is rate limited                                                                                | T50.5                              |

**Conformance references.** A27, A34, A38, A41, A52, A57, A59.

**Residual risk.** The comparison is user-assisted correlation, not phishing
resistance or a second factor; a user who approves without comparing grants
the malicious program a code. A local attacker that can read the CLI's
secrets or alter its terminal is out of scope (design §5.2.1). A stolen
refresh credential works until rotation or replay detection, within family
limits (default 12 h absolute / 1 h idle, at most 7 d / 24 h).

**Gaps.** None identified.

### TM-12 — Generic-provider-write bypass

**Attacker capability.** A tenant operator with some roles, an operator with
every role, a GitOps pipeline with import rights, or someone able to change
configuration files or trigger reloads.

**Attacks.**

- Change the active provider, its issuer, client ID, callback or assurance
  through PATCH, import, reload, or delete/disable of the active provider,
  avoiding epoch invalidation and the enrollment hold.
- Hide a semantic change inside credential-only rotation.
- Partially apply an import, ignoring unauthorized sections.
- Use a provider switch to also change WIF, audience, client or operator
  state.
- Roll back by whole-database restore.
- Use break-glass recovery for arbitrary edits.

**Specified mitigations.**

| Mitigation                                                                                                                                                                               | Source                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `TenantLoginState.active_provider_id` is the sole pointer; no writable active flag; active state is read-only in GET/export                                                              | C10; design §7.3; T13.9; ADR-021 |
| PATCH, delete/disable of the active provider, imports and reloads reject pointer, epoch or semantic changes                                                                              | Design §7.3                      |
| Credential-only rotation keeps issuer, client ID, auth method, callbacks and assurance; mixed edits rejected; no epoch advance                                                           | Design §7.3; T30.9               |
| The switch plan is an immutable dry-run with expected revisions; commit advances epochs and sets the hold; WIF, audience, client, origin, operator, gateway and signer mutation rejected | Design §7.3, §8; T51.3           |
| Whole-plan role validation for combined imports; no partial apply                                                                                                                        | Design §7.3; API-121             |
| Rollback uses the same guarded transaction with fresh epochs, never whole-database rollback                                                                                              | Design §7.3, §8; T51.8; LT-030   |
| Break-glass permits only operator restoration or the same validated switch                                                                                                               | Design §7.2                      |

**Conformance references.** A14, A17, A20, A42, A47, A63.

**Residual risk.** A single `provider_admin` can plan and commit a switch to
an IdP it controls. Existing links do not carry over and the hold blocks
unmatched subjects, but the same role also creates links (TM-10). The
upstream IdP can change its own semantics without any SkyOAuth write.

**Gaps.**

- **Gap (OQ-TM-7):** no second approval is specified for `provider_admin`'s
  identity-critical operations (switch commit, link creation, enrollment
  resume).

### TM-13 — Cookie leakage to backends

**Attacker capability.** Controls or compromises an application backend on an
enrolled host (billing API, static file server, health endpoint), or reads
its logs, retries or mirrors.

**Attacks.**

- Harvest session or flow cookies and CSRF tokens from forwarded requests
  and replay them through the gateway against another audience.
- Capture them from retries, mirrors, logs or traces.
- Return `Set-Cookie` to fix, overwrite or duplicate SkyOAuth cookies.
- Obtain an exemption through a path prefix, caller header or tenant flag.
- Reuse an internal assertion against another audience.

**Specified mitigations.**

| Mitigation                                                                                                                     | Source                                    |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| Every non-SkyOAuth route on an enrolled host removes all Cookie and `X-SkyOAuth-CSRF` at route level, independent of ext_authz | Design §4; T32.4; API-063, GW-020, GW-021 |
| Every non-SkyOAuth response has every `Set-Cookie` removed                                                                     | Design §4; GW-027                         |
| Exemptions only for fixed SkyOAuth endpoints routed to the verified SkyOAuth backend identity                                  | Design §4; GW-030                         |
| Removals, order and exemptions are in the approved projection; a missing removal rejects activation                            | Design §4, §4.2; GW-028, GW-060           |
| Duplicate cookies rejected; no copies into other metadata; redaction in gateway logs and traces                                | Design §4; GW-024–GW-026                  |
| Host-only `__Host-` cookies; no Domain broadening                                                                              | Design §4; API-055                        |
| Assertions are bound to route, audience and request                                                                            | Design §4.1, §6; TP-050                   |
| Tests use actual upstream bytes, including retries and mirrors                                                                 | Design §4; GW-040                         |

**Conformance references.** A08, A10, A18, A61.

**Residual risk.** Containment is not isolation from malicious JavaScript
served on the same origin (design §4; GW-029): a compromised backend that
serves the SPA can act through the victim's browser. A TLS-terminating edge
such as Cloudflare sees cookies. Each alternate gateway adapter needs its own
equivalent removal contract (design §4.2).

**Gaps.** None new. Open in the containment contract: OQ-GW-3 (exact
exemption list), OQ-GW-4 (verified backend identity), OQ-GW-12 ("enrolled
host").

### TM-14 — Shadow routes

**Attacker capability.** A namespace-scoped Kubernetes user who can create
HTTPRoutes or policies (an application team, CI deployer, Helm, Argo CD or
Flux), or a tenant `client_admin`. Cannot remove admission policies; cluster
administrators are trusted.

**Attacks.**

- Create a new, unlabeled, wildcard, omitted-host, more-specific or
  cross-namespace route that captures protected traffic without ext_authz or
  without cookie removal.
- Change `parentRefs`, `allowedRoutes` or namespace selectors.
- Attach a policy or override that disables or reorders auth filters on a
  protected route.
- Rewrite path or host, or cause route-cache rematching, so the request the
  backend sees differs from the one authorized.
- Edit the gateway out of band, or PATCH the registry, so registry and
  gateway choose different receivers.
- Make a disabled route fall back to a broader prefix.
- Reopen a gate with stale observations or a caller-supplied digest.

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                  | Source                             |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `security_admin` enrolls the protected set; a fail-closed ValidatingAdmissionPolicy plus RBAC limit writes to the route controller; new, unlabeled, wildcard, shadow and cross-namespace routes are guarded | Design §4.2; GW-050–GW-056         |
| The route controller is the sole writer; Helm, Argo CD and Flux submit but do not apply                                                                                                                     | Design §4.2; GW-057                |
| Routing-agreement admission on every change; registry and gateway generated from one reviewed bundle                                                                                                        | Design §4.1                        |
| Protected-scope projection of ordered effective filters; unknown filters stay protected or reject                                                                                                           | Design §4.2; GW-060–GW-063         |
| Exact path beats segment prefix; ties reject; disabled winners deny without fallback                                                                                                                        | Design §4.1                        |
| No rewrites or rematching on `human_session` routes; the backend compares the raw-target digest                                                                                                             | Design §4.1; GW-005, TP-054        |
| Service-computed digests from an isolated translator; per-proxy observations with epoch and sequence; known mismatch closes immediately                                                                     | Design §4.2; GW-010, GW-220–GW-225 |
| Backends are not directly reachable and validate the credential themselves                                                                                                                                  | Design §3.1; T25.4                 |

**Conformance references.** A18, A36, A58, A61.

**Residual risk.**

- Kubernetes administrators who can remove the guards or replace the data
  plane are outside the guarantee (design §4.2).
- M2 bearer routes on an unenrolled host or listener are outside the
  admission mechanism until enrolled (design §4.2); there, protection rests on
  backend credential validation and cluster RBAC.
- Detection is periodic (poll at most every 10 s; unchanged evidence usable
  up to 300 s), not instantaneous (design §4.2).

**Gaps.** None new beyond OQ-TM-11 (see TM-16). Open in the containment
contract: OQ-GW-6 (guarded inventory kinds), OQ-GW-12 ("enrolled host") and
OQ-GW-14 (admission exception list contradiction).

### TM-15 — Operator recovery

**Attacker capability.** One or more of: deployment-local access (pod exec,
node, Unix socket) without the recovery key; a stolen recovery key without
local access; control of the upstream IdP; an old signed recovery response;
an old database backup; the ability to social-engineer the recovery-key
holder.

**Attacks.**

- Reopen bootstrap through restart, empty configuration or restore, and
  enroll an attacker `security_admin`.
- Replay a signed response, or get a challenge signed for other arguments or
  another instance.
- Use break-glass for WIF edits, audience reassignment or token minting.
- Gain operator rights through OIDC roles, groups, email or WIF.
- Get operator keys copied into a pod or exported as a fallback.

**Specified mitigations.**

| Mitigation                                                                                                                                         | Source                      |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| Bootstrap is deployment-local and atomic, then durably closed; restart or empty configuration cannot reopen it; restore preserves bootstrap-closed | Design §7.2; T13.4; LT-100  |
| The challenge is bound to instance identity, operation/arguments digest and expected revision; short-lived, single-use and durably consumed        | Design §7.2; T13.5          |
| The workstation verifies and displays the challenge context before signing with the offline key                                                    | Design §7.2                 |
| Break-glass permits only bounded operator restoration or the validated provider switch/rollback                                                    | Design §7.2                 |
| Private keys stay on the workstation or hardware signer; unsupported adapters fail without key export                                              | Design §7.2; T13.7          |
| Independent `adm_*` identities; OIDC and WIF never grant operator authority; credential and role checked on every call                             | Design §7.2; T13.1; API-002 |
| Audit and alert on recovery; rotate recovery keys after use                                                                                        | Design §7.2                 |

**Conformance references.** A20, A22, A32, A48, A64.

**Residual risk.** The recovery-key holder with local channel access can
restore operator authority by design. Coercion or social engineering of that
holder is not addressed. Cluster and node administrators can reach the local
channel.

**Gaps.**

- **Gap (OQ-TM-8):** "bounded operator restoration" is not defined (which
  roles or credentials it may enroll or revoke), nor the challenge lifetime,
  the procedure and authority for rotating the recovery key after use, or
  whether more than one recovery key or a quorum is supported.
- **Gap (OQ-TM-9):** the sources do not say who may reach the "separately
  authorized deployment-local channel" (Unix socket permissions, exec RBAC).

### TM-16 — Runtime and database compromise

**Attacker capability.** Code execution in, or read or write access to, one
of: an auth-serving replica, the public signer, PostgreSQL or its backups,
Envoy, the route controller or its translator helper, or a backend.

**Specified limits by component.**

| Compromised component          | Spec limits                                                                                                                                                                  | Residual                                                                                                                       | Source                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------- |
| Auth replica (internal signer) | Cannot mint public access tokens; standby key in separate custody; live checks compare identity to stored records; disable and promote a clean standby; standby-use tripwire | Can forge `human_session` evidence and see cookies in Check metadata until the key is disabled; offline caches keep up to 60 s | Design §6.2; T32.14; TP-082 |
| Public signer                  | Isolated from public handlers; may be separately deployed or KMS/HSM; retired keys retained through TTL plus skew                                                            | Can mint any access token for any audience or tenant until key disable propagates                                              | Design §3.1, §6             |
| PostgreSQL read                | Secrets stored as keyed hashes; retry envelope encrypted with a key outside the database; reviewer and provider credentials are references; no private keys                  | Exposes policy, subjects and audit                                                                                             | Design §5.2.2, §7; tasks §3 |
| PostgreSQL write               | Store failure never expands privilege; restore preserves one-time state or quarantines                                                                                       | Can rewrite policy, role bindings, operator credentials and consumed state; design §9 calls this a separate high-impact risk   | Design §7, §9               |
| Envoy                          | Holds no signing key; backends require the authenticated gateway channel                                                                                                     | Sees cookies and tokens in transit; can skip removals                                                                          | Design §3.1, §4             |
| Route controller               | No signer, WIF or human authority; preparation helper sandboxed without controller credentials; approvals bind exact plans                                                   | Sole writer and sole reporter of observations for its scope (OQ-TM-11)                                                         | Design §4.2; GW-080–GW-085  |
| Backend                        | Receives no browser credentials; checker identity limited to its audience and tenants                                                                                        | Can present received bearer tokens within its audience until expiry                                                            | Design §4, §6.1             |

**Conformance references.** A11, A19, A31, A35, A62. No conformance row
targets database-write compromise; design §9 treats it as residual.

**Residual risk.** Root, runtime or database compromise remains a separate
high-impact risk (design §9). Authorization cannot undo an operation already
accepted.

**Gaps.**

- **Gap (OQ-TM-10):** the minimum isolation of the public signer is not
  fixed ("can be separately deployed or use KMS/HSM", design §3.1), and no
  public-key compromise procedure or administration endpoint is specified
  (related: OQ-API-3). See contradiction 3 in §7.
- **Gap (OQ-TM-11):** the route controller both writes protected gateway
  configuration and submits the per-proxy observations that prove it. The
  sources describe no independent observation source, so a compromised
  controller could install configuration and report matching evidence.
- **Gap (OQ-TM-12):** audit records are written atomically to the same
  database; the sources do not say whether audit and alerts must also reach a
  sink that a database-write attacker cannot alter.

## 6. Open questions

- **OQ-TM-1 — Threats outside the T00.7 list.** Design §9 lists SSRF, XSS,
  header spoofing, session fixation, credential resurrection and stale
  streams. T00.7 does not. Should this model, or another M0 document, cover
  them as separate entries?
- **OQ-TM-2 — GitHub-side preconditions.** Does a production binding depend
  on GitHub environment protection rules or branch protection, and are
  self-hosted (possibly shared) runners in scope? The sources require an
  `environment` predicate but say nothing on either point.
- **OQ-TM-3 — Reuse of internal assertions.** Must a backend reject a second
  use of the same `human_session` assertion `jti` for an ordinary request?
  The assertion binds method, scheme, authority and target but not the body
  (design §4.1); only continuation admission is one-per-`jti` (design
  §6.1.1).
- **OQ-TM-4 — Mix-up defense.** Is the RFC 9207 `iss` authorization-response
  parameter required where the provider supports it, given the issuer
  `/oauth/callback` is shared by all tenants' providers?
- **OQ-TM-5 — Native redirect matching.** Do registered `redirect_rules` fix
  the loopback port or allow a per-request port (RFC 8252 §7.3)? Which
  loopback literals and paths are allowed, and is `localhost` rejected?
- **OQ-TM-6 — Verified linking ceremony.** What proof establishes a verified
  link, how is a browser-bound linking transaction started and approved, and
  how does it relate to the `provider_admin` `/human-links` endpoint?
- **OQ-TM-7 — Separation of duty for identity-critical writes.** Should
  provider switch commit, link creation and enrollment resume need a second
  approver or another role? The sources allow one `provider_admin` to perform
  all three.
- **OQ-TM-8 — Recovery scope and key lifecycle.** What may "bounded operator
  restoration" enroll or revoke? What is the challenge lifetime? How, and by
  whom, is the recovery key rotated after use? Is a quorum of recovery keys
  supported?
- **OQ-TM-9 — Local recovery channel access.** Which deployment principals
  may reach the deployment-local bootstrap/recovery channel?
- **OQ-TM-10 — Public signer isolation and compromise response.** What
  isolation is the v0.1 minimum for the public signer, and what is the
  emergency disable and rotation procedure for a compromised public key?
- **OQ-TM-11 — Independent observation.** Is it accepted that the route
  controller is both the sole writer and the sole source of observations for
  its scope, or is an independent observation path required?
- **OQ-TM-12 — Audit sink independence.** Must audit events and alerts also
  be sent to a store outside PostgreSQL so a database-write compromise cannot
  erase them?

## 7. Contradictions and inconsistencies

1. **Threat list scope.** Design §9's threat list and the T00.7 list differ.
   T00.7 adds malicious CI, cookie leakage, shadow routes, operator recovery
   and runtime/database compromise as named threats; design §9 adds SSRF,
   XSS, header spoofing, session fixation, credential resurrection and stale
   streams. Gate M0 asks for a "threat matrix" without saying which list is
   authoritative (OQ-TM-1).
2. **Browser-bound linking versus operator linking.** Design §5.1 and T30.4
   require verified linking to use "an initiating-browser-bound transaction
   and explicit proof/approval". The tasks endpoint matrix gives
   `provider_admin` "controlled verified human enrollment/linking" through the
   operator API (`/admin/v1/tenants/{tenant}/human-links`), and design §5.1.1
   lets operators "preprovision through the existing verified-enrollment
   path". Whether an operator-created link must also be browser-bound is not
   stated (OQ-TM-6).
3. **Signer separation versus replica deployment.** Design §6.2 says
   signer-group replicas "have no public access-signing permission" and that
   a compromised internal signer "cannot mint public access tokens". Design
   §4 describes a baseline of "two or more stateless replicas" with separate
   listeners, and design §3.1 makes a separate public-signer deployment
   optional ("can be separately deployed"). If one replica serves both
   `/oauth/token` and the gateway Check, the §6.2 claim does not hold. The
   sources do not say which deployment the claim assumes (OQ-TM-10).

Contradictions already recorded in the contracts and relevant here: OQ-GW-8
(gate scope: bundle or origin), OQ-GW-14 (admission exception list) and
OQ-LT-14 (ADR-010 record).

## 8. Changing this model

Design §12 applies: a changed decision updates the design, the tasks plan,
the affected contracts, this threat model and the conformance references
together. The T00.7 checkbox stays unchecked until this model is reviewed.
