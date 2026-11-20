# SkyOAuth threat model

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Task covered:** T00.7 ([tasks](skyoauth-tasks.md) §2).
- **Derived from:** [design](skyoauth-design.md) §1.2, §1.3, §2 (C04, C08,
  C09, C10), §3, §3.1, §4, §4.1, §4.2, §5.1, §5.1.1, §5.2, §5.2.1, §5.2.2,
  §5.3, §5.4, §5.6, §5.7, §6, §6.1, §6.1.1, §6.2, §7, §7.1, §7.2, §7.3, §7.4,
  §8, §9, §10.2, §10.3; [tasks](skyoauth-tasks.md) §0, §2 (T00.7, T00.8,
  "Endpoint matrix", "Exchange selection and scope"), §3 ("Ownership",
  "One-time state", "Provider pointer/enrollment", "Stream state", "Key
  separation"), T10–T14, T20–T26, T30–T33, T40, T50–T52, §8 (conformance
  matrix), §11 (ADR-002, ADR-007, ADR-008, ADR-011, ADR-013, ADR-014, ADR-016,
  ADR-020, ADR-021, ADR-023).
- **Related contracts (proposed, M0; in [`docs/contracts/`](contracts/README.md)):**
  [public API](contracts/public-api.md) (`API-`),
  [errors and retry](contracts/errors-retry.md) (`ERR-`),
  [token profiles](contracts/token-profiles.md) (`TP-`),
  [identity registry](contracts/identity-registry.md) (`IR-`),
  [gateway containment](contracts/gateway-containment.md) (`GW-`) and
  [lifetimes](contracts/lifetimes.md) (`LT-`). They are cited by requirement
  ID.

## Conventions

- Each threat has a stable ID `TM-nn`. Each open question has an ID
  `OQ-TM-n`. Neither adds behavior.
- **Mitigations** restate the design and tasks plan and cite the section and,
  where one exists, the contract requirement ID. This document invents no
  mitigation. Where the sources give none for a listed attack, the entry
  records a **Gap** and an open question.
- An open question marked **Decided — lead decision, 2026-11-19** records the
  lead's decision and keeps the original question. A mitigation that comes
  only from such a decision is marked "(decided, OQ-TM-n)". Decisions that
  change spec text are listed in §6.1, with the design, tasks and contract
  sections that carry them.
- **Conformance references** are existing rows of the tasks §8 matrix. Where
  no row targets an attack, **Task tests** cite the tasks item that tests it
  (for example T52.3). This document defines no new test rows.
- **Residual risk** is what remains after the specified mitigations, including
  limits the design states itself (design §9).
- MUST, MUST NOT and similar words, where quoted, carry the meaning of the
  cited source.

## 1. Scope

This model covers the union of the T00.7 threat list and the design §9
threat list (OQ-TM-1, decided). TM-01 to TM-16 are the T00.7 list. TM-17 to
TM-23 add the design §9 threats that no T00.7 entry covers on its own.

| ID    | Threat                                | Listed in        |
| ----- | ------------------------------------- | ---------------- |
| TM-01 | Malicious CI                          | T00.7; design §9 |
| TM-02 | Issuer, cluster and key confusion     | T00.7; design §9 |
| TM-03 | Audience and tenant escalation        | T00.7; design §9 |
| TM-04 | Subject and resource-server confusion | T00.7; design §9 |
| TM-05 | Profile substitution                  | T00.7; design §9 |
| TM-06 | Replay                                | T00.7; design §9 |
| TM-07 | Login CSRF                            | T00.7; design §9 |
| TM-08 | OIDC callback abuse                   | T00.7; design §9 |
| TM-09 | Redirect URI confusion                | T00.7; design §9 |
| TM-10 | Identity-linking confusion            | T00.7; design §9 |
| TM-11 | Native-client impersonation           | T00.7; design §9 |
| TM-12 | Generic-provider-write bypass         | T00.7; design §9 |
| TM-13 | Cookie leakage to backends            | T00.7            |
| TM-14 | Shadow routes                         | T00.7; design §9 |
| TM-15 | Operator recovery                     | T00.7            |
| TM-16 | Runtime and database compromise       | T00.7; design §9 |
| TM-17 | Operator-credential compromise        | Design §9        |
| TM-18 | Assertion theft                       | Design §9        |
| TM-19 | Browser CSRF and XSS                  | Design §9        |
| TM-20 | Header spoofing                       | Design §9        |
| TM-21 | SSRF                                  | Design §9        |
| TM-22 | Credential resurrection               | Design §9        |
| TM-23 | Stale streams                         | Design §9        |

Design §9 threats and the entries that cover them:

| Design §9 threat                         | Entries      |
| ---------------------------------------- | ------------ |
| Compromised workflows/runners            | TM-01        |
| Issuer/key/cluster confusion             | TM-02        |
| Assertion theft/replay                   | TM-18, TM-06 |
| Cross-tenant audience issuance           | TM-03        |
| Subject-versus-resource-server confusion | TM-04        |
| Profile substitution                     | TM-05        |
| Signer/operator compromise               | TM-16, TM-17 |
| Login CSRF and callback injection        | TM-07, TM-08 |
| OIDC mix-up                              | TM-08        |
| Redirect URI confusion                   | TM-09        |
| Identity-linking confusion               | TM-10        |
| Native-client impersonation              | TM-11        |
| Session fixation                         | TM-07        |
| CSRF/XSS                                 | TM-19, TM-07 |
| Unprotected routes                       | TM-14, TM-13 |
| Header spoofing                          | TM-20        |
| SSRF                                     | TM-21        |
| Generic-provider-write bypass            | TM-12        |
| Credential resurrection                  | TM-22        |
| Stale streams                            | TM-23        |

Out of scope by design: device flow, active impersonation, upstream provider
exchange and vault, alternate gateway adapters and cloud STS (design §1.3,
§11). They appear only where the design requires them to stay disabled.

## 2. Assets

| Asset                                                                     | Held by                                                                                               | Source                                       |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Public access-token signing key                                           | Isolated public signer, optionally KMS/HSM                                                            | Design §3.1, §6                              |
| Internal assertion signer-group keys and eligible standby                 | Signer-group replicas; standby in separate custody                                                    | Design §6.2                                  |
| Operator mTLS keys and offline recovery key                               | Operator workstation or hardware signer, never a pod                                                  | Design §7.2                                  |
| TokenReview reviewer and upstream provider credentials                    | External secret references (`reviewer_credential_ref`, provider `credential_ref`)                     | Design §5.4, §7.3; tasks §3                  |
| Keyed-hash (HMAC) key for one-time-state and proof digests                | Auth replicas; custody not specified beyond digest-key rotation (T21.8)                               | Design §5.1, §5.3; tasks §3 "One-time state" |
| Refresh retry-envelope encryption key                                     | Outside the database, separate from signing keys, by protected reference (`retry_encryption_key_ref`) | Design §5.2.2; tasks §3                      |
| Checker mTLS keys                                                         | Resource-server backends                                                                              | Design §6.1                                  |
| Route-controller mTLS key and Kubernetes service-account token            | Route-controller replicas and their credentialed supervisor; never the translator helper              | Design §4.2; GW-082                          |
| Management-listener mTLS credentials                                      | Envoy management listener and the enrolled controller                                                 | Design §4.2; GW-100, GW-101                  |
| Envoy-to-SkyOAuth and Envoy-to-backend channel credentials                | Envoy, SkyOAuth private listeners, backends                                                           | Design §3.1, §4; T25.4                       |
| Downstream TLS Secrets referenced by protected routes                     | Kubernetes; read by the credentialed supervisor only                                                  | Design §4.2; GW-160, GW-163                  |
| Trust, policy and authority records                                       | PostgreSQL                                                                                            | Design §7                                    |
| One-time state: consumed proofs, flows, codes, refresh families, sessions | PostgreSQL, as keyed hashes                                                                           | Tasks §3 "One-time state"                    |
| Browser session, flow cookies and CSRF token                              | Browser (`__Host-` cookies), memory in the SPA library                                                | Design §4, §5.1, §10.2                       |
| Access JWTs, refresh credentials, internal assertions                     | Clients, gateway channel, OS credential store                                                         | Design §5.2.2, §6                            |
| Continuation IDs                                                          | Checker backend and SkyOAuth only                                                                     | Design §6.1.1                                |
| Protected gateway configuration and route-bundle approvals                | Route controller, Kubernetes, PostgreSQL                                                              | Design §4.2                                  |
| Application resources                                                     | Backend, under its own canonical tenant mapping and RBAC                                              | Design §3.1, §7.1                            |

## 3. Trust boundaries

| Boundary                                    | Rule                                                                                                                                                                | Source                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| External proof to SkyOAuth                  | Untrusted until verified by the selected registered source. `iss`, `kid`, source ID or grant ID never chooses a verifier URL, tenant or subject.                    | Design §3.1 (1)            |
| Upstream human IdP to SkyOAuth authority    | SkyOAuth owns issuance, tenants, audiences and operator authority. OIDC claims and WIF never grant `adm_*` rights.                                                  | Design §1, §3.1 (2), §7.2  |
| Envoy to application                        | Envoy authenticates transport, not application permission. Protected routes fail closed; client identity headers are stripped; backends are not directly reachable. | Design §3.1 (3), §4        |
| Backend authorization                       | The backend checks the exact profile, its audience, the canonical resource tenant and then RBAC.                                                                    | Design §3.1 (4), §7.1      |
| Public versus private listeners             | Gateway, policy, internal-key and operator listeners are private and authenticated; external clients cannot reach them.                                             | Design §3, §4              |
| Operator plane                              | Independent `adm_*` mTLS identities; recovery crosses a deployment-local channel with an offline-signed challenge.                                                  | Design §7.2                |
| Preparation supervisor to translator helper | The helper gets only sanitized input with placeholder Secrets and no credentials; the credentialed supervisor makes the scoped API calls.                           | Design §4.2; GW-082–GW-084 |
| Infrastructure administrators               | Kubernetes and cluster administrators who can remove guards or replace the data plane are trusted and outside the route guarantee.                                  | Design §4.2                |
| Browser origin                              | HttpOnly limits token extraction, not actions by same-origin malicious JavaScript.                                                                                  | Design §4, §9              |
| Cloudflare Tunnel and other edges           | Connectivity only, not per-route authorization; `CF-*` and `X-Forwarded-*` are trusted only inside the configured proxy chain.                                      | Design §4                  |

## 4. Threat summary

This is the Gate M0 threat matrix. Its conformance references, task tests and
open questions match the sections in §5.

| ID    | Primary specified mitigations                                                                                    | Conformance references                           | Task tests                        | Open questions                                  |
| ----- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | --------------------------------- | ----------------------------------------------- |
| TM-01 | Push-only immutable-ID bindings, grant-directed evaluation, no WIF refresh, 300 s access cap                     | A01, A02, A21, A25, A26, A36, A37, A50           | T22.5, T52.2                      | OQ-TM-2 (decided)                               |
| TM-02 | Source ID selects one verifier; fixed TokenReview endpoint; no token-directed keys                               | A03–A07, A15, A19, A28, A29, A54                 | T11.10, T52.1                     | OQ-TM-13 (decided)                              |
| TM-03 | Instance audience registry and assignments; signed tenant; backend canonical tenant check                        | A13, A26, A29, A31, A43, A46, A48, A49           | T52.6                             | —                                               |
| TM-04 | Checker identity separate from token subject; one audience per credential                                        | A25, A31, A44, A45, A56                          | —                                 | —                                               |
| TM-05 | Private `typ` plus signed profile plus ingress; disjoint key sets                                                | A10, A18, A30, A44, A55, A62                     | T52.1                             | —                                               |
| TM-06 | Atomic single-use consumption, one-time codes, refresh rotation, request-bound short assertions                  | A23, A24, A32, A34, A35, A52, A54, A56, A57, A61 | T40.15                            | OQ-TM-3 (decided)                               |
| TM-07 | Browser-bound flow cookie plus state; fresh session ticket; Origin plus CSRF                                     | A08, A09, A33, A51, A52                          | T31.5, T52.3                      | —                                               |
| TM-08 | Transaction-bound provider, issuer, callback, epoch, nonce and PKCE; separate app and native callbacks           | A33, A47, A51, A52, A60                          | T30.6, T30.7, T52.3               | OQ-TM-4 (decided)                               |
| TM-09 | Registered origin, callback and relative return paths; exact loopback redirect binding                           | A27, A40, A41, A46, A51, A59                     | T40.9, T52.3                      | OQ-TM-5 (decided)                               |
| TM-10 | Exact subject links, no email merge, enrollment hold, zero-privilege auto-create                                 | A22, A47, A51, A60                               | T30.8, T51.3, T52.3               | OQ-TM-6, OQ-TM-7 (decided)                      |
| TM-11 | Mandatory explicit confirmation with comparison value; no silent SSO approval                                    | A27, A34, A38, A41, A52, A57, A59                | T40.8, T52.3                      | —                                               |
| TM-12 | Sole active-provider pointer; guarded switch; narrow credential-only rotation                                    | A14, A15, A16, A17, A42, A47, A53, A63           | T51.11                            | OQ-TM-7 (decided)                               |
| TM-13 | Route-level Cookie/CSRF and Set-Cookie removal on every enrolled-host route except the exact exempt cookie paths | A08, A10, A18, A61                               | T52.4                             | —                                               |
| TM-14 | Fail-closed admission guard, sole-writer controller, protected-scope projection, observation                     | A18, A36, A58, A61                               | T52.4                             | OQ-TM-11 (decided)                              |
| TM-15 | Durably closed bootstrap; instance- and argument-bound single-use recovery challenge; offline key                | A20, A22, A32, A48, A64                          | T13.6, T52.5                      | OQ-TM-8, OQ-TM-9, OQ-TM-15 (decided)            |
| TM-16 | Signer isolation, standby custody and tripwire, keyed hashes, fail-closed stores, sandboxed translator           | A11, A19, A31, A35, A58, A62                     | T32.3, T50.3, T50.4, T52.5, T52.8 | OQ-TM-10–OQ-TM-12, OQ-TM-14, OQ-TM-16 (decided) |
| TM-17 | Per-call credential and role check, scoped roles, workstation-held keys, operator disable, recovery              | A32, A48, A64                                    | T13.6, T52.5                      | OQ-TM-6–OQ-TM-8, OQ-TM-12, OQ-TM-15 (decided)   |
| TM-18 | Audience-bound selected-source proofs, replay capability, request-bound private assertions, no logging           | A10, A23, A24, A54, A61                          | T52.4                             | —                                               |
| TM-19 | Origin plus CSRF, HttpOnly host-only cookies, no tokens in JavaScript, same-origin SPA transport                 | A09, A39, A40                                    | T33.5, T33.7                      | —                                               |
| TM-20 | Header stripping and overwrite, trusted-chain authority, no rewrites, unreachable backends                       | A18, A36, A46, A61                               | T25.4, T25.5, T52.4               | —                                               |
| TM-21 | Approved exact egress, fixed TokenReview endpoint, no token-directed URLs, bounded fetches                       | A03, A05                                         | T11.2, T24.3, T30.3               | OQ-TM-13 (decided)                              |
| TM-22 | Restore preserves consumed state or quarantines; fresh epochs; no revival on re-enable or promotion              | A17, A33, A34, A35                               | T51.8, T51.9                      | —                                               |
| TM-23 | Bounded continuation leases, recheck before deadline, per-`jti` admission, bearer close at expiry                | A12, A56                                         | T32.12, T52.6                     | —                                               |

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
  outside the job, including after cancellation (see also TM-18).
- Present GitHub's `actor` as a human login, or obtain a refresh credential
  for persistence.

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                | Source                                   |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Production bindings require immutable owner/repository IDs, explicit `event_name`, ref, environment and workflow identity; a job that uses a reusable workflow also binds that reusable-workflow identity | Design §5.3; T12.2, T22.2                |
| The production example is push-only; `pull_request_target`, `workflow_dispatch`, `issue_comment` and `workflow_run` are denied                                                                            | Design §5.3; T22.5                       |
| Predicates are ANDed exact strings; a configured claim absent from evidence is a non-match; required predicates cannot be omitted; deletion is reviewed widening                                          | Design §5.3; T12.2; ADR-008              |
| Generated source and grant selectors; evaluation only of bindings for the grant's actor and `allowed_binding_ids`; no subject/target/tenant/mode override                                                 | Design §5.7; API-010–API-015             |
| Omitted scope uses only explicit nonempty defaults; scopes within assignment, grant and service ceilings                                                                                                  | Design §5.7; IR-062, IR-063              |
| Signed allowlist constraints; backend canonical tenant and RBAC still required                                                                                                                            | Design §6; IR-120–IR-122, TP-040, TP-042 |
| No WIF refresh credential; access TTL at most 300 s; memory-only tokens, never logged                                                                                                                     | Design §5.3, §5.7, §6.1; TP-044, LT-013  |
| GitHub `actor` is audit provenance only; delegation records the workload as `act`                                                                                                                         | Design §5.3, §5.6; T12.4                 |
| Critical operations use the live check, so committed revocation denies new checks                                                                                                                         | Design §5.3, §6.1; API-070–API-074       |
| Exchange is rate limited                                                                                                                                                                                  | T50.5                                    |

**Conformance references.** A01, A02, A21, A25, A26, A36, A37, A50.

**Task tests.** T22.5, T52.2.

**Residual risk.**

- A run that legitimately satisfies the binding (malicious code merged to the
  bound ref through the repository's own review, a compromised action
  dependency, or a compromised runner during a push run) receives the grant's
  full authority. SkyOAuth cannot distinguish it.
- SkyOAuth does not rely on GitHub environment protection rules or branch
  protection (OQ-TM-2, decided). The binding's event, ref and workflow
  predicates carry the policy; `environment` is one more ANDed predicate.
  Anyone who can push to the bound ref, or change the bound workflow on it,
  can satisfy the binding.
- Self-hosted runners shared across trust domains are out of scope (OQ-TM-2,
  decided). SkyOAuth cannot protect a job whose runner a less trusted
  repository also uses.
- An exfiltrated access token is a bearer credential valid until expiry (at
  most 300 s); job cancellation does not revoke it (design §5.3).
- A `reusable` source permits repeated exchange of a stolen assertion until
  the assertion expires (TM-06, TM-18).

**Gaps.** None open. OQ-TM-2 is decided.

### TM-02 — Issuer, cluster and key confusion

**Attacker capability.** Controls a registered JWT issuer or Kubernetes
cluster (possibly in another tenant), or one that shares an issuer string
with a registered source. Can mint validly signed tokens for its own issuer,
craft JWT headers (`kid`, `jku`, `x5u`, `jwk`, `alg`) and host URLs. Or is a
tenant `trust_admin` configuring a source.

**Attacks.**

- Present a token from cluster B to the source for cluster A when both use
  the same issuer string.
- Have the verifier select a source by `iss` or `kid`, or probe clusters
  until one accepts.
- Use `jku`, `x5u`, an embedded `jwk`, `alg=none` or algorithm substitution.
- Upload a private key, or a conflicting `kid` in an overlapping keyset.
- Steer discovery or JWKS fetches to arbitrary URLs (SSRF, TM-21).
- Reference another tenant's keyset.
- Supply a TokenReview endpoint, CA or credentials; invent a `jti` from
  decoded input; force a fallback from TokenReview to local validation.

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                     | Source                                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| The source ID selects exactly one registered verifier; it is not proof of tenant or cluster; issuer is not a unique key; no probing                                                                            | Design §3.1, §5.4, §7.1; T11.7; API-013, IR-032              |
| TokenReview uses a fixed endpoint, versioned CA, reviewer reference, explicit `spec.audiences`, timeout and private egress without redirects                                                                   | Design §5.4; T11.8, T23.2                                    |
| Returned SA identity, UID and Pod evidence are bound to the selected cluster; no invented claims or `jti`                                                                                                      | Design §5.4; T23.3                                           |
| No degradation from failed TokenReview to local validation; local JWT mode is a separate enrollment                                                                                                            | Design §5.4; T23.6                                           |
| Reject `jku`, `x5u`, embedded keys, `alg=none`, weak substitution, private-key uploads and arbitrary redirects; bounded sizes and clocks                                                                       | Design §5.4; T11.5, T24.3                                    |
| Uploaded keysets are public-only, same-tenant, with explicit overlap; conflicting live `kid`/key pairs deny                                                                                                    | Design §5.4; T11.3, T11.9                                    |
| Discovery uses exact issuer, approved egress, algorithm/audience allowlists and bounded cache; no permissive fallback                                                                                          | Design §5.4; T11.2, T11.4                                    |
| Composite tenant references prevent cross-tenant source or keyset use                                                                                                                                          | Design §7.1; IR-031                                          |
| Verifier configurations, CA and reviewer references survive provider migration unchanged                                                                                                                       | Design §2 (C05), §8; T23.7                                   |
| SkyOAuth's own keys: ingress and profile select the trust set before `kid` lookup                                                                                                                              | Design §6.2; TP-010, TP-011                                  |
| Secret references (`ca_bundle_ref`, `reviewer_credential_ref`, provider `credential_ref`) resolve only within the tenant's own provisioned secret namespace (decided, OQ-TM-13)                                | Lead decision; design §5.4; T11.2, T11.8, T23.2 (§6.1)       |
| Discovery, JWKS and TokenReview egress destinations, including `token_review_endpoint`, come from an allowlist approved by instance `security_admin`; tenant operators only choose from it (decided, OQ-TM-13) | Lead decision; design §5.4, §7.2; T11.2, T11.8, T23.2 (§6.1) |

**Conformance references.** A03, A04, A05, A06, A07, A15, A19, A28, A29,
A54.

**Task tests.** T11.10, T52.1.

**Residual risk.**

- Clusters or issuers sharing one signing authority are not isolated from
  each other (design §5.4).
- Compromise of a registered external issuer's key lets the attacker mint
  proofs that match its bindings until an operator disables or rotates the
  source; that is an independent operator action (design §2).
- TokenReview revocation follows the cluster's documented semantics, not
  instantaneous revocation (design §5.4).
- A tenant operator can still reference any secret in its own tenant's
  namespace and choose any allowlisted egress destination; the allowlist and
  the namespace provisioning are trusted (OQ-TM-13, decided).

**Gaps.**

- OQ-TM-13 is decided: secret references resolve only within a per-tenant
  provisioned namespace, and egress destinations come from an allowlist that
  instance `security_admin` approves. Design §5.4, T11.2, T11.8, T23.2 and the
  tasks §3 schema (`EgressAllowlistEntry`, `Tenant.secret_namespace`) carry it
  (§6.1).
- OQ-TP-3 (allowed algorithms for SkyOAuth's own tokens) remains open in the
  token-profiles contract.

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
  as an application origin (see also TM-20).
- Widen scope by omission, exceed ceilings, or exploit a store failure.

**Specified mitigations.**

| Mitigation                                                                                                                                                                | Source                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Instance `security_admin` owns a globally unique audience registry; tenants cannot self-assign or create competing ones                                                   | Design §7.1; T14.1; IR-070, IR-071                |
| References require an active same-tenant assignment, rechecked at issuance and every live check; each exchange selects exactly one audience from the grant's set          | Design §7.1; T14.2; IR-080, IR-081, IR-083        |
| Signed `skyoauth_tenant`; the backend maps each resource to its canonical tenant before scope and RBAC; missing mapping denies                                            | C09; design §6, §7.1; IR-082, TP-073              |
| Composite tenant/object references, generated IDs, no global ID claim on import, non-enumerating errors                                                                   | Design §7.1, §7.4; IR-020–IR-023, IR-031, ERR-020 |
| Origin ownership is enrolled by instance `security_admin`; tenant comes from the registered origin and trusted gateway chain, never a query or untrusted forwarded header | Design §4; T14.7; IR-033, API-050                 |
| Scopes lie within every applicable ceiling; browser headers cannot select scope or audience                                                                               | Design §4.1, §6; IR-062–IR-065                    |
| Store failure never expands privilege                                                                                                                                     | Design §7; IR-170                                 |
| No role inheritance; combined imports require every role                                                                                                                  | Design §7.2, §7.3; API-120, API-121               |

**Conformance references.** A13, A26, A29, A31, A43, A46, A48, A49.

**Task tests.** T52.6.

**Residual risk.**

- For a shared multi-tenant audience, isolation depends on every backend
  mapping resources to the correct canonical tenant (design §7.1). SkyOAuth
  cannot verify that mapping.
- Human profiles use `backend_rbac`; human authorization correctness rests on
  backend RBAC (design §6).
- Instance `security_admin` can assign any audience to any tenant; it is a
  trusted instance role (TM-17).

**Gaps.** None new. OQ-IR-7 is decided: a grant may hold several resource
servers, and each exchange selects exactly one through `audience`, which
must be in the grant's set and covered by an active same-tenant assignment
(IR-083).

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
| Distinct public and internal key pairs with disjoint `kid` namespaces and trust sets; the trust set, not `iss`, separates key purposes       | Design §3.1, §6.2; TP-011, TP-031        |
| Bearer ingress rejects internal assertions; Envoy removes client-supplied `X-SkyOAuth-Assertion` and overwrites it; mixed credentials deny   | Design §4, §6; API-061, API-062          |
| Resource-server registration and route allowed profiles bound acceptance                                                                     | Design §4.1, §6; IR-110, TP-071          |

**Conformance references.** A10, A18, A30, A44, A55, A62.

**Task tests.** T52.1.

**Residual risk.** A compromised internal signer can forge `human_session`
evidence within its trust boundary (design §6.2; TM-16). Each alternative
gateway adapter must preserve typed semantics and needs its own review
(design §4, §4.2).

**Gaps.** None new. OQ-TP-2 is decided: internal assertions use the same
canonical issuer as access tokens (TP-031). OQ-TP-11 and OQ-API-10 are
decided: the assertion header is `X-SkyOAuth-Assertion` (API-061).

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
| Continuation admission     | One continuation per assertion `jti`; tombstone kept through assertion expiry plus skew                                                | Design §6.1.1; API-080, LT-080                  |
| Continuation ID            | Bound to checker identity, nonce and context; not a bearer capability                                                                  | Design §6.1.1; API-082                          |
| Recovery response          | Short-lived, single-use challenge bound to instance, operation, arguments and revision; durably consumed                               | Design §7.2; T13.5; LT-107                      |
| Back-channel logout token  | Signature, issuer, audience, events, time and replay verification                                                                      | Design §5.1; T30.6                              |
| Route observation          | Owner epoch and increasing sequence; old epochs and replayed reports cannot reopen a gate                                              | Design §4.2; API-111                            |
| Database restore           | Preserve consumed and bootstrap-closed state, or quarantine issuance (TM-22)                                                           | Design §7.2; T10.6; LT-100, LT-101              |

**Conformance references.** A23, A24, A32, A34, A35, A52, A54, A56, A57,
A61.

**Task tests.** T40.15.

**Residual risk.**

- A stolen access token is usable until expiry (at most 300 s); there is no
  sender constraint.
- A stolen `reusable` proof can be exchanged until the proof expires.
- A stolen refresh credential that the legitimate client has not yet used
  can be redeemed through the standard path with no request ID (design
  §5.2.2), subject to the family's current client, policy, epoch and deadline
  checks. The thief gets one successor and an access token. The legitimate
  client's next refresh then presents a consumed credential, which is replay
  and revokes the family, including the thief's successor (ERR-021). Until
  then, or until the family deadlines, the thief can keep rotating.
- The retry request ID is needed only to recover an already-committed
  response within the 30 s window. It is retry correlation, not client
  authentication, and not a theft control (design §5.2.2). A thief with both
  the credential and its matching ID can recover that same result within the
  window; the design states this trade-off explicitly.
- Verifiers MUST NOT reject a credential only because they have seen its
  `jti` before; the only per-`jti` one-use rules are continuation admission
  and `single_use` external proofs (TP-070; OQ-TM-3, decided). A
  `human_session` assertion can therefore be presented more than once within
  its 30 s lifetime. It binds method, scheme, authority and target but not
  the body (design §4.1), so a party on the gateway-to-backend path could
  resend it for the same target with a different body. The authenticated
  gateway channel (T25.4) and backend RBAC limit this; it is accepted
  residual risk.
- A crash can burn a single-use proof (availability only).

**Gaps.** None open. OQ-TM-3 is decided.

### TM-07 — Login CSRF

**Attacker capability.** A web attacker who can make the victim's browser
navigate (links, forms, frames, redirects) to application-origin or issuer
URLs, and who has an upstream account and can run their own login to obtain
a valid authorization response.

**Attacks.**

- Deliver the attacker's callback (code and state) to the victim's browser
  so the victim is logged in as the attacker.
- Force the victim to start a login, superseding a pending one.
- Plant a session cookie before login so that it survives login (session
  fixation).
- Cross-site unsafe cookie calls, including logout (see also TM-19).
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
| Login flows expire: default 10 min, ceiling 15 min                                                                                                         | LT-023                        |

**Conformance references.** A08, A09, A33, A51, A52.

**Task tests.** T31.5 and T52.3 (login CSRF, callback replay, cookie
confusion and fixation).

**Residual risk.**

- Forcing a navigation to `/_skyoauth/login` supersedes a pending login in the
  same cookie slot; the stale tab must restart (availability only).
- Login CSRF at the upstream IdP (the victim's browser holds the attacker's
  upstream session) makes the victim's own SkyOAuth login resolve to the
  attacker's identity. Defense depends on the upstream provider (design §9).
- Same-origin malicious JavaScript can act with the session (design §9;
  TM-19).

**Gaps.** None new. OQ-LT-1 is decided (LT-023).

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

| Mitigation                                                                                                                                                                                                                                                                   | Source                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Fixed registered app callback per origin and a distinct issuer native callback; flow kinds and cookies are never interchangeable                                                                                                                                             | Design §5.1, §5.2; API-032; T40.12                                    |
| The transaction stores expected issuer, callback, provider and epochs; ID-token issuer, audience, signature, nonce, time and authentication requirements are verified; PKCE S256                                                                                             | Design §5.1; tasks §3 `OIDCTransaction`; T30.1                        |
| Mix-up: verify the RFC 9207 authorization-response `iss` when the provider advertises it; otherwise use the provider's own exact issuer callback path `/oauth/callback/{provider_id}`, server-generated and exempt from cookie removal by exact path only (decided, OQ-TM-4) | Lead decision; design §4, §5.2; T30.1, T40.12; API-032, GW-036 (§6.1) |
| Provider and tenant epochs invalidate flows across switch and rollback                                                                                                                                                                                                       | Design §5.1, §7.3, §8                                                 |
| One-time consumption; state alone is not browser authentication                                                                                                                                                                                                              | Design §5.1                                                           |
| Fixed upstream authorization endpoint; top-level GET callback baseline; another response mode needs a tested profile                                                                                                                                                         | Design §5.1                                                           |
| Back-channel logout verification with indexed provider/subject/sid selection; no arbitrary claim lookup                                                                                                                                                                      | Design §5.1; T30.6                                                    |
| Enrollment policy and hold rechecked inside the callback's principal/link transaction                                                                                                                                                                                        | Design §5.1.1; tasks §3                                               |
| Login and callback are not gated by the route gate but deny before redirect unless the origin has an active pinned version and is security-enabled                                                                                                                           | API-132, API-134                                                      |
| SSRF-safe discovery; provider outage fails closed; upstream tokens discarded by default                                                                                                                                                                                      | Design §5.1; T30.3                                                    |

**Conformance references.** A33, A47, A51, A52, A60.

**Task tests.** T30.6 (back-channel logout), T30.7, T52.3 (mix-up, state,
nonce, PKCE, code replay, flow-cookie crossover).

**Residual risk.**

- An attacker who controls the tenant's active provider can authenticate as
  any linked user of that tenant (design §9).
- Before the OQ-TM-4 amendment (§6.1), the specified mix-up defense was the
  transaction's single expected provider plus ID-token `iss` verification,
  and the issuer `/oauth/callback` was shared by every tenant's provider. With
  it, the RFC 9207 `iss` check or a per-provider callback path adds
  authorization-response provenance (API-032, GW-036).

**Gaps.** None open. OQ-TM-4 is decided; OQ-API-1 (login and callback while
the gate is closed) is decided (API-132, API-134).

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

| Mitigation                                                                                                                                                                                                                | Source                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `ApplicationOrigin` binds one canonical HTTPS origin, callback URI and allowed relative return paths                                                                                                                      | Design §4; T14.5                                                |
| Return locations are normalized same-origin relative paths; protocol-relative URLs, backslashes, traversal and prefix confusion are rejected                                                                              | Design §4; API-051                                              |
| Unknown or ambiguous origins and spoofed `Host`/`Forwarded` deny before redirect; authority only from the trusted gateway chain                                                                                           | Design §4; API-050                                              |
| Native redirects are registered IP-loopback URIs; the exact chosen redirect must match at redemption; the code is bound to it                                                                                             | Design §5.2, §10.3; API-020, API-031                            |
| Registered rules fix scheme `http`, the IP literal (`127.0.0.1` and/or `[::1]`) and the path; the port varies per request and is bound exactly per transaction; `localhost` is rejected (decided, OQ-TM-5; RFC 8252 §7.3) | Lead decision; design §5.2, §10.3; T40.1, T40.9; API-031 (§6.1) |
| The comparison value includes the exact `redirect_uri`, and the page shows the loopback destination                                                                                                                       | Design §5.2, §5.2.1; API-037                                    |
| Upstream callbacks are fixed on the provider and preserved by switch                                                                                                                                                      | Design §4, §5.2, §7.3                                           |
| The SPA library rejects redirects for authenticated fetches; the Rust crate does not forward credentials across origins                                                                                                   | Design §10.2, §10.3                                             |
| Ingress rejects malformed targets                                                                                                                                                                                         | Design §4.1; GW-002                                             |

**Conformance references.** A27, A40, A41, A46, A51, A59.

**Task tests.** T40.9, T52.3.

**Residual risk.** A local process can bind its own loopback port and start
its own authorization with the public client ID (TM-11).

**Gaps.** None open. OQ-TM-5 is decided. OQ-API-4 (native authorize and
redemption parameter lists) remains open in the public-API contract.

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

| Mitigation                                                                                                                                                                                                                                                                                                                    | Source                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Links are exact tenant, provider, issuer and subject; never email                                                                                                                                                                                                                                                             | Design §2, §5.1.1; T12.1; IR-041                                                  |
| `preprovisioned` default; explicit `auto_create` makes one fresh zero-privilege principal under a unique constraint; disabled identities deny                                                                                                                                                                                 | Design §5.1.1; T30.4; IR-042                                                      |
| Switch and rollback set the enrollment hold; only an explicit audited resume bound to provider, generation and revision clears it                                                                                                                                                                                             | Design §5.1.1; T30.8                                                              |
| Linking requires an initiating-browser-bound transaction and explicit proof or approval; no callback account reassignment                                                                                                                                                                                                     | Design §5.1; T30.4                                                                |
| Operator enrollment that creates a new principal is operator-asserted and audited; a link to an existing principal needs a browser-bound transaction proving both identities, or, when the old IdP is unavailable during migration, an operator-asserted link with a second approver and user notification (decided, OQ-TM-6) | Lead decision; design §5.1, §5.1.1; tasks §2 matrix; T30.4, T51.3; API-155 (§6.1) |
| A link to an existing principal needs a distinct second `adm_*` approver unless an explicit audited instance policy allows single-actor mode (decided, OQ-TM-7)                                                                                                                                                               | Lead decision; design §7.2; tasks §2 matrix; API-155 (§6.1)                       |
| OIDC roles, groups and emails never grant operator authority                                                                                                                                                                                                                                                                  | Design §7.2                                                                       |

**Conformance references.** A22, A47, A51, A60.

**Task tests.** T30.8, T51.3 (verified links), T52.3.

**Residual risk.**

- `provider_admin` is trusted to create verified links. Before the OQ-TM-6
  and OQ-TM-7 amendments (§6.1), the sources let a malicious or compromised
  `provider_admin` link any upstream subject to any human principal of its
  tenant, which then inherits that principal's backend RBAC. With them, an
  operator-asserted link to an existing principal also needs a second
  approver (or the explicit single-actor instance policy) and notifies the
  user; collusion, or a single actor under that policy, remains residual.
- A compromised active IdP can impersonate any linked user (design §9).

**Gaps.** None open. OQ-TM-6 and OQ-TM-7 are decided; see also §7.1.

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

**Task tests.** T40.8, T52.3.

**Residual risk.** The comparison is user-assisted correlation, not phishing
resistance or a second factor; a user who approves without comparing grants
the malicious program a code. A local attacker that can read the CLI's
secrets or alter its terminal is out of scope (design §5.2.1). A stolen
refresh credential works until rotation or replay detection, within family
limits (default 12 h absolute / 1 h idle, at most 7 d / 24 h; TM-06).

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
- Activate a dormant impersonation grant through PATCH, import, a capability
  upgrade or a provider migration.
- Roll back by whole-database restore.
- Use break-glass recovery for arbitrary edits.

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                                                                                                                                                | Source                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `TenantLoginState.active_provider_id` is the sole pointer; no writable active flag; active state is read-only in GET/export                                                                                                                                                                                                               | C10; design §7.3; T13.9; ADR-021                            |
| PATCH, delete/disable of the active provider, imports and reloads reject pointer, epoch or semantic changes                                                                                                                                                                                                                               | Design §7.3                                                 |
| Credential-only rotation keeps issuer, client ID, auth method, callbacks and assurance; mixed edits rejected; no epoch advance                                                                                                                                                                                                            | Design §7.3; T30.9                                          |
| The switch plan is an immutable dry-run with expected revisions; commit advances epochs and sets the hold; WIF, audience, client, origin, operator, gateway and signer mutation rejected                                                                                                                                                  | Design §7.3, §8; T51.3                                      |
| Source configurations, bindings, grants and dormant impersonation records survive migration unchanged; unsupported impersonation stays disabled and cannot be activated by PATCH, import or capability upgrade                                                                                                                            | Design §2 (C05, C06), §5.6; T12.10                          |
| Whole-plan role validation for combined imports; no partial apply                                                                                                                                                                                                                                                                         | Design §7.3; API-121                                        |
| Rollback uses the same guarded transaction with fresh epochs, never whole-database rollback                                                                                                                                                                                                                                               | Design §7.3, §8; T51.8; LT-030                              |
| Break-glass permits only operator restoration or the same validated switch                                                                                                                                                                                                                                                                | Design §7.2                                                 |
| Every plan commit except a disable-only commit (authentication-critical changes to the active provider, activation from null, switch and rollback) needs a distinct second `adm_*` approver unless an explicit audited instance policy allows single-actor mode; a disable-only commit does not, because it fails safe (decided, OQ-TM-7) | Lead decision; design §7.2, §7.3, §8; T13.9; API-148 (§6.1) |

**Conformance references.** A14, A15, A16, A17, A42, A47, A53, A63.

**Task tests.** T51.11 (switch and rollback during an IdP outage; generic
pointer and semantic writes deny).

**Residual risk.** Before the OQ-TM-7 amendment (§6.1), a single
`provider_admin` could plan and commit a switch to an IdP it controls; with
it, that needs a second approver or the explicit single-actor instance
policy. Existing links do not carry over and the hold blocks unmatched
subjects (TM-10). The upstream IdP can change its own semantics without any
SkyOAuth write.

**Gaps.** None open. OQ-TM-7 is decided.

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

| Mitigation                                                                                                                                                                                                                                                                                                                                                           | Source                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Every route on an enrolled host, including the issuer host and non-exempt SkyOAuth endpoints, other than the exact exempt cookie paths removes all Cookie and `X-SkyOAuth-CSRF` at route level, independent of ext_authz                                                                                                                                             | Design §4; T32.4; API-063, GW-020, GW-021, GW-033 |
| Every response on those routes has every `Set-Cookie` removed                                                                                                                                                                                                                                                                                                        | Design §4; GW-027                                 |
| Exemptions only for the seven fixed SkyOAuth cookie endpoints and each exact registered per-provider issuer callback path `/oauth/callback/{provider_id}`, routed to the verified SkyOAuth backend identity; no prefix or pattern exemption; `/oauth/token`, `/oauth/revoke`, `/.well-known/*` and back-channel logout keep the removals (decided, OQ-GW-3, OQ-TM-4) | Design §4, §5.2; GW-030, GW-033–GW-036            |
| Removals, order and exemptions are in the approved projection; a missing removal rejects activation                                                                                                                                                                                                                                                                  | Design §4, §4.2; GW-028, GW-060                   |
| Duplicate cookies rejected; no copies into other metadata; redaction in gateway logs and traces                                                                                                                                                                                                                                                                      | Design §4; GW-024–GW-026                          |
| Host-only `__Host-` cookies; no Domain broadening                                                                                                                                                                                                                                                                                                                    | Design §4; API-055                                |
| Assertions are bound to route, audience and request                                                                                                                                                                                                                                                                                                                  | Design §4.1, §6; TP-050                           |
| Tests use actual upstream bytes, including retries and mirrors                                                                                                                                                                                                                                                                                                       | Design §4; GW-040                                 |

**Conformance references.** A08, A10, A18, A61.

**Task tests.** T52.4.

**Residual risk.** Containment is not isolation from malicious JavaScript
served on the same origin (design §4; GW-029): a compromised backend that
serves the SPA can act through the victim's browser (TM-19). A
TLS-terminating edge such as Cloudflare sees cookies. Each alternate gateway
adapter needs its own equivalent removal contract (design §4.2).

**Gaps.** None new. In the containment contract OQ-GW-3 (exemption list) is
decided (GW-033, GW-034, GW-036); OQ-GW-4 (verified backend identity) is
deferred to T32.4; OQ-GW-12 ("enrolled host") is decided.

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
| Routing-agreement admission on every change; registry and gateway generated from one reviewed bundle where practical                                                                                        | Design §4.1                        |
| Protected-scope projection of ordered effective filters; unknown filters stay protected or reject                                                                                                           | Design §4.2; GW-060–GW-063         |
| Exact path beats segment prefix; ties reject; disabled winners deny without fallback                                                                                                                        | Design §4.1                        |
| No rewrites or rematching on `human_session` routes; the backend compares the raw-target digest                                                                                                             | Design §4.1; GW-005, TP-054        |
| Service-computed digests from an isolated translator; per-proxy observations with epoch and sequence; known mismatch closes immediately                                                                     | Design §4.2; GW-010, GW-220–GW-225 |
| Backends are not directly reachable and validate the credential themselves                                                                                                                                  | Design §3.1; T25.4                 |

**Conformance references.** A18, A36, A58, A61.

**Task tests.** T52.4 (shadow-route admission, management-listener
configurations).

**Residual risk.**

- Kubernetes administrators who can remove the guards or replace the data
  plane are outside the guarantee (design §4.2).
- M2 bearer routes on an unenrolled host or listener are outside the
  admission mechanism until enrolled (design §4.2); there, protection rests on
  backend credential validation and cluster RBAC.
- Detection is periodic, not instantaneous: each traffic-eligible proxy is
  polled at least every 10 s, a stale alert fires at 30 s, and unchanged
  evidence is usable up to 300 s from collection start (design §4.2).
- The route controller is both the sole writer and the sole source of
  observations for its scope; this is accepted for v0.1 (OQ-TM-11, decided;
  TM-16).

**Gaps.** None new. OQ-TM-11 is decided. In the containment contract OQ-GW-6
(guarded inventory kinds) is open, OQ-GW-15 (issuer system-bundle admin
endpoints and issuer-host `begin`/`cleanup_to_closed`) is open and blocks
M1b, OQ-GW-12 ("enrolled host") is decided (GW-035, GW-116, GW-236) and OQ-GW-14 (admission exception list) is decided (GW-056).

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

| Mitigation                                                                                                                                                                                                                                                                                                                                    | Source                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Bootstrap is deployment-local and atomic, then durably closed; restart or empty configuration cannot reopen it; restore preserves bootstrap-closed                                                                                                                                                                                            | Design §7.2; T13.4; LT-100                        |
| The challenge is bound to instance identity, operation/arguments digest and expected revision; short-lived, single-use and durably consumed                                                                                                                                                                                                   | Design §7.2; T13.5                                |
| The challenge expires: default 5 min, maximum 15 min                                                                                                                                                                                                                                                                                          | LT-107                                            |
| The workstation verifies and displays the challenge context before signing with the offline key                                                                                                                                                                                                                                               | Design §7.2                                       |
| Break-glass permits only bounded operator restoration or the validated provider switch/rollback; it cannot edit WIF, reassign audiences or mint tokens                                                                                                                                                                                        | Design §7.2; API-152                              |
| Operator restoration only enrolls a replacement `security_admin` credential and revokes operator credentials; every break-glass transaction (operator restoration or provider switch/rollback) enrolls a replacement recovery public key in the same signed transaction and retires the used key; one recovery key in v0.1 (decided, OQ-TM-8) | Lead decision; design §7.2; T13.5; API-152 (§6.1) |
| The bootstrap/recovery socket is owned by the service UID with mode 0600 (decided, OQ-TM-9)                                                                                                                                                                                                                                                   | Lead decision; design §7.2; T13.4, T50.1 (§6.1)   |
| No online operation, including `security_admin` "signer/recovery policy", replaces the recovery key; only a transaction signed by the current recovery key over the local channel does (decided, OQ-TM-15)                                                                                                                                    | Lead decision; design §7.2; T13.5; API-152 (§6.1) |
| Private keys stay on the workstation or hardware signer; unsupported adapters fail without key export                                                                                                                                                                                                                                         | Design §7.2; T13.7                                |
| Independent `adm_*` identities; OIDC and WIF never grant operator authority; credential and role checked on every call                                                                                                                                                                                                                        | Design §7.2; T13.1; API-002                       |
| Audit and alert on recovery; rotate recovery keys after use                                                                                                                                                                                                                                                                                   | Design §7.2                                       |

**Conformance references.** A20, A22, A32, A48, A64.

**Task tests.** T13.6, T52.5 (workstation and hardware recovery drills).

**Residual risk.**

- The recovery-key holder with local channel access can restore operator
  authority by design. Coercion or social engineering of that holder is not
  addressed.
- `pods/exec` on the SkyOAuth namespace is equivalent to access to the local
  channel; it is limited to infrastructure administrators who are already
  trusted (OQ-TM-9, decided). Cluster and node administrators can reach the
  channel.
- One recovery key is a single point of custody in v0.1; a quorum is
  deferred (OQ-TM-8, decided).

**Gaps.** None open. OQ-TM-8, OQ-TM-9 and OQ-TM-15 are decided.

### TM-16 — Runtime and database compromise

**Attacker capability.** Code execution in, or read or write access to, one
of: an auth-serving replica, the token-issuing replica, the public signer,
PostgreSQL or its backups, Envoy, the route controller, its credentialed
preparation supervisor or its translator helper, or a backend.

**Specified limits by component.**

| Compromised component                                                        | Spec limits                                                                                                                                                                                                                                                                                                                                                                                                           | Residual                                                                                                                                                                                                                                                                                                                                                                      | Source                                           |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Check-serving auth replica (internal signer)                                 | No public access-signing permission (design §6.2; extended by OQ-TM-10, decided, to every process serving Check or holding internal keys); standby key in separate custody; live checks compare identity to stored records; disable and promote a clean standby; standby-use tripwire                                                                                                                                 | Can forge `human_session` evidence until the key is disabled; offline caches keep up to 60 s. Session cookies seen in Check metadata stay usable until those sessions are revoked or expire, or the tenant's `auth_generation` is advanced (decided, OQ-TM-14), not until the key is disabled                                                                                 | Design §6.2; T32.14; TP-082                      |
| Token-issuing replica (`/oauth/token`, `/oauth/authorize`, `/oauth/confirm`) | Needs public signing to issue access tokens; signer isolation keeps the private key out of the replica when the signer is separately deployed or uses KMS/HSM; the signer enforces structural limits (`typ`/profile, `iss`, registered audience, `exp`−`iat` ≤ 300 s) and logs every signature to the external sink (decided, OQ-TM-16)                                                                               | Isolation protects the key, not the signing service: the signer does not re-check issuance policy, so while compromised the replica can have the signer sign any structurally valid access token for any registered audience or tenant; accepted for v0.1, and each signature is logged externally (OQ-TM-16, decided). Sees proofs, codes and refresh credentials in transit | Design §3.1, §6; T50.3                           |
| Public signer                                                                | Isolated from public handlers; may be separately deployed or KMS/HSM; retired keys retained through TTL plus skew; emergency disable and rotation with a prepublished standby (decided, OQ-TM-10)                                                                                                                                                                                                                     | Can mint any access token for any audience or tenant until key disable propagates to verifier JWKS caches                                                                                                                                                                                                                                                                     | Design §3.1, §6                                  |
| PostgreSQL read                                                              | Secrets stored as keyed hashes; retry envelope encrypted with a key outside the database; reviewer and provider credentials are references; no private keys                                                                                                                                                                                                                                                           | Exposes policy, subjects and audit                                                                                                                                                                                                                                                                                                                                            | Design §5.2.2, §7; tasks §3                      |
| PostgreSQL write                                                             | Store failure never expands privilege; restore preserves one-time state or quarantines; security events also go to an operator-configured append-only, hash-chained external sink (syslog over TLS or OTLP logs); public-signer key enrollment, activation and publication are refused without one, while emergency disable and standby promotion always proceed with an alert and a local record (decided, OQ-TM-12) | Can rewrite policy, role bindings, operator credentials and consumed state; design §9 calls this a separate high-impact risk                                                                                                                                                                                                                                                  | Design §7, §9                                    |
| Envoy                                                                        | Holds no signing key; backends require the authenticated gateway channel                                                                                                                                                                                                                                                                                                                                              | Sees cookies and tokens in transit; holds its channel credentials; can skip removals                                                                                                                                                                                                                                                                                          | Design §3.1, §4                                  |
| Route controller                                                             | No signer, WIF or human authority; approvals bind exact plans; old epochs cannot reopen a gate                                                                                                                                                                                                                                                                                                                        | Sole writer and sole reporter of observations for its scope; accepted for v0.1, with backend credential validation compensating (OQ-TM-11, decided)                                                                                                                                                                                                                           | Design §4.2; GW-100–GW-106                       |
| Preparation supervisor (credentialed)                                        | Scoped API calls and scoped Secret reads only; records only nonsecret dependency metadata; real key material never enters helper input, logs, plans, results or dumps                                                                                                                                                                                                                                                 | Reads the real Secrets in its scope (for example downstream TLS private keys) and is on the credentialed side of the sandbox (design §4.2), so it also carries the route-controller residual                                                                                                                                                                                  | Design §4.2; GW-084, GW-160–GW-163; T32.3, T50.4 |
| Translator helper                                                            | Enforced sandbox: fixed binary and arguments, no shell, network, credentials, service-account automount or privileged sockets; bounded input and output through pipes; receives only deterministic nonproduction placeholder Secrets; the service binds its result to the pending operation                                                                                                                           | A wrong translation fails preparation or leaves observations unmatched, so the gate stays closed (availability). A sandbox escape gains the supervisor's position                                                                                                                                                                                                             | Design §4.2; GW-080–GW-085, GW-162; T32.3, T50.4 |
| Backend                                                                      | Receives no browser credentials; checker identity limited to its audience and tenants                                                                                                                                                                                                                                                                                                                                 | Can present received bearer tokens within its audience until expiry                                                                                                                                                                                                                                                                                                           | Design §4, §6.1                                  |

**Conformance references.** A11, A19, A31, A35, A58, A62. No conformance row
targets database-write compromise; design §9 treats it as residual.

**Task tests.** T32.3 and T50.4 (translator sandbox and Secret
containment), T50.3 (signer isolation), T52.5 (signer separation), T52.8
(independent review of controller and observer boundaries).

**Residual risk.** Root, runtime or database compromise remains a separate
high-impact risk (design §9). Authorization cannot undo an operation already
accepted. After an auth-replica compromise, exposed session cookies stay
valid until their sessions are revoked or expire, or until the tenant's
`auth_generation` advances: through an epoch-advancing provider transition
(design §7.3, §8) or through the revision-checked operation that advances it
without a provider change (decided, OQ-TM-14). That operation,
`POST /admin/v1/tenants/{tenant}/login-state/compromise-transitions` run by
tenant `provider_admin` (API-154), acts on one tenant: there is no
single-origin variant, and an instance-wide response runs it for every tenant
(decided, OQ-TM-14) through a separate endpoint that is still open
(OQ-ADR021-3). A
compromised token-issuing replica can have the public signer sign any
structurally valid access token for a registered audience until the replica
is contained; the external signature log supports detection and scoping, not
prevention (OQ-TM-16, decided).

**Gaps.**

- No threat-model question is open: OQ-TM-10, OQ-TM-11, OQ-TM-12, OQ-TM-14
  and OQ-TM-16 are decided. The OQ-TM-14 operation is specified (design §7.3,
  T13.9, API-154) and must exist before M3 (§6.1).
- Open elsewhere: the instance-wide response endpoint, with its per-tenant
  revision checks, atomicity and partial-failure rules (OQ-ADR021-3), blocks
  M1b and M3. OQ-API-2 is decided in part: tenant-wide revocation is that
  operation; revoking one session, refresh family or authentication context
  stays open in the public-API contract.

### TM-17 — Operator-credential compromise

**Attacker capability.** Holds a stolen operator mTLS private key, or
controls the workstation or hardware signer, of an instance `security_admin`
or a tenant operator (`trust_admin`, `client_admin`, `provider_admin`,
`auditor`). Can reach the private operator listener.

**Attacks.**

- Use every right of the stolen role within its scope.
- Persist by enrolling additional operator credentials or role assignments,
  or by revoking legitimate operators.
- Defeat recovery by replacing the recovery key, if an online path allows it.
- Hide activity by deleting or altering audit records.

**Blast radius by role (design §7.2).**

| Role                      | What a stolen credential can do                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Instance `security_admin` | Create and disable tenants; enroll operators and assign roles; register and assign audiences to any tenant; register checker identities, action registries and origin ownership; manage signer and recovery policy and internal assertion keys (API-151); approve route bundles and revoke approvals; register route-controller and provisioner identities |
| Tenant `trust_admin`      | Create workload and service principals, sources, keysets, bindings and grants for its tenant within instance audience ceilings, so it can enroll an issuer it controls and mint WIF tokens for the tenant's assigned audiences                                                                                                                             |
| Tenant `client_admin`     | Register OAuth clients; stage origins, routes and bundles; edit HumanAccessPolicies (up to the 7 d / 24 h refresh maxima) and OriginCapacityPolicy; security-disable origins and routes (API-145); cancel attempts                                                                                                                                         |
| Tenant `provider_admin`   | Configure inactive providers; plan switches and rollbacks; rotate provider credentials; create links and resume enrollment (with the OQ-TM-6 and OQ-TM-7 limits once amended)                                                                                                                                                                              |
| Tenant `auditor`          | Read redacted tenant configuration and audit                                                                                                                                                                                                                                                                                                               |

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                                                                       | Source                                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| The active local credential and role are checked on every call; a certificate alone is insufficient                                                                                                                                                              | Design §7.2; T13.1; API-002                                      |
| Private keys stay on the workstation or hardware signer, never in a pod; no key export fallback                                                                                                                                                                  | Design §7.2; T13.7; A64                                          |
| Roles are scoped and do not inherit; combined imports need every role                                                                                                                                                                                            | Design §7.2; API-120, API-121                                    |
| Tenant operators cannot exceed instance audience assignments or create operator authority                                                                                                                                                                        | Design §7.1, §7.2; IR-070, IR-071                                |
| Each sensitive operation has one named role and fixed limits                                                                                                                                                                                                     | API-140–API-152                                                  |
| Every write is validated, revision-checked and audited                                                                                                                                                                                                           | API-003                                                          |
| `security_admin` disables operator credentials through the operator enrollment endpoint; revoked keys deny                                                                                                                                                       | Design §7.2; T13.6; public-API operator endpoint matrix          |
| If `security_admin` itself is compromised, recovery enrolls a replacement `security_admin` credential, revokes operator credentials, enrolls a replacement recovery public key in the same signed transaction and retires the used key (decided, OQ-TM-8; TM-15) | Lead decision; design §7.2; T13.5; API-152 (§6.1)                |
| Every provider plan commit except a disable-only commit, and links to existing principals, need a distinct second approver (decided, OQ-TM-7)                                                                                                                    | Lead decision; design §7.2, §7.3; T13.9; API-148, API-155 (§6.1) |
| Security events, including operator writes, recovery, key operations, switches and standby tripwire, also go to an append-only external sink (decided, OQ-TM-12)                                                                                                 | Lead decision; design §7; T50.6; Gate M1a (§6.1)                 |
| No online path, including a stolen `security_admin` credential, can replace the recovery key; only a transaction signed by the current recovery key over the local channel can (decided, OQ-TM-15)                                                               | Lead decision; design §7.2; T13.5; API-152 (§6.1)                |

**Revocation and recovery.**

- A tenant-operator compromise: `security_admin` disables the credential.
  Because the credential is checked on every call, the next call denies.
  Writes already made stay in effect; operators review the audit and revert
  them through ordinary revision-checked writes, and an attacker's provider
  switch through the guarded rollback with fresh epochs (design §7.3).
- A `security_admin` compromise: another `security_admin` disables it, or,
  if none can, break-glass recovery enrolls a replacement and revokes
  operator credentials (TM-15).

**Conformance references.** A32, A48, A64.

**Task tests.** T13.6 (revoked keys, scope crossover), T52.5.

**Residual risk.**

- Writes accepted before revocation remain until reverted. Credentials issued
  under them remain valid to expiry (access tokens at most 300 s) or until
  revoked.
- A stolen `security_admin` credential has instance-wide authority within the
  role until it is disabled; detection depends on audit and alerts.
- Under the explicit single-actor instance policy (OQ-TM-7), one stolen
  `provider_admin` credential can still switch providers and link accounts.
- A stolen `security_admin` credential cannot disable break-glass recovery by
  replacing the recovery key (OQ-TM-15, decided), but it can revoke
  legitimate operators until recovery runs.

**Gaps.** None open. OQ-TM-15 is decided: design §7.2 "signer/recovery
policy" does not include replacing the recovery key; design §7.2, T13.5 and
API-152 carry it (§6.1).

### TM-18 — Assertion theft

**Attacker capability.** Reads an external proof (GitHub OIDC token,
Kubernetes projected service-account token, generic JWT) from a job log,
artifact, compromised step, node or file; or reads a `human_session`
internal assertion on the Envoy-to-backend path or from backend logs.

**Attacks.**

- Exchange a stolen proof at `/oauth/token` from outside the job.
- Present a stolen proof to another source, grant or tenant.
- Present a stolen internal assertion on the public bearer ingress, to
  another backend or for another request.

**Specified mitigations.**

| Mitigation                                                                                                                                                                            | Source                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| A proof is verified only at the selected source, against its exact audience, and must satisfy a binding for the selected grant's actor                                                | Design §5.3, §5.7; API-013; T12.3      |
| `reusable` proofs exchange only within their lifetime after fresh evaluation and rate limits; `single_use` proofs are consumed atomically                                             | Design §5.3; T21.6; T50.5              |
| Workload tokens are never logged or persisted by the Rust provider                                                                                                                    | Design §5.3; T22.3                     |
| An internal assertion lives at most 30 s and is bound to route, audience, method, scheme, authority and target digest                                                                 | Design §4.1, §6; TP-050                |
| It travels only in the overwritten private `X-SkyOAuth-Assertion` header over the authenticated gateway channel; client-supplied copies are removed; public bearer ingress rejects it | Design §4, §6; API-061, API-062; T25.4 |
| The internal trust set is disjoint from the public one                                                                                                                                | Design §6.2; TP-011                    |
| Assertions and digests are redacted from logs                                                                                                                                         | Design §4.1; GW-006; T50.6             |

**Conformance references.** A10, A23, A24, A54, A61.

**Task tests.** T52.4.

**Residual risk.** A stolen `reusable` proof gives its binding's authority to
whoever can reach the token endpoint until the proof expires; there is no
sender constraint. A stolen internal assertion can be presented again for
its bound request within 30 s (TM-06).

**Gaps.** None identified.

### TM-19 — Browser CSRF and XSS

**Attacker capability.** A cross-site web attacker (CSRF), or script running
in the application origin: XSS in the SPA, a compromised front-end
dependency, or a backend that serves same-origin content.

**Attacks.**

- Make a cross-site unsafe call that carries the session cookie.
- Read the session cookie or CSRF token from script.
- Read access or refresh tokens from browser storage.
- Have the SPA library attach session credentials to an off-origin target,
  follow a redirect off-origin, or reuse an off-origin health base.
- Act with the victim's session from injected same-origin script.

**Specified mitigations.**

| Mitigation                                                                                                                                      | Source                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| Unsafe cookie calls need exact `Origin` and `X-SkyOAuth-CSRF`                                                                                   | Design §5.1; API-053       |
| Session and flow cookies are `__Host-`, Secure, HttpOnly and SameSite=Lax                                                                       | Design §4, §5.1; API-055   |
| The SPA gets no access or refresh token, no token getter and no persistent credential storage; CSRF and session metadata stay in bounded memory | Design §10.2; T33.1        |
| The SPA library allows only configured same-origin HTTPS targets, uses same-origin Fetch mode, rejects redirects and ignores caller overrides   | Design §10.2; T33.6, T33.7 |
| An off-origin health base cannot become an authenticated target                                                                                 | Design §10.2               |
| Native confirmation needs exact Origin, CSRF and anti-framing                                                                                   | Design §5.2; API-034       |
| Backends cannot set cookies                                                                                                                     | Design §4; GW-027          |

**Conformance references.** A09, A39 (packaged browser core), A40.

**Task tests.** T33.5, T33.7.

**Residual risk.** HttpOnly limits token extraction, not authenticated
actions by same-origin malicious JavaScript (design §9; GW-029). SameSite=Lax
cookies accompany cross-site top-level GET navigations, so protection
assumes application GET routes are safe (inferred).

**Gaps.** None identified.

### TM-20 — Header spoofing

**Attacker capability.** An external client that sends crafted headers
through the public ingress or an edge, or that tries to reach a backend
directly.

**Attacks.**

- Send identity or assertion headers (`X-SkyOAuth-Assertion`, user headers)
  for the backend to trust.
- Send `Host`, `Forwarded`, `X-Forwarded-*` or `CF-*` to select an origin,
  tenant or provider.
- Send `X-Original-*` or similar headers to change the request the backend
  sees.
- Send headers that select scope or audience.
- Bypass Envoy by calling the backend directly.

**Specified mitigations.**

| Mitigation                                                                                                                  | Source                              |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Envoy strips client identity headers and overwrites the assertion header; client-supplied `X-SkyOAuth-Assertion` is removed | Design §3.1 (3), §4; API-061; T25.4 |
| Canonical authority only from the authenticated trusted gateway chain; spoofed `Host`/`Forwarded` deny before redirect      | Design §4; API-050, IR-033; T30.3   |
| `CF-*` and `X-Forwarded-*` are trusted only inside the configured proxy chain                                               | Design §4                           |
| Browser headers, cookies and query parameters cannot select scope or audience                                               | Design §4.1; IR-065                 |
| No rewrites or trust in client-supplied `X-Original-*`; the backend compares the raw-target digest                          | Design §4.1; GW-005, TP-054         |
| Backends are not directly reachable; internal channels are authenticated                                                    | Design §3.1, §4; T25.4              |
| Optional ForwardAuth never uses plain public-client identity headers                                                        | T32.9                               |

**Conformance references.** A18, A36, A46, A61.

**Task tests.** T25.4, T25.5, T52.4.

**Residual risk.** Edges inside the configured proxy chain are trusted. Each
alternative gateway adapter needs its own review (design §4).

**Gaps.** None new. OQ-GW-4 (verified backend identity) is deferred to
T32.4.

### TM-21 — SSRF

**Attacker capability.** A tenant operator who configures source or provider
URLs, an external issuer that controls its discovery and JWKS responses, or
a token presenter who controls JWT headers.

**Attacks.**

- Point discovery, JWKS, TokenReview or upstream OIDC metadata at internal
  addresses (cloud metadata services, private listeners).
- Use redirect chains to reach internal addresses.
- Use `jku` or `x5u` to make SkyOAuth fetch a URL.
- Return oversized or slow responses.

**Specified mitigations.**

| Mitigation                                                                                                                           | Source                    |
| ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- |
| Discovery uses the exact issuer, approved HTTPS egress, SSRF-safe metadata and JWKS fetches and bounded cache, redirects and refresh | Design §5.4; T11.2, T11.4 |
| TokenReview uses a fixed endpoint, versioned CA and private egress without redirects                                                 | Design §5.4; T11.8, T23.2 |
| `jku`, `x5u`, embedded keys and unsafe URLs are rejected                                                                             | Design §5.4; T11.5, T24.3 |
| Upstream OIDC discovery is SSRF-safe with bounded timeouts; the authorization endpoint is fixed                                      | Design §5.1; T30.3        |
| The internal key set comes from one fixed private endpoint, never a token-selected URL                                               | Design §6.2               |
| Request, token and claim sizes and discovery are bounded and rate limited                                                            | T50.5                     |

**Conformance references.** A03, A05.

**Task tests.** T11.2, T24.3, T30.3.

**Residual risk.** An egress destination on the allowlist that instance
`security_admin` approves is trusted; a tenant operator can choose any
allowlisted destination (OQ-TM-13, decided).

**Gaps.** None open. OQ-TM-13 is decided: tenant operators only choose
egress destinations from the approved allowlist, and secret references
resolve only within the tenant's provisioned namespace (TM-02, §6.1).

### TM-22 — Credential resurrection

**Attacker capability.** Holds an old credential or state (refresh
credential, session, consumed proof, revoked operator credential, closed
continuation), or can trigger a restore, rollback, re-enable, provider
switch-back, limit increase or standby promotion.

**Attacks.**

- Restore a database backup to revive consumed proofs, refresh families,
  sessions or open bootstrap.
- Roll back a provider to revive old sessions or flows.
- Re-enable an origin or route to revive closed continuations.
- Raise a refresh-family limit to revive an expired family.
- Promote a standby key to revive contexts admitted under a disabled key.
- Import configuration to reset consumed state.

**Specified mitigations.**

| Mitigation                                                                                                       | Source                             |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Restore preserves bootstrap-closed and consumed state, or quarantines issuance for a bounded time                | Design §7.2; T10.6; LT-100, LT-106 |
| Rollback and restore never revive credentials or consumed proofs; continuations are not restored as live streams | LT-101, LT-102; T51.8, T51.9       |
| Rollback uses fresh monotonic epochs                                                                             | Design §7.3; LT-030                |
| Proof consumption survives digest-key rotation, provider switch, rollback, failover and restore                  | Design §5.3; T21.8                 |
| Re-enablement cannot resurrect invalidated credentials or closed continuations                                   | Design §4.2                        |
| Limit increases apply only to newly approved families; elapsed or revoked state is never resurrected             | Design §5.2.2; LT-005, LT-010      |
| Standby promotion cannot resurrect contexts admitted under a disabled key                                        | Design §6.2                        |
| Ordinary import is not a replay restore                                                                          | T51.9                              |

**Conformance references.** A17, A33, A34, A35.

**Task tests.** T51.8, T51.9.

**Residual risk.** Restore quarantine costs availability. An attacker with
database write access can rewrite consumed state directly (TM-16).

**Gaps.** None identified.

### TM-23 — Stale streams

**Attacker capability.** A principal whose session, authorization or route
is revoked while a stream or download is open; a backend that fails to
close; a client that reconnects aggressively.

**Attacks.**

- Keep receiving protected bytes after revocation.
- Renew a lease after it expired, or reuse a continuation after close.
- Open many streams or leave orphans to exhaust capacity.
- Reconnect in a storm, or replay a mutation on reconnect.
- Continue a bearer stream past the access token's expiry.

**Specified mitigations.**

| Mitigation                                                                                                                                                                                                                     | Source                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------- |
| A continuation is bound to checker, nonce and context; rechecks occur before `authorized_until`; leases default to 15 s, at most 15 s for critical actions and 300 s for opted-in noncritical reads; contexts last at most 1 h | Design §6.1.1; LT-040                  |
| Terminal denial stops transmission; unavailable never renews a lease                                                                                                                                                           | Design §6.1.1; API-074, LT-041, LT-042 |
| One continuation per assertion `jti`; the tombstone outlives assertion expiry                                                                                                                                                  | Design §6.1.1; API-080, LT-080         |
| Close releases once; foreign close is non-enumerating                                                                                                                                                                          | Design §6.1.1; API-084                 |
| Per-session cap and shared quotas bound open streams; expired contexts stop counting                                                                                                                                           | Design §6.1.1; LT-043                  |
| Bearer streams close by the original token expiry, with no in-band replacement                                                                                                                                                 | Design §6.1; T26.6; LT-014             |
| Clients reconnect with capped backoff and jitter and fresh admission, never replaying mutations                                                                                                                                | Design §6.1.1, §10.2                   |

**Conformance references.** A12, A56.

**Task tests.** T32.12, T52.6.

**Residual risk.** Revocation takes effect within the selected remaining
lease (default 15 s; up to 300 s for opted-in noncritical reads), not
instantly. Orphans count against capacity until their lease ends. A backend
that ignores a denial keeps sending; the backend is trusted to stop.

**Gaps.** None identified.

## 6. Open questions

- **OQ-TM-1 — Threats outside the T00.7 list.** **Decided — lead decision,
  2026-11-19:** cover the union of the T00.7 and design §9 lists; done in §1
  and TM-17 to TM-23. Original question: design §9 lists SSRF, XSS, header
  spoofing, session fixation, credential resurrection and stale streams.
  T00.7 does not. Should this model, or another M0 document, cover them as
  separate entries?
- **OQ-TM-2 — GitHub-side preconditions.** **Decided — lead decision,
  2026-11-19:** SkyOAuth does not rely on GitHub environment protection or
  branch protection. Bindings pin event, ref and workflow; `environment` is an
  additional ANDed predicate. Self-hosted runners shared across trust domains
  are out of scope and recorded as residual risk (TM-01). Original question:
  does a production binding depend on GitHub environment protection rules or
  branch protection, and are self-hosted (possibly shared) runners in scope?
  The sources require an `environment` predicate but say nothing on either
  point.
- **OQ-TM-3 — Reuse of internal assertions.** **Decided — lead decision,
  2026-11-19:** resolved by TP-070: verifiers MUST NOT reject a credential
  only because they have seen its `jti` before. Reuse within the 30 s
  lifetime is residual risk (TM-06). Original question: must a backend reject
  a second use of the same `human_session` assertion `jti` for an ordinary
  request? The assertion binds method, scheme, authority and target but not
  the body (design §4.1); only continuation admission is one-per-`jti`
  (design §6.1.1).
- **OQ-TM-4 — Mix-up defense.** **Decided — lead decision, 2026-11-19:**
  require the RFC 9207 `iss` check when the provider advertises it; otherwise
  use per-provider callback paths on the issuer. Spec amendments: §6.1. Original question: is the RFC 9207 `iss` authorization-response
  parameter required where the provider supports it, given the issuer
  `/oauth/callback` is shared by all tenants' providers?
- **OQ-TM-5 — Native redirect matching.** **Decided — lead decision,
  2026-11-19:** following RFC 8252 §7.3, a registered rule fixes scheme
  `http`, the IP literal (`127.0.0.1` and/or `[::1]`) and the path; the port
  varies per request and is bound exactly per transaction; `localhost` is
  rejected. This resolves a tension in the sources: design §10.3 has the CLI
  bind an ephemeral listener and choose its port per authorization, while the
  identity-registry table ("Exact IP-loopback redirects" for
  `OAuthClient.redirect_rules`) and T40.1 ("Exact IP-loopback redirect
  rules") read as fixing the whole URI. Spec amendments: §6.1.
  Original question: do registered `redirect_rules` fix the loopback port or
  allow a per-request port (RFC 8252 §7.3)? Which loopback literals and paths
  are allowed, and is `localhost` rejected?
- **OQ-TM-6 — Verified linking ceremony.** **Decided — lead decision,
  2026-11-19:** two distinct operations. Operator enrollment that creates a
  new principal is operator-asserted and audited. Linking to an existing
  principal uses a browser-bound transaction that proves both identities; if
  the old IdP is unavailable during migration, an operator-asserted link is
  allowed with OQ-TM-7 approval and user notification. Spec amendments: §6.1. Original question: what proof establishes a verified
  link, how is a browser-bound linking transaction started and approved, and
  how does it relate to the `provider_admin` `/human-links` endpoint?
- **OQ-TM-7 — Separation of duty for identity-critical writes.** **Decided —
  lead decision, 2026-11-19:** provider switch and rollback commit, and links
  to existing principals, need a distinct second `adm_*` approver
  (`security_admin` or another `provider_admin`). Single-actor mode is
  allowed only through an explicit audited instance policy, for small
  installations (design §1.3). Enrollment resume creates only zero-privilege
  principals, so a single actor may perform it. The rule covers every plan
  commit except a disable-only commit: authentication-critical changes to the
  active provider, activation from null, switch and rollback. A disable-only
  commit fails safe and needs no second approver. Spec amendments: §6.1. Original question: should provider switch commit, link creation and
  enrollment resume need a second approver or another role? The sources allow
  one `provider_admin` to perform all three.
- **OQ-TM-8 — Recovery scope and key lifecycle.** **Decided — lead decision,
  2026-11-19:** operator restoration through recovery only enrolls a
  replacement `security_admin` credential and revokes operator credentials.
  The challenge TTL defaults to 5 min with a 15 min maximum (LT-107). Every
  break-glass transaction (operator restoration or provider switch/rollback)
  enrolls a replacement recovery public key in the same signed transaction
  and retires the used key. v0.1 has a single recovery key; a quorum is deferred. Spec amendments: §6.1. Original question: what may "bounded operator
  restoration" enroll or revoke? What is the challenge lifetime? How, and by
  whom, is the recovery key rotated after use? Is a quorum of recovery keys
  supported?
- **OQ-TM-9 — Local recovery channel access.** **Decided — lead decision,
  2026-11-19:** the socket is owned by the service UID with mode 0600.
  `pods/exec` on the SkyOAuth namespace is equivalent to channel access and is
  limited to infrastructure administrators who are already trusted. Original
  question: which deployment principals may reach the deployment-local
  bootstrap/recovery channel?
- **OQ-TM-10 — Public signer isolation and compromise response.** **Decided
  — lead decision, 2026-11-19:** processes that serve Check or hold internal
  keys get no public-signing permission, which is the separation T00.8 asks
  to ratify. Public-key emergency disable and rotation is decided: a
  prepublished standby, a bound on JWKS cache max-age and an admin endpoint
  (this resolves OQ-API-3). The token-issuing replica is modelled in TM-16.
  Spec amendments: §6.1. Original question: what isolation is the
  v0.1 minimum for the public signer, and what is the emergency disable and
  rotation procedure for a compromised public key?
- **OQ-TM-11 — Independent observation.** **Decided — lead decision,
  2026-11-19:** accepted as v0.1 residual risk. Backend credential
  validation compensates, T52.8 reviews the boundary, and an independent
  read-only observer may come later. Design §11 (M3 "isolated observer") and
  ADR-020 ("fixed mTLS observer") describe the isolated management listener
  that the controller reads (design §4.2), not an observer independent of the
  controller. Original question: is it accepted that the route controller is
  both the sole writer and the sole source of observations for its scope, or
  is an independent observation path required?
- **OQ-TM-12 — Audit sink independence.** **Decided — lead decision,
  2026-11-19:** security events (operator writes, recovery, key operations,
  provider switches and the standby tripwire) are also emitted to an
  append-only external sink. The database audit stays authoritative.
  **Decided — lead decision, 2026-11-19:** v0.1 requires an
  operator-configured sink: an append-only, hash-chained JSONL stream (one
  chain per instance) forwarded to a configured syslog-over-TLS or OTLP-logs
  endpoint. The endpoint, protocol and TLS trust or credential reference are
  instance deployment configuration, not a tenant secret namespace; the
  database holds only `audit_sink_config_digest` and `audit_sink_validated_at`,
  and observed sink health is a metric and health signal, not a revisioned row.
  "Configured" means the endpoint is set and validated at startup. A
  configuration change takes effect only on restart and first emits a "sink
  changed" event to the old sink, plus an audit event. Public-signer key
  enrollment, activation and publication are refused until a sink is
  configured. Emergency disable and standby promotion are never refused: a
  sink outage or missing sink raises an alert and a local append-only record,
  and the operation proceeds; if the sink configuration is removed while keys
  are published, the instance starts degraded with an alert and disable still
  works. Sink delivery failures are alerting events. (tasks Gate M1a
  and §3; ADR-002 item 4). It is implemented under T50.6. Still open: the
  sink TLS trust settings and alert routing.
  Spec amendments: §6.1. Original question: must audit events and
  alerts also be sent to a store outside PostgreSQL so a database-write
  compromise cannot erase them?
- **OQ-TM-13 — External secret references and egress approval.** **Decided
  — lead decision, 2026-11-19:** secret references resolve only within a
  per-tenant provisioned secret namespace, so a reference cannot name a
  secret provisioned for another tenant. Discovery, JWKS and TokenReview
  egress destinations come from an allowlist approved by instance
  `security_admin`; tenant operators only choose from it. The amendment must
  land before M1a (T11.8); it has landed in T11.2, T11.8, T23.2 and the tasks
  §3 schema (`EgressAllowlistEntry`, `Tenant.secret_namespace`). Spec amendments: §6.1. Original
  question: which external secrets may a tenant `trust_admin`
  (`token_review_endpoint`, `ca_bundle_ref`, `reviewer_credential_ref`) or
  `provider_admin` (provider `credential_ref`) reference, can a reference
  name a secret provisioned for another tenant, and who approves discovery
  and TokenReview egress destinations? (TM-02, TM-21)
- **OQ-TM-14 — Bulk session revocation.** **Decided — lead decision,
  2026-11-19:** add a revision-checked, audited operation that advances the
  tenant's `auth_generation` without a provider change, which invalidates the
  tenant's sessions in bulk. It advances only `auth_generation`; the provider
  `auth_epoch` advances only with a provider transition (lifetimes §4). It must be specified before M1b and M3. It is
  `POST /admin/v1/tenants/{tenant}/login-state/compromise-transitions`, run
  by tenant `provider_admin` as a single actor with no second approver; no
  single-origin variant (API-154). The instance-wide response that runs it for
  every tenant is a separate endpoint; its path, per-tenant revision checks,
  atomicity and partial-failure rules are open (OQ-ADR021-3). Spec amendments: §6.1. Original question: after an auth-replica
  compromise, exposed session cookies stay valid until their sessions are
  revoked or expire. Should there be an operation that revokes all sessions
  of a tenant, origin or instance without a provider transition? Related:
  OQ-API-2. (TM-16)
- **OQ-TM-15 — Online recovery-key rotation.** **Decided — lead decision,
  2026-11-19:** no online path replaces the recovery key. Only a transaction
  signed by the recovery key over the deployment-local channel does
  (OQ-TM-8). Spec amendments: §6.1. Original question: may an
  online `security_admin` replace or rotate the recovery public key
  ("signer/recovery policy", design §7.2), or only the signed recovery
  transaction (OQ-TM-8)? (TM-15, TM-17)
- **OQ-TM-16 — Signer re-check.** **Decided — lead decision, 2026-11-19:**
  v0.1 accepts the residual risk that the public signer does not re-check
  issuance policy. The signer enforces structural limits: `typ` and profile,
  `iss`, a registered audience, and `exp` − `iat` ≤ 300 s. It logs every
  signature to the external sink (OQ-TM-12). Spec amendments: §6.1. Original question: does a separately deployed public signer
  re-validate issuance policy for what it signs, or sign whatever the
  token-issuing replica submits? (TM-16)

### 6.1 Spec amendment follow-ups

These decisions change spec text. Under design §12 each needs the matching
amendment to the design, tasks plan and contracts. The spec-amendments PR
carries the design and tasks amendments and the contracts follow-up carries
the contract amendments; what is still open is named in the entry:

- **OQ-TM-4:** design §5.1 and §5.2 (RFC 9207 `iss` check, per-provider
  issuer callback paths); API-032 (previously named `/oauth/callback` as the
  only native upstream callback) and GW-036; T30.1, T40.12.
- **OQ-TM-5:** design §5.2 and §10.3; `OAuthClient.redirect_rules` in the
  identity registry; API-031; T40.1, T40.9.
- **OQ-TM-6:** design §5.1 and §5.1.1; the tasks endpoint matrix
  `/human-links` entry; API-155; T30.4, T51.3.
- **OQ-TM-7:** design §7.2, §7.3 and §8; API-148; the link operation
  (API-155); T13.9,
  T51.1. Still open (OQ-ADR012-3, ADR-012): whether a switch signed with the
  recovery key through the local recovery verifier while the IdP is
  unavailable needs the second approver or takes an audited single-actor
  exception; the lead decides before M1b. Spec follow-up against design §7.2
  and §7.3, T13.5, T13.9 and OQ-TM-7. Contracts: `single_actor_mode` is the
  explicit audited instance policy (identity-registry IR-053); the optional
  widening approver and second-approver approvals are identity-registry
  IR-052 and IR-054 (with OQ-ADR008-3).
- **OQ-TM-8:** design §7.2; T13.5; API-152 and T13.4 (scope of the recovery
  transaction: replacement `security_admin` credential, operator-credential
  revocation, replacement recovery public key). Still open: whether setting
  `single_actor_mode` is a further recovery transaction kind that also
  replaces the recovery key (identity-registry OQ-IR-13).
- **OQ-TM-9:** design §7.2 (recovery socket owned by the service UID, mode
  0600; `pods/exec` on the SkyOAuth namespace restricted to trusted
  infrastructure administrators); T13.4; T50.1.
- **OQ-TM-10:** design §3.1, §6 and §6.2; T20.2, T50.3; ADR-002; a public
  access-token key administration endpoint (OQ-API-3), now API-153 with
  API-042 and API-043 for the JWKS bounds.
- **OQ-TM-12:** design §7 and §7.2; ADR-002 item 4; tasks Gate M1a and §3
  (`InstanceSecurityPolicy`, `AuditEvent`); T13.3, T20.2, T50.6. Contracts
  (read-only sink fields, the key gate and the hash chain): identity-registry
  IR-053 and IR-055, public-api API-153 and API-156.
- **OQ-TM-13:** design §5.4 and §7.2 (per-tenant secret namespace for
  `ca_bundle_ref`, `reviewer_credential_ref` and provider `credential_ref`;
  `security_admin`-approved egress allowlist); T11.2, T11.8, T23.2; the tasks
  §3 schema (`EgressAllowlistEntry`, `Tenant.secret_namespace`); before M1a.
  Contracts: identity-registry IR-034 and IR-152 (degraded sources, `jwks_uri`
  at fetch and widening class: OQ-IR-12, decided); the public-api egress
  allowlist endpoints (OQ-API-13, decided).
- **OQ-TM-14:** design §5.1.1 and §7.3; tasks §3 (`TenantLoginState`); the
  public-API operator endpoint matrix (OQ-API-2), now API-154; the lifetimes
  contract §4
  epochs table (split: the compromise transition advances only
  `auth_generation`); T31.6; before M1b and M3. Still open (OQ-ADR021-3,
  ADR-021): the instance-wide response endpoint, its path, per-tenant revision
  checks, atomicity and partial-failure rules.
- **OQ-ADR023-1 and OQ-ADR023-2 (ADR-023, decided; amendments not yet
  applied):** disabling the active provider sets the enrollment hold;
  activation from null after any provider was ever active is a switch, sets
  the hold and cannot use the fresh-install `auto_create`; a true fresh install
  sets no hold. Design §5.1.1, T13.9 and the TM-10 rows still say only switch
  and rollback set the hold. Needed: design §5.1.1 and §7.3; tasks §3 (a
  durable record that a provider was ever active); T13.9; API-148 and the
  provider-switch commit row; TM-10.
- **OQ-TM-15:** design §7.2 ("signer/recovery policy" excludes replacing the
  recovery key); API-152; T13.5.
- **OQ-TM-16:** design §3.1 and §6 (public signer structural limits and
  signature logging); T20.2, T50.3; T50.6 (external sink).

## 7. Contradictions and deployment implications

### 7.1 Contradictions

1. **Browser-bound linking versus operator linking.** Design §5.1 and T30.4
   require verified linking to use "an initiating-browser-bound transaction
   and explicit proof/approval". The tasks endpoint matrix gives
   `provider_admin` "controlled verified human enrollment/linking" through the
   operator API (`/admin/v1/tenants/{tenant}/human-links`), and design §5.1.1
   lets operators "preprovision through the existing verified-enrollment
   path". Whether an operator-created link must also be browser-bound is not
   stated. Decided by OQ-TM-6 (enrollment of a new principal versus a link to
   an existing principal); design §5.1.1, T30.4 and the tasks matrix carry
   it (§6.1).

Contradictions recorded in the contracts and relevant here are decided:
OQ-GW-8 (gate scope, GW-115), OQ-GW-14 (admission exception list, GW-056)
and OQ-LT-14 (ADR-010 record).

### 7.2 Requirements with unstated deployment implications

1. **Signer separation.** Design §6.2 states that signer-group replicas "have
   no public access-signing permission" and that a compromised internal
   signer "cannot mint public access tokens". T00.8 ratifies distinct public
   and internal signer isolation, T50.3 isolates them, T52.5 tests the
   separation and ADR-002 records distinct public and internal signers. This
   is a requirement, not a contradiction, but the sources do not spell out
   what it means for the baseline of "two or more stateless replicas" (design
   §4) with a public signer that "can be separately deployed" (design §3.1).
   It means that a process serving Check or holding internal keys cannot also
   hold public signing permission (decided, OQ-TM-10). The replica that serves
   `/oauth/token` (which issues access tokens) together with `/oauth/authorize`
   and `/oauth/confirm` still needs public signing. Signer isolation protects
   the key, not the signing service. In v0.1 the signer enforces structural
   limits and logs every signature but does not re-check issuance policy
   (decided, OQ-TM-16); TM-16 models that replica and its residual risk.

## 8. Changing this model

Design §12 applies: a changed decision updates the design, the tasks plan,
the affected contracts, this threat model and the conformance references
together. The T00.7 checkbox stays unchecked until this model is reviewed.
