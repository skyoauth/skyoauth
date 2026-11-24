# ADR-020: Browser routing, route admission and deployment binding

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Questions still marked open under Open questions stay open: ratification closes none of them.
- **Tasks:** ratified with T00.6 (which names ADR-020 for the full-origin apply
  interruption and cleanup independence), T00.5 (protected-scope projection,
  activation modes, apply timeout, cancel, revoke and abort authority) and
  T00.16 (origin and route tenant-audience resolution) (the T00.5 and T00.16
  pairings are inferred from their wording). Implementation: T14.5, T14.7,
  T14.9, T32.3, T32.4, T32.11, T50.4, T52.8.
- **Baseline (tasks §11):** "Assigned origin/distinct app-native bindings and
  guarded Gateway/listener/host scope. M3 isolated pinned translation precedes
  approval; scoped list/result APIs discover/finalize work. Project protected
  vhosts and ordered effective filters/shared dependencies, excluding only
  proven-inert other-host filters; HCM changes may still drain connections.
  Sandbox the translator away from controller credentials. Mode is immutable
  preparation/approval input; wrong-mode execution and fallback deny.
  Registry-only activation reuses unchanged fresh deployment evidence without
  refreshing its age or closing the gate; real gateway apply interrupts origin
  cookie traffic, unchanged contexts get unavailable only to their lease,
  cleanup stays independent. Gateway approval binds a persisted bounded apply
  deadline and exact compensation; scoped administrative cancel preserves it,
  explicit security_admin revoke stops both write directions. Failed
  compensation permits only new approved gateway_apply supersession, fenced
  journal/inventory inheritance and a validated restore_pair or explicit
  non-serving cleanup_to_closed target. Secret substitution is
  supervisor-validated/adapter-tested, never real material in the helper or
  permission to invent missing dependencies; independent real dependency
  evidence remains mandatory. Renewable downstream TLS binds an approved
  reference/profile/writer, not observed leaf/resourceVersion: independently
  verified old/new overlap is bounded without gate closure/reapproval or age
  reset, confirmed invalid/unaccounted current or served material denies
  terminally; missing/late convergence is unavailable without renewal. Fresh
  complete current-candidate proof under the unchanged contract may clear only
  the TLS blocker/reset the bounded candidate state under a new sequence, never
  sample ages or closed contexts. Invalid issuances consume no accepted slot.
  Exact-mode Secrets instead rotate by staged frozen new reference and scheduled
  approved gateway_apply, retaining a usable guarded abort source; no in-place
  renewal or validity waiver. Global UID-keyed credential holds have scoped
  admin/provisioner views with foreign reasons opaque; only zero-hold CAS
  sealing plus fenced guard acknowledgement authorizes exact UID/RV/principal
  deletion. Retiring UIDs cannot gain new holds and unknown state remains
  protected. security_admin registers the deployed scope tuple; the service
  verifies it, infrastructure owns whole-namespace denial and the maximum writer
  envelope, and the reconciler changes only bounded service-approved live
  entries under a monotonic mutation guard. A non-referenceable cert-manager
  temporary-key class has fixed creator/owner/marker CREATE/DELETE rights and no
  UPDATE/reclassification; test cleanup through repeated issuance.
  Namespace/parameter reservations stay exclusive while disabled; same-ID PATCH
  preserves verified maintenance until candidate handoff, and disable drains via
  move-away/retirement before authenticated decommission releases reservations.
  Continuously protected same-consumer/contract holds keep their proofs during
  pending PATCH, after verified same-ID cutover and through
  protection-reconciler outage for compensation and inherited recovery. Cutover
  requires continuous compatible coverage, rejects prior-revision
  acknowledgements and requires current-revision evidence for new adoption.
  Known protection loss invalidates the proof. Deadlines do not extend.
  Untracked invalid staging uses metadata registration plus the same sealed
  cleanup, never a bypass. Scoped redacted admin reads expose attempt
  IDs/revisions/reasons/deadlines for cancel/recovery without controller access;
  a newer disable/forward expiry after begin triggers abort/reobserve, never
  restoring security state. Known out-of-plan mismatch closes immediately with
  terminal rechecks and no stale allowance. Sole-writer GitOps cost, >=2 fenced
  controllers, fixed mTLS observer, poll<=10s/stale30s/max300s and cluster-admin
  boundary remain explicit."
- **Contracts:** [gateway-containment.md](../contracts/gateway-containment.md)
  §5–§14; [lifetimes.md](../contracts/lifetimes.md) §6, §7, §10;
  [public-api.md](../contracts/public-api.md) §3, §6, §7.2, §8;
  [identity-registry.md](../contracts/identity-registry.md) §4.

## Context

Browser requests carry a cookie, not an audience. SkyOAuth must decide from the
request's origin and path which tenant, provider, resource server and policy
apply, and the gateway must route the same request to the same receiver (design
§4, §4.1). If a gateway edit, a shadow route or a shared listener filter could
change routing or authentication without SkyOAuth knowing, a valid session
cookie could reach a backend under the wrong policy (design §4.2; T00.7 "shadow
routes"). There is no distributed atomic write across the registry and Envoy, so
changes must be prepared, approved, applied and observed, and failures must be
compensated within bounded authority (design §4.1, §4.2). Downstream TLS
certificates renew routinely, while exact-mode credentials must never be deleted
while a deployment or abort path depends on them (design §4.2). The credential
containment rules applied on every route are ADR-007; lease outcomes under the
gate are ADR-010.

## Decision

### Assigned origins and distinct flow bindings

1. **Assigned origin.** `ApplicationOrigin` binds one canonical HTTPS origin to
   one tenant, callback, allowed return paths and approved audience IDs.
   Instance `security_admin` enrolls origin ownership; a tenant cannot claim
   another tenant's host, and v0.1 does not multiplex tenants on one origin
   (design §4; T14.5).
2. **Resolution.** Browser tenant and provider come from the registered origin
   and `TenantLoginState`, never from a `tenant` query or untrusted forwarded
   header; canonical authority is accepted only from the authenticated gateway
   chain. Unknown, ambiguous, spoofed or disabled origins deny before redirect
   (design §4; T14.7).
3. **Distinct app and native bindings.** App-origin `__Host-skyoauth_login` and
   issuer-origin `__Host-skyoauth_native` are separate host-only cookies with
   separate transactions; neither substitutes for the other (design §4, §5.1,
   §5.2; ADR-003, ADR-004).

### Route selection

4. `ApplicationRoute` versions record an exact or segment-prefix path, a
   nonempty method allowlist, exactly one resource server, accepted profiles,
   lease and stream duration. Cookie requests resolve only the versions pinned
   by the active `RouteBundleVersion`; headers, cookies, query and body never
   select an audience. Exact beats prefix; then the longest segment prefix;
   equal-precedence conflicts are rejected on write; the winner is selected
   before status is checked, and a disabled winner denies with no broader
   fallback (design §4.1; T14.7).
5. v0.1 allows one `RouteBundle` per `ApplicationOrigin`, so the gate is
   origin-wide (lead decision OQ-GW-8, GW-115).

### Guarded Gateway, listener and host scope

6. `security_admin` enrolls the protected set by cluster, Gateway UID, listener
   and hostname intersection. A `ValidatingAdmissionPolicy` and binding with
   `failurePolicy: Fail` and `validationActions: [Deny]`, plus RBAC, restrict
   writes affecting it to the route-controller service account, covering new and
   unlabeled routes, wildcard hostnames, shadow routes, parentRefs,
   cross-namespace attachment and namespace selectors. Installation is verified
   before protected traffic (design §4.2). The enrolment is stored in a
   dedicated protected-set entity, separate from `CredentialProtectionScope`
   (lead decision, 2026-11-19, OQ-ADR020-1); adding it to the tasks §3 logical
   model is a spec amendment follow-up (inferred). The issuer host, which is
   not an `ApplicationOrigin`, is the single exception to one bundle per
   origin: one instance-level system bundle, owned and prepared by instance
   `security_admin`, carries its protected scope, projection and observations.
   Adding a per-provider issuer callback path is a system-bundle apply (ADR-004
   item 2). An origin cannot be security-enabled without an enrolled protected
   scope: a new origin starts security-disabled with reason `not_enrolled`
   until the first approved `gateway_apply` covering its verified scope enables
   it (lead decision, 2026-11-19, OQ-GW-12; T14.5, T14.9).
7. Non-cookie bearer, public, auth and health paths on a protected host are
   managed in the same bundle with explicit authentication classes. Shared
   Gateway-wide policy or listener changes need approval of all affected bundles
   or are rejected (design §4.2).
8. Admission exceptions are exactly four: narrow status-only updates by the
   gateway controller, the scoped TLS-renewer update, the non-referenceable
   temporary-key CREATE and DELETE class and sealed retirement DELETE (lead
   decision OQ-GW-14, GW-056).
9. **Sole writer.** The route controller is the sole writer for the protected
   configuration. Helm, Argo CD and Flux may render and submit approved bundle
   inputs but do not apply managed objects while the guard is installed. This
   deployment dependency is recorded here; a future design admitting existing
   deployers' writes against approved digests is an alternative, not a second
   writer (design §4.2; T10.7).

### Preparation, projection and translator sandbox

10. **Preparation before approval.** Tenant `client_admin` requests preparation;
    the immutable `route_bundle_prepare` operation snapshots inputs, expected
    generation, versions, security preconditions, `activation_mode`, apply
    timeout and any recovery intent. The M3 controller's preparation worker runs
    the pinned translator and submits a scoped result; the service finalizes one
    immutable `RouteBundleVersion` with the expected gateway digest and a
    server-computed plan digest. Scoped list and read APIs let the controller
    discover and finalize work; no caller supplies the expected digest (design
    §4.2; T14.9, T32.3).
11. **Projection.** The same versioned `P(configuration, protected_scope)` is
    computed on prepared xDS and observed configuration: protected virtual hosts
    and filter chains, all routes and authentication classes on the host,
    reachable clusters and shared listener, HCM, TLS and normalization settings,
    and the ordered effective HTTP filter chain with its shared dependencies. A
    filter for another host is excluded only when the pinned adapter proves it
    inert on every protected request path; unknown reachability is retained.
    Excluding a filter from the digest does not mean HCM or listener changes
    cannot drain connections (design §4.2; T50.4).
12. **Sandbox.** The translator (`egctl x translate`) runs as an isolated,
    bounded helper with fixed binary and arguments, no shell, no network and no
    access to the controller's service-account token, mTLS key, kubeconfig or
    secret mounts. Missing-resource synthesis is disabled (design §4.2).
13. **Secret substitution.** The credentialed supervisor validates every
    referenced Secret's real existence, permissions, type, keys and material,
    records nonsecret `secret_dependencies` and substitutes an adapter-versioned
    nonproduction placeholder of the same shape. It is the only permitted
    substitution, must be adapter-tested to preserve projected structure, never
    puts real material in the helper and never invents a missing dependency;
    independent real dependency evidence remains mandatory for eligibility
    (design §4.2).

### Activation modes

14. **Immutable mode.** `activation_mode` (`registry_only` or `gateway_apply`)
    is an immutable preparation and approval input included in both digests;
    there is no automatic mode. Wrong-mode transitions reject without changing
    the gate, and a failed fast path never falls back to a disruptive apply
    (design §4.2).
15. **Registry-only.** `activate_registry_only` switches pins without gateway
    writes or gate closure only when managed resources, dependencies, scopes,
    adapter and projection versions, expected digest and serving-set generation
    are verified unchanged, observations are complete and fresh (within 30
    seconds) and `reenable_targets` is empty. It keeps the original samples,
    collection times and deadlines; it never refreshes their age or extends the
    deadline (design §4.2; T00.6).
16. **Gateway apply.** `begin` closes the origin gate before any write. In the
    words of T00.6 and this ADR's baseline: real gateway apply interrupts origin
    cookie traffic, unchanged contexts get unavailable only to their lease,
    cleanup stays independent. Throughout applying, abort_required, aborting and
    recovery_required, new gated application cookie requests and admissions get
    503 `route_configuration_unavailable` with bounded `Retry-After`; reopening
    requires fresh complete evidence (design §4.1, §4.2; ADR-010 item 19). The
    503 does not cover the routes that stay available while the gate is closed
    (API-130): the cleanup endpoints, and `/_skyoauth/login` and
    `/_skyoauth/callback`, which the route controller preserves during the apply
    and which are not subject to the gate (API-132, API-134). While the gate is
    closed, login and callback are served only if the origin has an active
    pinned `ApplicationOriginVersion` and the origin parent is security-enabled;
    otherwise they deny before any redirect, and all their own checks (API-050
    to API-052) still apply. They never mint an application assertion or
    forwarding authority (API-131). Decided (lead decision, 2026-11-19,
    OQ-API-1; design §4.2 amended).

### Approval, apply deadline, cancel and revoke

17. **Exact approval.** `security_admin` approves only a completed prepared
    version. The expiring approval binds the plan digest, version, expected
    generation, scopes, adapter inputs, parent security revisions,
    `reenable_targets`, mode and `abort_plan`; gateway apply also binds
    `apply_timeout_seconds` (default 120, at most the instance ceiling of 300)
    and grants exact compensation until `abort_until` later than its forward
    `expires_at`. A controller credential cannot substitute for preparer or
    approver (design §4.2).
18. **Persisted deadline.** `begin` durably sets
    `apply_deadline = min(begun_at + apply_timeout_seconds, approval.expires_at)`;
    ownership transfer never grants another interval; activation at or after the
    deadline rejects (design §4.2).
19. **Cancel versus revoke.** Scoped `client_admin` or `security_admin` cancel
    marks the current attempt `abort_required`, performs no gateway writes and
    keeps the approved compensation authority and deadlines. Only
    `security_admin` revoke stops both forward and compensating writes, moving
    an unfinished attempt to `recovery_required` with the gate closed (design
    §4.2).
20. **Administrative reads.** Scoped redacted admin reads expose attempt ID,
    revision, reason and deadlines for cancel and recovery without controller
    access, journal, manifests or Secret material, independent of the traffic
    gate (design §4.2).

### Abort, recovery and supersession

21. **Exact compensation.** Abort restores only the approved `abort_plan` under
    journal, UID, resourceVersion and ownership preconditions; `complete_abort`
    reopens the prior pair only on fresh complete evidence and restores no
    security state. A newer disable or forward expiry after begin triggers abort
    and reobservation, never restoring security state (design §4.2).
22. **Supersession.** Failed compensation leaves `recovery_required`; only a
    newly prepared and approved `gateway_apply` supersession may replace it,
    inheriting the fenced journal and recovery inventory. Its `abort_plan` is
    either a revalidated `restore_pair` or an explicitly approved non-serving
    `cleanup_to_closed` target that preserves fixed SkyOAuth cleanup endpoints
    and unrelated hosts (design §4.2).
23. **Security-revision-bound recovery.** Disable advances the parent's
    `security_revision` and invalidates captured plans; only explicit
    `reenable_targets` in a freshly approved activation clear named parents
    (design §4.2; gateway-containment §14).

### Downstream TLS renewal

24. **Renewable contract.** A `tls_renewal` listener binds an approved Secret
    reference, UID, type, listener and SNI, validation profile and enrolled
    renewal writers, not an observed leaf or resourceVersion. A permitted
    renewal changes neither the expected digest nor contexts (design §4.2).
25. **Bounded overlap.** Independently verified old and new leaves may overlap
    until `overlap_until` without gate closure, reapproval or sample-age reset.
    Missing or late convergence at the cutoff is unavailable without renewal;
    confirmed invalid or unaccounted current or served material denies
    terminally. Fresh complete current-candidate proof under the unchanged
    contract may clear only the TLS blocker and reset the bounded candidate
    state under a new sequence, never sample ages or closed contexts. Invalid
    issuances consume no accepted slot (design §4.2).
26. **cert-manager temporary keys.** A non-referenceable temporary-key class has
    fixed creator, owner and marker CREATE and DELETE rights, no UPDATE or
    reclassification, and is tested through repeated issuance (design §4.2).

### Exact-mode rotation and credential holds

27. **Exact-mode rotation.** Exact-mode Secrets rotate by a staged frozen new
    reference and a scheduled approved `gateway_apply`, retaining a usable
    guarded abort source; no in-place renewal or validity waiver (design §4.2).
28. **Global holds.** UID-keyed `CredentialDependency` holds span all bundles;
    scoped admin and provisioner views keep foreign reasons opaque. Only
    zero-hold CAS sealing plus a fenced guard acknowledgement authorizes
    deletion by exact UID, resourceVersion and principal. Retiring UIDs cannot
    gain holds, and unknown state stays protected; untracked invalid staging
    uses metadata registration plus the same sealed cleanup (design §4.2).
29. **Protection scopes.** `security_admin` registers the deployed scope tuple;
    the service verifies it; infrastructure owns whole-namespace denial and the
    maximum writer envelope; the reconciler changes only bounded
    service-approved live entries under a monotonic mutation guard. Namespace
    and parameter reservations stay exclusive while disabled; disable drains
    through move-away and retirement before decommission. Continuously protected
    same-consumer holds keep their proofs across PATCH, verified same-ID cutover
    and reconciler outage; known protection loss invalidates the proof (design
    §4.2; GW-210 to GW-213). Cutover requires continuous compatible coverage,
    rejects prior-revision acknowledgements and requires current-revision
    evidence for new adoption (GW-211 to GW-213, inferred mapping: no GW ID
    states the cutover rule itself). Deadlines do not extend (GW-121, GW-123,
    GW-132, GW-155).

### Observation and its limits

30. **Mechanism.** The controller reads a separate static mTLS management
    listener (EnvoyProxy bootstrap customization) with an exact GET allowlist of
    fixed `config_dump` targets; no generic admin proxy, no secrets dump, no
    pods/exec (design §4.2).
31. **Bounds.** Poll each traffic-eligible proxy at least every 10 seconds;
    stale and alert at 30 seconds; retain a verified deployment for at most 300
    seconds from sample collection start, with no allowance during gateway apply
    or known mismatch (design §4.2; T00.6).
32. **Known mismatch.** A current authenticated out-of-plan digest mismatch
    closes the gate immediately; rechecks return terminal deny with no stale
    allowance (design §4.2).
33. **Explicit costs.** The sole-writer GitOps cost, at least two fenced
    controller replicas, the fixed mTLS observer, the polling bounds and the
    cluster-admin trust boundary are stated; administrators who can remove the
    guards or replace the data plane are outside the guarantee (design §4.2;
    tasks §11).

## Consequences and requirements

- Contract requirements: GW-010 to GW-016 (configuration digests), GW-050 to
  GW-058 (protected scope and admission), GW-060 to GW-065 (projection), GW-070
  to GW-076 (preparation), GW-080 to GW-085 (sandbox), GW-090 to GW-092 (pinned
  inputs), GW-100 to GW-106 (management listener), GW-110 to GW-115, GW-120 to
  GW-126, GW-130 to GW-137, GW-140 to GW-146, GW-150 to GW-155 (activation,
  apply, roles, abort, supersession), GW-160 to GW-166, GW-170, GW-180 to
  GW-186, GW-190, GW-191, GW-200, GW-201, GW-210 to GW-213 (Secrets, TLS,
  holds), GW-220 to GW-227, GW-230 to GW-236 (observation, recovery and first enablement); LT-050
  to LT-055, LT-090 to LT-094; API-130 to API-134 (independence from the gate),
  API-140 to API-146 (approval boundaries).
- Every gateway apply on an origin interrupts all its cookie streams; operators
  schedule applies and exact-mode rotations accordingly (design §4.1, §4.2).
- GitOps tools cannot apply protected objects directly (design §4.2).
- Every alternate gateway adapter, including ForwardAuth, needs its own reviewed
  equivalent (design §4.2; T32.9).
- Conformance rows: A58 (primary), A46, A51, A52, A18, A61.

## Alternatives considered

- **Opt-in labels for protection.** Rejected; the protected set is enrolled by
  scope (design §4.2).
- **Distributed atomic write across registry and gateway.** Not claimed (design
  §4.1).
- **Automatic activation mode or fallback to apply.** Rejected (design §4.2).
- **Direct GitOps apply of protected objects.** Rejected while the guard is
  installed; admitting existing deployers against approved digests is a future
  alternative (design §4.2).
- **Trusted per-route audience metadata.** A future alternative under ADR-007
  and ADR-020 (design §4.1).
- **General rollback API for unfinished applies.** Rejected; compensation is
  bounded to the approved `abort_plan` (design §4.2).
- **In-place renewal of exact-mode credentials.** Rejected (design §4.2).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-GW-1** — management listener literals. Decided (lead decision,
  2026-11-19): T00.5 freezes the shape; literals move to T32.3 and T50.4.
- **OQ-GW-2** — pinned versions. Decided (lead decision, 2026-11-19): T00.5
  freezes what is pinned; the version pair is chosen in T32.3 and T50.4.
- **OQ-GW-3** — exemptions. Decided (lead decision, 2026-11-19): the seven
  fixed cookie endpoints plus each exact registered per-provider issuer
  callback path `/oauth/callback/{provider_id}` (GW-036, OQ-TM-4);
  per-endpoint retained headers still open.
- **OQ-GW-4** — verified SkyOAuth backend identity. Deferred (lead decision,
  2026-11-19) to T32.4.
- **OQ-GW-5** — literal filter chain and assertion-header stripping stage
  (open).
- **OQ-GW-6** — guarded inventory kinds are not enumerated (open).
- **OQ-GW-7** — digests. Decided (lead decision, 2026-11-19) in part: SHA-256
  over RFC 8785 JCS for configuration digests.
- **OQ-GW-8** — gate scope. Decided (lead decision, 2026-11-19): one bundle per
  origin.
- **OQ-GW-9** — compensation authority. Decided (lead decision, 2026-11-19): an
  unrevoked approval and current controller scope; disabling the preparer or
  approver does not stop it, only explicit revocation does.
- **OQ-GW-10** — cancel outside `applying`. Decided (lead decision, 2026-11-19):
  rejects with no state change.
- **OQ-GW-11** — numeric helper bounds (open).
- **OQ-GW-12** — enrolled host. Decided (lead decision, 2026-11-19): the issuer
  host is enrolled for containment; (a) one instance-level system bundle
  carries its protected scope, projection and observations; (b) an origin
  cannot be security-enabled without an enrolled protected scope (item 6).
- **OQ-GW-13** — supported exact-mode usages are not enumerated (open).
- **OQ-GW-14** — admission exceptions. Decided (lead decision, 2026-11-19):
  exactly four.
- **OQ-LT-4** — `abort_until` instance maximum (open).
- **OQ-LT-5** — forward approval expiry default and maximum (open).
- **OQ-LT-6** — ceiling semantics. Decided (lead decision, 2026-11-19):
  instance-configurable, hard-capped at 300 s; where it is configured is open.
- **OQ-LT-8** — controller and scope ownership lease durations (open).
- **OQ-LT-9** — stale reference point. Decided (lead decision, 2026-11-19) in
  part: measured from collection start; `fresh_until` and `valid_until` open.
- **OQ-LT-15** — TLS minimum remaining validity (open).
- **OQ-API-1** — login and callback during a closed gate. Decided (lead
  decision, 2026-11-19): not gated; allowed only with an active pinned origin
  version and a security-enabled origin.
- **OQ-API-6** — security-disable. Decided (lead decision, 2026-11-19): tenant
  `client_admin` only.
- **OQ-API-11** — grouped-path shorthand (open; lead lean recorded).
- **OQ-ERR-11** — 401 versus 503 precedence under a closed gate (open; lead lean
  recorded).
- **OQ-TM-1** — threats outside T00.7. Decided (lead decision, 2026-11-19): the
  threat model covers the union of the T00.7 and design §9 lists, which adds
  header spoofing and stale streams to the T00.7 shadow routes.
- **OQ-TM-11** — independent observation. Decided (lead decision, 2026-11-19):
  the controller as sole writer and sole observer is accepted v0.1 residual
  risk; the "fixed mTLS observer" is the controller-read management listener,
  not an independent observer.

New questions raised by this ADR:

- **OQ-ADR020-1 — Protected-set record.** Decided (lead decision, 2026-11-19):
  add a protected-set entity (item 6). Original question: `security_admin`
  enrolls the protected set by cluster, Gateway UID, listener and hostname
  (design §4.2), and approvals bind "protected scopes", but the tasks §3 logical
  model has no entity or endpoint that stores this enrolment separately from
  `CredentialProtectionScope`, which covers Secret namespaces.
- **OQ-ADR020-2 — TLS runtime key.** `TLSRenewalRuntime` is keyed by `bundle_id`
  and dependency (tasks §3), while design §4.2 binds it to the stable
  `dependency_contract_digest` across plan changes. Whether one Secret shared by
  two bundles (for example a shared listener) has one runtime or two, and which
  bundle's gate its outcome closes, is not stated. Open; to be decided before
  M1b/M3 (lead decision, 2026-11-19).
- **OQ-ADR020-3 — Controller replica count.** The baseline requires ">=2 fenced
  controllers" and T32.3 requires at least two replicas, but the sources do not
  say whether a single available replica is an alerted degraded state or blocks
  applies. Open; to be decided before M1b/M3 (lead decision, 2026-11-19).

## Tests

- A58 — selection precedence, preparation, approval, mode, incident recovery,
  digest and failover.
- A46 — origin-resolved tenant and provider; spoofed Host, Forwarded or tenant
  query.
- A51, A52 — app and native flow bindings.
- A18, A61 — containment and request binding on guarded routes.
- Gate independence during apply — while applying or recovery_required, a gated
  cookie request gets 503 `route_configuration_unavailable`, cleanup endpoints
  stay available, and `/_skyoauth/login` and `/_skyoauth/callback` are served
  with an active pinned origin version and a security-enabled parent and deny
  before any redirect otherwise (API-130 to API-134).
- Task tests: T14.9, T32.3, T50.4, T52.8.
