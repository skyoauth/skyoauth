# Identity, audience and authorization registry

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.4.
- **Derived from:** [design](../skyoauth-design.md) §1, §2 (C01, C03, C08,
  C09), §3.1, §4, §4.1, §5.1.1, §5.2, §5.2.1, §5.2.2, §5.3, §5.6, §5.7, §6,
  §6.1, §6.1.1, §7.1, §7.2, §7.4; [tasks](../skyoauth-tasks.md) §2 "Endpoint
  matrix", §2 "Exchange selection and scope", §3 (logical model,
  "Ownership", "Policy revisions", "IDs/names", "Source kinds", "Egress and
  secret namespaces", "Instance security policy"), T12.8–T12.9, T14.1–T14.7,
  §8 (A13, A29, A30, A43, A44, A45, A49), §11 (ADR-001, ADR-005, ADR-008,
  ADR-014, ADR-016, ADR-018, ADR-019, ADR-022);
  [threat model](../threat-model.md) OQ-TM-7, OQ-TM-12, OQ-TM-13.
- **Related contracts:** [token-profiles.md](token-profiles.md),
  [public-api.md](public-api.md).

This document freezes the issuer, identifier rules, principal kinds, the
instance-owned audience registry, scopes, the SkyOAuth claim and parameter
namespace, the constraint schemas, action-to-scope rules and the
"unknown means deny" rule. It restates the sources; open details are listed
under [Open questions](#open-questions). Items marked **Decided** there record
lead decisions that the normative text already reflects.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `IR-nnn`.

## 1. Authority split

| Authority                   | Owns                                                                                                                                                                                                                                                                                                                       | Source                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| Instance (`security_admin`) | Issuer and signing keys, tenants, operators and roles, `ResourceServer` audiences, `AudienceTenantAssignment`, `ResourceServerChecker`, `ResourceAction`, application-origin ownership, the egress-destination allowlist (`EgressAllowlistEntry`), the instance security policy (`InstanceSecurityPolicy`; IR-052, IR-053) | design §1, §7.1, §7.2; tasks §3 |
| Tenant (scoped roles)       | Trust sources, keysets, bindings, workload and service principals, grants, OAuth clients, origin and route versions, `HumanAccessPolicy`, human providers and links                                                                                                                                                        | design §7.1, §7.2               |
| Replaceable human IdP       | Upstream human authentication only; none of the above                                                                                                                                                                                                                                                                      | design §1, §2 C08               |
| Backend (resource server)   | Canonical resource ownership and resource RBAC                                                                                                                                                                                                                                                                             | design §1, §3.1, §6             |

- **IR-001** Issuer, signing keys, tenants, audience authority, clients and
  origins, principals, trust and policy, and operator authority MUST NOT be
  owned by the human IdP and MUST survive a human-provider switch. (design §1,
  §2 C03–C06)

## 2. Issuer

- **IR-010** There MUST be one stable canonical HTTPS issuer, independent of
  every human provider. (design §2 C01; tasks ADR-001)
- **IR-011** The SkyOAuth issuer MUST be distinct from upstream IdPs.
  Protected services MUST NOT need to trust GitHub, Kubernetes or Zitadel
  directly. (design §2 C08)
- **IR-012** A human-provider switch MUST NOT change the issuer or rotate
  signing keys. (design §6; tasks T51.10)
- **IR-013** Native authorization and its upstream callback are served on the
  issuer origin; browser auth routes are served on the registered application
  origin. (design §3)
- **IR-014** The audience a WIF proof is minted for (for example
  `https://identity.example.com` in a trust source's `audiences`) is the proof
  audience at the external source. It is distinct from the API audience in the
  issued token, which the instance audience assignment governs. (design §5.7
  example; tasks T22.1)

## 3. Identifiers and names

- **IR-020** All object IDs and public OAuth `client_id` values MUST be
  server-generated opaque random identifiers. A client MUST NOT choose a global
  ID on initial create. (design §7.4; tasks T10.2)
- **IR-021** `name` is a tenant-local label, unique only within its entity type
  and tenant. Names MUST NOT be accepted as exchange selectors and are not
  globally reserved. (design §7.4; tasks A49)
- **IR-022** Creation omits the ID and returns the generated ID and revision.
  Updates MUST specify the existing ID and expected revision within the
  authorized tenant. (design §7.4)
- **IR-023** ID prefixes indicate type, not authority. A verifier MUST NOT
  derive a profile, role or authorization from a prefix. (design §6, §7.4)
- **IR-024** IDs are opaque strings compared exactly (byte for byte). The
  prefixes and the length seen in examples are not part of a frozen ID format;
  clients and verifiers MUST NOT parse IDs or rely on a prefix or length.
  (design §7.4; lead decision, OQ-IR-4)

Prefixes seen in the design's examples (illustrative only; see IR-024):

| Prefix               | Object                         | Source            |
| -------------------- | ------------------------------ | ----------------- |
| `ten_`               | Tenant                         | design §5.7, §6   |
| `usr_`               | Human principal                | design §6         |
| `wld_`               | Workload principal             | design §5.7, §6   |
| `svc_`               | Service principal              | design §5.7, §6   |
| `adm_`               | Operator identity              | design §3.1, §7.2 |
| `client_`            | OAuth client ID                | design §5.2.1, §6 |
| `trust_`             | Trust source                   | design §5.7       |
| `keyset_`, `keyver_` | Trust keyset and version       | design §5.7       |
| `binding_`           | Principal binding              | design §5.7       |
| `grant_`             | Service grant                  | design §5.7       |
| `polrev_`            | Policy revision                | design §6         |
| `hauth_`             | Human authentication reference | design §6         |
| `jti_`               | Token ID                       | design §6         |
| `cluster_`           | Kubernetes cluster ID          | design §5.7       |

## 4. Tenants

- **IR-030** Every installation MUST have explicit tenants. Tenant IDs,
  audience ownership and isolation checks apply even to a single-tenant
  installation. (design §1.3)
- **IR-031** Tenant-owned objects MUST use composite tenant/object references
  so that no cross-tenant reference can exist. (design §7.1; tasks §3
  "Ownership")
- **IR-032** External issuer strings MUST NOT be treated as unique. Different
  tenants may register the same issuer, and independently keyed clusters may
  share one. (design §5.4, §7.1; tasks A29)
- **IR-033** The tenant of a browser request MUST come from the registered
  origin; the tenant of a native request MUST come from the registered
  `client_id`; the tenant of a WIF request MUST come from the selected source
  and grant, which MUST belong to the same tenant. (design §4, §5.2, §5.7)
- **IR-034** `Tenant.secret_namespace` MUST be unique, non-null, immutable and
  a server-generated opaque value; no operator chooses or changes it.
  `TrustSource.ca_bundle_ref`, `TrustSource.reviewer_credential_ref` and the
  human provider `credential_ref` MUST resolve only within the owning tenant's
  `secret_namespace`, so a reference cannot name a secret provisioned for
  another tenant. The audit sink configuration is instance deployment
  configuration, not a tenant secret namespace (IR-053). (design §5.4; tasks
  §3 "Egress and secret namespaces", T11.8, T23.2; lead decision, OQ-TM-13)

## 5. Principals

### 5.1 Principal kinds

| Kind     | Example prefix | Created by                                                                                      | Established by                                              | Appears in tokens as                                | Source                           |
| -------- | -------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------- | -------------------------------- |
| Human    | `usr_`         | `provider_admin` verified enrollment and linking, or `auto_create` at first login when opted in | Verified link of tenant, provider, exact issuer and subject | `sub` of `human_cli` and `human_session`            | design §5.1.1, §7.2; tasks T12.1 |
| Workload | `wld_`         | Tenant `trust_admin`                                                                            | Verified WIF evidence matched by a `PrincipalBinding`       | `sub` of direct `wif`; `act.sub` of delegated `wif` | design §5.6, §7.2                |
| Service  | `svc_`         | Tenant `trust_admin`, atomically with its `ServiceIdentity`                                     | Never authenticates; target of a delegation grant           | `sub` of delegated `wif`                            | design §5.6, §7.2; tasks §3      |

- **IR-040** Local principals MUST be distinct from upstream subjects. (design
  §3.1)
- **IR-041** Human resolution MUST use tenant, provider, exact issuer and
  subject. Email equality MUST NOT link or merge identities. (design §2,
  §5.1.1; tasks T12.1, A22)
- **IR-042** A newly created human principal MUST start with no backend
  resource privileges. (design §5.1.1)
- **IR-043** `trust_admin` MUST NOT create human principals. (design §7.2)
- **IR-044** A `ServiceIdentity` is a possible token subject, not an API
  receiver. It MUST NOT carry checker credentials and MUST NOT become checker
  authority by its audiences. (design §7.1; tasks §3 "Ownership", T14.3)
- **IR-045** A direct grant MUST have a null target service; a delegation grant
  MUST name a same-tenant service. (tasks §3 "Ownership")

Grant modes (design §5.6):

| Mode          | v0.1 status                                                                                   | Token `skyoauth_mode` |
| ------------- | --------------------------------------------------------------------------------------------- | --------------------- |
| `direct`      | Required                                                                                      | `direct`              |
| `delegation`  | Required                                                                                      | `delegation`          |
| Impersonation | Stored only with `status: disabled` and `activation_state: requires_reapproval`; never issued | Not issued            |

### 5.2 Operator identities and roles

Operators are independent `adm_*` identities with registered mTLS public
credentials. They are not `Principal` records and never appear in issued
tokens. (design §3.1, §7.2) Only an active local credential and role grant
operator authority; OIDC roles, groups, emails, human sessions and WIF
credentials never do. That rule is
[public-api.md API-002](public-api.md#1-listener-classes), which is canonical;
**IR-050** is withdrawn as a duplicate of it.

| Role             | Scope    | Explicit rights (summary)                                                                                                                                                                                                                                                                                                                                                                                                                | Source      |
| ---------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `security_admin` | Instance | Tenants; operators and roles; resource servers, assignments, checkers, actions; origin ownership; signer and recovery policy; egress-destination allowlist; instance security policy (`widening_second_approver` online; `single_actor_mode` and the audit sink configuration are deployment configuration, read-only online); capacity ceiling; controller and provisioner identities; protection-scope registry; route-bundle approval | design §7.2 |
| `trust_admin`    | Tenant   | Workload and service principals; sources, keysets, bindings, grants within instance audience ceilings                                                                                                                                                                                                                                                                                                                                    | design §7.2 |
| `client_admin`   | Tenant   | OAuth clients, origin and route versions, route bundles and preparation, `HumanAccessPolicy`, origin capacity                                                                                                                                                                                                                                                                                                                            | design §7.2 |
| `provider_admin` | Tenant   | Inactive providers, enrollment policy and hold, verified links, credential-only rotation, switch and rollback plans                                                                                                                                                                                                                                                                                                                      | design §7.2 |
| `auditor`        | Tenant   | Redacted configuration and audit reads                                                                                                                                                                                                                                                                                                                                                                                                   | design §7.2 |

- **IR-051** Withdrawn as a duplicate. Role non-inheritance follows
  [public-api.md API-120](public-api.md#72-approval-boundaries), which is
  canonical.

The instance security policy is one `InstanceSecurityPolicy` row per instance
(`widening_second_approver`, `single_actor_mode`, `audit_sink_config_digest`,
`audit_sink_validated_at`, `revision`). (tasks §3)

- **IR-052** `widening_second_approver` is off by default. When it is on, a
  trust-source, keyset, binding or grant write that the server detects as
  widening, and adding or re-enabling an `EgressAllowlistEntry` (IR-152),
  MUST NOT take effect until an `approve` operation (IR-054) by a distinct
  `security_admin` applies it, or one actor when `single_actor_mode` is on.
  When it is off, the widening flag, the expected
  revision and the atomic audit record suffice. Turning the setting on or off
  is the only online write to `InstanceSecurityPolicy`: an audited,
  revision-checked write by instance `security_admin` that MUST have a
  distinct second `security_admin` approver (IR-054), or one actor when
  `single_actor_mode` is on. (design §7.2; tasks §3 "Instance security
  policy"; ADR-008 item 12; lead decision, OQ-ADR008-3; Decided (lead
  decision, 2026-11-20), OQ-IR-12; public-api API-156)
- **IR-053** `single_actor_mode` (default false) is the explicit audited
  instance policy that lets one actor act where a distinct second approver is
  otherwise required: public-api API-142, API-148, API-155 and API-156,
  gateway-containment GW-116 and IR-052. It and the audit sink configuration
  are instance deployment configuration, read-only online; an online operator
  write MUST NOT change them. `single_actor_mode` is set at install, and the
  row mirrors it. Interim reading (lead, 2026-11-20), pending OQ-IR-13: a
  change is deployment configuration, applied at restart and recorded in an
  audit event at startup; whether the local signed recovery transaction can
  also set it is OQ-IR-13. The sink endpoint, protocol and TLS trust or
  credential reference are not stored in the database: the row holds only
  `audit_sink_config_digest` and `audit_sink_validated_at`, and observed sink
  health is a metric and health signal, not a revisioned row. A sink
  configuration change takes effect only on restart and first emits a sink
  changed event to the old sink, plus an audit event. "Configured" means set
  and validated at startup: the endpoint is set and the current configuration
  passed validation, and `audit_sink_validated_at` MUST correspond to the
  current `audit_sink_config_digest`, so an endpoint that is present but
  failed validation, or a changed configuration not yet validated, is not
  configured (the digest correspondence is inferred from "validated at
  startup" and restart-only changes). Public-signer key enrollment,
  activation and publication MUST be refused while no sink is configured;
  emergency disable and standby promotion MUST NOT be refused for a missing,
  unvalidated or unavailable sink, which raises an alert and a local
  append-only record. If the sink configuration is removed while keys are
  published, the instance starts degraded with an alert, and disable still
  works (public-api API-153). (design §7, §7.2; tasks §3 "Instance security
  policy", Gate M1a; ADR-002 item 4; lead decision, OQ-TM-7, OQ-TM-12,
  OQ-ADR008-3)
- **IR-054** A second-approver approval covers the operations that need a
  distinct second `security_admin` approver: the IR-052 toggle, widening
  writes while `widening_second_approver` is on (IR-052, IR-152; ADR-008 item 12) and other security-domain toggles. It is a second
  `AdministrativeOperation` of kind `approve` whose `approves_operation_id`
  names the pending operation and whose `actor_id` differs from that
  operation's `actor_id`, and the approver MUST hold `security_admin`; it is
  submitted through the public-api `/approve` operation endpoints (lead
  decision, OQ-API-13). It does not change other approval boundaries: a
  route-bundle approval is a `kind=route_bundle_approval` operation under
  gateway-containment GW-130 and GW-131, where one person MAY hold both the
  preparer and approver roles by explicit assignment, and the second
  approvers of public-api API-148 and API-155 (`security_admin` or another
  `provider_admin`) keep their own rules (their wire form is public-api
  OQ-API-15). (design §4.2; tasks §3 "Instance
  security policy"; ADR-008 item 12; lead decision, OQ-ADR008-3)
- **IR-055** Audit events form one hash chain per instance.
  `AuditEvent.sequence` is assigned in the same transaction as the audited
  write and strictly increases; `prev_hash` links each event to the previous
  one; the chain head lives in the database, whose audit stays authoritative.
  The external sink receives the chain as an append-only JSONL stream over
  syslog-over-TLS or OTLP logs. (design §7; tasks §3 "Instance security
  policy", Gate M1a; lead decision, OQ-TM-12)

## 6. Scopes

- **IR-060** A `scope` value is a space-separated list of scope tokens. The
  canonical scope string is the space-joined, bytewise ASCII-sorted unique
  tokens. For comparison v1, and therefore for the `/oauth/authorize` request
  whose comparison value it derives, duplicate and invalid tokens MUST be
  rejected. Whether other request surfaces reject duplicate tokens is
  OQ-IR-11. (design §5.2.1)
- **IR-066** A scope token MUST match the RFC 6749 §3.3 `scope-token` grammar,
  `1*( %x21 / %x23-5B / %x5D-7E )`; scope tokens are case-sensitive. A token
  outside this grammar is invalid. (lead decision, OQ-IR-3)
- **IR-061** Scopes MUST be explicit in every issued credential. (design §6)
- **IR-062** Every scope a credential carries MUST lie within every applicable
  ceiling:

| Credential       | Ceilings that MUST all contain the issued scopes                                                                        | Source                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `wif` direct     | `ResourceServer.scopes`, `AudienceTenantAssignment.allowed_scopes`, `ServiceGrant.scopes`                               | design §5.7, §7.1; tasks T21.5 |
| `wif` delegation | The above plus the target `ServiceIdentity.max_scopes`                                                                  | design §5.7; tasks §3, T21.5   |
| `human_cli`      | Approved requested scopes, `OAuthClient.allowed_scopes`, `HumanAccessPolicy.allowed_scopes`, assignment                 | design §6; tasks §3            |
| `human_session`  | Origin `HumanAccessPolicy` for the audience selected by the active pinned `ApplicationRouteVersion`, and the assignment | design §4.1, §6                |

- **IR-063** An omitted WIF scope MUST use only the grant's explicit nonempty
  `default_scopes`, which MUST be a subset of every applicable ceiling;
  otherwise `invalid_scope`. Explicit empty or excessive scopes MUST be
  denied, not trimmed or widened. This requirement is canonical; public-api
  API-016 refers to it. (design §5.7; tasks T12.8, A26)
- **IR-064** Native refresh with omitted scope MUST keep the previous scope set
  only while it is still allowed. Explicit narrowing MAY succeed. Refresh MUST
  NOT exceed the originally approved scopes. (design §5.2.2)
- **IR-065** Browser-supplied identity or scope headers, cookies, query
  parameters and JSON bodies MUST NOT select a scope, audience or policy.
  (design §4.1, §6)

## 7. Audience registry

### 7.1 Resource servers

- **IR-070** A `ResourceServer` MUST be created only by instance
  `security_admin`, with one globally unique exact audience. (design §7.1;
  tasks T14.1)
- **IR-071** Audience strings are not tenant-controlled. Tenants MUST NOT
  self-assign an existing audience or create a competing registration.
  (design §7.1; tasks A43)
- **IR-072** Issued credentials MUST carry exactly one registered API audience.
  (design §5.7, §6)

`ResourceServer(id, audience, name, allowed_profiles, scopes,
constraint_versions, status, revision)` (tasks §3).

### 7.2 Tenant assignments

`AudienceTenantAssignment(id, resource_server_id, tenant_id, allowed_profiles,
allowed_scopes, constraint_versions, status, revision)` (tasks §3).

- **IR-080** Service ceilings, WIF grants, OAuth clients, application origins
  and `HumanAccessPolicy` records MUST reference registered audience IDs and
  MUST be refused unless an active same-tenant assignment exists. (design
  §7.1; tasks T14.2)
- **IR-081** The assignment MUST be rechecked at issuance and at every live
  policy check. (design §7.1; tasks T14.2)
- **IR-082** A matching project name, scope or audience alone MUST NOT be
  sufficient authorization. (design §2 C09; tasks A43)
- **IR-083** A `ServiceGrant` (and a `ServiceIdentity`) MAY hold several
  resource servers in `resource_server_ids`. Each exchange MUST select exactly
  one through its `audience` parameter; the selected audience MUST be in the
  grant's set, in the target service's set for delegation, and covered by an
  active same-tenant assignment. (tasks §3 model; design §5.7; lead decision,
  OQ-IR-7)

### 7.3 Checkers

`ResourceServerChecker(id, resource_server_id, public_mtls_identity,
allowed_tenant_ids, status, revision)` (tasks §3).

- **IR-090** A checker identity MUST be bound to one resource server and an
  explicit tenant set, registered by instance `security_admin`, and MUST NOT
  be usable for another audience. (design §6.1, §7.1; tasks A45)

### 7.4 Actions (action-to-scope rules)

`ResourceAction(id, resource_server_id, action_name, required_scopes,
accepted_profiles, required_resource_dimensions, live_check_required,
stream_capable, max_stream_duration_seconds?, stream_class,
max_session_lease_seconds, status, revision)` (tasks §3).

| Field                          | Meaning                                                       | Milestone | Source                     |
| ------------------------------ | ------------------------------------------------------------- | --------- | -------------------------- |
| `action_name`                  | Canonical action coordinate sent by the checker               | M1a       | design §6.1; tasks T14.4   |
| `required_scopes`              | Scopes the credential must all carry for this action (IR-104) | M1a       | design §6.1                |
| `accepted_profiles`            | Profiles that may perform this action                         | M1a       | design §6.1                |
| `required_resource_dimensions` | Resource dimensions that must be present and matched          | M1a       | design §6.1                |
| `live_check_required`          | Whether a live check is mandatory                             | M1a       | design §6.1                |
| `stream_capable`               | Whether a browser stream continuation may be admitted         | M1b       | design §6.1.1; tasks T14.4 |
| `max_stream_duration_seconds`  | Optional stream duration bound                                | M1b       | tasks §3, T14.4            |
| `stream_class`                 | Stream classification (values: OQ-IR-8)                       | M1b       | tasks §3, T14.4            |
| `max_session_lease_seconds`    | Ceiling for continuation leases; default 15                   | M1b       | design §6.1.1; tasks T14.4 |

- **IR-100** Action rules MUST be persisted per resource server and
  administered only by instance `security_admin`. (design §7.1; tasks T14.4)
- **IR-101** `max_session_lease_seconds` defaults to 15. Only an action
  explicitly classified noncritical read-only MAY exceed 15, up to 300.
  Critical or mutating actions MUST stay at 15 seconds or less. (design
  §6.1.1)
- **IR-102** A route's `session_lease_seconds` (default 15) MUST NOT exceed the
  action ceiling. Tenant route editors MUST NOT exceed receiver ceilings.
  (design §6.1.1; tasks T14.4)
- **IR-103** Out-of-range or contradictory action configuration MUST be
  rejected, not silently widened. (design §6.1.1; tasks T14.4)
- **IR-104** A credential MUST carry every scope in the action's
  `required_scopes` for the action to be allowed. (design §6.1; combination:
  lead decision, OQ-IR-2)

### 7.5 Profile acceptance

A profile is usable for a request only if every layer below allows it.

| Layer                         | Field                                       | Source          |
| ----------------------------- | ------------------------------------------- | --------------- |
| Resource-server registration  | `ResourceServer.allowed_profiles`           | design §6, §7.1 |
| Tenant assignment             | `AudienceTenantAssignment.allowed_profiles` | design §7.1     |
| Cookie route (pinned version) | `ApplicationRouteVersion.allowed_profiles`  | design §4.1     |
| Action                        | `ResourceAction.accepted_profiles`          | design §6.1     |

- **IR-110** A profile that any applicable layer does not allow MUST be
  denied. (design §4.1, §6, §6.1)

## 8. Constraints

`skyoauth_constraints` is a signed object with a `version` and an
`authorization` mode. v0.1 defines version `1` with two modes.

- **IR-141** The v1 envelope, the members `version` and `authorization`, is
  fixed for every resource server. Allowlist dimension names and their value
  rules are defined per resource server by a versioned constraint schema (the
  versions listed in `ResourceServer.constraint_versions` and
  `AudienceTenantAssignment.constraint_versions`). A dimension that the
  applicable schema version does not define is an unknown field (IR-140).
  How the schema version relates to the `version` member is OQ-TP-7. (tasks §3
  model; lead decision, OQ-IR-1)

| Mode           | Profiles                     | Shape                                                                         | Source    |
| -------------- | ---------------------------- | ----------------------------------------------------------------------------- | --------- |
| `allowlist`    | `wif` only                   | `{"version":1,"authorization":"allowlist", <dimension>: [<value>, ...], ...}` | design §6 |
| `backend_rbac` | `human_cli`, `human_session` | Exactly `{"version":1,"authorization":"backend_rbac"}`                        | design §6 |

### 8.1 Allowlists (`wif`)

Design example: `{"version":1,"authorization":"allowlist","projects":["platform-production"],"environments":["production"]}`.
The `projects` and `environments` dimensions are those of the example's
resource server, not a global set (IR-141).

- **IR-120** Values within one dimension are alternatives. Different
  dimensions are ANDed with each other and with tenant, audience, scope and
  RBAC checks. (design §6)
- **IR-121** A missing or empty required dimension MUST deny. (design §6)
- **IR-122** A grant ID alone MUST NOT be sufficient. (design §6)
- **IR-123** The issued constraints MUST be the profile-appropriate narrowed
  constraints within the grant's `resource_constraints` and, for delegation,
  the service's `max_resource_constraints`. (tasks §3, T21.5)

### 8.2 `backend_rbac` (human profiles)

- **IR-130** Human constraints MUST make no project or environment membership
  claim. (design §6)
- **IR-131** `backend_rbac` is explicit authorization by the backend, not an
  exemption and not an automatic allow. The WIF profile MUST NOT use it.
  (design §3.1, §6)

### 8.3 Common constraint rules

- **IR-140** Unknown constraint fields, unknown versions and the wrong
  authorization mode for the profile MUST deny. (design §6; tasks T00.4, A30)

## 9. Backend authorization order

For every protected request the backend MUST perform these steps
(**IR-150**). (design §3.1, §6, §7.1; tasks A13, A43)

1. Validate the credential profile for its own registered audience
   ([token-profiles.md §8](token-profiles.md#8-verifier-obligations)).
2. Resolve the resource's canonical SkyOAuth tenant. A missing mapping MUST
   deny.
3. Compare that tenant with signed `skyoauth_tenant`, and the signed audience
   with its own. A mismatch MUST deny.
4. Check that the credential carries every scope the action requires
   (IR-104).
5. Evaluate the backend's current RBAC for the principal and resource, for
   every profile; no membership or permission MUST deny. `backend_rbac` makes
   this the only resource authorization for human profiles. For `allowlist`
   (`wif`), additionally check every required dimension; the dimensions are
   ANDed with tenant, audience, scope and RBAC (IR-120).
6. Where the action requires a live check, call `/internal/v1/policy/check`;
   unavailable is not an allow, and the backend still applies steps 2–5.

## 10. Registry allowlists

Other allowlists in the registry, each with the rule its source states:

| Allowlist                                       | Owner                                                           | Rule                                                                                                                                                                                                                                                                          | Source                                                                                                              |
| ----------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `ServiceGrant.allowed_binding_ids`              | Tenant `trust_admin`                                            | Nonempty; only these bindings of the grant actor are eligible; cross-actor references rejected                                                                                                                                                                                | design §5.7; tasks §2 "Exchange selection and scope"                                                                |
| `ApplicationOriginVersion.allowed_return_paths` | Tenant `client_admin`                                           | Normalized same-origin relative paths only                                                                                                                                                                                                                                    | design §4                                                                                                           |
| `ApplicationOriginVersion.resource_server_ids`  | Tenant `client_admin` within assignment                         | Approved API audiences for the origin                                                                                                                                                                                                                                         | design §4; tasks §3                                                                                                 |
| `ApplicationRouteVersion.methods`               | Tenant `client_admin`                                           | Nonempty method allowlist; unknown method denies                                                                                                                                                                                                                              | design §4.1                                                                                                         |
| `OAuthClient.redirect_rules`                    | Tenant `client_admin`                                           | IP-loopback redirect rules: each fixes scheme `http`, the IP literal (`127.0.0.1` and/or `[::1]`) and the path; the port varies per request and is bound exactly per transaction; `localhost` rejected (public-api API-031)                                                   | design §5.2, §10.3; tasks T40.1; lead decision (OQ-TM-5)                                                            |
| `TrustSource.audiences`, `algorithms`           | Tenant `trust_admin`                                            | Exact proof audiences and algorithm allowlist                                                                                                                                                                                                                                 | design §5.4                                                                                                         |
| `EgressAllowlistEntry`                          | Instance `security_admin`; tenant operators only choose from it | Exact discovery, JWKS and TokenReview destinations, unique per purpose and immutable; matched by value on create or change of `discovery_url` and `token_review_endpoint`, at fetch for a discovered `jwks_uri`; disable fails closed and degrades dependent sources (IR-152) | design §5.4, §7.2; tasks §3 "Egress and secret namespaces", T11.2, T11.8, T23.2; lead decision (OQ-TM-13, OQ-IR-12) |
| `ResourceServerChecker.allowed_tenant_ids`      | Instance `security_admin`                                       | Explicit tenant set                                                                                                                                                                                                                                                           | design §6.1                                                                                                         |
| `PrincipalBinding` match predicates             | Tenant `trust_admin`                                            | ANDed exact strings; a configured claim absent from evidence is a non-match; omitted optional predicates are unconstrained; required production predicates cannot be omitted                                                                                                  | design §5.3                                                                                                         |

- **IR-151** `TrustSource.kind` is `oidc_discovery`, `uploaded_jwks` or
  `kubernetes_token_review`; there is no fourth kind. Kubernetes local JWT
  validation is an `uploaded_jwks` or `oidc_discovery` source with
  `assertion_profile` `projected_service_account` and
  `stale_revocation_acknowledged` set. `stale_revocation_acknowledged` MUST be
  set for `projected_service_account` on `uploaded_jwks` or `oidc_discovery`
  and MUST be rejected on every other source; `kubernetes_token_review`
  performs a live review and does not take it. (tasks §3 "Source kinds";
  ADR-005; lead decision, OQ-ADR005-1)
- **IR-152** `EgressAllowlistEntry` records are instance-global and owned by
  instance `security_admin`; tenant operators only choose from them and read
  them through a read-only tenant view that lists every entry, an accepted
  v0.1 property (public-api §7.1). `purpose` is `oidc_discovery`, `jwks` or
  `token_review`; `exact_destination` is an exact URL (scheme, host, port and
  path); (`purpose`, `exact_destination`) MUST be unique, and both are
  immutable: a PATCH changes only `status`, and entries are not deleted.
  - On create, and on a write that changes `TrustSource.discovery_url` or
    `token_review_endpoint`, the new `discovery_url` MUST exactly match an
    enabled `oidc_discovery` entry and the new `token_review_endpoint` an
    enabled `token_review` entry, or the write is rejected. A disable, or a
    write that leaves both fields unchanged, MUST NOT be rejected for a
    missing or disabled entry, so a whole-plan import that carries a degraded
    source is not rejected for it (ADR-008 items 10 and 11). Write-time
    matching covers only these two fields; a dry run MAY offer a network
    check, which is not part of the write path.
  - A discovered `jwks_uri` is enforced at fetch and never followed unless it
    exactly matches an enabled `jwks` entry; otherwise no JWKS fetch is made,
    the source is degraded and an alert is raised.
  - Disabling an entry fails closed for new fetches: no new discovery or JWKS
    fetch through it, and a TokenReview call through it is denied with no
    fallback. Cached JWKS stay usable until their bounded expiry. Dependent
    sources are degraded.
  - Degraded is a derived health signal, not a stored `TrustSource.status`
    value: source reads show it with a reason, it is a metric with an alert,
    and the audit event of the entry write lists the affected source IDs.
    Re-enabling the entry clears it, since nothing is stored.
  - Adding or re-enabling an entry is widening-class and needs an IR-054
    approval when `widening_second_approver` is on; disabling is not
    widening.

  (design §5.4, §7.2; tasks §3 "Egress and secret namespaces", T11.2, T11.8,
  T23.2; ADR-008 item 12; lead decision, OQ-TM-13; Decided (lead decision,
  2026-11-20), OQ-IR-12)

## 11. Claim and parameter namespace

- **IR-160** SkyOAuth private JWT claims, OAuth request parameters and wire
  names MUST use the `skyoauth` namespace shown below. Adding, renaming or
  removing one MUST update the design, tasks, these contracts and the shared
  fixtures together. (design §12; tasks T00.4)

| Kind                     | Names                                                                                                                                                                                                                                                                                                  | Source                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Private JWT claims       | `skyoauth_tenant`, `skyoauth_profile`, `skyoauth_profile_version`, `skyoauth_policy_revision`, `skyoauth_constraints`, `skyoauth_mode`, `skyoauth_grant`, `skyoauth_authentication`, `skyoauth_application_origin`, `skyoauth_session`, `skyoauth_route`, `skyoauth_route_version`, `skyoauth_request` | design §4.1, §6; `skyoauth_route_version`: lead decision (OQ-TP-1) |
| Standard JWT claims used | `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `scope`, `act`, `client_id`, `auth_time`                                                                                                                                                                                                              | design §6                                                          |
| Protected `typ` values   | `skyoauth-access+jwt`, `skyoauth-internal+jwt`                                                                                                                                                                                                                                                         | design §6                                                          |
| Profile values           | `wif`, `human_cli`, `human_session`                                                                                                                                                                                                                                                                    | design §6                                                          |
| OAuth parameters         | `skyoauth_trust_source`, `skyoauth_grant_id`, `skyoauth_refresh_request_id`                                                                                                                                                                                                                            | design §5.2.2, §5.7                                                |
| Private grant type       | `urn:skyoauth:params:oauth:grant-type:service-delegation`                                                                                                                                                                                                                                              | design §5.7                                                        |
| Cookies                  | `__Host-skyoauth_login`, `__Host-skyoauth_session`, `__Host-skyoauth_native`                                                                                                                                                                                                                           | design §5.1, §5.2                                                  |
| Request headers          | `X-SkyOAuth-CSRF` (browser to SkyOAuth); `X-SkyOAuth-Assertion` (Envoy to backend, `human_session` assertion)                                                                                                                                                                                          | design §4, §5.1; `X-SkyOAuth-Assertion`: lead decision (OQ-API-10) |
| App-origin path prefix   | `/_skyoauth/`                                                                                                                                                                                                                                                                                          | design §4                                                          |
| Comparison domain label  | `skyoauth-native-confirm-v1`                                                                                                                                                                                                                                                                           | design §5.2.1                                                      |

## 12. Unknown means deny

| Unknown, missing or contradictory input                           | Result                                | Source                     |
| ----------------------------------------------------------------- | ------------------------------------- | -------------------------- |
| Profile value, profile version, contradictory claim set           | Reject                                | design §6                  |
| Constraint field, constraint version, wrong authorization mode    | Deny                                  | design §6                  |
| Missing or empty required allowlist dimension                     | Deny                                  | design §6                  |
| Action, resource or checker caller                                | Deny                                  | design §6.1                |
| Wrong tenant or audience at live check                            | Deny                                  | design §6.1                |
| Audience with no active same-tenant assignment                    | Refuse at write and at issuance       | design §7.1                |
| Canonical resource tenant mapping                                 | Deny                                  | design §6, §7.1            |
| Any principal without backend permission for the resource         | Deny                                  | design §2 C09, §6          |
| Route, method, policy, assignment or profile for a cookie request | Deny; no fallback to a broader route  | design §4.1                |
| Application origin, or spoofed Host or Forwarded value            | Deny before redirect                  | design §4                  |
| OAuth client                                                      | Reject                                | design §5.2.2              |
| Trust source, or token-supplied key URL or embedded key           | Reject                                | design §5.4                |
| Out-of-range or contradictory action or lease configuration       | Reject the write                      | design §6.1.1; tasks T14.4 |
| Unsupported grant mode (impersonation) at issuance                | Deny; never fall back to another mode | design §5.6                |
| Internal assertion kid still unknown after one bounded refetch    | Deny                                  | design §6.2                |
| Configured binding predicate absent from verified evidence        | Non-match                             | design §5.3                |
| Superseded or invalidated policy revision                         | Deny                                  | design §6.1                |

- **IR-170** Store or cache failure MUST NOT expand privilege. (design §7)

## Open questions

Items marked **Decided** record a lead decision; the normative text above
already reflects it, and the design and tasks documents still need the
follow-up. All other items are not resolved by this contract.

- **OQ-IR-1 — Constraint dimension catalogue.** **Decided** (lead decision,
  2026-11-19): each resource server has a versioned constraint schema that
  defines its dimensions; the v1 envelope (`version`, `authorization`) is fixed
  (IR-141). Original question: whether dimension names are a fixed global set
  for v1 or are defined per resource server.
- **OQ-IR-2 — `required_scopes` combination.** **Decided** (lead decision,
  2026-11-19): a credential needs all of an action's `required_scopes`
  (IR-104). Original question: all or any one.
- **OQ-IR-3 — Scope token grammar.** **Decided** (lead decision, 2026-11-19):
  the RFC 6749 §3.3 `scope-token` grammar (IR-066). Original question:
  comparison v1 rejects "invalid tokens", but the valid syntax was not given.
- **OQ-IR-4 — Normative ID format.** **Decided** (lead decision, 2026-11-19):
  IDs are opaque strings compared exactly; prefix and length are not frozen
  (IR-024). Original question: whether the `<prefix>_` plus 32 hex characters
  seen in examples is part of the frozen format.
- **OQ-IR-5 — `Principal.kind` values.** The logical model has
  `Principal.kind`, and the design names human, workload and service
  principals, but the literal enum values are not given.
- **OQ-IR-6 — Export field names versus the logical model (source
  contradiction).** The design §5.7 export fragment and the tasks §3 logical
  model name the same fields differently, and the sources do not say whether
  the export schema intentionally differs from the storage model or which
  names are frozen. The differences are:

  | Design §5.7 export           | Tasks §3 model                           |
  | ---------------------------- | ---------------------------------------- |
  | `issuer`                     | `TrustSource.exact_issuer`               |
  | `allowed_algs`               | `TrustSource.algorithms`                 |
  | `api_server`                 | `TrustSource.token_review_endpoint`      |
  | `keyset_id`                  | `TrustSource.jwks_keyset_id`             |
  | `versions[].public_jwks_ref` | `TrustKeysetVersion.public_jwks`         |
  | `source_id`                  | `PrincipalBinding.trust_source_id`       |
  | `match`                      | `PrincipalBinding.claim_match_policy`    |
  | `principal_id`               | `PrincipalBinding.workload_principal_id` |
  | `actor`                      | `ServiceGrant.actor_principal_id`        |
  | `act_as`                     | `ServiceGrant.target_service_id`         |
  | `audience` (one string)      | `ServiceGrant.resource_server_ids`       |
  | `constraints`                | `ServiceGrant.resource_constraints`      |
  | `max_lifetime_seconds`       | `ServiceGrant.max_ttl`                   |

  The `audience` row is also a contradiction in kind, not only in name: design
  §7.1 says grants and other records "reference registered audience IDs",
  while the export shows the audience string `control-plane-api`. Whether an
  export carries audience strings or `ResourceServer` IDs is not stated.

- **OQ-IR-7 — Grants with several audiences.** **Decided** (lead decision,
  2026-11-19): a grant may hold several resource servers and each request
  selects one through `audience` (IR-083). The design §5.7 export fragment
  shows a grant with a single `audience: control-plane-api`; that is one
  grant whose set happens to hold one resource server, not a rule that grants
  hold exactly one (its field name and value kind are OQ-IR-6). Follow-up: the
  design should describe the fragment that way. Original question: whether a
  grant may span several audiences.
- **OQ-IR-8 — Action criticality and `stream_class`.** Lease ceilings depend on
  whether an action is "critical", "mutating" or "noncritical read-only", but
  the `ResourceAction` model has no explicit field for that classification,
  and the values of `stream_class` are not defined.
- **OQ-IR-9 — Audience string syntax.** Audiences are "globally unique exact"
  strings; the example `control-plane-api` is not a URI. Allowed syntax and
  comparison rules (case, normalization) are not stated.
- **OQ-IR-10 — `human_session` constraint source for streams.** Human
  constraints carry no dimensions, while actions may list
  `required_resource_dimensions`. Whether required dimensions apply to human
  profiles (checked by backend RBAC) or only to `wif` allowlists is not stated.
- **OQ-IR-11 — Duplicate scope tokens outside comparison v1.** Design §5.2.1
  rejects duplicate and invalid scope tokens only when computing comparison
  v1. Design §5.7 and §5.2.2 deny duplicate request parameters and excessive
  scopes at `/oauth/token`, but do not say whether a WIF or refresh `scope`
  parameter containing the same token twice is rejected or treated as a set.

  Lead lean (not decided): keep duplicate scope tokens tolerated outside
  comparison v1 unless a source says otherwise. Set semantics everywhere is
  not adopted. (triage: spec-amendments PR)

- **OQ-IR-12 — Degraded trust sources after an egress entry is disabled.**
  **Decided** (lead decision, 2026-11-20): degraded is a derived health
  signal, not a stored `TrustSource.status` value: shown with a reason on
  source reads, a metric with an alert, and the affected source IDs listed in
  the audit event of the entry write; cached JWKS stay usable until their
  bounded expiry. Re-enabling the entry clears it, since nothing is stored. A
  discovered `jwks_uri` is enforced at fetch and never followed: it must
  exactly match an enabled `jwks` entry, otherwise no JWKS fetch is made, the
  source is degraded and an alert is raised. Write-time matching covers only
  `discovery_url` and `token_review_endpoint`; a dry run may offer the network
  check, outside the write path. Adding or re-enabling an entry is
  widening-class, disabling is not, and the second-approver requirement
  applies only when `widening_second_approver` is on (IR-052, IR-152; ADR-008 item 12).
  Original question: tasks §3 says disabling an `EgressAllowlistEntry` "marks
  dependent sources degraded", but `TrustSource.status` has no `degraded`
  value; whether degraded is a status value, a derived health signal or an
  audit-only mark, whether re-enabling clears it, whether a discovered
  `jwks_uri` with no enabled `jwks` entry is rejected at write or degraded at
  fetch, and whether adding an entry is a widening write were not stated.
- **OQ-IR-13 — How `single_actor_mode` changes after install.** Tasks §3 and
  ADR-008 item 12, as merged in #22, said `single_actor_mode` is set at install or by "the local
  signed recovery transaction", but public-api API-152, design §7.2 and T13.5
  limit break-glass transactions to operator restoration and the provider
  switch or rollback. Not stated: whether setting `single_actor_mode` is a
  third break-glass kind; whether that transaction also enrolls a replacement
  recovery key and retires the used one (OQ-TM-8); and whether a
  deployment-configuration change applied at restart alone can flip the
  value. Interim reading (lead, 2026-11-20): deployment configuration,
  applied at restart and audited at startup (IR-053).
- **OQ-IR-14 — Identity of instance-scope audit events.** The T10.1 schema
  records the startup event that mirrors `single_actor_mode` (IR-053) and the
  sink-change event with `tenant_id` null, the `InstanceSecurityPolicy`
  `instance_id` as `object_id`, and the row's revisions before and after the
  write (lead decision, 2026-11-20; `service/migrations/README.md`). Not
  stated: where `instance_id` comes from (generated at bootstrap or set in
  deployment configuration) and its format; which reserved system actor
  records events that the service writes on its own at startup, when no
  administrator acts; and the namespace and syntax of `AuditEvent.action`,
  whose values must name the entity, since `object_id` alone does not say
  what kind of object it identifies.
