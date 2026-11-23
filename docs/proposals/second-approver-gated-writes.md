# Proposal: second-approver flow for widening trust writes

Status: Proposed, not accepted. Drafted 2026-11-23 for the lead's review agent
and then the user's acceptance. Nothing here is implemented: no migration, no
production code, no endpoint, and no T00.x box is ticked. Every choice below
that goes beyond the written spec is a "provisional lead pick, 2026-11-23" (the
Decisions list numbers them D1 to D29); "(inferred)" marks a point where the
spec is silent. All of them, and the lead decisions the spec records, stay
provisional until the maintainer ratifies the ADRs (T00.8–T00.17, Gate M0); this
text ratifies no ADR. The widening ruling it builds on is the user's
(2026-11-22, relayed by the lead), not a pick.

## Problem

`service/src/trust/keyset.rs` (a keyset version create, enable and
disable) and `service/src/trust/source.rs` (a trust source create and
update), with the steps they share in `service/src/trust/write.rs`, are the
audited write paths of keyset versions and trust sources. Nothing calls
them (`service/src/trust/mod.rs:18-19`). They must stay unwired because:

- **Widening.** The user ruled (2026-11-22, relayed by the lead) that a
  keyset version write (a create, an enable, a re-enable) and a trust source
  write count as widening, so while `widening_second_approver` is on they
  need an IR-054 approval by a second approver
  (`docs/adr/ADR-008-policy-writes.md:216-222`, OQ-ADR008-3;
  `keyset.rs:19-24`; `source.rs:242-247`; the A04 paragraph of
  `docs/testing/conformance-layout.md:180`). Both modules apply a write at
  once on one operator's authority (`keyset.rs:29-35`), so a wired write
  would skip that approval (`source.rs:236-241`).
- **The in-transaction parse.** The overlap check parses up to 8 stored
  sets inside the transaction, on the same two workers as upload
  validation; "before any endpoint calls this module, the in-transaction
  parses need a permit or priority of their own, separate from Stage A's"
  (`keyset.rs:133-148`, `:277-278`).

What the spec fixes:

- The approve endpoints: "Gated write returns a pending operation and
  changes nothing; approver body carries its request_digest and expected
  revision; one transaction writes the approve operation and applies the
  change, rechecking revision and role; single-use, expiring pending
  operations ...; no embedded approval; under single_actor_mode no approve
  call and the audit event records single-actor", by a "Distinct second
  operator with the approver role the pending operation needs, never the
  requester" (tasks §2 "Endpoint matrix",
  `docs/skyoauth-tasks.md:149`); the tenant twin
  `/admin/v1/tenants/{tenant}/operations/{operation}/approve` (tasks:188;
  public-api `docs/contracts/public-api.md:451`, `:487`; OQ-API-13,
  public-api:699-724).
- The trust rows: `/trust-sources`, `/keysets`, `/bindings`, `/grants` are
  tenant `trust_admin` writes with "explicit widening approval"
  (tasks:151; public-api:457-460: "a distinct `security_admin` `approve`
  operation when `widening_second_approver` is on").
- The toggle: turning `widening_second_approver` on or off needs a distinct
  second `security_admin` approver, or one actor under `single_actor_mode`
  (tasks:147; public-api:449, API-156 at :519; identity-registry IR-052,
  `docs/contracts/identity-registry.md:417-429`).
- The entities. The design does not define the fields of either entity:
  design §7.2 only gives instance `security_admin` the instance security
  policy (`docs/skyoauth-design.md:660`), and design §4.2 uses
  `AdministrativeOperation(kind=route_bundle_approval)` (design:174). The
  logical model is tasks §3 (tasks:236-237 and tasks:377-381):

  ```text
  InstanceSecurityPolicy(instance_id, widening_second_approver,
                         single_actor_mode, audit_sink_config_digest?,
                         audit_sink_validated_at?, revision)
  AdministrativeOperation(id, tenant_id?, actor_id, kind, request_digest,
                          expected_revision, immutable_plan,
                          challenge_hash?, expires_at?, consumed_at?,
                          revoked_at?, revocation_operation_id?,
                          approves_operation_id?, revision, outcome,
                          audit_id)
  ```

  "An approval is a second AdministrativeOperation of kind approve whose
  approves_operation_id names the approved operation and whose actor_id
  differs from that operation's actor_id; for widening writes and
  security-domain toggles the approver holds security_admin" (tasks:465;
  IR-054, identity-registry:459-473). `single_actor_mode` is deployment
  configuration, mirrored read-only (IR-053, identity-registry:430-458).

- ADR-008: item 3, soft disable "is fail-safe and is not widening"
  (ADR-008:41-51); item 12, the server detects widening, "the flag only
  acknowledges that detection, and a write the server detects as widening
  without the flag is rejected" (ADR-008:91-114, OQ-ADR016-2 at :163-165
  and ADR-016:176-180); item 13, deleting a predicate is widening
  (ADR-008:115-119); item 15, provider plans, route-bundle approval,
  security-disable and enrollment resume have their own approval paths
  (ADR-008:125-129). OQ-TM-7 (ADR-008:166-172) is the separation-of-duty
  rule for provider plan commits; this flow borrows only its shape, "a
  distinct second `adm_*` approver unless an explicit audited instance
  policy allows single-actor mode" (ADR-008:169-171), which item 12 repeats
  for the toggle, "or one actor when the audited single-actor instance
  policy `single_actor_mode` is on" (ADR-008:102-103).
- The table: `administrative_operation` exists (`0005_operator.sql:236-330`)
  with immutable plan, digest, kind, actor, tenant, expected revision,
  expiry and approved operation (`:425-431`), set-once consumption and
  revocation (`:453-457`), no consume after revoke (`:459-464`) and
  `consumed_at < expires_at` (`:328-329`). The service rules the database
  leaves open are in `service/migrations/README.md:947-962` (a distinct
  approver, the digest echo, the tenant, an expiry, no secrets in the
  plan).

What it leaves open, and this proposal decides: what a pending trust write
stores and how its digest is built; the transactions and their lock order
against the `trust::keyset` and `trust::source` orders; which writes are
widening beyond the ruling; cancellation and rejection; the expiry bound
and read path (OQ-API-14, public-api:725-728); the audit trail; and the
race behaviour.

**Owner.** No task ID names the second-approver flow. The code and docs
attribute it to "T14.1, T14.2" (`keyset.rs:24-28` and `:265-267`,
`source.rs:236-246`, `service/migrations/README.md:3114-3116` and
`:3333-3334`, ADR-008:220, conformance-layout:180,
`tests/conformance/README.md:7`, `tests/security/a04.rs:136`), and some of
them name "the request layer of T14.1 and T14.2" too (`keyset.rs:27`,
`source.rs:237-238`, README:3115-3116 and :3334); but T14.1–T14.2 are the
audience registry and the IR-080 reference checks (tasks:533-534). Three
places also say the ruling is recorded in "ADR-008 item 12"
(conformance-layout:180, `tests/conformance/README.md:7`,
`tests/security/a04.rs:132`), while it is in the OQ-ADR008-3 entry
(ADR-008:216-222); item 12 carries the 2026-11-19 decision only. The
corrections are PR 4 and PR 8 below. The nearest owners are T13.3 (the
private operator API, "Open before M1a: how an approver reads a pending
operation and its expiry bound (OQ-API-14)", tasks:522), T13.2 (role
checks, tasks:521), T13.8 (`trust_admin` source provisioning, tasks:527),
T11.6 (audited disable and rotation, tasks:498), T10.4 (atomic audit and
optimistic concurrency, tasks:482) and T10.2 (generated IDs, tasks:480).
The A04 paragraph names T11.6, T13.8 and T13.2 for "the server's widening
detection" (conformance-layout:180). This proposal uses those IDs.

## Proposal

### 1. Which writes are widening, and what happens to them

The server classifies each write by a pure function of the write and,
only with the Q2 add-on, for a source update, the stored row read under
its lock. No caller input
decides it (ADR-008 item 12).

| Write                                                                                                                        | Widening                                                     | Basis                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `create_version`, enabled or disabled                                                                                        | yes                                                          | the ruling ("a create"); Q3                                                                                                                                                   |
| `enable_version`, a re-enable and an enable of an already enabled version included                                           | yes                                                          | the ruling ("an enable, a re-enable"); `keyset.rs:100-103` writes the latter like any other enable                                                                            |
| `disable_version`                                                                                                            | no                                                           | not among the ruling's writes (`keyset.rs:34-35`); ADR-008 item 3 by analogy                                                                                                  |
| `create_source`                                                                                                              | yes                                                          | the ruling                                                                                                                                                                    |
| `update_source` whose new `status` is `disabled` and whose every other mutable member equals the stored row's                | no, only if the user accepts Q2; until then yes (the ruling) | the ruling counts "a trust source write" (ADR-008:217-219); Q2 proposes ADR-008 item 3 by analogy and tasks:463 ("disabling is not widening" for an egress entry); (inferred) |
| any other `update_source`: an enable, a rename, a no-op, a disable that also changes a member, a change to a disabled source | yes                                                          | the ruling; `source.rs:49-52` already treats a disable that changes a member as a change                                                                                      |

So, until the user answers Q2, every trust source write is widening and
both classifications depend on the write kind only. The disable-only
exception is an add-on to PR 5 that lands only after the user accepts Q2:
then `classify_source_update(stored, changes)` returns "not widening"
exactly when `changes.status == Disabled` and the other fourteen members
of `TrustSourceChanges` (`model.rs:937-953`) equal the stored ones. A
finer per-member diff (fewer audiences narrows, a new algorithm widens) is
rejected (D1).

**The flag.** A widening write must carry `acknowledge_widening = true`.
Without it the write is refused with `WideningNotAcknowledged`, whether
`widening_second_approver` is on or off, since IR-052 still asks for "the
widening flag, the expected revision and the atomic audit record" when it
is off (identity-registry:422-424). A flag on a write that is not widening
is accepted and ignored (D2). Whether the toggle itself needs the flag is
not decided here (see "Not decided here").

**The mode** is decided inside the write's transaction, after the policy
row is locked (section 3), never by the caller:

| Widening | `widening_second_approver` | `single_actor_mode`                                        | Result                                                                    |
| -------- | -------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------- |
| no       | any                        | any                                                        | applied at once, as today                                                 |
| yes      | off                        | any                                                        | applied at once; flag, expected revision and audit event (IR-052; D23)    |
| yes      | on                         | on, and the requester also holds instance `security_admin` | applied at once; the event's outcome records single-actor (section 7; Q4) |
| yes      | on                         | otherwise                                                  | a pending operation; the target is not written                            |

### 2. The pending operation

A pending gated write is one `administrative_operation` row, with no new
column (D3):

| Column                                    | Pending gated write                                                                                                                                                             |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                                      | caller-generated (T10.2)                                                                                                                                                        |
| `tenant_id`                               | the target's tenant; `NULL` for the toggle (README:956-957: the tenant of its audit event)                                                                                      |
| `actor_id`                                | the requester's `admin_id`                                                                                                                                                      |
| `kind`                                    | `trust_keyset_version_create`, `trust_keyset_version_enable`, `trust_source_create`, `trust_source_update` or `instance_security_policy_update` (inferred names)                |
| `request_digest`                          | SHA-256 of the canonical request, 32 bytes (below)                                                                                                                              |
| `expected_revision`                       | the target's revision: the version (an enable), the source (an update), the policy row (the toggle); 0 for a create (README:933)                                                |
| `immutable_plan`                          | the validated payload (below)                                                                                                                                                   |
| `expires_at`                              | the request's `now` plus 24 hours (D5; OQ-API-14; Q1)                                                                                                                           |
| `consumed_at`                             | set once, by the approve                                                                                                                                                        |
| `revoked_at`, `revocation_operation_id`   | set once, together, by a cancel or a reject                                                                                                                                     |
| `approves_operation_id`, `challenge_hash` | `NULL`                                                                                                                                                                          |
| `outcome`                                 | `pending`, then `applied`, `cancelled` or `rejected` (inferred values; `outcome` and `revision` are the mutable columns, README:788-792); it stays `pending` after expiry (D22) |
| `audit_id`                                | the `administrative_operation.create` event, inserted first                                                                                                                     |

**The plan** (version 1, every member written by the server from typed
input, so it carries no member the caller chose). Every kind's plan holds
`requester_credential_id`, the ID of the `admin_credential` the request
was authorized with, which the approve requires still enabled and
unrevoked (D21).

- `trust_keyset_version_create`: `version_id`, `keyset_id`, `public_jwks`
  (the text of `ValidatedKeyset::public_json`, the canonical public
  projection, never the raw upload), `fingerprint`
  (`KeysetFingerprint::as_str`), `allowed_algorithms` (the sorted names of
  the `allowed` set Stage A validated against, `keyset.rs:550-563`; D25),
  `effective_at_us` and `expires_at_us` (whole microseconds since the
  epoch, floored as the writer floors them, `keyset.rs:104-112`;
  `expires_at_us` may be `null`), `status`, and `provenance` as its
  canonical JSON text (a string).
- `trust_keyset_version_enable`: `version_id`, `keyset_id` and the stored
  version's `fingerprint`, read at the request, so the approver sees which
  keys become live; the `0004` immutability triggers keep it fixed.
- `trust_source_create`: every member of `NewTrustSource`
  (`model.rs:909-930`), with `proof_bounds` as canonical JSON text.
- `trust_source_update`: `source_id`, every member of `TrustSourceChanges`
  (`proof_bounds` as text) and `changed`, the sorted names of the members
  that differ from the stored row at the request, for the reviewer.
- `instance_security_policy_update`: `widening_second_approver`.

No member holds a secret: the projection is public-only, provenance naming
a JWK private member is refused (`keyset.rs:89-94`), and the source's
`ca_bundle_ref` and `reviewer_credential_ref` are references
(README:960-962).

**The digest.**

```text
request_digest = SHA-256("skyoauth.administrative_operation.v1\n" || C)
C = canonical JSON of {"actor_id": <id>, "expected_revision": <i64>,
                       "expires_at": <i64>, "id": <id>, "kind": <kind>,
                       "plan": <plan>, "tenant_id": <id> | null}
```

`expires_at` is `floor_to_microsecond(now + 24 h)` (`model.rs:265`) as
whole microseconds since the epoch (inferred): the same value is bound
for the insert, so the `timestamptz` column returns it exactly and the
approve reads back what the digest covered. With `id`, `actor_id` and
`expires_at` in `C`, a digest names one operation of one requester with
one expiry, so an echo copied from another operation with the same plan
never matches.

`C` has its members sorted byte-wise at every level, the nested plan
included (`jsonb` returns object keys shortest first, so the reader
re-sorts), no insignificant whitespace,
strings escaped as the IR-056 event hash escapes them (`push_string` in
`service/src/persistence/registry/events.rs`), integers in decimal. The
plan holds only strings, integers, booleans, `null`, arrays and objects
of those, and free-form operator JSON
(`provenance`, `proof_bounds`) only as a string, so the `jsonb` column
returns the plan member for member and the digest can be recomputed from
the stored row exactly (`jsonb` keeps neither key order nor number
spelling). No new dependency: `sha2` and `serde_json` are already in
`service/Cargo.toml`. On the wire the digest is unpadded base64url
(inferred).

**Binding an approval to the request** (D6): the approver's body carries
`request_digest` and `expected_revision` (tasks:149). Under the row lock
the server compares both with the stored columns, byte for byte and
exactly; recomputes the digest from the stored ID, actor, kind, tenant,
expected revision, expiry and plan and compares it with the stored digest
(a mismatch is a
data-integrity error); and at the write compares the target's current
revision with `expected_revision` through the module's own check, so a
target that moved is `StaleRevision`.

**Expiry** is derived: an operation with `now >= expires_at` and no
`consumed_at` is expired, and nothing writes it (no job). Its `outcome`
stays `pending`; a reader derives "expired" from `expires_at` and its own
`now` (D22). The `0005` check `consumed_at < expires_at` backs the
approve's own check.

**Cancel and reject** both revoke: they insert an operation of kind
`cancel` (by the requester) or `reject` (by an eligible approver), whose
`request_digest` and `expected_revision` copy the pending operation's and
whose plan is `{}`, and set the pending row's `revoked_at`,
`revocation_operation_id` (the `0005` revocation check needs both) and
`outcome`. An expired operation may still be cancelled or rejected; a
consumed one may not.

**The approval** is an operation of kind `approve`: the approver as actor,
`approves_operation_id` the pending operation, the same `tenant_id`, its
`request_digest` and `expected_revision` copied, plan `{}`, outcome
`success`, no expiry. Its `audit_id` names its
`administrative_operation.approve` event, whose `object_id` is the
pending operation, not the approve operation (section 7). A cancel's or
reject's `audit_id` likewise names an event whose `object_id` is the
revoked operation.

Several pending operations may name one target. The first approved wins;
the others then fail their revision or overlap check (section 5).

### 3. The transactions

Every function below runs in a savepoint of the caller's transaction,
releases it on `Ok` and rolls it back on `Err` (`write.rs:61-80`), and runs
only under `READ COMMITTED` (step 0, `write.rs:30-41`), for the reasons of
`keyset.rs:226-237` and `source.rs:190-205`. The caller commits on `Ok`.

**Request** (`submit_*`, one transaction):

1. Pure checks before any statement: the provenance check
   (`keyset.rs:168-169`), the syntax of a created source's members
   (`source.rs:93-98`). The upload was validated before the transaction
   (Stage A, `keyset.rs:48-62`).
2. Step 0, then step 1: the requester's operator rows `FOR SHARE`
   (`write.rs:43-59`; for the toggle, instance `security_admin`). When Q4
   is accepted, the requester's instance `security_admin` binding, if any,
   is locked in the same ordered statement as the tenant binding
   (`authorize_roles_locked`, section 9). This step yields the requester's
   `admin_id` and credential ID; every later step is a post-authorization
   step function that takes them, shared with the approve (D26).
3. A widening write with the flag unset is refused here
   (`WideningNotAcknowledged`). Until the user accepts Q2 its class depends
   on the kind only; `disable_version` is never widening.
4. The `instance_security_policy` row `FOR SHARE` (new; D10). A missing
   row is `PolicyUnavailable` (D18). `disable_version` skips steps 3, 4
   and 6: its class is fixed.
5. The module's own locks and reads, unchanged: the parent `trust_keyset`
   `FOR NO KEY UPDATE` (`keyset.rs:181-185`) and its reads; or the
   `trust_source` row `FOR NO KEY UPDATE` (`source.rs:123-129`), now
   reading every mutable column, not only the destinations (for the
   plan's `changed`).
6. Only with the Q2 add-on of PR 5: a source update is classified from
   the stored row; a disable-only update is applied at once, and any other
   update with the flag unset is `WideningNotAcknowledged`.
7. The module's checks, unchanged: the cap of 8 and the overlap check (on
   the in-transaction pool, section 8); the syntax of changed members and
   the egress entries `FOR SHARE` (`source.rs:130-135`).
8. Applied at once (table above): the registry write and the domain event
   last, exactly the module's steps 6 and 7 (keyset) or 4 and 5 (source).
   Pending: the audit head through `append_audit_event`, the event
   `administrative_operation.create`, then the operation insert
   (README:1040-1041; the issue of a recovery challenge does the same,
   `service/src/persistence/registry/recovery.rs:48-66`). No registry
   write: the source row is never taken `FOR UPDATE` by a request, so a
   pending request does not block binding inserts or token exchanges
   (`source.rs:138-152`).

So a request runs every service check the direct write runs (D7): the
requester learns of those refusals at once, and an approver never reviews
a request the service would refuse as it stands. The database constraints
run only when the row is written, at approve: every `0004` and `0007`
CHECK, unique key and foreign key of the target table, and the `0011`
trigger `trust_source_egress_enabled`. For example:

- the non-empty checks `trust_source_id_check`, `trust_source_name_check`,
  `trust_source_exact_issuer_check`, `trust_source_discovery_url_check`,
  `trust_source_cluster_id_check`,
  `trust_source_token_review_endpoint_check`,
  `trust_source_ca_bundle_ref_check`, `trust_source_ca_fingerprint_check`,
  `trust_source_reviewer_credential_ref_check` and
  `trust_keyset_version_id_check`;
- `trust_source_audiences_check` and `trust_source_algorithms_check`
  (non-empty arrays), `trust_source_review_timeout_ms_check` (`> 0`) and
  `trust_source_stale_revocation_acknowledged_check` (must be true);
- the kind, replay and profile checks (`trust_source_*_kind_check`,
  `trust_source_single_use_replay_check`,
  `trust_source_token_review_profile_check`), the length and no-space
  checks, and `trust_keyset_version_validity_check`;
- the `0007` checks `trust_keyset_version_effective_at_range_check` and
  `trust_keyset_version_expires_at_range_check`;
- the unique keys (the version and source IDs, a source's
  `(tenant_id, name)` and `cluster_id`) and
  `trust_source_jwks_keyset_id_fkey`.

The unnamed `0004` checks carry PostgreSQL's default names, as
`KNOWN_CONSTRAINTS` lists them (`service/src/persistence/registry/error.rs`,
lines 329-400). These values come from the typed input (`NewTrustSource`,
`TrustSourceChanges`, `model.rs:909-953`, and the version's window), so a
request the service accepts can be approved and then refused at every approve.
Each refuses the approve as it refuses the direct write (`AlreadyExists`,
`Invariant`), writes nothing and leaves the operation pending (D14). PRs 4 and 5
may pre-validate the plainly typed ones (non-empty, `> 0`, `true`) at the
request where that is cheap (D27, a pick, not a promise); the others stay
approve-time. A savepoint dry run of the write at the request is rejected (D7).

**Approve** (`prepare_approval`, then `approve_operation`):

1. Outside any transaction, `prepare_approval` first authorizes, without a
   lock and exactly as step 2 below: the approver's lookup (a miss is
   `Unauthorized`), the scope check (`NotFound`), `SelfApproval`, and the
   unlocked state check (consumed, revoked, expired or a wrong kind is
   `NotApprovable`). Only then does it read the plan. For
   `trust_keyset_version_create` it parses the plan's `public_jwks` in
   full on the Stage A pool (`validate_keyset` against the plan's
   `allowed_algorithms` intersected with the caller's current `allowed`
   set, D25) and checks its fingerprint against the plan's. It returns
   the digest it read and the `ValidatedKeyset`, so no lock is held while
   the payload is parsed, and nothing is parsed for a caller who may not
   approve (D20).
2. Step 0. Then, without a lock: the approver's lookup (an instance
   `security_admin`; a miss is `Unauthorized`, before anything about the
   operation is read), and the operation's immutable `tenant_id`,
   `actor_id` and `kind`. An operation outside the path's scope (another
   tenant, a tenant operation on the instance path or the reverse) is
   `NotFound`; an approver whose `admin_id` is the `actor_id` is
   `SelfApproval`.
3. The operator rows of both actors `FOR SHARE`, in the `0005` order
   (`authorize_approval_locked`, section 9): the two `admin_identity` rows
   by ID, the two `admin_credential` rows by ID (the approver's, and the
   requester's `requester_credential_id` from the plan), then the
   approver's `security_admin` binding and the requester's role binding
   for the kind (tenant `trust_admin`, or instance `security_admin` for the
   toggle) by ID, then the lookups repeated as `authorize_operator_locked`
   does (`operator.rs:160-172`; the lookup requires an enabled and
   unrevoked credential, `operator.rs:504-516`, README:970-971). A
   requester whose identity is disabled, whose submitting credential is
   disabled or revoked, or who lost the role is `RequesterNotAuthorized`
   (Q5; D21).
4. The operation row `FOR NO KEY UPDATE`, read again: consumed, revoked or not
   an approvable kind is `NotApprovable` with its reason (expiry is checked in
   step 6, after the registry write); a digest or expected revision unequal to
   the echo, or a digest unequal to the one `prepare_approval` read, is
   `EchoMismatch`; a recomputed digest unequal to the stored one, or (a keyset
   create) a prepared `ValidatedKeyset::public_json` not byte for byte equal to
   the locked plan's `public_jwks`, is `PlanIntegrity` (D24).
5. The write's own steps for the kind, from the plan, through the same
   post-authorization step functions as the request, with the
   `Requester { admin_id, credential_id }` that step 3 checked (D26):
   steps 2 to 6 of
   `keyset.rs:178-202` (the parent lock, the target read and revision, the
   cap, the overlap check of the stored versions on the in-transaction
   pool, the insert or compare-and-set), or steps 2 to 4 of
   `source.rs:123-152` (the source row and revision, the class, the syntax
   of changed members, the entries `FOR SHARE`, the insert or
   compare-and-set). For the toggle: the policy row `FOR NO KEY UPDATE`
   and its compare-and-set. The policy row is not read for a trust kind:
   an approval stays valid if the toggle went off meanwhile (inferred).
   The step function ends with the registry write and appends nothing: it
   returns the row and the domain event, unstamped (D26).
6. **The clock** (D28): after the registry write and before the first
   append, the approve samples the injected clock once. `now >= expires_at`
   is `NotApprovable(Expired)`, and the savepoint rollback undoes the
   registry write, so nothing is written. Otherwise that one sample is
   both events' time and `consumed_at`; it is needed for nothing earlier,
   since trust rows store no write time and the modules' `now` feeds only
   the event timestamp (`source.rs:578`, `:664`; `keyset.rs:703`). Every
   wait that can be long comes before the sample: the operator, operation
   and target locks, the parse permit and the overlap parse, a conflicting
   uncommitted unique key at the insert, and a source compare-and-set's
   `FOR UPDATE`, which waits for every `principal_binding` and
   `consumed_assertion` insert through the source (`source.rs:136-152`). An
   approve that waited past the expiry is therefore refused, instead of
   recording a `consumed_at` taken before it waited, which the `0005`
   check (`consumed_at < expires_at`, `0005:328-329`), comparing the two
   stored values only, would accept.
7. Last, through `append_audit_event` (so the head is taken here):
   `administrative_operation.approve`, the approve operation insert, the
   domain event, and the update of the pending row (`consumed_at` the
   step 6 sample, `outcome = 'applied'`, revision + 1), whose row step 4
   already holds, so it does not wait (README:1042-1046). The waits inside
   the append (the tenant row `FOR KEY SHARE` and the audit head) come
   after the sample and are not covered (Limits).

A failure anywhere rolls the savepoint back: the target is unchanged and
the operation stays pending until it expires, so an approval refused for
an overlap can succeed once the conflict is disabled (D14).

**Cancel** (requester) **and reject** (approver): step 0; the actor's
lookup (cancel: the operation's `actor_id`, still holding the kind's role;
reject: an instance `security_admin` who is not the `actor_id`); the scope
check as in approve; the operator rows `FOR SHARE`; the operation row
`FOR NO KEY UPDATE` (consumed or already revoked: `NotApprovable`); then
the head: `administrative_operation.cancel` or `.reject`, the revoking
operation insert, the update of the pending row. This is the `0005`
revocation order exactly (README:1042-1046). A cancel authorizes the
operation's `actor_id` through any enabled, unrevoked credential of that
identity, not only the submitting one.

**Credential rotation and restoration** (D21; inferred consequences). A
requester who rotates their credential strands their own pending
operations: each is `RequesterNotAuthorized` at approve until it expires.
They cancel with the new credential (the cancel authorizes by `actor_id`)
and submit again. A restoration revokes every credential still unrevoked
(`recovery.rs:146-151`), so after it every pending operation is
`RequesterNotAuthorized` until it expires. It does not disable any
identity, and the replacement operator is a new identity
(`recovery.rs:152-158`): a requester, the replaced one included, can
cancel once a credential is enrolled for their identity. Until then a
`security_admin` rejects the operations, or they expire.

**The toggle** (`submit_widening_toggle`) follows the request steps with
the policy row as target: instance `security_admin`; then the policy row
`FOR NO KEY UPDATE`, never `FOR SHARE`, and its revision checked against
the request's `expected_revision` (`StaleRevision` if it moved), in both
branches; then either the compare-and-set and
`instance_security_policy.update` (`single_actor_mode` on, outcome
`success_single_actor`) or a pending `instance_security_policy_update`
operation, approved on the instance path by a distinct `security_admin`
(API-156). With `single_actor_mode` on, two concurrent toggles serialize
on the row and the second gets `StaleRevision` at its request. With it
off, neither updates the row at the request: both pass the revision
check, both go pending, and the second to be approved gets
`StaleRevision` at its approval, since the first approval moved the
revision. A write locks the rows it
updates `FOR NO KEY UPDATE` (README:1025-1026); a toggle that took
`FOR SHARE` and then updated would upgrade its lock, and two concurrent
toggles would each wait for the other's share lock and end in `40P01`, as
the review reproduced on PostgreSQL 17.12 (D19). A trust write takes the
row `FOR SHARE` (request step 4), so it and a toggle serialize. The toggle
is always gated, whatever its current value (ADR-008:100-105).
`single_actor_mode` and the sink fields stay unwritable online (IR-053).

### 4. What is checked again at approve, and what is not

| Checked again at approve                                                                                                                                     | Taken from the request, bound by the digest                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| the approver's `security_admin` role, enabled identity and credential (tasks:149: "rechecking revision and role")                                            | the payload itself: the projection, window, status and provenance; the source members  |
| the approver is not the requester; the requester's identity is enabled, its submitting credential enabled and unrevoked, and its role held (Q5; D21)         | the raw upload's Stage A validation (`keyset.rs:550-563`); only its projection is kept |
| the operation is pending, unexpired, unrevoked, of an approvable kind; the echo; the recomputed digest                                                       | the class: recomputed, and at an unchanged revision it is the same                     |
| the projection, parsed in full again before the transaction against the plan's `allowed_algorithms` and the current `allowed` set, and its fingerprint (D25) |                                                                                        |
| the parsed projection equal byte for byte to the locked plan's (D24)                                                                                         |                                                                                        |
| the database constraints, which run only here (section 3)                                                                                                    |                                                                                        |
| the target's revision; for a keyset, the parent lock, the cap of 8, the full parse of every compared stored version and the overlap check, all again         |                                                                                        |
| for a source, the syntax of changed members, the egress entries `FOR SHARE`, the `0004` kind checks and the `0011` guard                                     |                                                                                        |
| the provenance private-member check (pure, cheap)                                                                                                            |                                                                                        |

### 5. Races and failures

| Between request and approve                                                                                                | At approve                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a direct write (a disable, another update) moves the target's revision                                                     | `StaleRevision`; the operation stays pending and can never apply; the requester cancels it or it expires                                                                                                                                                                |
| a concurrent disable runs while the approve holds the target                                                               | they serialize on the `trust_keyset` or `trust_source` row; the second sees the first's revision                                                                                                                                                                        |
| an egress entry the change needs is disabled                                                                               | `EgressNotAllowed` (the service's entry check, `source.rs:509-532`). If the service check were skipped, the `0011` trigger `trust_source_egress_enabled` refuses the write with `23514`, `Invariant { kind: EgressEntryEnabled }` (README "What 0011 adds", :2136-2150) |
| an entry disable starts while the approve holds the entry `FOR SHARE`                                                      | the disable waits for the approve's commit; the source is then degraded at fetch (`source.rs:178-188`)                                                                                                                                                                  |
| another version was enabled and now overlaps                                                                               | `Overlap`; after that version is disabled, a new approve of the same operation passes                                                                                                                                                                                   |
| the keyset reached 8 enabled versions                                                                                      | `TooManyEnabledVersions`                                                                                                                                                                                                                                                |
| a version with the plan's `version_id` now exists                                                                          | `AlreadyExists` (the insert's `23505`)                                                                                                                                                                                                                                  |
| the parent keyset was disabled                                                                                             | written like any other (`keyset.rs:269-270`, inferred: the verifier reads the keyset's status)                                                                                                                                                                          |
| two approvers approve at once                                                                                              | they serialize on the operation row; the second reads it consumed: `NotApprovable(Consumed)`                                                                                                                                                                            |
| a cancel and an approve race                                                                                               | the same row lock; whichever is second gets `NotApprovable`                                                                                                                                                                                                             |
| the toggle went off                                                                                                        | the approve still applies (an approval is never less safe); the requester may cancel and submit again                                                                                                                                                                   |
| the toggle went on while a direct widening write was in flight                                                             | the write holds the policy row `FOR SHARE` from step 4 to its commit, so the toggle's `FOR NO KEY UPDATE` waits; a write that reaches step 4 after the toggle committed reads it on and goes pending                                                                    |
| two toggles at once                                                                                                        | `single_actor_mode` on: they serialize on the policy row `FOR NO KEY UPDATE` and the second gets `StaleRevision` at its request; off: both go pending and the second approved gets `StaleRevision` at its approval; never `40P01` (D19)                                 |
| a database constraint refuses the row (section 3)                                                                          | `AlreadyExists` or `Invariant`, as for the direct write; the operation stays pending                                                                                                                                                                                    |
| the approver's credential was revoked                                                                                      | `Unauthorized`                                                                                                                                                                                                                                                          |
| the requester's identity disabled, submitting credential disabled or revoked (a rotation, a restoration), or role disabled | `RequesterNotAuthorized` until it expires (D21; section 3)                                                                                                                                                                                                              |
| the operation expired                                                                                                      | `NotApprovable(Expired)`; the `0005` check refuses a consume at or after `expires_at` even if the service check were skipped                                                                                                                                            |
| the commit outcome is unknown to the approver's client                                                                     | a retried approve reads the operation consumed; the client reads the target                                                                                                                                                                                             |

### 6. Roles

- **Requester.** The role the endpoint row names: tenant `trust_admin` for
  the trust writes (tasks:151), instance `security_admin` for the toggle
  (tasks:147). Roles do not inherit (API-120).
- **Approver.** An instance `security_admin` (IR-054: "the approver MUST
  hold `security_admin`"), whose `admin_id` is not the requester's, even
  when one operator holds both roles. A second `trust_admin` cannot
  approve. A tenant operation is approved only on its tenant path and an
  instance operation only on the instance path; anything else is
  `NotFound` (README:953-955: an approval of a tenant operation stays in
  its tenant).
- **`single_actor_mode` on.** No approve call is made (tasks:149): the
  write applies at once and its event records the single-actor approval.
  Recommended reading (Q4): the one actor must also hold instance
  `security_admin`; otherwise the write goes pending as above.
- **`widening_second_approver` off.** No second approver; the flag, the
  expected revision and the audit event suffice (IR-052).
- **The toggle's own approval.** Always a distinct second `security_admin`,
  or one actor under `single_actor_mode` (tasks:147; API-156; A48).
- **Out of scope.** Provider plan commits, links, route-bundle approvals,
  security-disable and enrollment resume keep their own paths (ADR-008
  item 15; OQ-API-15, public-api:729-735). `approve_operation` refuses any
  kind outside its five (`NotApprovable(WrongKind)`), an
  `operator_restoration` challenge included.

### 7. Audit trail

| Step                     | Events, in chain order                                                                                                                                                 | Outcome                                                                                                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| request, pending         | `administrative_operation.create`, actor the requester, `object_id` the operation, new revision 1                                                                      | `success`                                                                                                                                                                                                    |
| request, applied at once | the module's event as today (`trust_keyset_version.create`, `.enable`, `trust_source.create`, `.update`, `instance_security_policy.update`)                            | `success` (not widening); `success_widening` (widening, toggle off; D23); `success_single_actor` (widening with the toggle on, row 3 of the mode table; Q4; and the toggle itself under `single_actor_mode`) |
| approve                  | `administrative_operation.approve` (actor the approver, `object_id` the pending operation, revisions 1 and 2), then the module's event (actor the requester, as today) | `success`                                                                                                                                                                                                    |
| cancel, reject           | `administrative_operation.cancel` or `administrative_operation.reject` (actor the canceller or rejecter, `object_id` the pending operation, revisions 1 and 2)         | `success`                                                                                                                                                                                                    |
| expiry                   | none (derived)                                                                                                                                                         |                                                                                                                                                                                                              |

`administrative_operation.create` and `.approve` are in `AUDIT_ACTIONS`
already (`event_actions.rs:24-31`, `:71-72`); `.cancel` and `.reject` are
new (inferred verbs; IR-059 fixes only the syntax). A consumer joins an
event's `object_id` to the operation row to read its `kind` and plan, as
for recovery challenges. The domain event keeps the requester as actor:
the change is the requester's, and the approval is the adjacent event.

**Outcomes.** A widening write applied at once with the flag while
`widening_second_approver` is off records `success_widening`, so an
auditor can tell an acknowledged widening from an ordinary write without
reclassifying it (D23), whatever `single_actor_mode` is. A widening write
applied at once with the toggle on (row 3 of the mode table) records
`success_single_actor`, as does the toggle itself when applied at once
under `single_actor_mode`, whatever its current value. Both are new
values of the existing `outcome`
string (`events.rs:401-402`: the IR-056 hash input holds it), not a new
member; the value set is inferred, since no contract lists outcome
values. Any change to the IR-056 envelope itself (a new member) is
ADR-level and is not proposed here.

**The fingerprint.** The envelope has no member for it (`keyset.rs:246-252`,
`:275-276`). This flow does not add one (D12; Q6): a gated create's plan
holds the projection and fingerprint for the life of the row, and the
version row keeps them immutable (IR-059 link through the row). A new
envelope member would change the IR-056 hash input and the sink format
(IR-055), an ADR-level change.

**Refusals** are not audited: a refused request or approve rolls back, as
every write does today.

### 8. The in-transaction parse permit

A second semaphore in `trust::keyset` for the parses that run while a
transaction holds the parent lock and the operator rows (D13):

- `IN_TRANSACTION_WORKERS = 2` (inferred), separate from
  `VALIDATION_WORKERS` (`keyset.rs:305-318`). Stage A and the approve's
  pre-parse (section 3) use `VALIDATION`; `parse_stored_versions`
  (`keyset.rs:575-590`) uses the new pool.
- A bounded wait, `IN_TRANSACTION_WAIT = 2 s` (inferred): a permit not
  granted in time is `ValidationBusy`, retryable; the savepoint rollback
  releases the parent lock. The wait needs `tokio::time::timeout`, so PR 1
  adds tokio's `time` feature to the non-dev dependency
  (`service/Cargo.toml:20` lists `macros`, `net`, `rt-multi-thread`,
  `signal` and `sync`; `time` is in the dev dependency only, `:28`).
- The cap of 8 still bounds each write to 8 compared sets
  (`keyset.rs:113-119`).
- The follow-up of `keyset.rs:146-148`, a stored marker that a projection
  passed the point checks, would remove the parse; it is not part of this
  flow.

### 9. Service API (proposal; names inferred)

```rust
// service/src/operation/mod.rs (new): kinds, digest, approve, cancel, reject.
pub const PENDING_OPERATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// SHA-256 of the canonical request. `Debug` prints `RequestDigest(..)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestDigest([u8; 32]);

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    TrustKeysetVersionCreate,
    TrustKeysetVersionEnable,
    TrustSourceCreate,
    TrustSourceUpdate,
    InstanceSecurityPolicyUpdate,
}

/// What a gated write returns: the write, or the pending operation.
pub enum Gated<T> {
    Applied(T),
    Pending(PendingOperation),
}

pub struct PendingOperation {
    pub id: String,
    pub kind: OperationKind,
    pub request_digest: RequestDigest,
    pub expected_revision: i64,
    pub expires_at: SystemTime,
}

/// The request's common input. `event_id` is the one event a request
/// appends (the domain event, or `administrative_operation.create`);
/// `operation_id` is used only when the write goes pending (T10.2).
pub struct Submission<'a> {
    pub public_identity: &'a str,
    pub acknowledge_widening: bool,
    pub operation_id: &'a str,
    pub event_id: &'a str,
    pub now: SystemTime,
}

pub enum ApprovalScope<'a> {
    Instance,
    Tenant(&'a str),
}

pub struct ApprovalEcho {
    pub request_digest: RequestDigest,
    pub expected_revision: i64,
}

pub struct ApprovalIds<'a> {
    pub approve_operation_id: &'a str,
    pub approve_event_id: &'a str,
    pub write_event_id: &'a str,
}

pub struct RevokeIds<'a> {
    pub revoking_operation_id: &'a str,
    pub event_id: &'a str,
}

/// Authorized and read without a lock, parsed outside any transaction.
pub struct PreparedApproval { /* operation ID, digest read, kind, payload */ }

/// The requester as step 1 authorized it (request) or as the plan names
/// it (approve); the post-authorization step functions take this.
/// `authorize_trust_admin` (`write.rs:43-59`) returns it in place of the
/// bare `admin_id` (PRs 4 and 5).
pub(crate) struct Requester {
    pub admin_id: String,
    pub credential_id: String,
}

/// The server clock, sampled by the approve after its registry write and
/// before its first append (D28). Production reads `SystemTime::now()`;
/// tests inject their own.
pub trait Clock: Sync {
    fn now(&self) -> SystemTime;
}

/// A step function's domain event, without its ID, time and outcome; the
/// caller stamps and appends it (the request with its `now`, the approve
/// with its one clock sample).
pub(crate) struct UnstampedEvent { /* action, object, revisions, tenant */ }

#[non_exhaustive]
pub enum Applied {
    KeysetVersion(TrustKeysetVersion),
    Source(TrustSource),
    InstanceSecurityPolicy(InstanceSecurityPolicy),
}

/// Authorizes first (as `approve_operation`, same `Unauthorized` and
/// `NotFound`), then reads and parses; `allowed` is the current set.
pub async fn prepare_approval(
    pool: &PgPool,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    allowed: &[Algorithm],
    now: SystemTime,
) -> Result<PreparedApproval, ApprovalError>;

pub async fn approve_operation(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    ids: &ApprovalIds<'_>,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError>;

pub async fn cancel_operation(
    transaction: &mut Transaction<'_, Postgres>,
    requester_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    ids: &RevokeIds<'_>,
    now: SystemTime,
) -> Result<(), ApprovalError>;

/// As `cancel_operation`, with the approver's `public_identity`.
pub async fn reject_operation(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    ids: &RevokeIds<'_>,
    now: SystemTime,
) -> Result<(), ApprovalError>;

pub async fn submit_widening_toggle(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    expected_revision: i64,
    widening_second_approver: bool,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError>;

// service/src/trust/keyset.rs
pub async fn submit_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewKeysetVersion<'_>,
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError>;

pub async fn submit_enable_version(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError>;
// disable_version: unchanged, never gated.

// Post-authorization steps (D26): no operator lookup of their own; both
// submit_* (after step 1) and approve_operation (after
// authorize_approval_locked) call them. Each takes the policy decision
// already made and runs the module's steps 2 to 6 (keyset) or 2 to 4
// (source), through the registry write; the caller appends the event.
pub(crate) async fn apply_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    new: &NewKeysetVersion<'_>,
) -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError>;
pub(crate) async fn apply_enable_version(/* as above, with tenant_id, id,
    expected_revision */)
    -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError>;

// service/src/trust/source.rs
pub async fn submit_create_source(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewTrustSource,
) -> Result<Gated<TrustSource>, SourceWriteError>;

pub async fn submit_update_source(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
) -> Result<Gated<TrustSource>, SourceWriteError>;

// Post-authorization steps (D26), as for keysets.
pub(crate) async fn apply_create_source(/* transaction, requester, new */)
    -> Result<(TrustSource, UnstampedEvent), SourceWriteError>;
pub(crate) async fn apply_update_source(/* transaction, requester,
    tenant_id, id, expected_revision, changes */)
    -> Result<(TrustSource, UnstampedEvent), SourceWriteError>;
// service/src/operation/mod.rs: apply_policy_toggle, likewise.

// service/src/persistence/registry/operation.rs (new): bare, check nothing
// the database does not, like the other registry writers.
pub struct AdministrativeOperation { /* the 0005 columns */ }
pub async fn insert_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
) -> Result<AdministrativeOperation, RegistryError>;
/// The row `FOR NO KEY UPDATE`.
pub async fn lock_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<AdministrativeOperation>, RegistryError>;
pub async fn consume_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError>;
pub async fn revoke_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    revoking_operation_id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError>;
/// The policy row `FOR SHARE` (a trust write); `NotFound` before bootstrap.
pub async fn lock_instance_security_policy_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstanceSecurityPolicy, RegistryError>;
/// The policy row `FOR NO KEY UPDATE` (the toggle, both branches; D19).
pub async fn lock_instance_security_policy(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstanceSecurityPolicy, RegistryError>;
/// Both actors' rows `FOR SHARE`; the requester's credential must be the
/// plan's, enabled and unrevoked (D21).
pub async fn authorize_approval_locked(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    requester_admin_id: &str,
    requester_credential_id: &str,
    requester_scope: OperatorScope<'_>,
    requester_role: AdminRole,
) -> Result<ApprovalAuthority, RegistryError>;
pub async fn authorize_roles_locked(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    roles: &[(OperatorScope<'_>, AdminRole)],
) -> Result<Option<RolesHeld>, RegistryError>;
```

The existing writers authorize by `public_identity` (`write.rs:43-59`), so
neither `submit_*` nor `approve_operation` can call them after its own
authorization: the approve authorizes the approver, and the requester
only by `admin_id`. Each writer is therefore split into step 1 and an
`apply_*` function that takes the authorized `Requester` (D26).
`create_version`, `enable_version`, `create_source` and `update_source`
become step 1 plus `apply_*`, ungated. They
stay public, documented as test-only like the bare registry writers
(`keyset.rs:36-46`), until the test session has moved
`service/tests/trust_keyset_version.rs` and
`service/tests/trust_source_egress.rs` to `submit_*`; then they become
crate-private (PR 7 below).

### 10. Errors

New variants, `#[non_exhaustive]` as today, `Display` fixed text per
variant and `Debug` the variant name (and a fixed reason), never a digest,
an ID, a revision, a destination, a `kid` or another value of the request
(as `keyset.rs:381-388` and `source.rs:326-331`):

- `KeysetWriteError`: `WideningNotAcknowledged`, `PolicyUnavailable`,
  `ValidationBusy`.
- `SourceWriteError`: `WideningNotAcknowledged`, `PolicyUnavailable`.
- `ApprovalError` (new): `Unauthorized`; `NotFound`;
  `NotApprovable(NotApprovableReason)` with `Consumed`, `Revoked`,
  `Expired`, `WrongKind`; `SelfApproval`; `EchoMismatch`;
  `RequesterNotAuthorized`; `PlanIntegrity` (a data-integrity error, not a
  client error); `PolicyUnavailable`; `StaleRevision` (the toggle's policy
  row, D19); `UnsupportedIsolation`;
  `Keyset(KeysetWriteError)`; `Source(SourceWriteError)`;
  `Registry(RegistryError)`. `source()` returns the inner
  `RegistryError` only, as today (`keyset.rs:492-499`).

No contract maps admin write errors to HTTP statuses
(`docs/contracts/errors-retry.md` has none), so the request layer's mapping
is inferred: `Unauthorized` and `SelfApproval` 403; `NotFound` 404;
`NotApprovable`, `EchoMismatch`, `RequesterNotAuthorized` and
`StaleRevision` 409; `WideningNotAcknowledged` 422; `PolicyUnavailable`,
`ValidationBusy` and `Retry` 503 with `Retry-After`; `PlanIntegrity` 500. A
pending write returns 202 with the operation's ID, digest and `expires_at`.

### 11. Schema (PROPOSAL ONLY, not a migration)

No new table or column. One optional migration, `0012` (D15), in the
`0010` and `0011` pattern: a tripwire for the two service rules the `0005`
review left to the service (README:949-955), plus an index for the read
path.

```sql
-- PROPOSAL ONLY. Not a migration file.

-- An approve names an operation of its own tenant (IS NOT DISTINCT FROM,
-- so an instance approve names an instance operation) and is never by that
-- operation's actor. Only kind 'approve': a route_bundle_approval also
-- names its preparation, and one person MAY hold both roles there (IR-054;
-- GW-130, GW-131).
CREATE FUNCTION skyoauth_check_operation_approval() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$ ... $$;  -- reads <schema>.administrative_operation, as 0011 reads
CREATE TRIGGER administrative_operation_approval_check
    AFTER INSERT ON administrative_operation
    FOR EACH ROW WHEN (NEW.kind = 'approve')
    EXECUTE FUNCTION skyoauth_check_operation_approval();
ALTER TABLE administrative_operation
    ENABLE ALWAYS TRIGGER administrative_operation_approval_check;
-- Raises 23514 naming administrative_operation_approves_same_tenant or
-- administrative_operation_approver_distinct (added to KNOWN_CONSTRAINTS).

-- A revocation (cancel, reject) names an operation of the revoked row's
-- tenant; checked where the link is written, on the revoked row.
-- INSERT too: 0005 lets an insert carry a revocation.
CREATE TRIGGER administrative_operation_revocation_check
    AFTER INSERT OR UPDATE OF revocation_operation_id
    ON administrative_operation
    FOR EACH ROW WHEN (NEW.revocation_operation_id IS NOT NULL)
    EXECUTE FUNCTION skyoauth_check_operation_revocation();
-- Raises 23514 naming administrative_operation_revokes_same_tenant.

-- The approver's read path (OQ-API-14): open operations of a tenant.
-- Rows without an expiry (approve, cancel, reject) are never open.
CREATE INDEX administrative_operation_open_by_tenant
    ON administrative_operation (tenant_id, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL
      AND expires_at IS NOT NULL;

-- The read query (D22): the index predicate, then the caller's clock and
-- the five approvable kinds. Outcome stays 'pending' after expiry.
SELECT ... FROM administrative_operation
 WHERE tenant_id = $1  -- a second statement for the instance: IS NULL
   AND consumed_at IS NULL AND revoked_at IS NULL
   AND expires_at IS NOT NULL AND expires_at > $2
   AND kind IN ('trust_keyset_version_create', 'trust_keyset_version_enable',
                'trust_source_create', 'trust_source_update',
                'instance_security_policy_update')
 ORDER BY id;
```

Privileges: the policy row `FOR SHARE` needs `SELECT` on
`instance_security_policy` and `UPDATE` on one of its columns; grant
`UPDATE (instance_id)`, the column `instance_security_policy_immutable`
keeps unchangeable, as `0010` and `0011` prescribe for their tables (the
grant takes effect once the migrate and runtime roles split, a T10.1
follow-up).

## Lock order (declaration)

The `0005` order puts the operator rows first and the audit head last
(README:1023-1046). The new locks sit as follows.

**Request** (direct or pending):

1. the requester's operator rows `FOR SHARE`, in the `0005` order
   (identity, credential, binding or bindings);
2. the `instance_security_policy` row (new): `FOR SHARE` for a trust
   write; `FOR NO KEY UPDATE` for the toggle, in both branches, since it
   is the row the toggle updates (README:1025-1026; D19);
3. the module's rows, in the module's order: the `trust_keyset` row
   `FOR NO KEY UPDATE`; or the `trust_source` row `FOR NO KEY UPDATE`
   (update), then the egress entries `FOR SHARE`, discovery before
   TokenReview;
4. applied at once only: the registry write (the version row; the source
   row `FOR UPDATE` from the compare-and-set on);
5. the audit head, last: the domain event; or the
   `administrative_operation.create` event and the operation insert.

**Approve:**

1. both actors' operator rows `FOR SHARE`, in the `0005` order: the
   identities by ID, the two credentials by ID (the approver's and the
   requester's submitting one), the bindings by ID;
2. the pending operation row `FOR NO KEY UPDATE` (`administrative_operation`
   is the fifth `0005` table, README:1030-1032);
3. the module's rows, as request step 3 (for the toggle, the policy row
   `FOR NO KEY UPDATE`);
4. the registry write (a source compare-and-set takes the source row
   `FOR UPDATE` here);
5. the one clock sample and the expiry check (D28), with every row the
   decision depends on locked;
6. the audit head, last (`append_audit_event`, which first takes the
   tenant row `FOR KEY SHARE`): the approve event, the approve operation
   insert, the domain event, then the update of the pending row, locked in
   step 2.

**Cancel and reject:** the operator rows, the pending row
`FOR NO KEY UPDATE`, then the head, the event, the revoking operation and
the update of the pending row.

Against the README order: the policy row (a `0002` table) comes before the
trust tables, which also holds by name (`instance_security_policy` <
`trust_keyset` < `trust_source`). The egress entry sorts first by name but
is locked after the source row, as `source.rs:160-176` already declares for
a direct update, for the same reasons: the stored row decides which entry
to lock, an egress entry writer must lock no `trust_source` row, and
`FOR SHARE` does not conflict with `FOR SHARE`. The registry write comes
before the head, as in the direct writes, because it references no new
operation and because a source compare-and-set waiting while holding the
head would deadlock with a consumer's own audit append
(`source.rs:153-158`); only the inserts that need the head and the update
of the already locked pending row come after it.

No new cycle: the toggle locks no trust row and takes the policy row
before the head, and takes it `FOR NO KEY UPDATE` from the start, never
`FOR SHARE` and then an upgrade, so two toggles serialize on it instead of
each holding a share lock the other's update waits for (`40P01`, D19).
With `single_actor_mode` on, the second gets `StaleRevision` at its
request; with it off, neither request updates the row, both go pending,
and the second gets `StaleRevision` at its approval. A trust write's
`FOR SHARE` and a toggle's `FOR NO KEY UPDATE` conflict, so they
serialize too, and neither holds a lock the other takes later; two
approvals of one operation serialize on its row; an approval and a direct
write of one target serialize on the target row; an approval and an entry
disable behave as a direct update does (`source.rs:178-188`).
The restoration's credential locks meet the approve's `FOR SHARE` as they
meet any operator write (`recovery.rs`, "A deadlock that fails closed").
One operation is applied per transaction, and the caller's transaction
writes the versions of one keyset only (`keyset.rs:215-224`). Under
`READ COMMITTED` only; a `40001` or `40P01` is `RegistryError::Retry`.

## Limits

- No lock and no marker holds the target between request and approve (D8):
  a direct write turns a pending operation stale, and the approver's work
  is lost. Revision compare-and-set detects it; nothing prevents it.
- The overlap check runs twice, at the request and at the approve.
- Refusals are not audited, and a failed approve leaves no trace in the
  database (D14).
- `now` is the service's clock, as for every write here; the table has no
  creation time, so the 24-hour bound is the service's rule, not the
  database's (README:958-959 asks only for an expiry). The approve samples
  it after its registry write, just before its first append (D28). The
  waits inside the append, for the tenant row `FOR KEY SHARE` and the audit
  head, come after the sample, so an approve can commit after `expires_at`
  with a `consumed_at` before it. This is accepted because every row the
  decision depends on stays locked from before the sample until the
  commit; the wait is bounded by other transactions' appends, not by this
  one; the audit chain has no rule ordering events by timestamp; and every
  existing write already stamps its event before its head wait. The
  overshoot is small only if other transactions hold the tenant row and
  the head briefly, which holds while every writer commits promptly after
  its append (an assumption, not a guarantee).
- The `0012` guard, if accepted, is a tripwire against application DML,
  not a security boundary (README "Limits"); it cannot check roles or the
  digest.
- Rows are never deleted (`administrative_operation_no_delete`, `0006`):
  expired and revoked operations stay, with their public plans, readable
  by auditors.
- Not covered here, though the same machinery applies: binding and grant
  writes and deletes (tasks:151-152; A37); the egress entry writer, whose
  add and re-enable are widening-class (IR-052; tasks:148); and the parent
  keyset's create and re-enable, a widening keyset write under the ruling
  whose kinds this proposal does not define; none has a service write path
  yet.
- Distinctness is per `admin_id`, not per person. A single instance
  `security_admin` can enrol a second operator identity and grant it
  `security_admin` (tasks:183; design:660), then approve its own requests
  through it. The audit chain shows the enrolment and the grant, but no
  check here prevents it while the toggle is on (Q7).
- An approver sees the service checks' verdict at the request, not the
  database constraints', which run only at approve (section 3).

## Tests

The implementation PRs must have (owned by the test session; section
"Implementation notes"):

- **Machinery.** A pending insert writes `administrative_operation.create`
  first, outcome `pending`, `expires_at` now + 24 h, and a digest equal to
  its recomputation from the stored row; an approve by a distinct
  `security_admin` writes the approve operation, the events in the order
  above, `consumed_at` and outcome `applied`.
- **Refusals.** Self-approval by an operator holding both roles; an approver
  with only `trust_admin`; a revoked approver credential; a digest one byte off,
  of another length, and an expected revision off by one; a digest copied from
  another operation with the same plan; `prepare_approval` by a caller who may
  not approve (no parse runs: `Unauthorized` or `NotFound` as from
  `approve_operation`); a requester whose submitting credential was disabled
  (status `disabled`, `revoked_at` null), revoked, rotated away or revoked by a
  restoration, or whose identity was disabled (D21), and the requester's cancel
  with a new credential after a rotation; a prepared projection that differs
  from the locked plan's (D24); expiry at exactly `expires_at` and one
  microsecond before (injected clock); an approve that waits on a lock (the
  target row held by another connection) while the injected clock is advanced
  past `expires_at` is `NotApprovable(Expired)` and writes nothing, and with the
  clock left before it, records the post-write sample as `consumed_at`; a
  source update whose compare-and-set waits behind a `FOR KEY SHARE` holder
  (an uncommitted binding insert through the source) while the injected
  clock is advanced past `expires_at` is refused and writes nothing (D28);
  consumed, revoked, wrong kind (a recovery challenge's ID); another tenant's
  operation on a tenant path, a tenant operation on the instance path and the
  reverse (`NotFound`); a requester whose role was disabled (Q5); a cancel by
  another `trust_admin`; a cancel after consume.
- **Races** (two connections, both commit orders): two approves; approve
  and cancel; approve and a direct write of the target; two toggles with
  `single_actor_mode` on (the second `StaleRevision` at its request) and
  off (both pending; the second `StaleRevision` at its approval); the
  toggle and a direct widening write (the
  write's `FOR SHARE` against the toggle's `FOR NO KEY UPDATE`); approve
  and an entry disable; none ends in `40P01`.
- **Classification.** Every row of the table in section 1, both values of
  the flag, the toggle off and on, `single_actor_mode` off and on; until
  Q2 is accepted, a disable-only source update goes pending like any other
  source write.
- **Database constraints at approve.** A request that a unique key or a
  `0004` check refuses only at the write (a source name taken between
  request and approve) is approved and refused, writes nothing and stays
  pending.
- **Audit outcomes.** `success_widening` for an acknowledged widening
  write with the toggle off, whatever `single_actor_mode` is;
  `success_single_actor` for one applied with the toggle on under
  `single_actor_mode`, and for the toggle itself applied at once;
  `success` otherwise (D23).
- **Read path.** The open-operations query returns no expired, consumed,
  revoked or approve, cancel or reject row (D22). A positive instance
  case: a pending toggle is listed on the instance path (`tenant_id = $1`
  bound to `NULL` matches nothing, so a single-statement implementation
  would silently list nothing there). The digest recomputed from a read
  response alone, with no other input, equals the stored one (D29),
  including for a version whose `effective_at_us` and `expires_at_us` are
  above 2^53 (the plan as canonical text; the envelope integers parsed as
  exact i64).
- **Keysets.** A gated create writes no `trust_keyset_version` row until
  approved; an overlap introduced between request and approve refuses, and
  passes after the conflict is disabled; the cap reached meanwhile;
  `StaleRevision` after a disable of an enable's target; the plan holds
  the projection, never the raw upload, and provenance as text; a plan
  whose projection does not match its fingerprint is `PlanIntegrity`.
- **The permit.** With the Stage A pool saturated, an in-transaction parse
  still gets a worker; the wait bound gives `ValidationBusy` with the
  parent lock released (the tests' own pools, as `on_pool` allows,
  `keyset.rs:528-548`).
- **Sources.** An entry disabled between request and approve refuses with
  `EgressNotAllowed`; through the bare writer, the `0011` guard refuses;
  a pending request holds no `FOR UPDATE` on the source (`pg_locks`, a
  binding insert does not wait); only if the user accepts Q2 (the PR 5
  add-on), a disable-only update is applied at once while the toggle is
  on.
- **Toggle** (A48): pending without a second `security_admin`; applied by a
  distinct one; one actor under `single_actor_mode`; no online write to
  `single_actor_mode` or the sink fields.
- **Policy row.** Missing: `PolicyUnavailable`, nothing written.
- **Savepoint.** Every `Err` leaves no operation, no event and no target
  change, and the caller's transaction usable; a non-`READ COMMITTED`
  transaction is refused before any lock.
- **Redaction.** `Display` and `Debug` of every new variant contain no
  digest, ID, revision or destination (`service/tests/redaction.rs`).
- **Catalog** (if `0012`): trigger and function names, `tgenabled = 'A'`,
  pinned `search_path`, the two names in `KNOWN_CONSTRAINTS`.

Mutants: the actor comparison dropped; the digest echo or the recompute
dropped; the expiry predicate dropped; the policy row read without
`FOR SHARE` (the toggle race); the toggle's policy row taken `FOR SHARE`
(two toggles); `prepare_approval` parsing before it authorizes; the
requester's credential check dropped, or its `status` check dropped;
the clock sampled before the locks, or before the registry write; a
member left out of the read
response's digest envelope; a create classified as not widening; the
approve's overlap check skipped; the in-transaction parse moved back to
the Stage A pool.

## Decisions (provisional lead picks, 2026-11-23)

1. **D1.** **Classification is computed by the server.** Until the user
   answers Q2, it follows the ruling exactly: every trust source write and
   every keyset version create and enable is widening, and only
   `disable_version` is not (ADR-008:217-219). The disable-only source
   exception, computed from the stored row, is an add-on to PR 5 that
   lands only after the user accepts Q2. Rejected: a caller flag that
   decides (ADR-008 item 12 forbids it); a per-member widening and
   narrowing diff of sources (error-prone over fourteen members, and the
   ruling counts every source write); shipping the disable-only exception
   before Q2 is answered (it goes beyond the ruling).
2. **D2.** **The flag** is required on every widening write, toggle on or off,
   and ignored on a non-widening one. Rejected: refusing a flag on a
   non-widening write (friction with no gain).
3. **D3.** **Reuse `administrative_operation`**, no new column. Rejected: a
   separate pending-write table (would duplicate the `0005` expiry,
   consume and revoke guards); a staged disabled row in the target table
   (a source has no staged form, and a staged keyset version is visible to
   every reader).
4. **D4.** **The plan holds the validated public payload.** Rejected: the raw
   upload (it may hold private members, A05); a digest only, with the
   payload sent again at approve (the approver could not review it).
5. **D5.** **24-hour expiry**, fixed (OQ-API-14 is open; Q1). Rejected: the
   15-minute challenge bound of LT-107 (too short for a second person);
   no bound (stale intent).
6. **D6.** **Digest over a canonical form, recomputed at approve.** Rejected: a
   digest of the raw request bytes (not reproducible from `jsonb`);
   trusting the stored digest alone (the immutability trigger is a
   tripwire, not a boundary).
7. **D7.** **Two transactions, every service check in both; the database
   constraints (`0004`, `0011`, the unique keys) run at approve only**,
   when the row is written. Rejected: checks at the request only (the
   state moves); at the approve only (late refusals, and approvers review
   invalid requests); one transaction spanning the approval (impossible
   across requests, and it would lock the target for hours); a savepoint
   dry run of the write at the request, rolled back, to run the database
   constraints early (a source update's dry run is the compare-and-set,
   which takes the source row `FOR UPDATE`, which section 3 says a request
   never does: it would wait for and block binding inserts and exchanges,
   and its verdict would still be stale at approve).
8. **D8.** **No hold on the target** between request and approve. Rejected: a
   pending marker that blocks other writes (a requester could freeze a
   source; a `disable_version` must stay immediate, and no request may
   block another's).
9. **D9.** **Registry write before the head** in the approve; the declared lock
   order. Rejected: the README's by-name order for the egress entry (it
   would differ from the direct update of the same source).
10. **D10.** **The policy row `FOR SHARE`** in every widening trust request
    (the toggle: D19). Rejected: an unlocked read (a widening write could
    commit unapproved just after the toggle went on).
11. **D11.** **Roles** as in section 6: a distinct instance `security_admin`
    approves; a tenant operation only on its tenant path; the requester's
    role is checked again (Q5); single-actor needs `security_admin` too
    (Q4).
12. **D12.** **Audit**: the events of section 7, the requester as the domain
    event's actor, the new verbs `cancel` and `reject`, outcomes
    `success_single_actor` and `success_widening` (D23), no fingerprint
    member (Q6). Rejected: an
    approve operation by the same actor under `single_actor_mode` (IR-054
    requires a different actor for an approval).
13. **D13.** **A separate in-transaction permit**, 2 workers, 2-second wait.
    Rejected: one pool with priority (tokio's semaphore is FIFO, and two
    long uploads could still delay a lock-holding transaction); more
    Stage A workers (no isolation); the stored marker now (a migration and
    a trust argument of its own; it stays the follow-up).
14. **D14.** **A failed approve leaves the operation pending.** Rejected:
    recording the failure in a second transaction (a write path for refusals
    no other write has).
15. **D15.** **Migration `0012`** (optional guard and index). It reverses, for
    these two rules only, the `0005` review's acceptance that they stay
    service rules (README:953-955), so it needs the user's acceptance with
    this proposal. Rejected: no backstop for self-approval.
16. **D16.** **The toggle is the first gated kind**: the smallest, no JWK
    cost, and it exercises the whole machinery (A48).
17. **D17.** **One operation applied per transaction.**
18. **D18.** **A missing policy row refuses** a widening write (ADR-008 item
    4: store failures never expand privilege).
19. **D19.** **The toggle takes the policy row `FOR NO KEY UPDATE`** and
    checks its revision, in both branches; a trust write takes it
    `FOR SHARE`. A concurrent toggle can cause a request-time
    `StaleRevision` only in the direct (`single_actor_mode`) branch; in
    the gated branch the request leaves the revision unchanged, so two
    requests on one revision both go pending and the revision check refuses
    the second application. Rejected: `FOR SHARE` then a compare-and-set (two
    concurrent toggles deadlock, `40P01`, as the review reproduced on
    PostgreSQL 17.12; README:1025-1026 asks for `FOR NO KEY UPDATE` on a
    row the write updates, never `FOR UPDATE`).
20. **D20.** **`prepare_approval` authorizes before it reads the plan**:
    the approver's lookup, the scope check, self-approval and the unlocked
    state check, with the same `Unauthorized` and `NotFound` as
    `approve_operation`; only then does it read and parse. Rejected:
    parsing first (any caller could spend Stage A workers on any
    operation's payload, and the refusal order would tell an outsider that
    an operation exists).
21. **D21.** **The plan stores the requester's submitting credential ID**;
    at approve that credential must be enabled and unrevoked (a credential
    may be `disabled` with `revoked_at` null, `0005:139-144`; the lookup
    requires both, `operator.rs:504-516`), the requester's identity
    enabled and the kind's role held, or the approve is
    `RequesterNotAuthorized`. A rotation or a restoration therefore strands
    pending operations until they expire (section 3). Rejected: the role
    check alone (a revoked
    credential, the usual response to a compromised key, would not stop a
    request it submitted); revoking pending operations when a credential
    is revoked (a write into another subsystem's path).
22. **D22.** **The open-operations index and read query**: index predicate
    `consumed_at IS NULL AND revoked_at IS NULL AND expires_at IS NOT NULL`;
    the query adds `expires_at > now` and the five kinds; `outcome` stays
    `pending` after expiry and readers derive "expired". Rejected: a job
    that writes `expired` (a writer with no actor, and the `0005` set-once
    columns need none).
23. **D23.** **A flag-acknowledged widening write applied at once** while
    the toggle is off records outcome `success_widening`. Rejected: plain
    `success` (an auditor would have to reclassify every write to find
    them); a new envelope member (an IR-056 change, ADR-level).
24. **D24.** **The approve compares the prepared projection byte for byte**
    with the locked plan's `public_jwks` before writing it; a mismatch is
    `PlanIntegrity`. Rejected: trusting the unlocked read (the digest check
    covers the row, not what was parsed).
25. **D25.** **The plan stores the `allowed` algorithms** Stage A used, and
    the approve validates against their intersection with the caller's
    current set, so an approval never admits an algorithm either side
    would refuse (OQ-TP-3 is open: ADR-005:140, token-profiles.md:51).
    Rejected: `KNOWN_ALGORITHMS` at approve (wider than the request's
    set); the current set only (the approver could not see what the
    request was validated against).
26. **D26.** **Post-authorization step functions** (`apply_create_version`,
    `apply_enable_version`, `apply_create_source`, `apply_update_source`,
    `apply_policy_toggle`) take the authorized
    `Requester { admin_id, credential_id }`, which `authorize_trust_admin`
    returns in place of the bare `admin_id` (PRs 4 and 5), run through the
    registry write and return the domain event unstamped; both `submit_*`
    (which stamps it with its `now`) and `approve_operation` (which stamps
    it with its one clock sample, D28) call them and append the event.
    Rejected: calling the existing writers from the approve (they authorize
    by `public_identity`, `write.rs:43-59`, which the approve does not have
    for the requester); duplicating the steps in `crate::operation`.
27. **D27.** **PRs 4 and 5 may pre-validate the plainly typed database
    constraints** at the request where it is cheap: the non-empty strings
    and arrays, `review_timeout_ms > 0`, `stale_revocation_acknowledged`
    true, with the same refusal the database gives. A pick, not a promise:
    the constraints stay the authority, and the kind, replay, profile,
    range, unique and foreign-key checks stay approve-time. Rejected:
    duplicating every constraint in the service (drift); none (a request
    the service accepts is refused at every approve for a typo).
28. **D28.** **The approve samples a fresh server clock after its registry
    write, just before `append_audit_event`**, through an injected `Clock`,
    and uses that one sample for the expiry check, both events and
    `consumed_at`; an expired result rolls the savepoint back, so nothing
    is written. Trust rows store no write time, so nothing earlier needs
    it. Only the waits inside the append remain after the sample (Limits).
    Rejected: one `now` passed in before the locks (an approve that waited
    past the expiry would be recorded as consumed before it); a sample
    after the row locks but before the registry write (a source
    compare-and-set's `FOR UPDATE` waits for every binding insert and
    token exchange through the source, `source.rs:136-152`, and an insert
    waits on a conflicting uncommitted unique key); a database clock
    (`clock_timestamp()`; every other write here takes the caller's clock,
    and tests could not inject it).
29. **D29.** **The read response returns the whole digest envelope**: the
    operation `id`, the requester's `actor_id`, `kind`, `tenant_id`,
    `expected_revision`, `expires_at` as the integer microseconds the
    preimage uses (beside any display form) and the plan exactly as the
    preimage holds it, so the operator client can recompute the digest
    from the response alone (Q1). The plan is returned as its canonical
    text (a JSON string holding the bytes the preimage embeds), not as a
    JSON value: the `0007` range lets `effective_at_us` and `expires_at_us`
    exceed 2^53, which a client parsing numbers as floating point would
    round, recomputing a different digest and blocking approval of a
    far-future window. The envelope's own integers (`expected_revision`,
    `expires_at`) are exact i64 and the client must parse them as such.
    Rejected: returning the digest without
    its inputs (the approver, a different operator, cannot know the
    requester's `actor_id`).

## Resolved (provisional; ADRs unratified)

Decided before this proposal and used as given, all provisional until the
maintainer ratifies the ADRs (Gate M0): the widening ruling for
keyset versions and sources (the user's, 2026-11-22); the server's
detection and the flag (ADR-008 item 12, OQ-ADR008-3, OQ-ADR016-2); the
wire shape of the approve endpoints (OQ-API-13); the approver role (IR-054);
the IR-152 egress backstop (`0011`, README "What 0011 adds"); soft disable
as fail-safe for bindings and grants (ADR-008 item 3).

## Open

Questions for the user, each with the recommended answer:

1. **Q1.** **Expiry and read path (OQ-API-14).** Recommended: a fixed 24-hour
   `expires_at`; `GET /admin/v1/tenants/{tenant}/operations/{operation}` and a
   list of open operations (and the instance twins), readable by instance
   `security_admin`, the requester and the tenant `auditor`, returning the
   digest and the whole digest envelope: the operation `id`, the requester's
   `actor_id`, `kind`, `tenant_id`, `expected_revision`, `expires_at` as the
   integer microseconds the preimage uses, and the plan as its canonical text
   (D29). The operator client recomputes the digest from that response alone
   before echoing it, so an approver never echoes a digest it has not checked
   against what it read.
2. **Q2.** **Is a disable-only source update widening?** The ruling says "a
   trust source write", so until the user answers, it is (D1). Recommended:
   accept the exception, not widening, like a soft disable of a binding or
   grant (ADR-008 item 3, by analogy), so a source can be shut off at once
   while the toggle is on; it then lands as the PR 5 add-on.
3. **Q3.** **Is a disabled keyset version create widening?** It makes no key
   live. Recommended: yes, as the ruling's text says; the cost is one approval
   for a create-then-enable, and the rotation path creates enabled anyway.
4. **Q4.** **Under `single_actor_mode`, must the one actor also hold
   `security_admin`?** Recommended: yes; a `trust_admin` without it gets a
   pending operation that a `security_admin` approves. This is in tension
   with tasks:149 ("under single_actor_mode no approve call"): once the
   fallback leaves a request pending, an approve call is made under
   `single_actor_mode`, so accepting Q4 also reads tasks:149 as applying
   to a requester who holds `security_admin`.
5. **Q5.** **Is the requester checked again at approve?** The spec names
   the approver's role only (public-api:451). Recommended: yes, the role,
   the identity and the submitting credential (D21); a requester who lost
   `trust_admin`, or whose credential was revoked, should not have a
   change applied in their name.
6. **Q6.** **A fingerprint in the audit event?** Recommended: no, for now; the
   plan and the version row hold it, and an envelope member is an ADR-level
   change to the IR-056 hash input. The cost is that the external sink
   cannot show which plan an approval covered; a `request_digest` member
   is the better ADR follow-up than the fingerprint, since it names the
   whole plan of every kind.
7. **Q7.** **Gate `security_admin` grants while the toggle is on?** One
   `security_admin` can enrol a second identity and grant it
   `security_admin`, then approve through it (Limits). Recommended: yes,
   as a follow-up: while `widening_second_approver` is on, a grant of
   instance `security_admin` (and the enrolment of an identity that
   receives one) is itself a gated kind needing a distinct existing
   `security_admin`; until then, record the residual risk as accepted.

**Not decided here** (for the lead): how an approver learns of a pending
operation (notification); metrics, including whether `SelfApproval` and
`EchoMismatch` count as security signals; whether the toggle itself needs
`acknowledge_widening`; whether the IR-053 startup mirror of
`single_actor_mode` bumps the policy row's revision, which would leave
every pending toggle stale; and whether each coding PR is paired with its
test PR or the test PR follows.

## Implementation notes

**What stays unwired until the user accepts.** Everything: no endpoint
calls `trust::keyset`, `trust::source` or the new functions, and nothing
wires them at startup (`mod.rs:18-19`). Even after the PRs below merge, no
endpoint lands before the request layer exists (generated IDs, T10.2; the
raw body bound; NUL rejection; the role of each endpoint; T13.3) and the
read path of Q1 is decided. `disable_version` stays unwired with the rest.

**PR decomposition** (the coding session owns production code, migrations
and code comments; the test session owns tests, security scenarios, CI,
the harness and `docs/testing/conformance-layout.md`):

| PR  | Session | Content                                                                                                                                                                                                                                                                                                                                                                                                      | After   |
| --- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| 1   | coding  | the in-transaction permit (section 8), with tokio's `time` feature added to the non-dev dependency and the module docs' precondition marked done                                                                                                                                                                                                                                                             | —       |
| 2   | coding  | `persistence::registry::operation` (section 9), the policy row lock, `authorize_approval_locked`, `authorize_roles_locked`, `cancel` and `reject` in `AUDIT_ACTIONS`; `0012` and its README section if accepted                                                                                                                                                                                              | —       |
| 3   | coding  | `crate::operation`: digest, kinds, `prepare_approval`, `approve_operation`, `cancel_operation`, `reject_operation`, the toggle                                                                                                                                                                                                                                                                               | 2       |
| 4   | coding  | keyset kinds: `authorize_trust_admin` returning `Requester { admin_id, credential_id }`, `apply_*` split, D27 pre-validation if cheap, `submit_create_version`, `submit_enable_version`, the approve dispatch; the T14.1/T14.2 attribution and "the request layer of T14.1 and T14.2" corrected in `keyset.rs` (:24-28, :265-267), `source.rs` (:236-246) and the migrations README (:3114-3116, :3333-3334) | 1, 3    |
| 5   | coding  | source kinds: `Requester` from `authorize_trust_admin` (shared with PR 4, whichever lands first), `apply_*` split, D27 pre-validation if cheap, `submit_create_source`, `submit_update_source` (every source write widening), the full stored-row read; the disable-only classification only as an add-on after the user accepts Q2                                                                          | 3       |
| 6   | test    | tests for PRs 1 to 5 as each lands (section "Tests"), the policy-row fixture, moving the trust tests to `submit_*`, the A48 toggle legs                                                                                                                                                                                                                                                                      | each PR |
| 7   | coding  | the ungated entry points made crate-private                                                                                                                                                                                                                                                                                                                                                                  | 6       |
| 8   | test    | the test session's files: `conformance-layout.md` (the mapping below; the A04 paragraph's T14.1/T14.2 attribution and "ADR-008 item 12" wording, :180), `tests/conformance/README.md` (:7, both), `tests/security/a04.rs` (:132 the item-12 wording, :136 the attribution); no stage status change until a test claims it                                                                                    | 6       |

ADR-008:220, which repeats the T14.1/T14.2 attribution, is the lead's to
correct; neither session edits it.

**Conformance mapping** (no stage moves by this proposal):

- A48 M1a (T13.3, T13.8, T13.10; conformance-layout:160): the toggle's
  approval, self-approval, an approver without `security_admin`, the
  single-actor positive. PRs 2, 3, 6.
- A04 M1a (conformance-layout:116, :180; T11.6, T13.8, T13.2): "the audited
  rotation and disable through the trust_admin keyset endpoints, with the
  expected revision, the atomic audit event and the server's widening
  detection". The service parts land with PR 4; the endpoint part waits
  for wiring.
- A05 M1a (conformance-layout:117; T11.2): the entry disabled between
  request and approve. PR 5.
- A29 M1a (conformance-layout:141; T10.8): that stage is `implemented`
  (`tests/conformance/README.md:7`), and its closed list covers the
  composite foreign keys of `0004` only (`tests/security/a29.rs:47-65`).
  An approval, cancel or reject of another tenant's operation is a
  crossing for that list only if `0012` is accepted, since only then does
  the database refuse it; the test then lands with the list change (PR 6,
  PR 8). Otherwise it is covered outside A29, as A24 covers
  `consumed_assertion_trust_source_id_fkey`, by the service tests of the
  scope check (section "Tests").
- A37 M1a (conformance-layout:149; T12.2): predicate removal through the
  same machinery, once binding writes have a service path (not here).
- A47 M1b (conformance-layout:159): out of scope; the approve endpoint's
  kind check keeps provider plans out (ADR-008 item 15).
- A64 M1a (conformance-layout:176): an approve sent by `skyoauth-operator`
  against the Linux service, once the endpoint exists.

**Spec IDs not located.** No task, ADR item or conformance row names the
second-approver flow itself (see "Owner" above); the code's "T14.1, T14.2"
does not match the tasks doc. The design defines neither
`AdministrativeOperation` nor `InstanceSecurityPolicy` fields (the logical
model is tasks §3). No contract maps admin errors to HTTP statuses. The
expiry bound and read path are OQ-API-14, still open.
