# Proposal: second-approver flow for widening trust writes

Status: Accepted (Q1-Q7 and the 0005 trigger ruled by the user, 2026-11-23); PRs 1 to 5, 7, 9 and 10 merged (PR 10 as #123); PR 6 in progress (#116 merged); PR 8 not started (see "Implementation notes"). ADRs ratified directionally (maintainer, 2026-11-24); D1 to D29 accepted as implementation choices that ordinary review can change.

Drafted 2026-11-23 for the lead's review agent and then the user's
acceptance. The user ruled on 2026-11-23 (relayed by the lead): "Accept all
your recommendations, except 0012, as we don't need to keep data until a
beta release", and, on clarification, that the `0012` trigger is folded
into migration `0005` itself (section 11; D15); the read-path index of the
same sketch is a provisional lead pick, not ruled. Implemented so far: the
in-transaction permit (PR 1), the registry operation module with the `0005`
guard and index (PR 2), `crate::operation` with the toggle (PR 3), the
keyset kinds (PR 4), the source kinds with the Q2 disable-only add-on
(PR 5), the ungated entry points made crate-private (PR 7), the bare
registry trust writers made crate-private (PR 9), and the
registry's operator writers, audit append and operation-row writers made
crate-private (PR 10, #123); the tests of PR 6 have started (#116, merged). Not
yet: the rest of the tests (PR 6), the test session's documents (PR 8),
and any endpoint. Every other choice below that
goes beyond the written spec is a "provisional lead pick, 2026-11-23" (the
Decisions list numbers them D1 to D29); "(inferred)" marks a point where the spec is silent. The
maintainer ratified the ADRs directionally on 2026-11-24 (T00.8–T00.17
ticked; Gate M0 is left to the lead's separate PR): these picks, and the
lead decisions the spec records, are accepted as implementation choices,
not frozen, that ordinary review can change. This text ratifies no ADR. The widening ruling it builds on is the user's
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
  revocation (`:453-457`; a repeat with the same value is not refused), no consume after revoke (`:459-464`) and
  `consumed_at < expires_at` (`:328-329`). The service rules the database
  leaves open are in `service/migrations/README.md:1079-1103` (a distinct
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
`source.rs:236-246`, `service/migrations/README.md:3131-3133` and
`:3350-3351`, ADR-008:220, conformance-layout:180,
`tests/conformance/README.md:7`, `tests/security/a04.rs:136`), and some of
them name "the request layer of T14.1 and T14.2" too (`keyset.rs:27`,
`source.rs:237-238`, README:3132-3133 and :3351); but T14.1–T14.2 are the
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

The server classifies each write by a pure function of the write and, for
a source update, the stored row read under its lock (the Q2 exception). No
caller input decides it (ADR-008 item 12).

| Write                                                                                                                                             | Widening                                                        | Basis                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `create_version`, enabled or disabled                                                                                                             | yes                                                             | the ruling ("a create"); Q3                                                                                                                                                                               |
| `enable_version`, a re-enable and an enable of an already enabled version included                                                                | yes                                                             | the ruling ("an enable, a re-enable"); `keyset.rs:100-103` writes the latter like any other enable                                                                                                        |
| `disable_version`                                                                                                                                 | no                                                              | not among the ruling's writes (`keyset.rs:34-35`); ADR-008 item 3 by analogy                                                                                                                              |
| `create_source`                                                                                                                                   | yes                                                             | the ruling                                                                                                                                                                                                |
| `update_source` whose new `status` is `disabled` and whose every other mutable member equals the stored row's                                     | no (Q2, ruled by the user, 2026-11-23); before that ruling, yes | the 2026-11-22 ruling counts "a trust source write" (ADR-008:217-219); Q2, accepted, makes this exception, by analogy with ADR-008 item 3 and tasks:463 ("disabling is not widening" for an egress entry) |
| any other `update_source`: an enable, a rename, a no-op on an enabled source, a disable that also changes a member, a change to a disabled source | yes                                                             | the ruling; `source.rs:49-52` already treats a disable that changes a member as a change                                                                                                                  |

Before the Q2 ruling every trust source write was widening and both
classifications depended on the write kind only. The user accepted Q2
(2026-11-23, relayed by the lead), so the disable-only exception, an add-on to
PR 5, is implemented there: `classify_source_update(stored, changes)` returns "not widening"
exactly when `changes.status == Disabled` and the other fourteen members of
`TrustSourceChanges` (`model.rs:937-953`) equal the stored ones. A finer
per-member diff (fewer audiences narrows, a new algorithm widens) is rejected
(D1).

**The flag.** A widening write must carry `acknowledge_widening = true`.
Without it the write is refused with `WideningNotAcknowledged`, whether
`widening_second_approver` is on or off, since IR-052 still asks for "the
widening flag, the expected revision and the atomic audit record" when it
is off (identity-registry:422-424). A flag on a write that is not widening
is accepted and ignored (D2). The toggle turned off is a widening write
and needs the flag (the user's ruling, 2026-11-24; the library implements
it (`submit_widening_toggle`), T13.3 wires it; see "Open"). Without it the
write is refused with `WideningNotAcknowledged` before any operation goes
pending, under `single_actor_mode` too (the write still needs `security_admin`). Ruled by the user, 2026-11-24
(relayed by the lead): the requirement applies to every request that sets
`widening_second_approver` to false, whatever the current value (a same-value
false to false write included), because widening is computed server-side
from the kind of write (the user's ruling, 2026-11-22) and `prepare_approval`
authorizes before it reads state; a request that sets true is never widening.

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
| `tenant_id`                               | the target's tenant; `NULL` for the toggle (README:969-970: the tenant of its audit event)                                                                                      |
| `actor_id`                                | the requester's `admin_id`                                                                                                                                                      |
| `kind`                                    | `trust_keyset_version_create`, `trust_keyset_version_enable`, `trust_source_create`, `trust_source_update` or `instance_security_policy_update` (inferred names)                |
| `request_digest`                          | SHA-256 of the canonical request, 32 bytes (below)                                                                                                                              |
| `expected_revision`                       | the target's revision: the version (an enable), the source (an update), the policy row (the toggle); 0 for a create (README:946)                                                |
| `immutable_plan`                          | the validated payload (below)                                                                                                                                                   |
| `expires_at`                              | the request's `now` plus 24 hours (D5; OQ-API-14; Q1)                                                                                                                           |
| `consumed_at`                             | set once, by the approve                                                                                                                                                        |
| `revoked_at`, `revocation_operation_id`   | set once, together, by a cancel or a reject                                                                                                                                     |
| `approves_operation_id`, `challenge_hash` | `NULL`                                                                                                                                                                          |
| `outcome`                                 | `pending`, then `applied`, `cancelled` or `rejected` (inferred values; `outcome` and `revision` are the mutable columns, README:801-805); it stays `pending` after expiry (D22) |
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
(README:973-975).

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
   (`source.rs:93-98`), and D27's pre-validation where a PR implements it
   (PRs 4 and 5). The upload was validated before the transaction
   (Stage A, `keyset.rs:48-62`).
2. Step 0, then step 1: the requester's operator rows `FOR SHARE`
   (`write.rs:43-59`; for the toggle, instance `security_admin`). When Q4
   is accepted, the requester's instance `security_admin` binding, if any,
   is locked in the same ordered statement as the tenant binding
   (`authorize_roles_locked`, section 9; it returns `Some` when any listed
   role is held, so the caller checks `holds(0)` for the required one, a
   required test of PRs 4 and 5). This step yields the requester's
   `admin_id` and credential ID; every later step is a post-authorization
   step function that takes them, shared with the approve (D26).
3. A widening write with the flag unset is refused here
   (`WideningNotAcknowledged`). Its class depends on the kind only, except
   a source update's, which skips this step and is checked at step 6;
   `disable_version` is never widening.
4. The `instance_security_policy` row `FOR SHARE` (new; D10). A missing
   row is `PolicyUnavailable` (D18). `disable_version` skips steps 3, 4
   and 6: its class is fixed. A source update locks the row here whatever
   its class, so one lock order holds, and refuses a missing row only at
   step 6, once it is known to be widening (inferred).
5. The module's own locks and reads, unchanged: the parent `trust_keyset`
   `FOR NO KEY UPDATE` (`keyset.rs:181-185`) and its reads; or the
   `trust_source` row `FOR NO KEY UPDATE` (`source.rs:123-129`), now
   reading every mutable column, not only the destinations (for the
   plan's `changed`).
6. The Q2 add-on of PR 5 (Q2 ruled by the user, 2026-11-23): a source update is
   classified from the stored row; a disable-only update is applied at once
   with outcome `success`, without the flag and whatever the policy row
   says, even before bootstrap (inferred); any other update with the flag
   unset is `WideningNotAcknowledged`, and then a missing policy row is
   `PolicyUnavailable`.
7. The module's checks, unchanged: the cap of 8 and the overlap check (on
   the in-transaction pool, section 8); the syntax of changed members and
   the egress entries `FOR SHARE` (`source.rs:130-135`).
8. Applied at once (table above): the registry write and the domain event
   last, exactly the module's steps 6 and 7 (keyset) or 4 and 5 (source).
   Pending: the audit head through `append_audit_event`, the event
   `administrative_operation.create`, then the operation insert
   (README:1053-1054; the issue of a recovery challenge does the same,
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
   unlocked state check (a wrong kind, then consumed, revoked or expired, is
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
   `SelfApproval`; a kind outside the flow, or not of the path's scope, is
   `NotApprovable(WrongKind)`, since the kind decides the requester's role
   that step 3 locks. Then, still without a lock, the plan's
   `requester_credential_id`, which step 3 locks (a plan without it is
   `PlanIntegrity`). The kind and the plan are immutable (`0005`), so step
   4 reads the same values under the lock.
3. The operator rows of both actors `FOR SHARE`, in the `0005` order
   (`authorize_approval_locked`, section 9): the two `admin_identity` rows
   by ID, the two `admin_credential` rows by ID (the approver's, and the
   requester's `requester_credential_id` from the plan), then the
   approver's `security_admin` binding and the requester's role binding
   for the kind (tenant `trust_admin`, or instance `security_admin` for the
   toggle) by ID, then the lookups repeated as `authorize_operator_locked`
   does (`operator.rs:160-172`; the lookup requires an enabled and
   unrevoked credential, `operator.rs:504-516`, README:983-984). A
   requester whose identity is disabled, whose submitting credential is
   disabled or revoked, or who lost the role is `RequesterNotAuthorized`
   (Q5; D21).
4. The operation row `FOR NO KEY UPDATE`, read again: consumed or revoked is
   `NotApprovable` with its reason (the kind was checked in step 2; expiry is
   checked in step 6, after the registry write); a digest or expected revision unequal to
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
   `source.rs:123-152` (the source row and revision, the syntax of
   changed members, the entries `FOR SHARE`, the insert or
   compare-and-set). The class is not computed again: the expected
   revision pins the stored row, and the approve checks the plan's
   `changed` against that row (PR 5, inferred). For the toggle: the
   policy row `FOR NO KEY UPDATE` and its compare-and-set. The policy row is not read for a trust kind:
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
   already holds, so it does not wait (README:1181-1187). The waits inside
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
revocation order exactly (README:1181-1187). A cancel authorizes the
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
updates `FOR NO KEY UPDATE` (README:1038-1039); a toggle that took
`FOR SHARE` and then updated would upgrade its lock, and two concurrent
toggles would each wait for the other's share lock and end in `40P01`, as
the review reproduced on PostgreSQL 17.12 (D19). A trust write takes the
row `FOR SHARE` (request step 4), so it and a toggle serialize. The toggle
is always gated, on or off, whatever its current value (IR-052,
identity-registry:423-427; ADR-008:100-103).
`single_actor_mode` and the sink fields stay unwritable online (IR-053).

### 4. What is checked again at approve, and what is not

| Checked again at approve                                                                                                                                     | Taken from the request, bound by the digest                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| the approver's `security_admin` role, enabled identity and credential (tasks:149: "rechecking revision and role")                                            | the payload itself: the projection, window, status and provenance; the source members  |
| the approver is not the requester; the requester's identity is enabled, its submitting credential enabled and unrevoked, and its role held (Q5; D21)         | the raw upload's Stage A validation (`keyset.rs:550-563`); only its projection is kept |
| the operation is pending, unexpired, unrevoked, of an approvable kind; the echo; the recomputed digest                                                       | the class: not recomputed; `changed` is checked on the row the expected revision pins  |
| the projection, parsed in full again before the transaction against the plan's `allowed_algorithms` and the current `allowed` set, and its fingerprint (D25) |                                                                                        |
| the parsed projection equal byte for byte to the locked plan's (D24)                                                                                         |                                                                                        |
| the database constraints, which run only here (section 3)                                                                                                    |                                                                                        |
| the target's revision; for a keyset, the parent lock, the cap of 8, the full parse of every compared stored version and the overlap check, all again         |                                                                                        |
| for a source, the syntax of changed members, the egress entries `FOR SHARE`, the `0004` kind checks and the `0011` guard                                     |                                                                                        |
| the provenance private-member check (pure, cheap)                                                                                                            |                                                                                        |

### 5. Races and failures

| Between request and approve                                                                                                | At approve                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| a direct write (a disable, another update) moves the target's revision                                                     | `StaleRevision`; the operation stays pending and can never apply; the requester cancels it or it expires                                                                                                                                                                                                                                                                                                                 |
| a concurrent disable runs while the approve holds the target                                                               | they serialize on the `trust_keyset` or `trust_source` row; the second sees the first's revision                                                                                                                                                                                                                                                                                                                         |
| an egress entry the change needs is disabled                                                                               | `EgressNotAllowed` (the service's entry check, `source.rs:509-532`). If the service check were skipped, the `0011` trigger `trust_source_egress_enabled` refuses the write with `23514`, `Invariant { kind: EgressEntryEnabled }` (README "What 0011 adds", :2151-2165)                                                                                                                                                  |
| an entry disable starts while the approve holds the entry `FOR SHARE`                                                      | the disable waits for the approve's commit; the source is then degraded at fetch (`source.rs:178-188`)                                                                                                                                                                                                                                                                                                                   |
| another version was enabled and now overlaps                                                                               | `Overlap`; after that version is disabled, a new approve of the same operation passes                                                                                                                                                                                                                                                                                                                                    |
| the keyset reached 8 enabled versions                                                                                      | `TooManyEnabledVersions`                                                                                                                                                                                                                                                                                                                                                                                                 |
| a version with the plan's `version_id` now exists                                                                          | `AlreadyExists` (the insert's `23505`)                                                                                                                                                                                                                                                                                                                                                                                   |
| the parent keyset was disabled                                                                                             | written like any other (`keyset.rs:269-270`, inferred: the verifier reads the keyset's status)                                                                                                                                                                                                                                                                                                                           |
| two approvers approve at once                                                                                              | they serialize on the operation row; the second reads it consumed: `NotApprovable(Consumed)`                                                                                                                                                                                                                                                                                                                             |
| a cancel and an approve race                                                                                               | the same row lock; whichever is second gets `NotApprovable`                                                                                                                                                                                                                                                                                                                                                              |
| the toggle went off                                                                                                        | the approve still applies (an approval is never less safe); the requester may cancel and submit again                                                                                                                                                                                                                                                                                                                    |
| the toggle went on while a direct widening write was in flight                                                             | the write holds the policy row `FOR SHARE` from step 4 to its commit, so the toggle's `FOR NO KEY UPDATE` waits; a write that reaches step 4 after the toggle committed reads it on and goes pending                                                                                                                                                                                                                     |
| two toggles at once                                                                                                        | `single_actor_mode` on: they serialize on the policy row `FOR NO KEY UPDATE` and the second gets `StaleRevision` at its request; off: both go pending and the second approved gets `StaleRevision` at its approval; never `40P01` (D19)                                                                                                                                                                                  |
| a database constraint refuses the row (section 3)                                                                          | `AlreadyExists` or `Invariant`, as for the direct write; the operation stays pending                                                                                                                                                                                                                                                                                                                                     |
| the approver's credential was revoked                                                                                      | `Unauthorized`                                                                                                                                                                                                                                                                                                                                                                                                           |
| the requester's identity disabled, submitting credential disabled or revoked (a rotation, a restoration), or role disabled | `RequesterNotAuthorized` until it expires (D21; section 3)                                                                                                                                                                                                                                                                                                                                                               |
| the operation expired                                                                                                      | `NotApprovable(Expired)`; the `0005` check refuses a consume at or after `expires_at` even if the service check were skipped                                                                                                                                                                                                                                                                                             |
| the commit outcome is unknown to the approver's client                                                                     | a retry that runs `prepare_approval` again reads the operation consumed (`NotApprovable(Consumed)`); the client reads the target. A retry with the same `PreparedApproval` reads it consumed too, unless the requester's identity, submitting credential or role changed meanwhile: step 3 comes before step 4, so that retry is `RequesterNotAuthorized` (and `Unauthorized` after a change to the approver's own rows) |

### 6. Roles

- **Requester.** The role the endpoint row names: tenant `trust_admin` for
  the trust writes (tasks:151), instance `security_admin` for the toggle
  (tasks:147). Roles do not inherit (API-120).
- **Approver.** An instance `security_admin` (IR-054: "the approver MUST
  hold `security_admin`"), whose `admin_id` is not the requester's, even
  when one operator holds both roles. A second `trust_admin` cannot
  approve. A tenant operation is approved only on its tenant path and an
  instance operation only on the instance path; anything else is
  `NotFound` (README:966-968: an approval of a tenant operation stays in
  its tenant).
- **`single_actor_mode` on.** No approve call is made (tasks:149): the
  write applies at once and its event records the single-actor approval.
  Ruled (Q4, by the user, 2026-11-23): the one actor must also hold
  instance `security_admin`; otherwise the write goes pending as above.
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
/// bare `admin_id` (PR 4; PR 5 shares it).
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
/// `allowed` is the set `validate_upload` validated `new.keys` against;
/// the plan records it (D25).
pub async fn submit_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewKeysetVersion<'_>,
    allowed: &[Algorithm],
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

// Post-authorization steps (D26), as for keysets. An update is split in
// two (PR 5): the stored row's lock, which the request classifies from,
// and the steps after it.
pub(crate) async fn apply_create_source(/* transaction, requester, new */)
    -> Result<(TrustSource, UnstampedEvent), SourceWriteError>;
pub(crate) async fn lock_source(/* transaction, tenant_id, id,
    expected_revision */) -> Result<TrustSource, SourceWriteError>;
pub(crate) async fn apply_locked_update(/* transaction, requester,
    stored, changes */)
    -> Result<(TrustSource, UnstampedEvent), SourceWriteError>;
// service/src/operation/mod.rs: apply_policy_toggle, likewise.

// service/src/persistence/registry/operation.rs (new): bare, check nothing
// the database does not, like the other registry writers. The three
// writers are crate-private since PR 10 (see "PR 10 as implemented").
pub struct AdministrativeOperation { /* the 0005 columns */ }
pub(crate) async fn insert_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
) -> Result<AdministrativeOperation, RegistryError>;
/// The row `FOR NO KEY UPDATE`.
pub async fn lock_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<AdministrativeOperation>, RegistryError>;
pub(crate) async fn consume_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError>;
pub(crate) async fn revoke_administrative_operation(
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
become step 1 plus `apply_*`, ungated. They stayed public, documented as
test-only like the bare registry writers (`keyset.rs:36-46`), until PR 7
made them private to `trust` (`pub(super)`); PR 9 then made those bare
registry writers crate-private too (see "PR 9 as implemented"). The plan was to move their
callers to `submit_*` first; PR 7 keeps the callers on the ungated writes
instead, through a `#[doc(hidden)]` module that only a `test-support`
feature compiles (see "PR 7 as implemented"). The callers are
`service/tests/trust_keyset_version.rs`,
`service/tests/trust_source_egress.rs`, `direct_create` in
`service/tests/keyset_approval.rs` (it calls the ungated
`create_version` to set up rows) and the service path of
`service/tests/schema_trust_source_egress_guard.rs` (its `trust::`
import of `create_source` and `update_source`, and their calls in the
case runner), and `service/tests/source_approval.rs` (its `direct_create`
and `direct_update` helpers, which call the ungated `create_source` and
`update_source` to set up rows, and the race tests that call
`update_source` directly as the competing write).

### 10. Errors

New variants, `#[non_exhaustive]` as today, `Display` fixed text per
variant and `Debug` the variant name (and a fixed reason), never a digest,
an ID, a revision, a destination, a `kid` or another value of the request
(as `keyset.rs:381-388` and `source.rs:326-331`):

- `KeysetWriteError`: `WideningNotAcknowledged`, `PolicyUnavailable`,
  `ValidationBusy`; PR 4 adds `StoredFingerprintMismatch` (inferred: the
  stored keys of a version being enabled do not recompute to its stored
  fingerprint, a data-integrity error like `PlanIntegrity`).
- `SourceWriteError`: `WideningNotAcknowledged`, `PolicyUnavailable`.
- `ApprovalError` (new): `Unauthorized`; `NotFound`;
  `NotApprovable(NotApprovableReason)` with `Consumed`, `Revoked`,
  `Expired`, `WrongKind`; `SelfApproval`; `EchoMismatch`;
  `RequesterNotAuthorized`; `PlanIntegrity` (a data-integrity error, not a
  client error); `PolicyUnavailable`; `StaleRevision` (the toggle's policy
  row, D19); `UnsupportedIsolation`; `WideningNotAcknowledged` (the toggle
  turned off); `Keyset(KeysetWriteError)`; `Source(SourceWriteError)`;
  `Registry(RegistryError)`. `source()` returns the inner
  `RegistryError` only, as today (`keyset.rs:492-499`).

No contract maps admin write errors to HTTP statuses
(`docs/contracts/errors-retry.md` has none), so the request layer's mapping
is inferred: `Unauthorized` and `SelfApproval` 403; `NotFound` 404;
`NotApprovable`, `EchoMismatch`, `RequesterNotAuthorized` and
`StaleRevision` 409; `WideningNotAcknowledged` 422; `PolicyUnavailable`,
`ValidationBusy` and `Retry` 503 with `Retry-After`; `PlanIntegrity` and
`StoredFingerprintMismatch` 500. A
pending write returns 202 with the operation's ID, digest and `expires_at`.

### 11. Schema (text to merge into `0005`)

_Superseded in part by the 2026-11-24 amendment of `0005`: the approval
guard now covers every kind that names an operation, reading `actor_id`
for an `approve` only, and an audit guard is added (README, "Approval,
audit and revocation guards"); the sketch and its privileges predate it._

No new table or column, and no new migration file. The proposal offered an
optional migration `0012` in the `0010` and `0011` pattern: a tripwire for the
two service rules the `0005` review left to the service (README:962-968), plus
an index for the read path. On 2026-11-23 (relayed by the lead) the user
accepted the tripwire trigger in a changed form: the distinct approver and
same-tenant tripwire trigger, with its `INSERT OR UPDATE OF
revocation_operation_id` variant, is folded into migration `0005` itself, not
added as `0012` (D15). The read-path index was part of the same sketch and is
folded into `0005` too as a provisional lead pick (inferred), not ruled. This
is allowed by
the pre-beta exception to the forward-only rule (`service/migrations/README.md`,
"Conventions"), ruled by the user on 2026-11-23 (relayed by the lead): "we don't
need to keep data until a beta release" and "I meant db migration are not needed
intra releases." On 2026-11-24 the user ruled: "Amend the design to clarify
that only migration across tagged public releases are supported, i.e, there is
no need to do migration before the first beta releases. The db migration
mechanism must be there and tested." Upgrades are supported only between
tagged public releases, from the first one (the first beta); before it there is
no upgrade path, though the mechanism is provided and tested, and an existing
migration may be amended in place; the forward-only rule applies from the
first tagged release (date set by the maintainer). An edited `0005` changes
its checksum, so a database created before the edit must be recreated;
`migrate` refuses it otherwise. The
implementation PR also rewrites the README's `0005` text that leaves these two
rules to the service (README:1081-1092) and adds the new names to
`KNOWN_CONSTRAINTS`.

The sketch below is corrected to what `0005` now holds (PR 2): the first
version left out the revocation function, the `ENABLE ALWAYS` of the
revocation trigger and the `SECURITY INVOKER` clause both functions carry,
and did not say how a guard treats a missing row or whether it locks. As
implemented (inferred where marked in `0005`): the functions are created
schema-qualified as the `0010` and `0011` readers are; a guard that does not
find the referenced row passes it, which happens only in replica mode, where
the foreign keys do not fire (as in `0010`); the guards read without a row
lock, since `tenant_id` and `actor_id` are immutable and the foreign-key
check already holds the row `FOR KEY SHARE`; and the tenant is compared
before the actor.

```sql
-- Text to merge into 0005_operator.sql (not a new migration file).

-- An approve names an operation of its own tenant (IS NOT DISTINCT FROM,
-- so an instance approve names an instance operation) and is never by that
-- operation's actor. Only kind 'approve': a route_bundle_approval also
-- names its preparation, and one person MAY hold both roles there (IR-054;
-- GW-130, GW-131).
-- Created in a DO block with the schema from current_schema(), as 0010 and
-- 0011 create their table readers; it reads the approved row's tenant_id
-- and actor_id without a row lock and passes a row whose approved
-- operation it does not find (replica mode, where the foreign key does not
-- fire).
CREATE FUNCTION skyoauth_check_operation_approval() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
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
CREATE FUNCTION skyoauth_check_operation_revocation() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS $$ ... $$;  -- reads the revoking row's tenant_id, as above
CREATE TRIGGER administrative_operation_revocation_check
    AFTER INSERT OR UPDATE OF revocation_operation_id
    ON administrative_operation
    FOR EACH ROW WHEN (NEW.revocation_operation_id IS NOT NULL)
    EXECUTE FUNCTION skyoauth_check_operation_revocation();
ALTER TABLE administrative_operation
    ENABLE ALWAYS TRIGGER administrative_operation_revocation_check;
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
(README:1036-1059). The new locks sit as follows.

**Request** (direct or pending):

1. the requester's operator rows `FOR SHARE`, in the `0005` order
   (identity, credential, binding or bindings);
2. the `instance_security_policy` row (new): `FOR SHARE` for a trust
   write; `FOR NO KEY UPDATE` for the toggle, in both branches, since it
   is the row the toggle updates (README:1038-1039; D19);
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
   is the fifth `0005` table, README:1043-1045);
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
  database's (README:971-972 asks only for an expiry). The approve samples
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
- The guard folded into `0005` (section 11) is a tripwire against
  application DML, not a security boundary (README "Limits"); it cannot
  check roles or the digest.
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
  check here prevents it while the toggle is on. Q7 (ruled by the user,
  2026-11-23) gates such grants while the toggle is on, as a follow-up;
  until it lands the residual risk is accepted.
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
  the flag, the toggle off and on, `single_actor_mode` off and on; a
  disable-only source update is not widening (Q2, ruled by the user,
  2026-11-23), while a disable that also changes a member is.
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
  binding insert does not wait); with the PR 5 add-on (Q2, ruled by the
  user, 2026-11-23), a disable-only update is applied at once while the
  toggle is on.
- **Toggle** (A48): pending without a second `security_admin`; applied by a
  distinct one; one actor under `single_actor_mode`; no online write to
  `single_actor_mode` or the sink fields.
- **Policy row.** Missing: `PolicyUnavailable`, nothing written.
- **Savepoint.** Every `Err` leaves no operation, no event and no target
  change, and the caller's transaction usable; a non-`READ COMMITTED`
  transaction is refused before any lock.
- **Redaction.** `Display` and `Debug` of every new variant contain no
  digest, ID, revision or destination (`service/tests/redaction.rs`).
- **Catalog** (the `0005` trigger, section 11): trigger and function
  names, `tgenabled = 'A'`, pinned `search_path`, the three raised names in
  `KNOWN_CONSTRAINTS`, and the new triggers and index in the `0005`
  catalog tests that pin every `0005` trigger
  (`service/tests/schema_operator.rs`) and every constraint name
  (`service/tests/registry.rs`).

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

1. **D1.** **Classification is computed by the server.** Every keyset
   version create and enable is widening and `disable_version` is not
   (ADR-008:217-219). Every trust source write is widening except a
   disable-only update, computed from the stored row: the user accepted
   that exception (Q2, ruled by the user, 2026-11-23, relayed by the
   lead), and it lands as an add-on to PR 5. Until that ruling the pick
   was to follow the 2026-11-22 ruling exactly and treat every source
   write as widening. Rejected: a caller flag that decides (ADR-008 item
   12 forbids it); a per-member widening and narrowing diff of sources
   (error-prone over fourteen members, and the ruling counts every other
   source write); shipping the disable-only exception before Q2 was
   answered (it went beyond the ruling then).
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
5. **D5.** **24-hour expiry**, fixed (OQ-API-14 is open in the contract; Q1,
   ruled by the user, 2026-11-23). Rejected: the
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
15. **D15.** **The distinct-approver and same-tenant guard, and the read-path
    index, in `0005`** (section 11). Proposed as an optional migration `0012`.
    The user accepted the tripwire trigger, 2026-11-23, in the changed form: the
    distinct-approver / same-tenant tripwire trigger (and the `INSERT OR UPDATE
OF revocation_operation_id` variant) is folded into migration `0005` itself,
    not added as `0012`. The read-path index was part of the same sketch and is
    folded into `0005` too as a provisional lead pick (inferred), not ruled. It
    reverses, for these two rules only, the `0005` review's acceptance that they
    stay service rules (README:966-968). An edited `0005` changes its checksum,
    so a database created before the edit must be recreated (the pre-beta
    exception, `service/migrations/README.md` "Conventions"). Rejected: no
    backstop for self-approval; a new `0012` file (the user's ruling).
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
    PostgreSQL 17.12; README:1038-1039 asks for `FOR NO KEY UPDATE` on a
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
    `apply_enable_version`, `apply_create_source`, `lock_source` with
    `apply_locked_update`, `apply_policy_toggle`) take the authorized
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

## Resolved (accepted with the directional ADR ratification)

Decided before this proposal and used as given, all accepted as
implementation choices with the maintainer's directional ratification of the
ADRs (2026-11-24; ordinary review can change them): the widening ruling for
keyset versions and sources (the user's, 2026-11-22); the server's
detection and the flag (ADR-008 item 12, OQ-ADR008-3, OQ-ADR016-2); the
wire shape of the approve endpoints (OQ-API-13); the approver role (IR-054);
the IR-152 egress backstop (`0011`, README "What 0011 adds"); soft disable
as fail-safe for bindings and grants (ADR-008 item 3).

**Ruled by the user, 2026-11-23, relayed by the lead.** The user accepted the
recommended answer to each of Q1 to Q7 ("Accept all your recommendations, except
0012, as we don't need to keep data until a beta release"); the tripwire trigger
of `0012` was accepted in a changed form, folded into `0005` (D15); the
read-path index of the same sketch is folded into `0005` too as a provisional
lead pick (inferred), not ruled. Each answer below is the recommendation as
ruled; with the directional ratification of the ADRs (maintainer,
2026-11-24) these rulings are accepted in the same way as the 2026-11-22
ruling: as implementation choices that ordinary review can change.

1. **Q1.** **Expiry and read path (OQ-API-14).** Ruled: a fixed 24-hour
   `expires_at`; `GET /admin/v1/tenants/{tenant}/operations/{operation}` and a
   list of open operations (and the instance twins), readable by instance
   `security_admin`, the requester and the tenant `auditor`, returning the
   digest and the whole digest envelope: the operation `id`, the requester's
   `actor_id`, `kind`, `tenant_id`, `expected_revision`, `expires_at` as the
   integer microseconds the preimage uses, and the plan as its canonical text
   (D29). The operator client recomputes the digest from that response alone
   before echoing it, so an approver never echoes a digest it has not checked
   against what it read.
2. **Q2.** **Is a disable-only source update widening?** The 2026-11-22 ruling
   says "a trust source write", so until this ruling it was (D1). Ruled: the
   exception is accepted, not widening, like a soft disable of a binding or
   grant (ADR-008 item 3, by analogy), so a source can be shut off at once while
   the toggle is on; it lands as the PR 5 add-on.
3. **Q3.** **Is a disabled keyset version create widening?** It makes no key
   live. Ruled: yes, as the ruling's text says; the cost is one approval
   for a create-then-enable, and the rotation path creates enabled anyway.
4. **Q4.** **Under `single_actor_mode`, must the one actor also hold
   `security_admin`?** Ruled: yes; a `trust_admin` without it gets a
   pending operation that a `security_admin` approves. This is in tension
   with tasks:149 ("under single_actor_mode no approve call"): once the
   fallback leaves a request pending, an approve call is made under
   `single_actor_mode`, so the ruling also reads tasks:149 as applying
   to a requester who holds `security_admin`.
5. **Q5.** **Is the requester checked again at approve?** The spec names
   the approver's role only (public-api:451). Ruled: yes, the role,
   the identity and the submitting credential (D21); a requester who lost
   `trust_admin`, or whose credential was revoked, should not have a
   change applied in their name.
6. **Q6.** **A fingerprint in the audit event?** Ruled: no, for now; the
   plan and the version row hold it, and an envelope member is an ADR-level
   change to the IR-056 hash input. The cost is that the external sink
   cannot show which plan an approval covered; a `request_digest` member
   is the better ADR follow-up than the fingerprint, since it names the
   whole plan of every kind.
7. **Q7.** **Gate `security_admin` grants while the toggle is on?** One
   `security_admin` can enrol a second identity and grant it
   `security_admin`, then approve through it (Limits). Ruled: yes,
   as a follow-up: while `widening_second_approver` is on, a grant of
   instance `security_admin` (and the enrolment of an identity that
   receives one) is itself a gated kind needing a distinct existing
   `security_admin`; until then, record the residual risk as accepted.

## Open

No question of this proposal is open.

**Ruled by the user, 2026-11-24, relayed by the lead:** the ruling that
turning `widening_second_approver` off needs `acknowledge_widening` applies
to every request that sets it to false, whatever the current value, a
same-value false to false write included. The reasons are
that widening is computed server-side from the kind of write (the user's
ruling, 2026-11-22) and that `prepare_approval` authorizes before it reads
state; a request that sets true is never widening. Omitting the flag
returns `WideningNotAcknowledged` before any operation goes pending, also
under `single_actor_mode`. The contract text (IR-052, API-156) is not
changed by this PR; those edits are deferred to a follow-up PR.

**Not decided here** (for the lead): how an approver learns of a pending
operation (notification); metrics, including whether `SelfApproval` and
`EchoMismatch` count as security signals; whether the IR-053 startup mirror of
`single_actor_mode` bumps the policy row's revision, which would leave
every pending toggle stale; and whether each coding PR is paired with its
test PR or the test PR follows.

## Implementation notes

**PR 3 as implemented** (`service/src/operation/`; picks marked inferred
in its module docs). The kinds, `Applied` and `ApprovalError` hold the
toggle's only: the trust kinds, `Applied::KeysetVersion` and
`Applied::Source`, and `ApprovalError::Keyset` and `ApprovalError::Source`
came with PR 4 (the keyset ones, with the `allowed` parameter of
`prepare_approval`) or with PR 5 (the source ones). `SystemClock` is the production `Clock`. The toggle's
compare-and-set is the crate-private registry writer
`set_widening_second_approver`, so no ungated setter is public. The
toggle's plan is exactly `requester_credential_id` and
`widening_second_approver`, with no version member; any other shape is
`PlanIntegrity`. The approve applies D24 to the toggle too: the prepared
plan must equal the locked plan. `acknowledge_widening` was ignored by the
toggle in PRs 3 to 7, which is always gated; since the user's ruling of
2026-11-24 the toggle refuses a request that sets false without the flag
(`WideningNotAcknowledged`; relayed by the lead; see "Open"). The toggle
authorizes with the local instance `security_admin` lookup, not the trust writes'
`authorize_trust_admin`.
A cancel looks up the path's role (instance `security_admin`, tenant
`trust_admin`, the role of every kind of the flow on that path) before it
reads the operation; another operator is `Unauthorized` (on a tenant path
`NotFound` since PR 4, below). The operations a
cancel, a reject and an approve insert have outcome `success`, and the
toggle's event applied at once `success_single_actor` (section 7; the value
set is inferred). The stored digest is checked before the echo: one that is
not 32 bytes (`prepare_approval` and the approve) or that the row does not
recompute to (the approve) is `PlanIntegrity`; only a valid stored digest
unequal to the echo is `EchoMismatch`. A toggle to the current value (a
no-op) is accepted like any other (inferred): applied at once it writes the
same value at the next revision; pending, its approval only advances the
revision, so every other pending toggle goes stale. That the toggle is
gated both ways is IR-052's (identity-registry:423-427: "Turning the
setting on or off ... MUST have a distinct second `security_admin`
approver"; tasks:147; ADR-008:100-103), not a pick.

**PR 4 as implemented** (`service/src/trust/keyset.rs`,
`service/src/trust/write.rs`, `service/src/operation/`; picks marked
inferred in the module docs). `submit_create_version` takes the `allowed`
set the upload was validated against (the sketch above now shows it).
`authorize_trust_admin` returns `Requester`; the gated requests lock the
tenant `trust_admin` binding and the instance `security_admin` binding in
one `authorize_roles_locked` statement whatever the policy says
(inferred), and require `holds(0)`, so a `security_admin` without the
tenant role is `Unauthorized`. The order is the isolation, the requester,
the flag (`WideningNotAcknowledged`), the policy row `FOR SHARE`
(`PolicyUnavailable` before bootstrap), then the mode; a pending request
runs the write's own checks under its locks (D7) and `ValidationBusy`
keeps PR 1's meaning. Request-time pure checks (D27): the provenance, an
empty version ID (refused as `Invariant` on
`trust_keyset_version_id_check`, as the insert would be), and a key whose
algorithm is outside `allowed` (inferred: `Upload`, as `validate_keyset`
refuses it). A create's plan is its ten members: the requester's
credential, the version and keyset IDs, the canonical projection text and
its fingerprint, the sorted `allowed` names, the window in whole
microseconds, the status, and the provenance as compact JSON text
(inferred: text, so the `jsonb` column returns it exactly, whatever
numbers it holds); an enable's is the credential, the version, its keyset
and its stored fingerprint. At approve, an enable whose version's keyset or fingerprint
is not the plan's is `PlanIntegrity` (inferred: both are immutable); a
keyset write's refusal, a stale target revision included, is
`ApprovalError::Keyset` (inferred: the toggle keeps its own
`StaleRevision`). The approve operation's tenant is the operation's, which
is the target's (the `0005` guard requires it). `Applied` is `Debug`,
`Clone` and `PartialEq` but no longer `Eq` (a version's provenance is
JSON). On a tenant path a cancel of
another operator's operation is now `NotFound`, like a missing one (the PR
5 row's item, done here since PR 4 adds the first tenant kind); on the
instance path it stays `Unauthorized`. An enable, direct, requested or
approved, refuses a version whose parsed stored keys do not recompute to
its stored `fingerprint` (the one its plan names) with the new
`KeysetWriteError::StoredFingerprintMismatch` (inferred: a variant of its
own, since the keys break no JWK set rule `StoredVersion` names); the
check sits in the one status step the request and the approval share,
after the parse and under its one permit, so at approve it is
`ApprovalError::Keyset(StoredFingerprintMismatch)`, not `PlanIntegrity`
(a plan whose fingerprint is not the stored one stays `PlanIntegrity`).

PR 4's mutants (outside the repository; this records the verdicts).
Equivalent in PR 4, two: the cancel's kind-role guard dropped (recorded in
"Left open for PR 5" below), and `authorize_trust_admin` returning the
admin ID as the credential ID (recorded here: the ungated writes, its only
callers, never read `Requester::credential_id`; the gated writes take it
from `authorize_widening_write`). Not equivalent, though PR 4's
keyset-scoped run missed it: a revoked credential accepted by the
operator statement, killed by
`operator::tests::the_statement_checks_every_status_role_and_scope` and
`registry_operator`'s
`a_revoked_credential_is_refused_even_without_the_status_check` and
`every_miss_is_the_same_none`. Two mutants that PR 4's first run did not
include, and that survived its tests in review, are now killed:
`prepare_approval` parsing a keyset create's projection before it
authorizes (D20), by `the_preparation_authorizes_before_it_parses_the_plan`
(moving the whole authorization after the plan's read is also killed by
`operation_approval` tests), and the
approve's comparison of the stored digest with the prepared one dropped,
by `an_approval_refuses_a_digest_other_than_the_prepared_one`. The
stored-fingerprint check dropped is killed at the request and at the
approval, each by a test of its own.
What PR 4 does not test: `keyset_approval.rs` has no plan-restoration
test (a plan changed past the guard before the preparation and put back
before the approval is #116's toggle test; PR 4's D24 tests change the
locked plan after the preparation and leave it changed, and its one
restoration test puts back a digest); and the keyset path's policy row
`FOR SHARE` is tested by `NOWAIT` lock-strength probes only, with no race
of a keyset request against a toggle (the toggle's race is #116's
emulation). The races PR 4 runs on two connections are on the operation
row, the `trust_keyset` row and a version ID's insert.

**PR 5 as implemented** (`service/src/trust/source.rs`,
`service/src/trust/write.rs`, `service/src/operation/source_plan.rs`,
`service/src/operation/`; picks marked inferred in the module docs).
`submit_create_source` and `submit_update_source` are the gated writes;
`create_source` and `update_source` become step 1 plus
`apply_create_source`, or plus `lock_source` and `apply_locked_update`
(the sketch above now shows the split), and stayed public until PR 7. The
request steps that PR 4 ran together are split in `write.rs`
(`authorize_gated_requester`, `require_acknowledged`, `lock_policy_shared`,
`widening_mode`) so that an update can classify after its stored-row lock.
A create's refusal order is PR 4's. An update's is the requester, the
stored row (`NotFound`, `StaleRevision`), then, for a widening update only,
the flag and a missing policy row (inferred); the policy row is locked
`FOR SHARE` before the source row for every update, a disable-only one
included, so the lock order does not depend on the class (inferred). Q2:
`classify_source_update` compares the fourteen other members with the
stored row by value; `proof_bounds` by the database's `jsonb` equality on
the locked row (key order and a number's spelling are no change, and a
stored number beyond `f64` precision, which only a row written outside the
service can hold, is compared exactly, so an echo that rounds it is a
change), at the request and again at the approve (inferred).
`serde_json` is built with `float_roundtrip`, so a float in a plan's
`proof_bounds` text reads back to the value the request compared;
without it, some floats (`1.132605069600529e-13`) came back one unit off
and the approve refused a valid plan as `PlanIntegrity`. A disabled source
written with its stored members is disable-only too (inferred). A
disable-only update is applied at once with outcome `success`, even before
bootstrap (inferred: the mode table's first row does not read the policy).
D27 at the request, before any statement, so before the requester:
the syntax of a create's destinations, then the non-empty, `> 0` and
`true` checks of section 3's list and the `skyoauth_string_list` domain,
each refused as the `Invariant` the database names, the domain first and
then the table checks by name, as PostgreSQL runs them (inferred: scope
and order; the kind, profile, replay, length, character, unique and
foreign-key checks stay approve-time). A source parses nothing in the
transaction, so `ValidationBusy` does not arise. The plans are
`CreateSourcePlan` and `UpdateSourcePlan`
(`service/src/operation/source_plan.rs`), each with its fifteen mutable members in a private `source` field, built
by its constructor or parsed from a stored plan. A create's plan is its 21
members: the requester's credential, the source's ID, tenant, kind, keyset
and cluster, and the fifteen mutable members; an update's is 18: the
credential, the source's ID, the fifteen members as requested and
`changed`, the sorted names of the members that differ from the stored
row (inferred: member names are the registry's; `proof_bounds` as compact
JSON text, as a keyset create's provenance). Every member is public: the
CA bundle and the reviewer credential are named by reference only. At
approve, a create plan whose tenant is not the operation's, and an update
plan whose `changed` is not what its changes change on the row at the
expected revision, are `PlanIntegrity` (inferred); the class is not
computed again, since that revision pins the row it was read from
(inferred); a source write's refusal, a stale target revision included, is
`ApprovalError::Source`. The approval rechecks the syntax and each entry
under its own locks (operator rows, operation row, source row, entries),
so an entry disabled after the request is `Source(EgressNotAllowed)`, not
the `0011` guard's `Invariant`; the guard then finds the entry the
approval holds. That the guard refuses on the service path, as
`Invariant { kind: EgressEntryEnabled }`, when the service's own entry
check is skipped, is verified only by a mutant (the reviewer's, which
dropped the check); no committed test reaches the guard through the
service, which always checks the entry first. The guard's own refusal and
the bare registry writers' mapping of it are tested in
`service/tests/schema_trust_source_egress_guard.rs` and
`service/tests/trust_source_egress.rs`. `service/tests/source_approval.rs`
tests, on two connections where a race is involved: the plan and digest of both kinds,
the mode table with the disable-only row, `WideningNotAcknowledged` for
every widening shape (a disable plus a change, an enable, a re-enable, a
no-op on an enabled source, a changed `proof_bounds` value), floats that
need the shortest round trip through the plan text and through a request
body, `proof_bounds` beyond `f64` precision written by raw SQL, the refusal
order before bootstrap, D27 against the database's own refusal case by
case, canonical-form destinations at the request and at approve, the entry
disabled between request and approve (A05) and the approval waiting for an
uncommitted entry disable while it holds the source row, the clock with
the compare-and-set waiting behind an uncommitted `consumed_assertion`
insert (`FOR KEY SHARE`) in both directions of the expiry, the expiry
boundary, D24 (a plan unequal to its digest, and a locked plan changed
past the `0005` trigger after the preparation), the preparation's
authorize-before-parse, a digest other than the prepared one, the
requester's binding and credential states, a break-glass restoration
between request and approve (the restored operator's approval is
`RequesterNotAuthorized`), a name taken before the approve (refused,
pending), the tenant-path cancel and reject, two approves, approve and
cancel, approve and a direct write in both commit orders, and the policy
row on the real path: a source create holding it `FOR SHARE` against
`submit_widening_toggle` holding it `FOR NO KEY UPDATE`, both commit
orders, and an update that waits for the toggle before it locks its
source row. Not tested: a source plan changed past the guard before the
preparation and put back before the approval (#116's toggle test covers
the comparison it relies on), and PostgreSQL 17 locally (the PR's runs
used 16.15; CI uses 17).

PR 5's mutants (outside the repository; this records the verdicts): 74,
covering the class of an update, the shared gate steps and
`authorize_trust_admin`, the lock order (the policy row before the source
row, the source row's strength, the requester first), the clock before the
source write and between the source row's lock and the compare-and-set,
the plans' members, D24 and D27 (scope and order), canonical form and the
egress entries at the request and the approve, the dispatch, the
cancel and reject guards, the approve operation's tenant (M31), the
events, the pending rows, the savepoints, the isolation, and `proof_bounds`
compared in memory or always equal, at the request and at the approve.
72 are killed.
Two are equivalent: the cancel's kind-role guard dropped (PR 4's verdict
holds with the source kinds, since `requester_role` maps every tenant kind
to tenant `trust_admin`), and an approve that classifies the update again
and refuses a disable-only one (a request-written plan is never
disable-only against the row its expected revision pins, since the approve
also checks `changed` against that row; only a raw plan could be, and
applying a disable widens nothing). The savepoints of the two `submit_*`
functions survived the first run, because a `COMMIT` of an aborted
transaction rolls back without an error; a test that keeps using the
caller's transaction after a refusal and probes the locks with `NOWAIT`
kills them.

**Left open for PR 5** (PR 5's outcome follows this paragraph). The user ruled on 2026-11-24 that `acknowledge_widening`
applies to the toggle turned off (a widening write like any other: without
the flag it is refused with `WideningNotAcknowledged`); PRs 3 and 4 ignored
the flag for it, the library now implements it (`submit_widening_toggle`)
and T13.3 wires it. Three PR 3 mutants are equivalent only because the toggle is
the one kind, and become live with the trust kinds; killing them is a
required test of PRs 4 and 5: the clock sampled between the target's lock
and the registry write (PR 4 kills it with a keyset create, whose insert
waits on another transaction's uncommitted version with the same ID; a
source compare-and-set can wait there too, to test in PR 5); the cancel's
kind-role guard dropped (a tenant kind, PR 4 or 5); plus the approve
operation inserted with tenant NULL (M31; PR 4 kills it, since the
`0005` guard refuses an approve outside its operation's tenant). PR 4
found the kind-role guard still equivalent with the keyset kinds and
expects it to stay so with every kind: the path check before it already
refuses any kind whose requester role is not the path's (`requester_role`
and `requester_request` encode the same table; a unit test pins it), so
the guard is a defence for a future kind only. The D24 comparison of the
prepared payload with the locked plan dropped is not equivalent in PR 3:
`prepare_approval` checks only the stored digest's length, so a plan
written past the immutability guard before the preparation and put back
before the approval passes the recompute (D6) and the echo, and only D24
refuses it (`a_plan_written_past_its_guard_is_plan_integrity`, #116,
8b80158). PR 4 must still kill it for a keyset create's projection, and does:
a plan whose projection text is not the canonical text the preparation
parsed, and a locked plan changed after the preparation with the `0005`
immutability trigger disabled in between, are both `PlanIntegrity`.
PR 5 kills the clock mutant with a source compare-and-set waiting behind an
uncommitted `consumed_assertion` insert, kills the approve operation
inserted with tenant NULL with the source kinds too, kills the D24
comparison dropped for both source kinds, and finds the kind-role guard
still equivalent. Ruled after PR 5 (the user, 2026-11-24): `acknowledge_widening`
applies to the toggle turned off, and a toggle off without it gets
`WideningNotAcknowledged`; `submit_widening_toggle` implements it, T13.3 wires it.

**PR 7 as implemented** (`service/src/trust/`, `service/Cargo.toml`;
picks marked inferred in the code comments). `create_version`,
`enable_version`, `create_source` and `update_source` are `pub(super)`:
visible only within `trust`, so a caller anywhere else in the crate (an
endpoint module, `crate::operation`) is a privacy error (E0603) in every
build; `trust` no longer re-exports them. They were `pub(crate)` in the
first round of review; `pub(super)` is the reviewer's narrowing (provisional
lead pick, 2026-11-23). Nothing in `crate::operation` needs them: the
approval calls the `apply_*` steps. `disable_version` stays public:
section 9 lists only the four, a disable is not widening (section 1) and
has no gated form, so it stays the disable's write path. The callers did
not move to `submit_*`: `trust_keyset_version.rs` and
`trust_source_egress.rs` test the ungated writes' own behaviour (an event
outcome `success`, no policy row needed), and the setup helpers and race
tests of `keyset_approval.rs`, `source_approval.rs` and
`schema_trust_source_egress_guard.rs` need a write that is not gated.
Integration tests are crates of their own and cannot call a
restricted-visibility function, so a `test-support` cargo feature, off by
default, compiles a `#[doc(hidden)]` module `trust::test_support` with a
wrapper of the same name and signature for each of the four (such an
item cannot be re-exported), and the package's dev-dependency on itself
with that feature turns it on for test targets only (inferred: the
mechanism). Cargo applies a dev-dependency's features only to a build
that needs dev-dependencies, so `cargo build`, `cargo run` and
`cargo check --lib` leave it off; `--all-features` (every CI build but the
scenario jobs') and any build of a test target turn it on. The tests
change their imports only. The self-dependency adds one line to
`Cargo.lock` (`skyoauth-service` in its own dependency list) and no
package. In a build without the feature the four are dead code, which
`#[cfg_attr(not(feature = "test-support"), expect(dead_code))]` states,
so a caller inside `trust`, a public forwarder of another name included,
makes the expectation unfulfilled, a warning in such a build (inferred).

`service/tests/ungated_writes_private.rs` proves that a normal build
neither exposes nor calls them. It runs `cargo check --workspace --lib
--bins`, offline and `--locked`, in a target directory under
`CARGO_TARGET_TMPDIR`, with the outer build's `CARGO_*`, `RUSTFLAGS` and
coverage settings removed; the whole workspace, so that a member that
enables `test-support` through a normal or build dependency changes the
build. It then asserts that `skyoauth-service`'s library was built with no
feature and emitted no diagnostic (so an unfulfilled `expect(dead_code)`
fails it, though CI's own builds pass `--all-features` and never see that
warning; inferred), and compiles probe crates against the library's
metadata with `rustc`: one that names the public writes (`submit_*`,
`disable_version`) must compile, and each of the four, named at its
module, at `trust` and at `trust::test_support`, must fail as a private
or unresolved path (E0603, E0432). It needs no database and is not
ignored (inferred); its first run checks every dependency of the
workspace's libraries (about 37 s on four cores, alone; about 36 s inside
a full parallel run), later runs reuse that directory (about 1 s). A
compile-fail doctest cannot prove it: doctests build with the
dev-dependencies, so they see the feature. A second test in the same file
reads `keyset.rs` and `source.rs` and requires each writer to be
`pub(super)` right after its `expect(dead_code)` attribute, so that
removing the guard and adding a forwarder in the same change does not pass
either (inferred).

PR 7's mutants (outside the repository; this records the verdicts):
seventeen, all killed, none equivalent. By `ungated_writes_private`'s
build check (the library's diagnostics), ten: each of the four writers
made `pub` (and `create_version` made `pub` with `#[doc(hidden)]`, and
`update_source` made `pub` and re-exported from `trust`),
`trust::test_support` compiled without the feature, a public forwarder of
another name in `keyset.rs` and in `trust/mod.rs`, and a crate-visible
forwarder in `trust` called from `app()`. By its features check, two:
`test-support` made a default feature, and the scenario crate enabling it
through a normal dependency. By its probes alone (the diagnostics check
disabled), one: `create_version` made `pub`; the first round's run, before
the diagnostics check existed, killed every visibility mutant with the
probes. By the source check, one: the `expect(dead_code)` removed together
with a public forwarder added. By the compiler, three, not by the test: a
reference to an ungated writer from `app()` and from `crate::operation`
(E0603, the effect of `pub(super)`), and `disable_version` made
crate-private (`trust` re-exports it).

**PR 9 as implemented** (`service/src/persistence/registry/`,
`service/Cargo.toml`, `tests/Cargo.toml`; picks marked inferred in the code
comments). `create_trust_keyset_version`, `update_trust_keyset_version`,
`create_trust_source` and `update_trust_source` are `pub(crate)`, and
`persistence::registry` re-exports them `pub(crate)`. They cannot be
narrower: they live in `persistence::registry::trust`, and their callers are
in `crate::trust`, a sibling of `crate::persistence`, which `pub(super)` or
`pub(in crate::persistence)` would not reach (`pub(in path)` names only an
ancestor). Those callers are steps of the trust write path, the gated ones
included, so the writers are live in every build: `insert_create_version`
(through `apply_create_version`: `submit_create_version` when it applies
at once, the approval, and the ungated `create_version`), `apply_status`
(`disable_version`, `submit_enable_version` when it applies at once, the
approval's `apply_enable_version`, and the ungated `enable_version`), and
`apply_create_source` and `apply_locked_update` (`submit_create_source`
and `submit_update_source` when they apply at once, the approval, and the
ungated writes). PR 7's `expect(dead_code)` guard therefore cannot apply
to them. The mechanism is the lead's (provisional lead pick, 2026-11-23);
the visibility is inferred. Integration and scenario tests reach
them through a `#[doc(hidden)]` module `persistence::registry::test_support`,
compiled only with the `test-support` feature, with a wrapper of the same
name and signature for each. `skyoauth-scenarios` gets the feature through
a `[dev-dependencies]` entry on `skyoauth-service` only; its `[dependencies]`
entry and its library in `tests/src` stay without it. Its manifest's "No
features" note is about features of its own, which this is not, and a
comment says so. The `scenarios-pg` job builds its test target with
`-p skyoauth-scenarios --test pg` and no `--features`; a test target needs
dev-dependencies, so the feature is on there with no workflow change. The
tests change their paths only (`registry::create_trust_source` becomes
`registry::test_support::create_trust_source`, and so on; the `at_max!`
macro of `registry_trust.rs` takes a path). Nothing else moved: no
migration, no endpoint, no new gated kind, no dependency, and `Cargo.lock`
is unchanged (the scenario package already depended on the service).

`service/tests/ungated_writes_private.rs` covers the four. Its build check
is unchanged and still covers the whole workspace, so the scenario package
enabling the feature through a normal dependency fails its features check.
Its probes now also require each registry writer to fail to resolve at
`persistence::registry::<name>`, at the private module
`persistence::registry::trust::<name>`, at
`persistence::registry::test_support::<name>` and at
`trust::test_support::<name>`, and each of six crate-private steps of
`trust` at its module and at `trust`; the control probe also names the
registry items that stay public (the keyset version and trust source
readers, and the row and input types the wrappers use). The six steps
apply a write without authorizing, gating or auditing it themselves: the
four callers above and the two that call them, `apply_create_version` and
`apply_enable_version`. PR 7's `expect(dead_code)` covers only its four
`pub(super)` writers, so before this PR's review round nothing watched
these six: a public function in `trust/source.rs` that authorized an
operator and then called `apply_create_source` passed every check, and a
probe could name it. Since the writers and the steps are live, a
forwarder of another name or a new caller would not show as a
diagnostic, so a source check stands in for the dead-code guard
(inferred): outside comment lines, the library may name each writer and
each step only where a table in the test lists, 44 places in
`persistence/registry/{mod,trust,test_support}.rs`, `trust/keyset.rs`,
`trust/source.rs` and `operation/approval.rs` (the definitions, the
re-exports and `use`s, the wrappers, and the callers), each keyed by the
first line of the top-level item that holds the mention, its visibility
included, and with the count of mentions. A definition or a caller made
`pub`, a forwarder anywhere in the crate, and a new caller each fail it,
and its message lists the unexpected and the missing entries one per line.
The key relies on `rustfmt` putting every top-level item in column 0, so
the check also fails if the library's source, with its whitespace
removed, contains `rustfmt::skip`, `#[path`, `path="` or `include!(`
(none does today): an indented item kept by `rustfmt::skip` would count
under the item before it. It is a text check: a name built by a macro
would escape it (no macro in the crate does that), and a rewrite that
keeps every item's count (a mention moved inside the same item) is not
ruled out by it.

PR 9's mutants (outside the repository; this records the verdicts):
twenty-six, twenty-four killed. Seventeen run against the whole test, all
killed. By the source check, ten: each of the four writers made `pub`,
`create_trust_source` made `pub` and re-exported `pub` (its probe kills
it too), `registry::trust` made a public module with a writer `pub` (its
probe too), a public forwarder of another name in `trust/source.rs` and in
`registry/mod.rs`, and a crate-visible caller referenced from `app()` and
from `crate::operation`. By the features check, two: the scenario package
enabling `test-support` through its `[dependencies]` entry, and
`test-support` made a default feature. By the probes, one: the registry's
`test_support` compiled without the feature. By the diagnostics check,
three: a caller (`apply_create_source`) made `pub` (a `private_interfaces`
warning; the source check kills it too), a registry reader
(`get_trust_source`) taken out of the public re-export (an unused import),
and PR 7's `create_version` made `pub`. By the compiler, one: a writer
re-exported `pub` while still `pub(crate)` (E0364). Nine more run with a
check disabled, to show which check carries a mutant: with the source
check off, a public forwarder of another name survives (no probe can name
it and the writer is live, so no diagnostic either: the source check is
what kills it), and a writer made `pub` but still re-exported `pub(crate)`
survives; that one is equivalent in effect, since the writer stays
unreachable from outside the crate (a private module, a crate-private
re-export), and only the source check, which keeps the written visibility
`pub(crate)`, kills it. The other seven are killed: the public re-export
of a writer by its probe alone; a caller made `pub`, with and without a
re-export from `trust`, by the diagnostics check with the source check off
and by its probes alone with both off; the reader taken out by the control
probe; and PR 7's `create_version` made `pub` by its probe. The two
caller-made-`pub` mutants of that first round were caught with the source
check off only by a `private_interfaces` warning, an accident of their
signatures (they take the crate-private `Requester`), not by design.

The review round added twelve mutants and reran all of round 1's against
the final test: thirty-eight in all, thirty-three killed, and the round-1
verdicts hold (a caller made `pub` is now also killed by the source
check). Of the twelve, nine are killed. By the source check, three: a
public function in `trust/source.rs` that authorizes a trust admin and
then calls `apply_create_source`, a public forwarder in `crate::operation`
that calls it with a `Requester` it builds itself, and a public function
in `trust/keyset.rs` that calls `apply_status` (an enable with no audit
event). By the layout refusal, four: an indented `#[rustfmt::skip]`
function after `apply_create_source` that calls it (with the refusal off,
the count check kills it too); a count-preserving one under the `use` of
the registry in `trust/source.rs`, with that `use` entry replaced by a
path at the call (only the refusal kills it); the same with
`#[rustfmt :: skip]`; and a `#[path]` module (the diagnostics check too).
By the build check, one: the scenario library naming
`registry::test_support`, which compiles in a test build, where the
feature is on, and fails the no-feature check of the workspace. Three
survive: the authorizing `apply_create_source` caller with the source
check off, which is the test before the review round (nothing watched the
six steps); the
count-preserving layout mutant with the refusal off; and a non-default
feature of the scenario package that turns on
`skyoauth-service/test-support`, which a build without features never
sees (accepted; the release-build item under "Still open" covers it).

**PR 10 as implemented** (`service/src/persistence/registry/`; picks
marked inferred in the code comments). The lead assigned the writers of
rows 2, 6 and 7 of the survey under "Still open" (provisional lead pick,
2026-11-23). `create_admin_identity`, `create_admin_credential` and
`create_admin_role_binding` are `pub(super)` in `registry::operator`,
visible only within `persistence::registry`, which re-exports them
privately: their only callers outside tests are `bootstrap_instance`
(`bootstrap.rs:521`, `:530`, `:541`) and `restore_operator`
(`recovery.rs:1097`, `:1106`, `:1117`), both in the registry, so a caller
anywhere else in the crate is a privacy error (E0603) in every build
(inferred: the narrowest visibility that reaches them).
`update_admin_role_binding` is `pub(super)` too and has no caller in the
crate, so it takes PR 7's form: without the feature it is dead code, which
`#[cfg_attr(not(feature = "test-support"), expect(dead_code, ...))]`
states, so a caller in the registry, a public forwarder included, makes
the expectation unfulfilled, a warning in such a build. `append_audit_event`
is `pub(crate)`: the audited writes of the registry (`bootstrap_steps`,
`issue_steps`, `restore_steps`), of `crate::trust` (each module's
`append_stamped`) and of `crate::operation` (`approve_steps`,
`revoke_steps`, `toggle_steps` and `insert_pending`) call it, and
`crate::trust` and `crate::operation` are siblings of `crate::persistence`,
which `pub(super)` or `pub(in crate::persistence)` would not reach.
`insert_administrative_operation`,
`consume_administrative_operation` and `revoke_administrative_operation`
are `pub(crate)` for the same reason: `operation/approval.rs` calls all
three and `operation/toggle.rs` the insert (in `insert_pending`, which the
gated `submit_*` writes of `crate::trust` call). The tests reach all eight
through wrappers of the same name in `persistence::registry::test_support`
and change their paths only (`registry::create_admin_identity` becomes
`registry::test_support::create_admin_identity`; an imported append or
operation-row writer moves into a `test_support` group of the import):
169 mentions in 11 integration and 5 scenario test files, and the `seed`
of a database unit test in `trust::keyset`, which reaches the creates
through `test_support` too (the crate's own test build has the feature,
through the package's dev-dependency on itself). The scenario library
(`tests/src`) calls none of them. The input and row types
(`NewAdminIdentity`, `NewAuditEvent`, `NewAdministrativeOperation` and the
rest) stay public: the wrappers take and return them. Nothing else moved:
`bootstrap_instance`, `issue_recovery_challenge` and `restore_operator`
stay public (the open decision below), so another crate can still enroll a
`security_admin` through them, and making the creates crate-private does
not change that; `disable_admin_identity` and `revoke_admin_credential`,
which only narrow, stay public. No migration, no endpoint, no new gated
kind, no dependency, no workflow change, and `Cargo.lock` is unchanged.

`service/tests/ungated_writes_private.rs` covers the eight. Its probes
require each to fail to resolve at `persistence::registry::<name>`, at its
private defining module (`operator`, `events` or `operation`; there as a
private path, E0603, since the review round, so a renamed module or a stale
table fails the test instead of passing it) and at
`persistence::registry::test_support::<name>`; the control probe also
names the operator, audit and operation readers and types that stay public
and the five registry writers that deliberately stay public
(`restore_operator`, `issue_recovery_challenge`, `bootstrap_instance`,
`disable_admin_identity`, `revoke_admin_credential`), so narrowing one of
them fails it. The source check's table gains 62 places for the eight
names, 106 in all: the definitions, the re-exports, the wrappers, the
`use`s, the callers above and the unit test's `seed`, each keyed by the
first line of the item that holds it and counted. The guard test now also
requires `update_admin_role_binding` to be `pub(super)` right after its
`expect(dead_code)`. The review round hardened the source check (see the
next paragraphs): an `impl` block at any depth is an item key of its own,
so the `seed` rows are keyed by the test module's `impl Drop for Db`;
mentions are counted with comments and string and character literals
removed; and the check refuses `<name> as` for a listed name (whitespace
removed, outside comments and literals) and a level set for
`non_local_definitions` or `warnings` in the library's source, the
package's or the workspace's manifest or the workspace's cargo
configuration, on top of the layout escapes it already refused (inferred,
all four).

PR 10's mutants (outside the repository; this records the verdicts), round
1: forty-nine, forty-one killed. Thirty run against the whole test, all
killed. By the source check, twenty: each of the eight writers made `pub`
(for `update_admin_role_binding` the guard test too); a writer made `pub`
and re-exported `pub`, for the identity create, the append, the operation
insert and the binding update (their probes too); a public forwarder of
another name of the append and of the binding create in `registry/mod.rs`,
and of the binding update in `operator.rs` (the guard's diagnostic too);
the guard removed together with that forwarder (the guard test too); and a
new crate-visible caller, live from `app()`, of the binding create in
`registry/grant.rs`, of the append and of the operation insert in
`crate::operation`, and of the binding update in `registry/recovery.rs`
(the guard's diagnostic too). By the features check, one: the scenario
package enabling `test-support` through its `[dependencies]` entry. By the
diagnostics check, three: the registry's `test_support` compiled without
the feature (the binding update's expectation unfulfilled),
`bootstrap_instance` re-exported `pub(crate)` (dead code; with that check
off, the control probe), and PR 7's `create_version` made `pub` (the guard test too). By the
build check, one: the scenario library naming
`registry::test_support::append_audit_event`. By the layout refusal, three:
an indented `#[rustfmt::skip]` public forwarder of the binding create in
`bootstrap.rs`, a count-preserving one under its `use` block with that
`use` entry replaced by a path at the call, and the same in
`trust/keyset.rs` for the append. By the compiler, two: the append
re-exported `pub` while still `pub(crate)` (E0364), and a caller of the
identity create in `crate::operation`, outside the registry (E0603, the
effect of `pub(super)`). Nineteen more run with a check disabled, to show
which check carries a mutant; eight survive, each only with that check
disabled. With the source check off, a writer made `pub` but re-exported
as before (the identity create, the append, and, with the guard test off
too, the binding update) survives; that is equivalent in effect, since the
writer stays unreachable from outside the crate (a private module, a
restricted re-export) and, for the update, still dead without the
feature, and only the source check, which keeps the written visibility,
kills it. With the source check off, a public forwarder of the append or of
the binding create in `registry/mod.rs`, and a new caller of the binding
create in `registry/grant.rs`, survive: no probe can name a forwarder of
another name and those writers are live, so no diagnostic either; the
source check is what kills them. With the layout refusal off, the
count-preserving forwarder in `trust/keyset.rs` survives, and the one in
`bootstrap.rs` survives only with the diagnostics check off as well (in a
private module a `pub` forwarder is dead code, a warning, an accident of
where it sits). The other eleven are killed: the made-`pub`-and-re-exported
writers by their probes alone (and the binding update's by the guard
test); the binding update's forwarder and its new caller, and the guard
removed with a forwarder, by PR 7's diagnostic or the guard test with the
source check off; the indented forwarder after `claim_policy` by the count
check with the refusal off (its dead-code warning too); the
count-preserving one in `bootstrap.rs` by that dead-code warning alone with
the refusal off; and `bootstrap_instance` re-exported
`pub(crate)`, and `disable_admin_identity` made `pub(super)`, by the
control probe with the diagnostics check off.

Round 1 missed four mutants that passed the whole test, each a
count-preserving forwarder through which another crate could enroll a
`security_admin` binding or append an audit event: a public method of an
`impl NewAdminRoleBinding` nested in `bootstrap_steps` that calls the
binding create, the call rewritten to that method (the `impl` with
`allow(non_local_definitions)`); the same in `trust::keyset`'s
`append_stamped` for the append; and an alias in `bootstrap.rs`'s `use`
(`create_admin_role_binding as enroll_binding`) with the original name kept
in a trailing comment, or in a string literal, and a public forwarder of
the alias re-exported `pub`. The source check missed them because it keyed
a mention by the item in column 0 only, counted comments after code and
literals as mentions, and allowed aliases; the hardening above is the fix.
The review round's run: 111 mutants, round 1's forty-nine, PR 9's
thirty-eight ported to this tree, and twenty-four new; ninety-four killed.
With every check on, every one is killed but PR 9's accepted survivor, a
non-default feature of the scenario package that turns on `test-support`
(the release-build item under "Still open"). Of the new ones, the four
escapes and the alias split over two lines are killed by the new
refusals, and each new check holds on its own: with the refusal off, the
nested-`impl` key kills the two `impl` forwarders and the count, with
comments and literals removed, kills the three aliases; without its
`allow`, the nested `impl` draws `non_local_definitions`, which the
diagnostics check refuses. A `macro_rules!` that expands such an `impl`
from the writer's name passed to it, whose `impl` line names nothing, is
killed by that warning, or by the refusal when an `allow` of
`non_local_definitions` or `warnings` silences it (in the source, a
`cfg_attr` included, or in the package's `[lints]` table). A probe table
that names a module that does not exist (`operators`) fails the E0603
requirement. Seventeen survive: PR 9's accepted one, and sixteen each only
with a check disabled: the two
`impl` forwarders with the nested-`impl` key and the refusal both off; the
macro with the refusal off (with an `allow` of either lint); and round 1's
eight and PR 9's four, as before. What still escapes, by inspection and
not run: a lint level set outside the repository (a user's cargo
configuration, `RUSTFLAGS` in the build's environment) together with a
macro-expanded `impl`; code a procedural macro or a build script
generates (the library has neither, and `include!` is refused); a public
forwarder, under another name, of a caller one level up (`bootstrap_steps`,
`insert_pending`, `append_stamped` and the like), which the check does not
list, as it lists only the writers and the six trust steps; and whatever
the check's small lexer misreads, since it is not rustc's (a unit test
covers the cases it handles).

Still open after PRs 7, 9 and 10:

- Other registry writers that widen or change the security posture stay
  public, with no authorization, no gate and, but for the audited ones,
  no audit event. PR 9 surveyed them and changed none; PR 10 made the
  writers of rows 2, 6 and 7 below crate-private (marked done there; see
  "PR 10 as implemented"). The rest have no caller in the crate outside
  tests, so they would need PR 7's `expect(dead_code)` form; for
  `issue_recovery_challenge` and `restore_operator` see the open decision
  below, and `bootstrap_instance` has no in-crate caller either. Which of
  them to make crate-private, and in which PR, is the lead's to decide.
  The rank is the reviewer's, by the damage if the writer were wired to the
  wrong caller (nothing is wired today, and every one needs database write
  rights; provisional lead pick, 2026-11-23). Line numbers are PR 9's
  tree, under `service/src/persistence/registry/`; "test files" counts the
  integration and scenario test files that name the writer.

  | Rank | Writers                                                                                                                                                                                                                                                                                    | Where                                                                            | What they write                                                                                      | Callers in the crate, and why listed                                                                                                                                                                                                                                                                                                                                                                                                                                         |
  | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | 1    | `issue_recovery_challenge`, `restore_operator`                                                                                                                                                                                                                                             | `recovery.rs:925`, `:1032`                                                       | a replacement `security_admin`, every operator credential revoked, the recovery key replaced         | none outside tests; the registry verifies no signature (its module: the verifier does, before the restore), so a caller that issues a challenge and restores enrolls a `security_admin`; break-glass (T13.5), not a trust write; 4 test files each; see the open decision below                                                                                                                                                                                              |
  | 2    | `create_admin_identity`, `create_admin_credential`, `create_admin_role_binding`, `update_admin_role_binding`                                                                                                                                                                               | `operator.rs:586`, `:646`, `:716`, `:759`                                        | operators, their credentials and role bindings, `security_admin` included, and a binding's re-enable | **Done (PR 10):** the three creates `pub(super)` (callers `bootstrap_instance` and `restore_operator`, PR 9's form), the update `pub(super)` with PR 7's `expect(dead_code)` (no caller). Widen operator authority with no authorization and no audit event; not a trust write. Making the creates crate-private does not stop a caller enrolling a `security_admin` while `issue_recovery_challenge` and `restore_operator` stay public; 13 to 14 test files (9 the update) |
  | 3    | `bootstrap_instance`                                                                                                                                                                                                                                                                       | `bootstrap.rs:481`                                                               | the policy row, the recovery state and the first `security_admin`                                    | none outside tests; refuses once bootstrap is closed (`AlreadyClosed`); until then, whoever calls first enrolls the first `security_admin`; 10 test files                                                                                                                                                                                                                                                                                                                    |
  | 4    | `create_principal_binding`, `update_principal_binding`                                                                                                                                                                                                                                     | `grant.rs:162`, `:227`                                                           | which claims of a trust source map to a workload principal                                           | none; widen who is accepted, checked only for the required predicates; 10 and 6 test files                                                                                                                                                                                                                                                                                                                                                                                   |
  | 4    | `create_service_identity`, `update_service_identity`, `add_service_identity_resource_server`, `create_service_grant`, `update_service_grant`, `add_service_grant_binding`, `add_service_grant_resource_server`                                                                             | `grant.rs:265`, `:330`, `:371`, `:445`, `:528`, `:565`, `:635`                   | service identities, grants, and their binding and audience sets                                      | none; widen what an exchange may obtain; the database's guards (`0009`, `0010`) check consistency, not authority; 3 to 10 test files each                                                                                                                                                                                                                                                                                                                                    |
  | 4    | `create_resource_server`, `update_resource_server`, `create_audience_tenant_assignment`, `update_audience_tenant_assignment`, `create_resource_server_checker`, `update_resource_server_checker`, `add_resource_server_checker_tenant`, `create_resource_action`, `update_resource_action` | `audience.rs:47`, `:100`, `:124`, `:188`, `:211`, `:261`, `:290`, `:355`, `:410` | audiences, tenant assignments, checkers and their tenant sets, actions                               | none; an enabled assignment or a checker tenant admits a tenant to an audience; 1 to 7 test files each                                                                                                                                                                                                                                                                                                                                                                       |
  | 5    | `create_tenant`, `update_tenant`, `create_principal`, `update_principal`                                                                                                                                                                                                                   | `tenant.rs:38`, `:97`, `:121`, `:176`                                            | tenants and principals, a re-enable included                                                         | none outside tests; a re-enable widens; 22, 2, 13 and 1 test files                                                                                                                                                                                                                                                                                                                                                                                                           |
  | 6    | `append_audit_event`                                                                                                                                                                                                                                                                       | `events.rs:541`                                                                  | one chained audit event                                                                              | **Done (PR 10):** `pub(crate)`; every audited write (PR 9's form); widens no trust, but a caller can append a well-chained event of its choosing (the trail's integrity); 11 test files                                                                                                                                                                                                                                                                                      |
  | 7    | `insert_administrative_operation`, `consume_administrative_operation`, `revoke_administrative_operation`                                                                                                                                                                                   | `operation.rs:344`, `:382`, `:406`                                               | the gate's own operation rows                                                                        | **Done (PR 10):** `pub(crate)`; `crate::operation` (PR 9's form); write no target: an operation is applied only by `crate::operation`, whose apply steps are crate-private, and the `0005` guard checks the rows; 5, 1 and 1 test files                                                                                                                                                                                                                                      |
  | 8    | `create_trust_keyset`, `update_trust_keyset`                                                                                                                                                                                                                                               | `trust.rs:44`, `:97`                                                             | a keyset and its `status`                                                                            | none outside tests; section 1 does not classify a keyset's status (the ruling names version and source writes); 9 and 4 test files                                                                                                                                                                                                                                                                                                                                           |

  Not listed: `set_widening_second_approver` (`operation.rs:452`) is
  already `pub(crate)`; the egress allowlist and the instance policy have
  no public registry writer (`instance.rs` only reads); `consume_assertion`
  and `consume_assertion_set` only insert replay records; and
  `disable_admin_identity`, `revoke_admin_credential`,
  `remove_resource_server_checker_tenant` (`audience.rs:321`),
  `remove_service_identity_resource_server` (`grant.rs:399`),
  `remove_service_grant_binding` (`grant.rs:598`) and
  `remove_service_grant_resource_server` (`grant.rs:663`) only narrow.

- **Decided (the user, 2026-11-24, relayed by the lead; see
  docs/proposals/recovery-verified-response.md): the recovery writers.**
  The text below states the question as it stood. `issue_recovery_challenge` and `restore_operator`
  cannot simply be made crate-private. The design puts the
  deployment-local bootstrap and recovery verifier in the service binary
  (`skyoauth-service` subcommands, `service/src/main.rs`; design :666,
  :724; tasks :30, :84), and the binary is a crate of its own that uses
  the library as any other crate does. Two options: move the Ed25519
  signature check into the library, so that the library's own verifier is
  the writers' only caller (probably a new dependency); or make
  `restore_operator` take a "verified response" type that only the
  library's verifier can construct. Separately, `recovery.rs:22` says the
  signature check "belongs to the future operator crate"; the design
  docs give the workstation binary `skyoauth-operator` (`operator/`) the
  signing of the challenge only, and its verification to the service
  binary's local verifier (design :666, :723-724; tasks :84, :189-190), so
  that comment does not match them (not changed here).
- A release build must not pass `--all-features` or `test-support` (none
  exists yet; the PR that adds one owns it). A `compile_error!` cannot
  key on the profile: cargo exposes no profile `cfg`, and
  `debug_assertions` is only a proxy that would also refuse
  `cargo test --release`, so PR 7 adds none. The same rule covers a
  non-default feature of a workspace member that turns on
  `skyoauth-service/test-support` (a `[features]` entry in
  `tests/Cargo.toml`, say): `ungated_writes_private.rs` checks a build
  without features only, so such an entry passes it, and `--all-features`
  would turn it on (a PR 9 review mutant). A release build must not pass
  `--all-targets` either: with the test targets, cargo unifies the
  dev-dependencies' features into the one library build, so
  `cargo build --release --workspace --all-targets` builds the library
  with `test-support` (what `cargo tree -e features -i skyoauth-service`
  shows with the dev-dependencies and does not without them), and any
  dependent can enable the feature. The absence of the writers' symbols
  from a release binary is weak evidence (an unreferenced function is
  dropped, an inlined one leaves no symbol); the probes that compile a
  dependent crate against the library without the feature are the check.
- Decided (the user, 2026-11-24): `acknowledge_widening` applies to the
  toggle turned off; a toggle off without it gets `WideningNotAcknowledged`,
  like every other widening write. The library implements it; T13.3 wires it.

**Line numbers.** Line numbers into the code and the migrations README
refer to `f5adb74` (before PR 1), except the PR 4 row below, recomputed
after PR 1.

**Runtime sizing test.** The endpoint-wiring PR owns the runtime builder: it
pins `max_blocking_threads` headroom for both parse pools plus other blocking
work (sqlx's lookups, tokio's own) in a test. PR 1 documents the requirement
and checks only the worker counts against tokio's default blocking limit.

**What stays unwired.** The user ruled on Q1-Q7 and on the `0005`
trigger on 2026-11-23 (D1 to D29 otherwise stayed provisional lead picks;
since 2026-11-24 they are accepted as implementation choices that ordinary
review can change), so PRs 1 to
5 below may start; the lead says when. Until they land, no
endpoint calls `trust::keyset`, `trust::source` or the new functions, and
nothing wires them at startup (`mod.rs:18-19`). Even after the PRs below
merge, no endpoint lands before the request layer exists (generated IDs,
T10.2; the raw body bound; NUL rejection; the role of each endpoint;
T13.3); the read path of Q1 is ruled, but its endpoint waits for that
layer too. `disable_version` stays unwired with the rest.

**PR decomposition** (the coding session owns production code, migrations
and code comments; the test session owns tests, security scenarios, CI,
the harness and `docs/testing/conformance-layout.md`):

| PR  | Session | Content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | After   |
| --- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| 1   | coding  | the in-transaction permit (section 8), with tokio's `time` feature added to the non-dev dependency and the module docs' precondition marked done                                                                                                                                                                                                                                                                                                                                                   | —       |
| 2   | coding  | `persistence::registry::operation` (section 9), the policy row lock, `authorize_approval_locked`, `authorize_roles_locked`, `cancel` and `reject` in `AUDIT_ACTIONS`; the guard (ruled) and the index (provisional lead pick, not ruled) of section 11 merged into `0005` in place (no new file), with the README's `0005` text and the new names in `KNOWN_CONSTRAINTS`; a database created before must be recreated                                                                              | —       |
| 3   | coding  | `crate::operation`: digest, kinds, `prepare_approval`, `approve_operation`, `cancel_operation`, `reject_operation`, the toggle                                                                                                                                                                                                                                                                                                                                                                     | 2       |
| 4   | coding  | keyset kinds: `authorize_trust_admin` returning `Requester { admin_id, credential_id }`, `apply_*` split, D27 pre-validation if cheap, `submit_create_version`, `submit_enable_version`, the approve dispatch; the T14.1/T14.2 attribution and "the request layer of T14.1 and T14.2" corrected in `keyset.rs` (:24-28, :290-292), `source.rs` (:236-246) and the migrations README (:3131-3133, :3362-3363)                                                                                       | 1, 3    |
| 5   | coding  | source kinds: `Requester` from `authorize_trust_admin` (done in PR 4), `apply_*` split, D27 pre-validation, `submit_create_source`, `submit_update_source`, the full stored-row read; the disable-only classification as its add-on (Q2, ruled by the user, 2026-11-23); the tenant-path cancel's `NotFound` is done (PR 4). Implemented (see "PR 5 as implemented")                                                                                                                               | 3       |
| 6   | test    | tests for PRs 1 to 5 as each lands (section "Tests"), including the `0005` guard's tests and the `0005` catalog pins, the policy-row fixture, moving the trust tests of the gated path to `submit_*` (the tests of the ungated writes and their setup and race helpers stay on them through `trust::test_support`; see "PR 7 as implemented"), the A48 toggle legs                                                                                                                                 | each PR |
| 7   | coding  | the ungated entry points made crate-private (since review, `pub(super)`: private to `trust`), reached by the tests through the `test-support` feature. Implemented (see "PR 7 as implemented")                                                                                                                                                                                                                                                                                                     | 6       |
| 8   | test    | the test session's files: `conformance-layout.md` (the mapping below; the A04 paragraph's T14.1/T14.2 attribution and "ADR-008 item 12" wording, :180), `tests/conformance/README.md` (:7, both), `tests/security/a04.rs` (:132 the item-12 wording, :136 the attribution); no stage status change until a test claims it                                                                                                                                                                          | 6       |
| 9   | coding  | the bare registry trust writers (`create_trust_keyset_version`, `update_trust_keyset_version`, `create_trust_source`, `update_trust_source`) behind the same `test-support` mechanism at the registry layer, the tests and the scenario crate getting the feature through `[dev-dependencies]` (the lead's finding; provisional lead pick, 2026-11-23). Implemented (see "PR 9 as implemented")                                                                                                    | 7       |
| 10  | coding  | the operator writers (`create_admin_identity`, `create_admin_credential`, `create_admin_role_binding`, `update_admin_role_binding`), `append_audit_event` and the operation-row writers (`insert_administrative_operation`, `consume_administrative_operation`, `revoke_administrative_operation`) behind the same `test-support` mechanism, rows 2, 6 and 7 of the survey under "Still open" (the lead's assignment; provisional lead pick, 2026-11-23). Implemented (see "PR 10 as implemented") | 9       |

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
- A29 M1a (conformance-layout:142 and the A29 row of "Second-approver flow
  coverage", :204; T10.8): that stage is `implemented`. Its closed list in
  `tests/security/a29.rs` covers the composite foreign keys of `0004` and,
  since PR #121, the two `0005` guards
  `administrative_operation_approves_same_tenant` and
  `administrative_operation_revokes_same_tenant` (D15). An approve, or a
  revocation by a cancel, that names an operation of another scope is
  refused, tenant A↔B and instance↔tenant in both directions, by
  `a29_neg_approve_of_other_tenants_operation`,
  `a29_neg_approve_across_instance_and_tenant`,
  `a29_neg_revocation_by_other_tenants_operation` and
  `a29_neg_revocation_across_instance_and_tenant`, with the control
  `a29_pos_same_scope_approve_and_revocation_are_written`. The stage keeps
  its status and stamp. The revocation guard's INSERT leg (no public
  writer), `administrative_operation_approver_distinct` and the flow's own
  scope check (`NotFound` before a guard is reached) stay service tests.
  `consumed_assertion_trust_source_id_fkey` stays with A24. (a) and (b)
  of the review (an operation naming another tenant's audit event; a
  non-approve kind naming another tenant's operation) are refused by
  `0005` since its amendment of 2026-11-24 (the user's ruling, relayed by
  the lead; provisional): `administrative_operation_audit_same_tenant`,
  and the approval guard for every kind that names an operation, so the
  section 11 sketch's "Only kind 'approve'" now holds for the actor (its
  check and its read; README "What 0005 adds"). Both are on the list
  now, in both directions between the tenants and between the instance
  and each tenant: `a29_neg_operation_names_other_tenants_audit_event`,
  `a29_neg_audit_event_across_instance_and_tenant`,
  `a29_neg_other_kind_names_other_tenants_operation`,
  `a29_neg_other_kind_names_operation_across_instance_and_tenant` and
  `a29_neg_double_crossing_reports_the_approval_guard`, with the controls
  `a29_pos_same_scope_audit_event_and_named_operation_are_written` and
  `a29_pos_route_bundle_approval_by_its_preparer_is_written` (a
  `route_bundle_approval` by its preparer's actor is written).
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
expiry bound and read path are OQ-API-14, still open in the contract; Q1
(ruled by the user, 2026-11-23) settles them for this flow.
