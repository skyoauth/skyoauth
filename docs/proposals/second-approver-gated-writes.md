# Proposal: second-approver flow for widening trust writes

Status: proposal only, drafted 2026-11-23 for the lead's review agent and
then the user's acceptance. Nothing here is implemented: no migration, no
production code, no endpoint, and no T00.x box is ticked. Every choice below
that goes beyond the written spec is a "provisional lead pick, 2026-11-23"
(the Decisions list numbers them D1 to D18); "(inferred)" marks a point
where the spec is silent. All of them, and the lead decisions the spec
records, stay provisional until the maintainer ratifies the ADRs
(T00.8–T00.17, Gate M0); this text ratifies no ADR. The widening ruling it
builds on is the user's (2026-11-22, relayed by the lead), not a pick.

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
  logical model is tasks §3 (tasks:236-237 and tasks:377-380):

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
  rule for provider plan commits; this flow borrows only its "distinct
  second `adm_*` approver unless `single_actor_mode`" shape (ADR-008:98-99).
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
attribute it to "T14.1, T14.2" (`keyset.rs:24-28`, `source.rs:236-246`,
`service/migrations/README.md:3114-3116` and `:3333-3334`, ADR-008:220,
conformance-layout:180), but T14.1–T14.2 are the audience registry and the
IR-080 reference checks (tasks:533-534). The nearest owners are T13.3 (the
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
a source update, the stored row read under its lock. No caller input
decides it (ADR-008 item 12).

| Write                                                                                                                        | Widening | Basis                                                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------ |
| `create_version`, enabled or disabled                                                                                        | yes      | the ruling ("a create"); Q3                                                                            |
| `enable_version`, a re-enable and an enable of an already enabled version included                                           | yes      | the ruling ("an enable, a re-enable"); `keyset.rs:100-103` writes the latter like any other enable     |
| `disable_version`                                                                                                            | no       | not among the ruling's writes (`keyset.rs:34-35`); ADR-008 item 3                                      |
| `create_source`                                                                                                              | yes      | the ruling                                                                                             |
| `update_source` whose new `status` is `disabled` and whose every other mutable member equals the stored row's                | no       | ADR-008 item 3 by analogy; tasks:463 ("disabling is not widening" for an egress entry); (inferred); Q2 |
| any other `update_source`: an enable, a rename, a no-op, a disable that also changes a member, a change to a disabled source | yes      | the ruling; `source.rs:49-52` already treats a disable that changes a member as a change               |

So `classify_keyset_write` depends on the write kind only, and
`classify_source_update(stored, changes)` returns "not widening" exactly
when `changes.status == Disabled` and the other fourteen members of
`TrustSourceChanges` (`model.rs:937-953`) equal the stored ones. A finer
per-member diff (fewer audiences narrows, a new algorithm widens) is
rejected (D1).

**The flag.** A widening write must carry `acknowledge_widening = true`.
Without it the write is refused with `WideningNotAcknowledged`, whether
`widening_second_approver` is on or off, since IR-052 still asks for "the
widening flag, the expected revision and the atomic audit record" when it
is off (identity-registry:422-424). A flag on a write that is not widening
is accepted and ignored (D2).

**The mode** is decided inside the write's transaction, after the policy
row is locked (section 3), never by the caller:

| Widening | `widening_second_approver` | `single_actor_mode`                                        | Result                                                                    |
| -------- | -------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------- |
| no       | any                        | any                                                        | applied at once, as today                                                 |
| yes      | off                        | any                                                        | applied at once; flag, expected revision and audit event (IR-052)         |
| yes      | on                         | on, and the requester also holds instance `security_admin` | applied at once; the event's outcome records single-actor (section 6; Q4) |
| yes      | on                         | otherwise                                                  | a pending operation; the target is not written                            |

### 2. The pending operation

A pending gated write is one `administrative_operation` row, with no new
column (D3):

| Column                                    | Pending gated write                                                                                                                                              |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                                      | caller-generated (T10.2)                                                                                                                                         |
| `tenant_id`                               | the target's tenant; `NULL` for the toggle (README:956-957: the tenant of its audit event)                                                                       |
| `actor_id`                                | the requester's `admin_id`                                                                                                                                       |
| `kind`                                    | `trust_keyset_version_create`, `trust_keyset_version_enable`, `trust_source_create`, `trust_source_update` or `instance_security_policy_update` (inferred names) |
| `request_digest`                          | SHA-256 of the canonical request, 32 bytes (below)                                                                                                               |
| `expected_revision`                       | the target's revision: the version (an enable), the source (an update), the policy row (the toggle); 0 for a create (README:933)                                 |
| `immutable_plan`                          | the validated payload (below)                                                                                                                                    |
| `expires_at`                              | the request's `now` plus 24 hours (D5; OQ-API-14; Q1)                                                                                                            |
| `consumed_at`                             | set once, by the approve                                                                                                                                         |
| `revoked_at`, `revocation_operation_id`   | set once, together, by a cancel or a reject                                                                                                                      |
| `approves_operation_id`, `challenge_hash` | `NULL`                                                                                                                                                           |
| `outcome`                                 | `pending`, then `applied`, `cancelled` or `rejected` (inferred values; `outcome` and `revision` are the mutable columns, README:788-792)                         |
| `audit_id`                                | the `administrative_operation.create` event, inserted first                                                                                                      |

**The plan** (version 1, every member written by the server from typed
input, so it carries no member the caller chose):

- `trust_keyset_version_create`: `version_id`, `keyset_id`, `public_jwks`
  (the text of `ValidatedKeyset::public_json`, the canonical public
  projection, never the raw upload), `fingerprint`
  (`KeysetFingerprint::as_str`), `effective_at_us` and `expires_at_us`
  (whole microseconds since the epoch, floored as the writer floors them,
  `keyset.rs:104-112`; `expires_at_us` may be `null`), `status`, and
  `provenance` as its canonical JSON text (a string).
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
C = canonical JSON of {"expected_revision": <i64>, "kind": <kind>,
                       "plan": <plan>, "tenant_id": <id> | null}
```

`C` has its members sorted byte-wise, no insignificant whitespace,
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
exactly; recomputes the digest from the stored kind, tenant, expected
revision and plan and compares it with the stored digest (a mismatch is a
data-integrity error); and at the write compares the target's current
revision with `expected_revision` through the module's own check, so a
target that moved is `StaleRevision`.

**Expiry** is derived: an operation with `now >= expires_at` and no
`consumed_at` is expired, and nothing writes it (no job). The `0005` check
`consumed_at < expires_at` backs the approve's own check.

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
`success`, no expiry.

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
   (`authorize_roles_locked`, section 8).
3. A keyset write with the flag unset is refused here
   (`WideningNotAcknowledged`): its class depends on the kind only.
4. The `instance_security_policy` row `FOR SHARE` (new; D10). A missing
   row is `PolicyUnavailable` (D18). `disable_version` skips this step and
   step 7: its class is fixed.
5. The module's own locks and reads, unchanged: the parent `trust_keyset`
   `FOR NO KEY UPDATE` (`keyset.rs:181-185`) and its reads; or the
   `trust_source` row `FOR NO KEY UPDATE` (`source.rs:123-129`), now
   reading every mutable column, not only the destinations.
6. A source update: classify; with the flag unset and the class widening,
   `WideningNotAcknowledged`.
7. The module's checks, unchanged: the cap of 8 and the overlap check (on
   the in-transaction pool, section 7); the syntax of changed members and
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

So a request runs every check the direct write runs (D7): the requester
learns of a refusal at once, and an approver never reviews a request that
was already invalid.

**Approve** (`prepare_approval`, then `approve_operation`):

1. Outside any transaction, `prepare_approval` reads the operation row
   without a lock. For `trust_keyset_version_create` it parses the plan's
   `public_jwks` in full on the Stage A pool (`validate_keyset` with
   `KNOWN_ALGORITHMS`, as `keyset.rs:567-571` parses a stored set) and
   checks its fingerprint against the plan's. It returns the digest it
   read and the `ValidatedKeyset`, so no lock is held while the payload
   is parsed.
2. Step 0. Then, without a lock: the approver's lookup (an instance
   `security_admin`; a miss is `Unauthorized`, before anything about the
   operation is read), and the operation's immutable `tenant_id`,
   `actor_id` and `kind`. An operation outside the path's scope (another
   tenant, a tenant operation on the instance path or the reverse) is
   `NotFound`; an approver whose `admin_id` is the `actor_id` is
   `SelfApproval`.
3. The operator rows of both actors `FOR SHARE`, in the `0005` order
   (`authorize_approval_locked`, section 8): the two `admin_identity` rows
   by ID, the approver's `admin_credential`, then the approver's
   `security_admin` binding and the requester's role binding for the kind
   (tenant `trust_admin`, or instance `security_admin` for the toggle) by
   ID, then the lookups repeated as `authorize_operator_locked` does
   (`operator.rs:160-172`). A requester who lost the role is
   `RequesterNotAuthorized` (Q5).
4. The operation row `FOR NO KEY UPDATE`, read again: consumed, revoked,
   expired (`now >= expires_at`) or not an approvable kind is
   `NotApprovable` with its reason; a digest or expected revision unequal
   to the echo, or a digest unequal to the one `prepare_approval` read, is
   `EchoMismatch`; a recomputed digest unequal to the stored one is
   `PlanIntegrity`.
5. The write's own steps for the kind, from the plan: steps 2 to 6 of
   `keyset.rs:178-202` (the parent lock, the target read and revision, the
   cap, the overlap check of the stored versions on the in-transaction
   pool, the insert or compare-and-set), or steps 2 to 4 of
   `source.rs:123-152` (the source row and revision, the class, the syntax
   of changed members, the entries `FOR SHARE`, the insert or
   compare-and-set). For the toggle: the policy row `FOR NO KEY UPDATE`
   and its compare-and-set. The policy row is not read for a trust kind:
   an approval stays valid if the toggle went off meanwhile (inferred).
6. Last, through `append_audit_event` (so the head is taken here):
   `administrative_operation.approve`, the approve operation insert, the
   domain event, and the update of the pending row (`consumed_at = now`,
   `outcome = 'applied'`, revision + 1), whose row step 4 already holds,
   so it does not wait (README:1042-1046).

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
revocation order exactly (README:1042-1046).

**The toggle** (`submit_widening_toggle`) follows the request steps with
the policy row as target: instance `security_admin`, the policy row
`FOR SHARE` and its revision, then either the compare-and-set and
`instance_security_policy.update` (`single_actor_mode` on) or a pending
`instance_security_policy_update` operation, approved on the instance path
by a distinct `security_admin` (API-156). It is always gated, whatever the
toggle's current value (ADR-008:100-105). `single_actor_mode` and the sink
fields stay unwritable online (IR-053).

### 4. What is checked again at approve, and what is not

| Checked again at approve                                                                                                                             | Taken from the request, bound by the digest                                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| the approver's `security_admin` role, enabled identity and credential (tasks:149: "rechecking revision and role")                                    | the payload itself: the projection, window, status and provenance; the source members            |
| the approver is not the requester; the requester still holds the kind's role (Q5)                                                                    | the upload's Stage A validation against the request's `allowed` algorithms (`keyset.rs:550-563`) |
| the operation is pending, unexpired, unrevoked, of an approvable kind; the echo; the recomputed digest                                               | the class: recomputed, and at an unchanged revision it is the same                               |
| the projection, parsed in full again before the transaction, and its fingerprint                                                                     |                                                                                                  |
| the target's revision; for a keyset, the parent lock, the cap of 8, the full parse of every compared stored version and the overlap check, all again |                                                                                                  |
| for a source, the syntax of changed members, the egress entries `FOR SHARE`, the `0004` kind checks and the `0011` guard                             |                                                                                                  |
| the provenance private-member check (pure, cheap)                                                                                                    |                                                                                                  |

### 5. Races and failures

| Between request and approve                                            | At approve                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a direct write (a disable, another update) moves the target's revision | `StaleRevision`; the operation stays pending and can never apply; the requester cancels it or it expires                                                                                                                                                                |
| a concurrent disable runs while the approve holds the target           | they serialize on the `trust_keyset` or `trust_source` row; the second sees the first's revision                                                                                                                                                                        |
| an egress entry the change needs is disabled                           | `EgressNotAllowed` (the service's entry check, `source.rs:509-532`). If the service check were skipped, the `0011` trigger `trust_source_egress_enabled` refuses the write with `23514`, `Invariant { kind: EgressEntryEnabled }` (README "What 0011 adds", :2136-2150) |
| an entry disable starts while the approve holds the entry `FOR SHARE`  | the disable waits for the approve's commit; the source is then degraded at fetch (`source.rs:178-188`)                                                                                                                                                                  |
| another version was enabled and now overlaps                           | `Overlap`; after that version is disabled, a new approve of the same operation passes                                                                                                                                                                                   |
| the keyset reached 8 enabled versions                                  | `TooManyEnabledVersions`                                                                                                                                                                                                                                                |
| a version with the plan's `version_id` now exists                      | `AlreadyExists` (the insert's `23505`)                                                                                                                                                                                                                                  |
| the parent keyset was disabled                                         | written like any other (`keyset.rs:269-270`, inferred: the verifier reads the keyset's status)                                                                                                                                                                          |
| two approvers approve at once                                          | they serialize on the operation row; the second reads it consumed: `NotApprovable(Consumed)`                                                                                                                                                                            |
| a cancel and an approve race                                           | the same row lock; whichever is second gets `NotApprovable`                                                                                                                                                                                                             |
| the toggle went off                                                    | the approve still applies (an approval is never less safe); the requester may cancel and submit again                                                                                                                                                                   |
| the toggle went on while a direct widening write was in flight         | the write holds the policy row `FOR SHARE` from step 4 to its commit, so the toggle's compare-and-set waits; a write that reaches step 4 after the toggle committed reads it on and goes pending                                                                        |
| the approver's credential was revoked or the requester's role disabled | `Unauthorized` or `RequesterNotAuthorized`                                                                                                                                                                                                                              |
| the operation expired                                                  | `NotApprovable(Expired)`; the `0005` check refuses a consume at or after `expires_at` even if the service check were skipped                                                                                                                                            |
| the commit outcome is unknown to the approver's client                 | a retried approve reads the operation consumed; the client reads the target                                                                                                                                                                                             |

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
  item 15; OQ-API-15, public-api:729-736). `approve_operation` refuses any
  kind outside its five (`NotApprovable(WrongKind)`), an
  `operator_restoration` challenge included.

### 7. Audit trail

| Step                     | Events, in chain order                                                                                                                                                 | Outcome                                   |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| request, pending         | `administrative_operation.create`, actor the requester, `object_id` the operation, new revision 1                                                                      | `success`                                 |
| request, applied at once | the module's event as today (`trust_keyset_version.create`, `.enable`, `trust_source.create`, `.update`, `instance_security_policy.update`)                            | `success`, or `success_single_actor` (Q4) |
| approve                  | `administrative_operation.approve` (actor the approver, `object_id` the pending operation, revisions 1 and 2), then the module's event (actor the requester, as today) | `success`                                 |
| cancel, reject           | `administrative_operation.cancel` or `administrative_operation.reject` (actor the canceller or rejecter, `object_id` the pending operation, revisions 1 and 2)         | `success`                                 |
| expiry                   | none (derived)                                                                                                                                                         |                                           |

`administrative_operation.create` and `.approve` are in `AUDIT_ACTIONS`
already (`event_actions.rs:24-31`, `:71-72`); `.cancel` and `.reject` are
new (inferred verbs; IR-059 fixes only the syntax). A consumer joins an
event's `object_id` to the operation row to read its `kind` and plan, as
for recovery challenges. The domain event keeps the requester as actor:
the change is the requester's, and the approval is the adjacent event.

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
  releases the parent lock.
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

/// Read without a lock and parsed outside any transaction.
pub struct PreparedApproval { /* operation ID, digest read, kind, payload */ }

#[non_exhaustive]
pub enum Applied {
    KeysetVersion(TrustKeysetVersion),
    Source(TrustSource),
    InstanceSecurityPolicy(InstanceSecurityPolicy),
}

pub async fn prepare_approval<'e>(
    executor: impl PgExecutor<'e>,
    scope: ApprovalScope<'_>,
    operation_id: &str,
) -> Result<PreparedApproval, ApprovalError>;

pub async fn approve_operation(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    ids: &ApprovalIds<'_>,
    now: SystemTime,
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
/// The policy row `FOR SHARE`; `NotFound` before bootstrap.
pub async fn lock_instance_security_policy_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstanceSecurityPolicy, RegistryError>;
pub async fn authorize_approval_locked(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    requester_admin_id: &str,
    requester_scope: OperatorScope<'_>,
    requester_role: AdminRole,
) -> Result<ApprovalAuthority, RegistryError>;
pub async fn authorize_roles_locked(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    roles: &[(OperatorScope<'_>, AdminRole)],
) -> Result<Option<RolesHeld>, RegistryError>;
```

`create_version`, `enable_version`, `create_source` and `update_source`
become the ungated steps that `submit_*` and `approve_operation` call. They
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
  client error); `PolicyUnavailable`; `UnsupportedIsolation`;
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
CREATE TRIGGER administrative_operation_revocation_check
    AFTER UPDATE OF revocation_operation_id ON administrative_operation
    FOR EACH ROW WHEN (NEW.revocation_operation_id IS NOT NULL)
    EXECUTE FUNCTION skyoauth_check_operation_revocation();
-- Raises 23514 naming administrative_operation_revokes_same_tenant.

-- The approver's read path (OQ-API-14): open operations of a tenant.
CREATE INDEX administrative_operation_open_by_tenant
    ON administrative_operation (tenant_id, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
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
2. the `instance_security_policy` row `FOR SHARE` (new);
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
   identities by ID, the approver's credential, the bindings by ID;
2. the pending operation row `FOR NO KEY UPDATE` (`administrative_operation`
   is the fifth `0005` table, README:1030-1032);
3. the module's rows, as request step 3 (for the toggle, the policy row
   `FOR NO KEY UPDATE`);
4. the registry write;
5. the audit head, last: the approve event, the approve operation insert,
   the domain event, then the update of the pending row, locked in step 2.

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
(`source.rs:153-158`); only the inserts that need the head and the update of
the already locked pending row come after it.

No new cycle: the toggle locks no trust row and takes the policy row before
the head; two approvals of one operation serialize on its row; an approval
and a direct write of one target serialize on the target row; an approval
and an entry disable behave as a direct update does (`source.rs:178-188`).
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
- `now` is the caller's clock, as for every write here; the table has no
  creation time, so the 24-hour bound is the service's rule, not the
  database's (README:958-959 asks only for an expiry).
- The `0012` guard, if accepted, is a tripwire against application DML,
  not a security boundary (README "Limits"); it cannot check roles or the
  digest.
- Rows are never deleted (`administrative_operation_no_delete`, `0006`):
  expired and revoked operations stay, with their public plans, readable
  by auditors.
- Not covered here, though the same machinery applies: binding and grant
  writes and deletes (tasks:151-152; A37), and the egress entry writer,
  whose add and re-enable are widening-class (IR-052; tasks:148); none has
  a service write path yet.

## Tests

The implementation PRs must have (owned by the test session; section
"Implementation notes"):

- **Machinery.** A pending insert writes `administrative_operation.create`
  first, outcome `pending`, `expires_at` now + 24 h, and a digest equal to
  its recomputation from the stored row; an approve by a distinct
  `security_admin` writes the approve operation, the events in the order
  above, `consumed_at` and outcome `applied`.
- **Refusals.** Self-approval by an operator holding both roles; an
  approver with only `trust_admin`; a revoked approver credential; a digest
  one byte off, of another length, and an expected revision off by one;
  expiry at exactly `expires_at` and one microsecond before (injected
  clock); consumed, revoked, wrong kind (a recovery challenge's ID);
  another tenant's operation on a tenant path, a tenant operation on the
  instance path and the reverse (`NotFound`); a requester whose role was
  disabled (Q5); a cancel by another `trust_admin`; a cancel after consume.
- **Races** (two connections, both commit orders): two approves; approve
  and cancel; approve and a direct write of the target; the toggle and a
  direct widening write (policy row `FOR SHARE`); approve and an entry
  disable; none ends in `40P01`.
- **Classification.** Every row of the table in section 1, both values of
  the flag, the toggle off and on, `single_actor_mode` off and on.
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
  binding insert does not wait); a disable-only update is applied at once
  while the toggle is on.
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
`FOR SHARE` (the toggle race); a create classified as not widening; the
approve's overlap check skipped; the in-transaction parse moved back to
the Stage A pool.

## Decisions (provisional lead picks, 2026-11-23)

1. **D1.** **Classification is computed** from the write kind and, for a source
   update, the stored row; only a pure disable of a source and
   `disable_version` are not widening. Rejected: a caller flag that decides
   (ADR-008 item 12 forbids it); a per-member widening and narrowing diff
   of sources (error-prone over fourteen members, and the ruling counts
   every source write).
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
7. **D7.** **Two transactions with the full checks in both.** Rejected: checks
   at the request only (the state moves); at the approve only (late refusals,
   and approvers review invalid requests); one transaction spanning the
   approval (impossible across requests, and it would lock the target for
   hours).
8. **D8.** **No hold on the target** between request and approve. Rejected: a
   pending marker that blocks other writes (a requester could freeze a
   source, and a disable must stay immediate).
9. **D9.** **Registry write before the head** in the approve; the declared lock
   order. Rejected: the README's by-name order for the egress entry (it
   would differ from the direct update of the same source).
10. **D10.** **The policy row `FOR SHARE`** in every widening request.
    Rejected: an unlocked read (a widening write could commit unapproved just
    after the toggle went on).
11. **D11.** **Roles** as in section 6: a distinct instance `security_admin`
    approves; a tenant operation only on its tenant path; the requester's
    role is checked again (Q5); single-actor needs `security_admin` too
    (Q4).
12. **D12.** **Audit**: the events of section 7, the requester as the domain
    event's actor, the new verbs `cancel` and `reject`, outcome
    `success_single_actor`, no fingerprint member (Q6). Rejected: an
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

## Resolved

Decided before this proposal and used as given: the widening ruling for
keyset versions and sources (the user's, 2026-11-22); the server's
detection and the flag (ADR-008 item 12, OQ-ADR008-3, OQ-ADR016-2); the
wire shape of the approve endpoints (OQ-API-13); the approver role (IR-054);
the IR-152 egress backstop (`0011`, README "What 0011 adds"); soft disable
as fail-safe for bindings and grants (ADR-008 item 3).

## Open

Questions for the user, each with the recommended answer:

1. **Q1.** **Expiry and read path (OQ-API-14).** Recommended: a fixed 24-hour
   `expires_at`; `GET /admin/v1/tenants/{tenant}/operations/{operation}`
   and a list of open operations (and the instance twins), readable by
   instance `security_admin`, the requester and the tenant `auditor`,
   returning the plan, digest, expected revision and expiry.
2. **Q2.** **Is a disable-only source update widening?** The ruling says "a
   trust source write". Recommended: not widening, like a soft disable of a
   binding or grant (ADR-008 item 3), so a source can be shut off at once
   while the toggle is on.
3. **Q3.** **Is a disabled keyset version create widening?** It makes no key
   live. Recommended: yes, as the ruling's text says; the cost is one approval
   for a create-then-enable, and the rotation path creates enabled anyway.
4. **Q4.** **Under `single_actor_mode`, must the one actor also hold
   `security_admin`?** Recommended: yes; a `trust_admin` without it gets a
   pending operation that a `security_admin` approves.
5. **Q5.** **Is the requester's role checked again at approve?** The spec
   names the approver's role only (public-api:451). Recommended: yes; a
   requester who lost `trust_admin` should not have a change applied in their
   name.
6. **Q6.** **A fingerprint in the audit event?** Recommended: no, for now; the
   plan and the version row hold it, and an envelope member is an ADR-level
   change to the IR-056 hash input.

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

| PR  | Session | Content                                                                                                                                                                                                         | After   |
| --- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| 1   | coding  | the in-transaction permit (section 8), with the module docs' precondition marked done                                                                                                                           | —       |
| 2   | coding  | `persistence::registry::operation` (section 9), the policy row lock, `authorize_approval_locked`, `authorize_roles_locked`, `cancel` and `reject` in `AUDIT_ACTIONS`; `0012` and its README section if accepted | —       |
| 3   | coding  | `crate::operation`: digest, kinds, `prepare_approval`, `approve_operation`, `cancel_operation`, `reject_operation`, the toggle                                                                                  | 2       |
| 4   | coding  | keyset kinds: classification, `submit_create_version`, `submit_enable_version`, the approve dispatch; the T14.1/T14.2 attribution corrected in `keyset.rs`, `source.rs` and the migrations README               | 1, 3    |
| 5   | coding  | source kinds: classification, `submit_create_source`, `submit_update_source`, the full stored-row read                                                                                                          | 3       |
| 6   | test    | tests for PRs 1 to 5 as each lands (section "Tests"), the policy-row fixture, moving the trust tests to `submit_*`, the A48 toggle legs                                                                         | each PR |
| 7   | coding  | the ungated entry points made crate-private                                                                                                                                                                     | 6       |
| 8   | test    | `conformance-layout.md` and the registry text: the mapping below and the A04 paragraph's attribution; no stage status change until a test claims it                                                             | 6       |

The lead decides who corrects ADR-008:220, which repeats the T14.1/T14.2
attribution.

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
- A29 M1a (conformance-layout:141; T10.8): add "an approval, cancel or
  reject of another tenant's operation" to its closed list of crossings,
  as T10.8 requires for a new tenant-owned crossing.
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
