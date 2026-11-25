# Proposal: a deployment-policy mirror write does not bump the policy revision

Status: reviewed; the rule is accepted. Drafted 2026-11-25 for the lead's
review; the review of the same day accepted the rule and took the picks
recorded under "Decisions" (O1 to O4, O6 and O7: lead decisions,
2026-11-25, changeable through ordinary review; none touches a user
ruling). O5 stays open for the user. Nothing is implemented: this text
changes no code, no migration and no contract. The rule itself was
already a lead decision: "a mirror write must not bump the revision"
(tasks section 13, "Plan splits", `docs/skyoauth-tasks.md:1025`; lead
decision, 2026-11-24, changeable through ordinary review). This text works
it out: which columns it covers, what the database allows today, the
database change it needs, how the write is audited, which existing tests
the change breaks and what it must be tested with. "(inferred)" marks a
pick this text makes where the sources are silent and the review did not
rule. Line numbers refer to `main` at `2dbad64`.

It answers the open point of
`docs/proposals/second-approver-gated-writes.md` ("Not decided here",
:1583-1587): "whether the IR-053 startup mirror of `single_actor_mode`
bumps the policy row's revision, which would leave every pending toggle
stale".

## Background

- **The mirror.** `single_actor_mode` and the audit sink configuration are
  instance deployment configuration, read-only online: "an online operator
  write MUST NOT change them. `single_actor_mode` is set at install, and
  the row mirrors it" (identity-registry IR-053, :430-458). A change is
  "applied at restart and recorded in an audit event at startup" (IR-053;
  confirmed by the user, 2026-11-24, ADR-008 item 12,
  `docs/adr/ADR-008-policy-writes.md:106-111`). The row holds only
  `audit_sink_config_digest` and `audit_sink_validated_at` for the sink;
  `audit_sink_validated_at` must correspond to the current digest, and "an
  endpoint that is present but failed validation ... is not configured"
  (IR-053). The mirror is the service writing those values from its
  deployment configuration into the `instance_security_policy` row. It
  does not exist yet (`service/src/persistence/registry/bootstrap.rs:131-138`;
  `service/src/persistence/registry/instance.rs:1-5`).
- **The only online write.** Turning `widening_second_approver` on or off
  "is the only online write to `InstanceSecurityPolicy`: an audited,
  revision-checked write" with a distinct second `security_admin`
  approver, or one actor when `single_actor_mode` is on (IR-052,
  :417-429; public-api API-156; tasks :147).
- **The pending toggle.** A gated toggle that is not applied at once is
  one `administrative_operation` row of kind
  `instance_security_policy_update` whose `expected_revision` is the
  policy row's revision at the request (second-approver proposal,
  section 2, :211). Its plan is exactly `requester_credential_id` and
  `widening_second_approver` (same proposal, "Implementation notes", PR 3,
  :1592). `expected_revision` is immutable (`0005`,
  `service/migrations/0005_operator.sql:425-431`) and is covered by the
  `request_digest` (proposal section 2, "The digest"), so a pending
  operation can never be moved to a newer revision.
- **The check at approval.** The approve locks the policy row and calls
  `lock_policy_at(transaction, locked.expected_revision)`
  (`service/src/operation/approval.rs:527-528`), which returns
  `StaleRevision` when the row's revision differs
  (`service/src/operation/toggle.rs:67-80`). The compare-and-set then
  sets `revision = revision + 1 ... AND revision = $2`
  (`service/src/persistence/registry/operation.rs:333-339`). A stale
  pending operation "stays pending and can never apply; the requester
  cancels it or it expires" (proposal section 5, :564).

## Problem

A worked example, with the database as it is today:

1. The policy row is at revision 7: `widening_second_approver` false,
   `single_actor_mode` false, a configured sink with digest `D1`.
2. `security_admin` A requests the toggle to true. `single_actor_mode` is
   off, so a pending `instance_security_policy_update` operation is
   stored with `expected_revision` 7.
3. Before a second `security_admin` approves, the service restarts with a
   changed sink configuration (digest `D2`). The mirror writes `D2` and a
   new `audit_sink_validated_at`. The `0002` trigger
   `skyoauth_check_revision()` refuses any UPDATE of the row that does not
   advance `revision` by exactly 1
   (`service/migrations/0002_foundation.sql:46-62`, attached to the row
   at :161-164), so the mirror must write revision 8.
4. `security_admin` B approves the operation. `lock_policy_at` reads
   revision 8 against the stored 7 and returns `StaleRevision`. The
   operation can never apply. A must cancel and request again, and B must
   approve a new operation.

Nothing operator-owned changed between steps 2 and 4: the plan holds only
`widening_second_approver`, which the mirror never writes. The refusal
protects nothing; it only costs an approval round. A mirror that wrote the
row at every startup would make every restart, a rolling deploy included,
turn every pending toggle unapprovable.

Only the toggle is affected. The other gated kinds pin the revision of
their own target (a keyset version or a trust source; proposal section 2,
:211), and trust writes read the policy row only `FOR SHARE` to decide the
mode at the request (`service/src/trust/write.rs:181-193`).
`single_actor_mode` is read at the request, not at the approve
(`toggle.rs:253-254`; `write.rs:188`; `approval.rs` does not read it).
Tenant rows are not affected either: the `tenant` table holds none of the
mirrored values (`0002`:69-77; `0007` adds only `revision`), the tenant
read model's `single_actor_mode` and `widening_second_approver` are
"server-provided mirrors of `InstanceSecurityPolicy`" read from the policy
row (public-api :437, :454; tasks :140-141), and no gated kind targets a
tenant row (proposal section 2, :209).

## What the database allows today

- `instance_security_policy` (`0002`:135-150) has `instance_id`,
  `widening_second_approver`, `single_actor_mode`,
  `audit_sink_config_digest`, `audit_sink_validated_at` and `revision`.
- Every UPDATE must set `revision` to `OLD.revision + 1`, whatever columns
  it changes; anything else is `SK001` (`skyoauth_check_revision()`,
  `0002`:46-62; trigger `instance_security_policy_revision`, :161-164,
  `ENABLE ALWAYS`, so also under `session_replication_role = replica`).
  The schema test
  `instance_security_policy_revision_advances_by_one_and_row_is_kept`
  (`service/tests/schema_foundation.rs:668-704`) pins this.
- So a mirror write that keeps the revision is refused by the database
  today. The rule needs a migration change.
- The database cannot tell the mirror from an operator write: "one
  database role serves both the online API and the startup mirror of
  deployment configuration" (`0002`:129-134), and IR-053's read-only rule
  is a service rule (`service/migrations/README.md:208-211`).
- Other triggers on the row keep their meaning:
  `instance_security_policy_immutable` (`instance_id`, `0002`:155-159) and
  `instance_security_policy_sink_validation` (a changed digest needs a
  `NULL` or later `audit_sink_validated_at`, :166-193).
- `audit_event.previous_revision` and `new_revision` are each only checked
  `>= 1` (`0002`:291-292); nothing relates them, so an event with both
  equal is accepted.

## Proposal

### 1. The rule

A mirror write changes only mirrored columns and keeps the row's
`revision`. It appends no ordinary revision-checked change: it is not a
compare-and-set on an expected revision, and no pending operation can go
stale because of it. The row's `revision` versions the operator-owned
state only, which is what a pending toggle's `expected_revision` pins.

### 2. Mirrored and operator-owned columns

| Column                     | Owner                                   | Source                                        |
| -------------------------- | --------------------------------------- | --------------------------------------------- |
| `instance_id`              | immutable; counts as operator-owned     | IR-057; `0002`:155-159                        |
| `widening_second_approver` | operator-owned: the only online write   | IR-052; public-api API-156                    |
| `single_actor_mode`        | mirrored                                | IR-053; public-api :449 ("read-only mirrors") |
| `audit_sink_config_digest` | mirrored                                | IR-053; public-api :449                       |
| `audit_sink_validated_at`  | mirrored                                | IR-053; public-api :449                       |
| `revision`                 | moves only with an operator-owned write | this rule                                     |
| any column added later     | operator-owned unless named as mirrored | O1                                            |

`widening_second_approver` is not mirrored from deployment configuration.
The word "mirror" is used for it only in the tenant read model, where both
booleans are read-only copies of the policy row (tasks :140-141;
public-api :454); that is a read path, not a write of the policy row.

A write that changes an operator-owned column is an operator write and
bumps the revision, even if a mirror path issued it. Under IR-053 no
operator write changes a mirrored column, so the two kinds of write touch
disjoint columns, and one UPDATE that changes both is refused (O2).

### 3. The mirror write

For the S8 PR (O4 and O7 are lead decisions; the rest inferred):

- **When.** The S8 startup path runs the mirror on every start, and the
  transaction commits before the service serves any admin write (O7). A
  service that cannot complete it does not serve admin writes (inferred:
  fail closed, since the row would not reflect the deployment).
- **No row yet.** If no policy row exists, the mirror inserts it at
  revision 1 with the configured values and a lowercase hyphenated
  UUIDv7 `instance_id` (the startup-path follow-up,
  `service/migrations/README.md:3386-3393`), audited as
  `instance_security_policy.create` (already in `AUDIT_ACTIONS`,
  `service/src/persistence/registry/event_actions.rs:95`). Bootstrap then
  adopts the row, per the lead's ruling of 2026-11-21 (identity-registry
  section 5.2, "Adopting the policy row", :249-272; `bootstrap.rs:119-138`).
- **A row exists.** The mirror locks it `FOR NO KEY UPDATE` (the lock the
  toggle takes, proposal D19), compares the mirrored columns with the
  deployment configuration and its validation, and, only if one differs,
  updates the differing columns and leaves `revision` as it is. With
  nothing different it writes nothing and appends no event. Its lock
  serializes with a trust write's `FOR SHARE` and with a toggle or approve,
  as any write of the row does.
- **Sink validation (O4).** The sink is validated at every startup. The
  mirror writes `audit_sink_validated_at` only when:
  - the digest changed: the validation time on success, `NULL` on failure;
  - the digest is unchanged and the stored time is `NULL`, and validation
    now passes: the validation time;
  - the digest is unchanged and validation now fails while the stored
    time is set: `NULL`, so a sink "present but failed validation" reads
    as not configured (IR-053).

  An unchanged digest that validates again is not written: no refresh, no
  event. If the clock has gone back, a changed digest with a time not
  later than the stored one is refused by the sink-validation trigger
  (`0002`:166-193) and startup fails closed (inferred). O4 depends on D6
  (see O5): if D6 rules the sink out of scope, it is moot.

- **Order.** The mirror appends its events after the row write, taking the
  audit head last, in the order the migrations README sets
  (`README.md:219-232`). It locks no tenant row (`tenant_id` is `NULL`).
- **Replicas (O7).** The last startup wins; every change it makes is
  audited. The service logs and exports a metric when its deployment
  configuration differs from the row (inferred names; the S8 PR names
  them). There is no fencing now. A consequence to record: one stray
  replica started with `single_actor_mode = true` turns single-actor mode
  on for the whole instance, until a startup with the intended
  configuration turns it off again. That follows from IR-053 trusting
  deployment configuration; the audit event and the mismatch metric are
  the detection.
- IR-053 places the mirror at startup. A periodic reconcile while running
  is not found in the sources; if S8 adds one, the same rule applies.

### 4. The revision no longer guards the mode a request runs in

Today a mirror change bumps the revision, so an operator who read the row
before a restart and then requests the toggle gets `StaleRevision`. Under
this rule the revision does not move, so the request passes
`lock_policy_at` and runs in the mode the row now holds: if a restart
turned `single_actor_mode` on, a requester who also holds `security_admin`
gets the toggle applied at once with outcome `success_single_actor`
instead of `StaleRevision`; if it turned the mode off, the request goes
pending instead of applying. This is not a safety regression: the mode is
read under the row lock taken by the request (`toggle.rs:253-254`;
`write.rs:181-193` for trust writes, which never pinned the policy
revision), so it is the committed configuration, and the approve never
consults it (`approval.rs` does not read `single_actor_mode`). The
outcome tells the requester which mode applied. A test must pin this
(see "Tests").

### 5. The database change

**The trigger (O1, O2).** Replace the function of the trigger
`instance_security_policy_revision` with a table-specific
`skyoauth_check_policy_revision()` (name inferred), keeping the trigger
name, `BEFORE INSERT OR UPDATE`, `ENABLE ALWAYS` and the pinned
`search_path = pg_catalog, pg_temp`. The mirrored column names are passed
as trigger arguments (`TG_ARGV`), and the function diffs `to_jsonb(OLD)`
and `to_jsonb(NEW)` as `skyoauth_reject_immutable_change()` does
(`0002`:20-44): every column other than the named mirrored ones and
`revision` counts as operator-owned, so a column added later cannot slip
through as unversioned. An argument that names no column is an error, as
in that guard. On INSERT it requires revision 1, as today. On UPDATE:

| The UPDATE changes                                  | `revision` must           |
| --------------------------------------------------- | ------------------------- |
| one or more operator-owned columns, no mirrored one | become `OLD.revision + 1` |
| one or more mirrored columns, no operator-owned one | stay `OLD.revision`       |
| both kinds                                          | refused (`SK001`)         |
| nothing                                             | become `OLD.revision + 1` |

The last row keeps today's same-value toggle working: "applied at once it
writes the same value at the next revision" (proposal "Implementation
notes", PR 3). It also makes a mirror that writes unchanged values without
a bump fail loudly. The database still cannot catch a mirror that writes
unchanged values with a bump, since that is indistinguishable from a
same-value toggle; a service test covers it (see "Tests").

The trigger is a tripwire on the column split, not on who writes: the
role is shared (`0002`:129-134), so an UPDATE of `single_actor_mode` by
any caller passes as a mirror write, exactly as an online write of it
passes today. Keeping it out of the online API stays a service rule
(IR-053).

**Mechanism and timing.** If S8 merges before the first tagged release,
`0002` is amended in place under the pre-beta exception
(`service/migrations/README.md:22-37`); after the first tag it is a new
migration that does `CREATE FUNCTION`, `DROP TRIGGER` and `CREATE TRIGGER`
for `instance_security_policy_revision`, then `ENABLE ALWAYS`. An in-place
amendment changes the checksum of `0002` (the checksum covers comments
too, README :22-25), so a database migrated from the earlier text fails
`migrate` with `VersionMismatch(2)` and is recreated, not migrated
(README :30-37). The same amendment updates the `0002` comments that
describe the old rule: `skyoauth_check_revision()`'s "every UPDATE
advances it by exactly 1" (:46-47) and the table comment on the shared
role and the startup mirror (:129-134).

### 6. Audit

A change of a mirrored value is audited: "the row mirrors it read-only and
a change emits an audit event" (tasks :465; IR-053; ADR-008 OQ-ADR008-3,
:206-216). The shape:

- actor `{"type": "system", "id": "system"}` (IR-058, which names "the
  startup event of IR-053", :525-527);
- `tenant_id` `NULL` and `object_id` the `instance_id` (IR-057;
  `README.md:187-191`; OQ-IR-14, identity-registry :1006-1017);
- `previous_revision` and `new_revision` both the row's unchanged
  revision, N and N (O3). `NULL` would contradict the README's "the row's
  real revisions before and after the write" (`README.md:187-191`) and
  OQ-IR-14, which records "the row's revisions before and after the
  write";
- one event per concern changed, in one transaction (O3):
  `instance_security_policy.change_sink` for any change of a sink column
  (the digest, the validation time, or both), and
  `instance_security_policy.mirror` only for a change of
  `single_actor_mode`, so `.mirror` stays the `single_actor_mode` event
  (`event_actions.rs:12-15`, :94-98; identity-registry :571-573). When both
  change, the order is `change_sink`, then `mirror` (inferred);
- `outcome` `success` (inferred, as the other events; the value set is
  inferred).

The sink-changed record that IR-053 sends "first ... to the old sink" is
the external sink's, not a row write, and is outside this proposal.

### 7. The S2a and S8 split

- S2a is the egress allowlist writer only (tasks :1025;
  `docs/testing/conformance-layout.md:96`, :211). It has no mirror and
  writes no column of `instance_security_policy`; this rule does not
  touch it.
- S8 owns the deployment-policy mirror (tasks :1025). Its full scope is
  not found in the sources beyond that note and D7 ("taken after S8",
  tasks :1022). Inferred: the database change of section 5 lands in the S8
  PR, so the rule and its only writer arrive together. Until then no
  service code writes a mirrored column: bootstrap inserts defaults
  (`bootstrap.rs:131-138`) and the conformance stand-in `seed_policy`
  inserts the row before bootstrap (`conformance-layout.md:96`). Neither is
  an UPDATE. The test helpers that UPDATE mirrored columns are listed
  under "Tests"; the stand-in is to be replaced by the mirror when it
  exists (same item).

## Tests

### Existing tests the trigger change breaks

The helpers below set mirrored columns by SQL. They are mirror stand-ins
and must not bump the revision. Each item names the test, where it
breaks and what changes. Line numbers verified at `2dbad64`.

`service/tests/schema_foundation.rs`:

1. `audit_sink_validation_belongs_to_the_current_digest` (:710-772). Every
   sink UPDATE carries `revision = revision + 1` (:720, :728, :739-744,
   :749-753, :768). Under the new trigger a mirrored change with a bump is
   `SK001`, and a `BEFORE` trigger fires before `CHECK` constraints, so
   the cases that expect `23514` from a `CHECK` (:720, :743, :744) would
   get `SK001` from the revision trigger instead, and the `SK001` cases at
   :739-742 would pass for the wrong reason (the revision, not the
   sink-validation guard). Drop the bump from every sink UPDATE so each
   case still tests its own guard; the widening UPDATE at :731-736 keeps
   its bump; the final revision at :763 becomes 2, not 6.
2. `update_guards_ignore_operators_on_the_callers_search_path`
   (:1266-1330). The setup UPDATE of `audit_sink_validated_at` (:1269-1275)
   bumps and would fail; drop the bump. The case at :1308 (digest change
   with a bump) would be refused by the revision rule rather than the
   sink-validation guard; drop its bump. The final revision at :1323
   becomes 1. See also the new cases below.
3. `assert_guards_hold` (:1476-1519), used by
   `foundation_guards_reject_forbidden_writes` (:1523) and
   `foundation_guards_hold_under_replica_role` (:1536), so two tests
   break. The case at :1502, `SET single_actor_mode = true` without a
   bump, is accepted under the new rule; it becomes
   `SET single_actor_mode = true, revision = revision + 1` (refused). The
   case at :1503 (digest change with a bump) would be refused by the
   revision rule; drop its bump so the sink-validation guard refuses it.

`service/tests/registry.rs`:

4. `instance_policy_and_egress_entries_are_read` (:1856). The UPDATE at
   :1875-1880 sets both sink columns with `revision = 2`; it becomes a
   non-bumping UPDATE, and the assertion at :1892 becomes revision 1.

`service/tests/operation_approval.rs`: the helper `single_actor_mode`
(:811-819, documented "policy revision 2") sets `single_actor_mode` with a
bump and would fail. It drops the bump and its comment becomes "policy
revision 1". Its six call sites break with it:

5. `single_actor_mode_applies_the_toggle_at_once` (:2210, call :2212):
   the hard-coded revisions `(2, true), (3, false)` and the event revisions
   (:2222-2245) shift down by one.
6. `under_single_actor_mode_turning_the_toggle_off_needs_the_acknowledgement`
   (:2502, call :2504): the hard-coded revisions (2, 3, 4, 5 in the
   requests, `written` and the events from :2506) shift down by one.
7. `the_acknowledgement_is_checked_after_the_authorization_before_any_lock_or_write`
   (:2560, call :2565): reads the revision, so only the helper fix.
8. `the_toggle_locks_the_policy_row_for_no_key_update` (:2653, call
   :2657): reads the revision; helper fix only.
9. `policy_writes_serialize_on_the_policy_row` (:2834, call :2862): reads
   the revision; helper fix only.
10. `policy_writes_behind_a_trust_write_do_not_deadlock` (:2900, call
    :2962): reads the revision; helper fix only.

`service/tests/keyset_approval.rs` and `service/tests/source_approval.rs`:
the helper `set_policy` (keyset :347-358, source :440-451) sets both flags
with a bump in ONE UPDATE. Whenever `single_actor_mode` changes, that is a
combined UPDATE with a bump, refused. It is split into two UPDATEs: the
operator part, `widening_second_approver` with `revision = revision + 1`
(always, so the revisions the tests expect do not move), then the mirror
stand-in, `single_actor_mode` without a bump and only
`WHERE single_actor_mode IS DISTINCT FROM $2`, since an UPDATE that
changes nothing must bump. The tests that change `single_actor_mode`
through it break until then:

11. keyset `the_mode_follows_the_policy_and_the_requesters_roles` (:1103,
    loop at :1108);
12. keyset `only_a_trust_admin_of_the_tenant_requests` (:1199, loop at
    :1205);
13. keyset `a_requesters_instance_binding_is_held_for_share` (:1304, call
    :1306);
14. source `a_disable_only_update_is_not_widening_and_lands_at_once`
    (:1471, loop at :1476);
15. source `the_mode_follows_the_policy_and_the_requesters_roles` (:1600,
    loop at :1604);
16. source `only_a_trust_admin_of_the_tenant_requests` (:1696, loop at
    :1701);
17. source `a_source_request_and_a_policy_toggle_serialize_on_the_policy_row`
    (:3166, calls :3170 and :3215).

Not affected: `instance_security_policy_revision_advances_by_one_and_row_is_kept`
(:668-704; its refused UPDATE of `widening_second_approver` without a bump,
:680, is still refused); `schema_operation_approval_guard.rs:1466-1479`
(`42501` before any trigger, and `instance_id` still `SK001`); the reset at
`operation_approval.rs:2733-2740` (an operator change with a bump); the
`set_policy` loops that keep `single_actor_mode` false (keyset :2251,
source :2122); `REVISIONED` in `service/tests/schema_registry_shape.rs:227`,
which does not list the policy row, so its trigger-function assertion
(:640-690) still holds.

### New tests

Database (`schema_foundation.rs` style, in both replication modes):

- an UPDATE of `single_actor_mode` that keeps the revision is accepted,
  and one that bumps it is refused with `SK001`;
- the same for `audit_sink_config_digest` with a later or `NULL`
  `audit_sink_validated_at`, and for `audit_sink_validated_at` alone; the
  sink-validation trigger still refuses a changed digest that keeps the
  old validation time;
- an UPDATE of `widening_second_approver` still needs exactly
  `OLD.revision + 1`;
- an UPDATE that changes `widening_second_approver` and a mirrored column
  is refused, with or without a bump;
- an UPDATE that changes nothing is refused without a bump and accepted
  with one;
- a column added to the table in the test (and not named as mirrored)
  counts as operator-owned: changing it without a bump is refused;
- a trigger argument that names no column is an error;
- the search-path shadowing test
  (`update_guards_ignore_operators_on_the_callers_search_path`, :1266)
  gains cases for the new function: with the caller's `=` shadowed, a
  mirrored change with a bump and an operator change without one are both
  still refused. The new function also joins `BUILTIN_ONLY_FUNCTIONS`
  (`schema_foundation.rs:190-194`), since it reads no table (inferred).

Service (S8):

- a pending toggle at revision N survives a mirror re-sync that changes
  `single_actor_mode` or the sink: the row stays at N, and the approve then
  applies and moves it to N + 1;
- a mirror re-sync with nothing to change writes nothing: no UPDATE, no
  event, the revision unchanged; an unchanged digest that validates again
  writes nothing (O4);
- a failed validation with an unchanged digest sets
  `audit_sink_validated_at` to `NULL`, keeps the revision and appends one
  `change_sink` event; the sink then reads as not configured;
- a mirror change writes the events of section 6: system actor, `NULL`
  tenant, the `instance_id`, previous and new revision both N, `.mirror`
  only for `single_actor_mode`, and a chain that still verifies;
- with no row, the startup inserts it at revision 1 with the configured
  values and an `instance_security_policy.create` event, and bootstrap
  adopts it;
- the mirror commits before the first admin write is served;
- a toggle requested at revision N after a restart turned
  `single_actor_mode` on applies at once with `success_single_actor`, and
  one after a restart turned it off goes pending (section 4);
- an operator toggle still bumps, and a second pending toggle at the old
  revision still gets `StaleRevision` at its approval (proposal section 5,
  :576; already covered by the A48 tests, kept);
- a mirror write and a toggle approve that run at once serialize on the
  row lock, and the approve applies whichever commits first.

## Alternatives considered

- **Keep bumping (status quo).** Every mirror change makes every pending
  toggle unapprovable, with no safety gain, since the toggle's plan does
  not depend on a mirrored column. Rejected; it also contradicts the lead
  decision (tasks :1025).
- **A relaxed trigger** that accepts `OLD.revision` or
  `OLD.revision + 1` on any UPDATE of this row. Rejected (O1): it no longer
  catches a mirror bump or a combined write, and it would also let an
  operator change of `widening_second_approver` keep its revision; the
  review showed that the refused case at `schema_foundation.rs:680`
  (`SET widening_second_approver = false` without a bump) is then
  accepted.
- **A separate mirror table.** The mirrored columns move to their own row
  (for example `instance_deployment_config`), and the policy row keeps
  `widening_second_approver` and `revision`. Rejected: it changes the
  logical model, which lists the mirrored fields on
  `InstanceSecurityPolicy` (tasks :465; second-approver proposal :79-81),
  and IR-053, which says "the row mirrors it"; the readers that decide the
  mode from one row (`write.rs:181-193`, `toggle.rs:253-254`) and the
  trust writes' `FOR SHARE` lock would need a second row and lock; and the
  gain over a trigger change is small.
- **A separate `mirror_revision` column, excluded from the compare-and-set.**
  The mirror bumps `mirror_revision` and operator writes bump `revision`,
  so a reader caching the row by revision would see mirror changes.
  Rejected (O6): no reader caches the row by revision (there is no ETag
  and no cache), it adds a column to the logical model, needs the same
  trigger change, and leaves the audit event's
  `previous_revision`/`new_revision` ambiguous between the two counters.
  It stays the fallback if a revision-keyed cache is ever added.
- **Version the plan on operator-owned columns only.** Keep the bump, and
  at approve compare the plan's target state (the current
  `widening_second_approver`) instead of the revision. Rejected: it breaks
  the uniform compare-and-set every write uses (public-api API-003; tasks
  :149, "rechecking revision and role"), the approver's echoed
  `expected_revision` would no longer name the current row, and a value
  compare misses an on-then-off sequence that the revision catches.
- **Rebase pending operations on a mirror write.** Rejected:
  `expected_revision` is immutable and inside the request digest (`0005`
  :425-431; proposal section 2).

The recommendation is the rule as stated with the trigger change of
section 5: one new function, no new column or table, the revision keeps
one meaning (operator-owned state), and the database enforces the column
split as a tripwire.

## Decisions (lead, 2026-11-25)

Lead decisions from the review of this proposal, changeable through
ordinary review; none touches a user ruling.

- **O1.** The strict trigger of section 5, hardened: every column other
  than the three mirrored ones and `revision` is operator-owned, by a
  jsonb diff with the mirrored names passed as trigger arguments. The
  relaxed variant is rejected; it would also let an operator change of
  `widening_second_approver` keep its revision
  (`schema_foundation.rs:680` would be accepted).
- **O2.** A combined UPDATE of an operator-owned and a mirrored column is
  refused (`SK001`), as a tripwire.
- **O3.** Previous and new revision both N (`NULL` contradicts
  `README.md:187-191` and OQ-IR-14); one audit event per concern;
  `instance_security_policy.change_sink` for any sink-column change, so
  `instance_security_policy.mirror` stays the `single_actor_mode` event
  only (`event_actions.rs:12-15`).
- **O4.** Taken after D6, and moot if D6 rules the sink out: validate the
  sink at every startup, but do not refresh `audit_sink_validated_at` when
  the digest is unchanged and validation passes; write it only when the
  digest changed (the validation time on success, `NULL` on failure) or it
  was `NULL` and validation now passes. A failed validation of an
  unchanged digest sets it to `NULL` (IR-053: "present but failed
  validation" is not configured).
- **O6.** Accepted: there is no ETag and no cache keyed on the policy
  row's revision, so a mirror change not moving the revision hides
  nothing. The `mirror_revision` column is not taken; it stays a rejected
  alternative and the fallback.
- **O7.** (a) The S8 startup path runs the mirror on every start, before
  serving; if no row exists it inserts it at revision 1 with the
  configured values (`instance_security_policy.create`), and bootstrap
  then adopts it (ruling of 2026-11-21). (b) The last startup wins, every
  change is audited, a log line and a metric report a mismatch between
  the configuration and the row, and there is no fencing now; a stray
  replica with `single_actor_mode = true` weakens the gate for the whole
  instance, which follows from IR-053 trusting deployment configuration.

## Open

- **O5 (user).** The sink parts of the mirror depend on D6, which "awaits
  a user decision on the audit sink's scope" (tasks :1022). O4 is taken
  on the assumption that the sink stays in scope; if D6 rules it out, the
  mirror covers `single_actor_mode` only and O4 is moot.

## Reconciliation

When accepted, the S8 PR (or a docs PR before it) updates:

- `docs/proposals/second-approver-gated-writes.md`, "Open", "Not decided
  here" (:1583-1587): the mirror point is answered here;
- `service/migrations/README.md`:
  - "What 0002 adds" (:109-114), which says `skyoauth_check_revision()`
    requires "exactly +1 on every update", with the policy row's own rule;
  - the instance-scope events item (:187-199), with the equal revisions;
  - the service rules (:208-211) and "check the expected revision of every
    write (compare and set)" (:214), with the mirror's exception;
  - "What 0007 adds", "Revisions" (:1517-1522), which says every revisioned
    table has a trigger on `skyoauth_check_revision()`;
- the `0002` comments at :46-47 and :129-134, in the same amendment as the
  trigger (section 5);
- `service/src/persistence/registry/mod.rs:64-70`, whose module docs say
  every update moves the row to `expected + 1` as the `0002` guard
  requires, with the mirror writer's exception;
- identity-registry IR-053, in the contract PR that also carries the
  pending API-152 wording (tasks :465), with one sentence that a mirror
  write keeps the row's revision;
- `docs/testing/conformance-layout.md:96`, when the mirror replaces
  `seed_policy`.
