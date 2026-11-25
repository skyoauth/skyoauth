# Proposal: a deployment-policy mirror write does not bump the policy revision

Status: proposal only, drafted 2026-11-25 for the lead's review and, where
marked, the user's decision. Nothing is implemented. The rule itself is
already a lead decision: "a mirror write must not bump the revision"
(tasks section 13, "Plan splits", `docs/skyoauth-tasks.md:1025`; lead
decision, 2026-11-24, changeable through ordinary review). This text
works it out: which columns it covers, what the database allows today,
the database change it needs, how the write is audited and what it must
be tested with. "(inferred)" marks a pick this text makes where the
sources are silent; every point that needs a lead or user ruling is in
"Open items". It changes no code, no migration and no contract. Line
numbers refer to `main` at `2dbad64`.

It answers the open point of
`docs/proposals/second-approver-gated-writes.md` ("Not decided here",
:1585-1587): "whether the IR-053 startup mirror of `single_actor_mode`
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
  `audit_sink_config_digest` and `audit_sink_validated_at` for the sink,
  and `audit_sink_validated_at` must correspond to the current digest
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
  `widening_second_approver` (same proposal, "Implementation notes", PR 3).
  `expected_revision` is immutable (`0005`,
  `service/migrations/0005_operator.sql:425-430`) and is covered by the
  `request_digest` (proposal section 2, "The digest"), so a pending
  operation can never be moved to a newer revision.
- **The check at approval.** The approve locks the policy row and calls
  `lock_policy_at(transaction, locked.expected_revision)`
  (`service/src/operation/approval.rs:527-528`), which returns
  `StaleRevision` when the row's revision differs
  (`service/src/operation/toggle.rs:67-79`). The compare-and-set then
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
protects nothing; it only costs an approval round. If the mirror writes
the row at every startup (for example, if `audit_sink_validated_at` is
refreshed by every startup's validation: not stated, see "Open items",
O4), every restart of the service, a rolling deploy included, makes every
pending toggle unapprovable.

Only the toggle is affected. The other gated kinds pin the revision of
their own target (a keyset version or a trust source; proposal section 2,
:211), and trust writes read the policy row only `FOR SHARE` to decide the
mode at the request
(`service/src/trust/write.rs:181-193`). `single_actor_mode` is read at the
request, not at the approve (`toggle.rs:253-254`; `write.rs:188`;
`approval.rs` does not read it). Tenant rows are not affected either: the
`tenant` table holds none of the mirrored values (`0002`, :69-77; `0007`
adds only `revision`), the tenant read model's `single_actor_mode` and
`widening_second_approver` are "server-provided mirrors of
`InstanceSecurityPolicy`" read from the policy row (public-api
:437, :454; tasks :140-141), and no gated kind targets a tenant row
(proposal section 2, :209).

## What the database allows today

- `instance_security_policy` (`0002`, :135-150) has `instance_id`,
  `widening_second_approver`, `single_actor_mode`,
  `audit_sink_config_digest`, `audit_sink_validated_at` and `revision`.
- Every UPDATE must set `revision` to `OLD.revision + 1`, whatever columns
  it changes; anything else is `SK001` (`skyoauth_check_revision()`,
  `0002`:46-62; trigger `instance_security_policy_revision`, :161-164,
  `ENABLE ALWAYS`, so also under `session_replication_role = replica`).
  The schema test
  `instance_security_policy_revision_advances_by_one_and_row_is_kept`
  (`service/tests/schema_foundation.rs:668-700`) pins this.
- So a mirror write that keeps the revision is refused by the database
  today. The rule needs a migration change.
- The database cannot tell the mirror from an operator write: "one
  database role serves both the online API and the startup mirror of
  deployment configuration" (`0002`:128-134), and IR-053's read-only rule
  is a service rule (`service/migrations/README.md:207-211`).
- Other triggers on the row are unaffected by the rule:
  `instance_security_policy_immutable` (`instance_id`, :155-159) and
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

| Column                     | Owner                                     | Source                                        |
| -------------------------- | ----------------------------------------- | --------------------------------------------- |
| `instance_id`              | immutable (bootstrap or a startup insert) | IR-057; `0002`:155-159                        |
| `widening_second_approver` | operator-owned: the only online write     | IR-052; public-api API-156                    |
| `single_actor_mode`        | mirrored                                  | IR-053; public-api :449 ("read-only mirrors") |
| `audit_sink_config_digest` | mirrored                                  | IR-053; public-api :449                       |
| `audit_sink_validated_at`  | mirrored                                  | IR-053; public-api :449                       |
| `revision`                 | moves only with an operator-owned write   | this rule                                     |

`widening_second_approver` is not mirrored from deployment configuration.
The word "mirror" is used for it only in the tenant read model, where both
booleans are read-only copies of the policy row (tasks :140-141;
public-api :454); that is a read path, not a write of the policy row.

A write that changes an operator-owned column is an operator write and
bumps the revision, even if a mirror path issued it. Under IR-053 no
operator write changes a mirrored column, so the two kinds of write touch
disjoint columns, and a single UPDATE that changes both is an error
(inferred; section 4).

### 3. The mirror write

(inferred, for the S8 PR)

- It runs in one transaction at startup: it locks the row
  `FOR NO KEY UPDATE` (the lock the toggle takes, proposal D19), compares
  the mirrored columns with the validated deployment configuration and,
  only if one differs, updates the differing columns and leaves
  `revision` as it is. With nothing different it writes
  nothing and appends no event. Its lock serializes with a trust write's
  `FOR SHARE` and with a toggle or approve, as any write of the row does.
- It appends its event after the row write, taking the audit head last,
  in the order the migrations README sets (`README.md:219-232`). It locks
  no tenant row (`tenant_id` is `NULL`).
- IR-053 places the mirror at startup. A periodic reconcile while running
  is not found in the sources; if S8 adds one, the same rule applies.

### 4. The database change

The pre-beta rule allows amending `0002` in place
(`service/migrations/README.md:30-44`). Proposed amendment (inferred
shape; names inferred): replace the function of the trigger
`instance_security_policy_revision` with a table-specific
`skyoauth_check_policy_revision()`, keeping the trigger name,
`BEFORE INSERT OR UPDATE`, `ENABLE ALWAYS` and the pinned `search_path`.
On INSERT it requires revision 1, as today. On UPDATE:

| The UPDATE changes                                 | `revision` must           |
| -------------------------------------------------- | ------------------------- |
| `widening_second_approver`, no mirrored column     | become `OLD.revision + 1` |
| one or more mirrored columns, not the operator one | stay `OLD.revision`       |
| both kinds                                         | refused (`SK001`)         |
| nothing                                            | become `OLD.revision + 1` |

The last row keeps today's same-value toggle working: "applied at once it
writes the same value at the next revision" (proposal "Implementation
notes", PR 3). It also makes a mirror that writes unchanged values without
a bump fail loudly, so a mirror cannot silently do a no-op UPDATE. The
database still cannot catch a mirror that writes unchanged values with a
bump, since that is indistinguishable from a same-value toggle; the
service test of section 6 covers it.

The amendment is a tripwire on the column split, not on who writes: the
role is shared (`0002`:128-134), so an UPDATE of `single_actor_mode` by any
caller passes as a mirror write, exactly as an online write of it passes
today. Keeping it out of the online API stays a service rule (IR-053).

Knock-on changes the amendment needs (from the tests that pin the
current shape): `schema_foundation.rs:668-700` keeps passing (its refused
UPDATE of `widening_second_approver` without a bump is still refused) and
gains the cases of section 6; the new function joins
`BUILTIN_ONLY_FUNCTIONS` (`schema_foundation.rs:190-194`), since it reads no
table (inferred). `REVISIONED` in `service/tests/schema_registry_shape.rs:227`
does not list the policy row, so its trigger-function assertion
(:640-690) is unaffected. The registry's module docs say every update
moves the row to `expected + 1` "as the `0002` guard requires"
(`service/src/persistence/registry/mod.rs:60-80`); that stays true for
every compare-and-set, and the mirror writer is not one.

### 5. Audit

A change of a mirrored value is audited: "the row mirrors it read-only and
a change emits an audit event" (tasks :465; IR-053; ADR-008 OQ-ADR008-3,
:206-215). The event shape is mostly fixed already:

- actor `{"type": "system", "id": "system"}` (IR-058, which names "the
  startup event of IR-053", :525-529);
- `tenant_id` `NULL` and `object_id` the `instance_id` (IR-057;
  `README.md:187-191`; OQ-IR-14, identity-registry :1006-1017);
- action `instance_security_policy.mirror` for `single_actor_mode` and
  `instance_security_policy.change_sink` for a sink change; both names are
  inferred and already in `AUDIT_ACTIONS`
  (`service/src/persistence/registry/event_actions.rs:12-15`, :94-98;
  identity-registry :570-574).

Picks (inferred):

- `previous_revision` and `new_revision` are both the row's unchanged
  revision, N and N. The README asks for "the row's real revisions before
  and after the write" (`README.md:187-191`); under this rule they are
  equal. A consumer of the chain then sees from the event itself that the
  write did not move the revision. (Alternative: both `NULL`; see O3.)
- One event per concern changed, in one transaction:
  `instance_security_policy.change_sink` when the digest changed, then
  `instance_security_policy.mirror` when `single_actor_mode` changed. A
  refresh of `audit_sink_validated_at` alone, with the digest unchanged,
  writes `instance_security_policy.mirror`, so every UPDATE of the row has
  an event (see O3 and O4).
- `outcome` `success` (inferred, as the other events; the value set is
  inferred).

The sink-changed record that IR-053 sends "first ... to the old sink" is
the external sink's, not a row write, and is outside this proposal.

### 6. The S2a and S8 split

- S2a is the egress allowlist writer only (tasks :1025;
  `docs/testing/conformance-layout.md:96`, :211). It has no mirror and
  writes no column of `instance_security_policy`; this rule does not
  touch it.
- S8 owns the deployment-policy mirror (tasks :1025). Its full scope is
  not found in the sources beyond that note and D7 ("taken after S8",
  tasks :1022). Inferred: the `0002` amendment lands in the S8 PR, so the
  rule and its only writer arrive together; until then nothing writes a
  mirrored column but bootstrap's insert of defaults
  (`bootstrap.rs:131-138`) and the conformance stand-in `seed_policy`,
  which inserts the row before bootstrap
  (`conformance-layout.md:96`). Neither is an UPDATE, so neither is
  affected. The stand-in is to be replaced by the mirror when it exists
  (same item).

## Tests

What the rule implies; the test session decides the files and names.

Database (`service/tests/schema_foundation.rs` style, in both
replication modes):

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
  with one.

Service (S8):

- a pending toggle at revision N survives a mirror re-sync that changes
  `single_actor_mode` or the sink: the row stays at N, and the approve then
  applies and moves it to N + 1;
- a mirror re-sync with nothing to change writes nothing: no UPDATE, no
  event, the revision unchanged;
- a mirror change writes the events of section 5: system actor, `NULL`
  tenant, the `instance_id`, previous and new revision both N, and a chain
  that still verifies;
- an operator toggle still bumps, and a second pending toggle at the old
  revision still gets `StaleRevision` at its approval (proposal section 5,
  :576; already covered by the A48 tests, kept);
- a mirror write and a toggle approve that run at once serialize on the
  row lock, and the approve applies whichever commits first.

## Alternatives considered

- **Keep bumping (status quo).** Every mirror change, and possibly every
  startup (O4), makes every pending toggle unapprovable, with no safety
  gain, since the toggle's plan does not depend on a mirrored column.
  Rejected; it also contradicts the lead decision (tasks :1025).
- **A separate mirror table.** The mirrored columns move to their own row
  (for example `instance_deployment_config`), and the policy row keeps
  `widening_second_approver` and `revision`. The generic revision trigger
  stays as it is. Rejected: it changes the logical model, which lists the
  mirrored fields on `InstanceSecurityPolicy` (tasks :465; second-approver
  proposal :79-81), and IR-053 and API-156, which say "the row mirrors
  it"; the readers that decide the mode from one row (`write.rs:181-193`,
  `toggle.rs:253-254`) and the trust writes' `FOR SHARE` lock would need a
  second row and lock; and the gain over a trigger amendment is small.
- **A separate `mirror_revision` column, excluded from the compare-and-set.**
  The mirror bumps `mirror_revision` and operator writes bump `revision`.
  It keeps mirror changes versioned, so a reader caching the row by
  revision sees them (O6). Not recommended now: it adds a column to the
  logical model, needs the same trigger amendment, and leaves the audit
  event's `previous_revision`/`new_revision` ambiguous between the two
  counters. It stays the fallback if the lead wants mirror changes
  versioned.
- **Version the plan on operator-owned columns only.** Keep the bump, and
  at approve compare the plan's target state (the current
  `widening_second_approver`) instead of the revision. Rejected: it breaks
  the uniform compare-and-set every write uses (public-api API-003; tasks
  :149, "rechecking revision and role"), the approver's echoed
  `expected_revision` would no longer name the current row, and a value
  compare misses an on-then-off sequence that the revision catches.
- **Rebase pending operations on a mirror write.** Rejected:
  `expected_revision` is immutable and inside the request digest (`0005`
  :425-430; proposal section 2).

The recommendation is the rule as stated with the `0002` trigger
amendment: one changed function, no new column or table, the revision
keeps one meaning (operator-owned state), and the database enforces the
column split as a tripwire.

## Open items

Each needs a ruling before or in the S8 PR. "Lead" means the lead may
rule; "user" means it goes to the user.

- **O1 (lead).** The database enforcement: the strict table of section 4
  (recommended), or a relaxed trigger that accepts `OLD.revision` or
  `OLD.revision + 1` on any UPDATE of this row (weaker: it no longer
  catches a mirror bump that changes a mirrored column, nor a combined
  write). Both amend `0002` in place.
- **O2 (lead).** Whether a combined UPDATE of an operator-owned and a
  mirrored column is refused (inferred here) or bumps.
- **O3 (lead).** The audit picks of section 5: equal previous and new
  revisions rather than `NULL`; one event per concern; an event for an
  `audit_sink_validated_at`-only refresh, which adds one event per startup
  if O4 is "every startup".
- **O4 (lead).** Whether every startup re-validates the sink and refreshes
  `audit_sink_validated_at` with an unchanged digest. IR-053 says
  "validated at startup"; whether the stored time moves at each startup is
  not stated. It decides how often the mirror writes.
- **O5 (user).** The sink parts of the mirror depend on D6, which "awaits a
  user decision on the audit sink's scope" (tasks :1022).
- **O6 (lead).** A reader that caches the policy row by `revision` (for
  example an operator client) no longer sees a mirror change through the
  revision. Accept, or take the `mirror_revision` fallback.
- **O7 (lead, for S8).** Not found in the sources: whether the mirror also
  runs after bootstrap inserts a row with defaults (bootstrap writes
  nothing to an adopted row, `bootstrap.rs:119-138`), and how replicas
  started with different deployment configurations during a rolling
  restart avoid writing the row back and forth. The rule keeps such writes
  from staling pending toggles, but each still appends events.

## Reconciliation

When accepted, the S8 PR (or a docs PR before it) updates:

- `docs/proposals/second-approver-gated-writes.md`, "Open", "Not decided
  here": the mirror point is answered here;
- `service/migrations/README.md`, the instance-scope events item
  (:187-199) and the service rules (:207-211), with the new trigger rule
  and the equal revisions;
- identity-registry IR-053, in the contract PR that also carries the
  pending API-152 wording (tasks :465), with one sentence that a mirror
  write keeps the row's revision;
- `docs/testing/conformance-layout.md:96`, when the mirror replaces
  `seed_policy`.
