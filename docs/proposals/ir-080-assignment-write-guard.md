# Proposal: database guard for IR-080 assignment references (T14.2)

Status: accepted; implementation pending (ruled by the user, 2026-11-22,
relayed by the lead). The acceptance includes reversing the migrations README
rule for these two tables (see "Open" below), and the same trigger pattern is
also to guard the IR-152 egress check (`trust_source` destinations against
`egress_allowlist_entry`). No migration and no code yet. Before that ruling
the status was "proposal only", with all picks provisional, dated 2026-11-21,
until the maintainer decides. Picks marked "(inferred)" are the coding
session's reading; picks marked "lead" are lead rulings of the same date, and
they stay provisional until the maintainer ratifies the ADRs (Gate M0).

## Problem

IR-080 requires that a service identity or grant reference a resource server
only through an active same-tenant assignment, and the task T14.2 checks this
at write time. The tables `service_identity_resource_server` and
`service_grant_resource_server` reference the assignment through a composite
foreign key `(tenant_id, resource_server_id)` to `audience_tenant_assignment`
(migration `0004`). The foreign key proves the assignment exists. It does not
prove it is enabled.

A check-then-insert above the registry ("read the assignment, see `enabled`,
insert the row") races. The foreign key check takes `FOR KEY SHARE` on the
assignment row, and `FOR KEY SHARE` does not conflict with an `UPDATE` of
`status`, which is not a key update. So a disable can commit between the check
and the insert, and the row then references a disabled assignment, with no
error from the database.

## Proposal

Two `BEFORE INSERT` triggers, one per table (names inferred, for example
`service_identity_resource_server_assignment_active` and
`service_grant_resource_server_assignment_active`):

- `ENABLE ALWAYS`, pinned `search_path = pg_catalog, pg_temp`, `SECURITY
INVOKER` like the other guards, so a writer needs `SELECT` on
  `audience_tenant_assignment`.
- Each reads the assignment row for `(NEW.tenant_id, NEW.resource_server_id)`
  with `FOR SHARE`. That lock conflicts with the row lock of a `status`
  `UPDATE`, so the insert and a concurrent disable serialize: whichever
  comes second sees the other's result.
- A disabled assignment raises a `check_violation` (23514) that names a
  constraint (inferred; so it is a typed refusal, not the SK001 guard
  error). The name is added to `KNOWN_CONSTRAINTS` and to the catalog test
  `registry_constraint_names_match_the_catalog`. The registry maps it to a
  typed `InvariantKind`.
- A missing assignment is left to the foreign key (23503): the trigger finds
  no row and returns, and the foreign key then refuses the insert.
- Only INSERT is covered: `0004` makes these list rows immutable (UPDATE is
  refused by `*_immutable`), and a DELETE needs no check.

This reverses the rule in the migrations README, "the database does not
enforce these rules; the service must", for these two tables only. Clients,
application origins and human-policy references have no tables yet, so they
stay service-side until their tables exist.

## Lock order (declaration)

The `0005` lock order puts operator rows first and the audit head last. The
new lock sits between the owner row and the audit head:

1. the operator rows, in the `0005` order (credentials, `recovery_state`,
   the operation row);
2. the owner row of the list (service identity or grant), as the registry
   writers already take it;
3. the assignment row `FOR SHARE` (new, taken by the trigger at the list
   insert);
4. the audit head, last.

Operator and tenant status updates that also touch an assignment must take
the assignment row before the audit head. A disable of an assignment takes the
assignment row `FOR NO KEY UPDATE` (the `UPDATE` itself) and then appends its
audit event, so it follows the same order. Under `REPEATABLE READ` or
`SERIALIZABLE`, an insert against an assignment disabled after the writer's
snapshot fails with 40001, which maps to `Retry`.

## Limits

- Replica mode (`session_replication_role = replica`) skips the trigger, like
  every guard of this schema. This is a tripwire against application DML, not
  a security boundary (see the 0009 "Limits").
- It checks the assignment only at insert. Re-enabling or disabling the
  assignment later does not revalidate existing rows (lead, Q3 and Q4 below).

## Tests

- Refuse a disabled assignment at insert, for both tables; accept an enabled
  one; a creating CTE statement.
- A two-connection race: T1 inserts a row (holding `FOR SHARE`); T2's disable
  blocks until T1 commits. The reverse order: T2's disable commits first, T1's
  insert is refused.
- Catalog proof: trigger and function names, `tgenabled = 'A'`, pinned
  `search_path`, the constraint name in `KNOWN_CONSTRAINTS`.
- A replica-mode test pinning the limit, if the maintainer wants it pinned.
- Registry mapping: the typed error for a disabled assignment, and 40001
  to `Retry` at `REPEATABLE READ` and `SERIALIZABLE`.

Mutants: drop `FOR SHARE` (the race test), trigger not `ENABLE ALWAYS`, the
status check dropped, the trigger missing on one table, and the error mapped
to the wrong variant.

## Decisions (lead rulings, 2026-11-21, provisional)

1. Refuse a disabled assignment at write time (IR-080: "refused unless an
   active same-tenant assignment exists"). Yes.
2. A disabled resource server is allowed as a dormant reference at write time;
   the live check denies it (IR-081). So the trigger does not read
   `resource_server.status`.
3. Enabling a disabled assignment does not revalidate existing references.
   They stay dormant until the live check.
4. Stranding is fine: disabling an assignment that existing rows reference is
   not blocked, because the live recheck denies them.
5. This is a separate migration from the 0009 stored-marker follow-up.

## Open

- The migration number (the next free number after `0009`, or a number shared
  with the stored-marker follow-up) is open.
- Whether the maintainer accepts reversing the README rule for these two
  tables. Decided: accepted (ruled by the user, 2026-11-22, relayed by the
  lead); implementation pending. The README rule itself changes with the
  migration that adds the triggers, not before.
