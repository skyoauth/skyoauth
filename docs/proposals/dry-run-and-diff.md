# Proposal: dry-run and diff of admin writes (T13.3)

Status: Draft, plan only. Nothing here is implemented, and it changes no
code. Drafted for the lead's review with the S4 slice (the admin router's
operation reads). Choices marked "(inferred)" are this draft's picks for the
lead to confirm or change; the open items are listed at the end. It ratifies
no ADR, ticks no task and changes no contract under `docs/contracts/`.

T13.3 asks for an operator API "with revisions/diff/dry-run/audit", and the
M1a lead decisions assign dry-run and diff to it
([tasks §13](../skyoauth-tasks.md#13-m1a-lead-decisions-2026-11-24), "Plan
splits"). Revisions and audit exist: every write of `crate::admin` is
revision-checked and appends one audit event in the same savepoint, and the
gated trust writes and the instance policy toggle store a pending operation
whose plan is the canonical text that
`GET /admin/v1/tenants/{tenant}/operations/{operation}` returns verbatim
(D4, `service/src/admin_http`). This proposal plans the missing two: a way
to ask "what would this write do" without doing it, and the shape of the
answer.

## 1. The hook: run the write in a transaction that never commits

A dry-run runs the real write function, unchanged, in a savepoint of a
transaction that is always rolled back, and returns what the write returned
plus a diff computed before the rollback (inferred).

- **One function, no mode flag in the write path.** `crate::admin` gets one
  wrapper, sketched as
  `dry_run(pool, |transaction| write(transaction, request, ...)) -> Result<DryRun<T>, AdminWriteError>`.
  It begins its own transaction, checks the isolation level as every write
  does, reads the "before" state it needs (section 2), runs the write
  through the existing `in_savepoint`, computes the diff from the write's
  `Audited { row, event }` and the before state, and then rolls the whole
  transaction back. The write functions take no `dry_run: bool` and do not
  know they are previewed. Rejected alternative: a flag on `AdminRequest`
  that skips the audit append or the row write inside each write. Every
  such branch is a place where a mutant (or a bug) turns a real write into
  an unaudited one, and the preview would stop exercising the checks the
  real write runs (the audit append's guards, the foreign keys, the
  compare-and-set).
- **The type keeps it from committing.** The wrapper takes the pool, not
  the caller's transaction, so no caller can commit after it; the
  transaction is dropped or rolled back on every path, `Ok` and `Err`
  alike. A unit test shows that a dry-run leaves no row, no event and the
  chain head where it was, and an integration test runs every write of
  `crate::admin` once as a dry-run and once for real and compares the
  dry-run's diff with the committed change.
- **What a dry-run consumes.** A generated ID is used up, as for a failed
  write (D1: IDs are random, never a sequence, so nothing is skipped or
  reused). No other state outlives the rollback. Writes with effects
  outside the database are not previewed by running them: a trust keyset
  validation that would call the validation worker, and any later write
  that fetches from the network, either preview their database part only
  or refuse the dry-run (open item 3).
- **Gated writes.** The second-approver flow already previews: the
  pending operation's plan is the preview, and its approver reads it before
  approving. A dry-run of a gated write runs the request step
  (`submit_*` up to the pending row) and returns the plan that would be
  stored, without storing it (the rollback takes the pending row and its
  `administrative_operation.create` event back). It never runs the approval
  or the apply step (inferred). Approving remains the only way to apply.

## 2. The diff: canonical plan text or a row diff

Two outputs fit, and the plan proposes both, one per kind of write
(inferred):

- **Gated writes: the canonical plan text.** The same string the operation
  reads return and the digest covers (`operation::canonical_plan`), with
  the would-be envelope (kind, tenant, expected revision, expiry) but no
  `id` and no `request_digest`: the ID is regenerated on the real request,
  so a digest of the dry-run would never match a stored one, and showing it
  would invite comparing them. An operator who wants to know what an
  approver will see gets exactly that text.
- **Direct writes: a row diff.** For the writes of `crate::admin` that
  apply at once there is no plan. The answer is the action the audit event
  would carry (`tenant.disable`, `resource_server.update` and so on, the
  module's classification table), the object's kind and ID, the revision
  before and after, and two objects, `before` and `after`, holding only the
  members that change, as canonical JSON (the plan's canonical form:
  sorted members, integers as integers). A create has `before: null` and
  its ID is shown as `null` with `"generated": true` rather than the
  throwaway ID of the dry-run (inferred). Set changes (a checker's tenant
  set, an assignment's ceiling) are shown as `added` and `removed` lists
  rather than two whole sets.
- **Why not one form for both.** A row diff of a gated write would show the
  pending operation row, not the change the operation will make once
  approved; a plan for a direct write would be a second, unreviewed
  serialization of every write's input. Each output reuses what already
  exists for its kind.
- **What a diff never holds.** The same rules as the error mapping of
  `crate::admin_http`: no private key bytes (a keyset upload's private
  members are refused before any write), no secret namespace value (shown
  as `changed: true` only; inferred), and no value the caller cannot already
  read through a `GET` of the same object with the same role.

## 3. Authorization and audit

- **Authorization: the write's own.** A dry-run runs the write, so it
  authorizes as the write does: the same role, the same scope, the same
  disabled-tenant rule. A caller who may not make the write gets the
  write's 403, so a dry-run is never a read for someone who cannot read
  the object. Its refusals map through the same table as the write's
  (`crate::admin_http`, "Error mapping"): a dry-run of a stale revision is
  409 `stale_revision`, which is itself a useful answer.
- **Audit: none in the database chain.** The write's audit event is
  appended inside the dry-run and rolled back with it, so the chain shows
  no dry-run (refusals are not audited either). Whether a dry-run should
  reach the external audit sink as a read-like security event is part of
  D6, which awaits the user's decision on the sink's scope (open item 1).
  The response says it is a dry-run (a `dry_run: true` member and its own
  route or query parameter; open item 2), so a client cannot mistake it
  for an applied write.

## 4. Concurrency and cost

- **Locks.** A dry-run takes every lock the write takes, for as long as the
  write runs: the operator rows and the tenant row `FOR SHARE`, the target
  row's compare-and-set, and the audit chain head, last. The chain head
  serializes all audited writes, so a dry-run holds up every other write
  for its own duration, as a real write does. The wrapper therefore sets a
  short `lock_timeout` and `statement_timeout` in its transaction (inferred:
  the same as the writes', once those are set) and rolls back the moment
  the diff is computed. Today a lock or statement timeout (`55P03`,
  `57014`) is `RegistryError::Other`, 503 without `Retry-After`; only
  `40001` and `40P01` are `Retry`. Whether a dry-run's timeout becomes
  `Retry` is part of open item 5.
- **The result is advisory.** The diff describes the database at the
  moment of the dry-run. The real write is still a compare-and-set on the
  revision the dry-run reports, so a change in between makes the real
  write 409 `stale_revision` rather than applying something other than
  what was previewed. A client that wants that guarantee sends the
  dry-run's `before` revision as the write's expected revision.
- **Cost.** A dry-run costs a write plus a rollback, with no fsync of a
  commit. It is rate-limited with the writes, not the reads (inferred),
  and it is never cached.

## 5. Routes

Not part of this plan's first step, and no route is served before the
rustls acceptor (D5): the admin router has the reads only. When the writes
get routes, a dry-run is either `POST .../{object}:dry-run` style sibling
routes or a `dry_run=true` query parameter on each write route (open item
2). Either way the handler calls the wrapper of section 1 and never the
write with a flag.

## Open items

1. **External sink.** Whether a dry-run emits an event to the external
   audit sink, and of which kind, waits for D6 (the sink's scope).
2. **Route shape.** Sibling routes or a query parameter, decided with the
   write routes; the contract (`docs/contracts/public-api.md`) has neither
   yet.
3. **Writes with effects outside the database.** Whether a dry-run of a
   trust keyset version create runs the validation worker (cost, and a
   worker call that is not rolled back) or previews the database part
   only and says so.
4. **Generated values in a create's diff.** The picks above (`null` with
   `"generated": true`, `changed: true` for a secret namespace) are
   inferred; a contract may want a different rendering.
5. **Timeouts.** The `lock_timeout` and `statement_timeout` values, shared
   with the writes, are not set anywhere yet.
6. **Contract text.** None of this is in `docs/contracts/`; the response
   shapes need contract wording before a client relies on them.
