# Proposal: separate migrate and runtime database roles (T10.1 follow-up)

Status: Draft, plan only. Drafted 2026-11-26 for the lead's review. Nothing
here is implemented: this text changes no code, no migration, no contract
and no test, adds no dependency and serves no endpoint. Each choice is
labelled **lead pick** (an implementation choice open to ordinary review)
or **open user question** (it changes a deployment contract or a ruling);
the list is under "Decisions requested". Line numbers refer to `main` at
`939c4cd`. The privilege claims below were checked by reading the SQL and
the code; none was run against PostgreSQL for this text (see "Not
verified").

T10.1 owns "a runtime database role that does not own the tables, separate
from the migration role (today one `SKYOAUTH_DATABASE_URL` serves both),
which is what makes the append-only triggers more than a tripwire"
([tasks](../skyoauth-tasks.md), T10.1). The migrations README says the same
under "Limits" (`service/migrations/README.md:2548-2556`): the guard triggers
are a tripwire, the table owner or a superuser can disable or drop them, and
"the real control is a runtime role that does not own the tables, together
with the pinned `search_path` of the guard functions".

## Today

- **One variable, read by `migrate` only.** `SKYOAUTH_DATABASE_URL`
  (`service/src/persistence/config.rs:8`) is read by
  `DatabaseConfig::from_env` (:279-326), and only `migrate` calls it
  (`service/src/main.rs:78-90`). The server opens no database connection:
  `serve()` binds `SKYOAUTH_ADDR` and serves `app()` (`main.rs:66-74`), which
  has `/healthz` only (`service/src/lib.rs:31-32`); the root `README.md`
  says "The server does not need a database yet". `AdminState` holds a pool
  (`service/src/admin_http/mod.rs:264-271`), but nothing serves the admin
  router before the rustls acceptor (S6). So "one URL serves both" is true
  of the deployment contract, not yet of a running server, and the split
  can land before the first slice that gives `serve()` a pool.
- **No grants.** No migration of `0001` to `0011` issues a `GRANT` or a
  `REVOKE`, and none creates a `SECURITY DEFINER` function. Every table,
  `_sqlx_migrations` included, is owned by the role that ran `migrate`. The
  README prescribes grants in prose ("What 0004 adds" :796-801, "What 0005
  adds" :1032-1038 and :1141-1154, :1284, "What 0010 adds" :2277-2304,
  "What 0011 adds" :2475-2490, "Follow-ups" :2668-2698), and the `0005`,
  `0010` and `0011` texts say their grants take effect once the migrate and
  runtime roles split.
- **No sequences.** IDs are random text (`service/src/ids.rs`); no table
  has a `serial` or identity column, so the runtime role needs no sequence
  privilege.

## 1. The two roles

- **R1 (lead pick).** Two roles. The **migrate role** runs `migrate` and is
  the owner of every table and function, as today (root `README.md`: "the
  migration role must own it, or at least have `CREATE` on the `public`
  schema"); no separate `NOLOGIN` owner role. The **runtime role** owns
  nothing and holds exactly the privileges of section 4. It is a `NOLOGIN`
  group role that receives the grants; the server logs in as a member of it
  (`GRANT skyoauth_runtime TO <login role>`), so a credential rotates by
  adding a new member without rerunning `migrate`. The documentation names
  them "migrate role" and "runtime role"; the group role's default name is
  part of R3.
- **R2 (lead pick).** The grants live in one embedded SQL file that is not
  a migration (sketched as `service/src/persistence/runtime_privileges.sql`,
  outside `service/migrations/`, which `sqlx::migrate!` reads). `migrate`
  applies it after the migrations, in one transaction, to the configured
  runtime role: `REVOKE ALL` on the schema's tables from the role, then the
  grants of section 4 and `USAGE` on the schema. Re-applied on every run, it
  converges: a corrected grant reaches an existing database without a new
  migration, and the migrations stay free of deployment role names.
  Rejected: `GRANT`s inside the migrations to a fixed role name (a
  cluster-wide name hard-coded into checksummed files, a role that must
  exist at migrate time, and from the first tagged release a new migration
  for every privilege change).

## 2. Configuration

- **R3 (open user question): the variables.** Recommendation:
  - `SKYOAUTH_DATABASE_URL` keeps its name and becomes the runtime URL: the
    server, and the later bootstrap and recovery subcommands, use it.
  - `SKYOAUTH_MIGRATE_DATABASE_URL` (new) is read by `migrate` only.
  - `SKYOAUTH_DATABASE_RUNTIME_ROLE` (new, default `skyoauth_runtime`) is
    read by `migrate` only and names the group role of R2.
  - Precedence: `migrate` uses `SKYOAUTH_MIGRATE_DATABASE_URL` when it is
    set and nonempty, and then applies the grants. When it is unset,
    `migrate` falls back to `SKYOAUTH_DATABASE_URL`, applies no grants and
    logs a WARN that the deployment has one role and the guards are a
    tripwire only. Today's documented command keeps working.
  - With the migrate URL set, `migrate` refuses before migrating when the
    runtime role does not exist, is the migrate role, is a superuser, or is
    a member of the migrate role (checked with `pg_has_role`).

  The names, the default and the fallback change the deployment contract
  (root `README.md`, "Database migrations"), so they are the user's.

- **R4 (lead pick): TLS, errors and `Debug`.** Both URLs go through the same
  `DatabaseConfig::from_lookup` path, with the variable name passed in
  instead of the constant at `config.rs:284`. Each gets the strict default
  on its own (`verify-full` for a remote host without `sslmode`, `PGSSLMODE`
  ignored, a WARN for a weaker explicit mode; `config.rs:485`); nothing,
  `sslrootcert` included, is inherited from the other URL. `ConfigError`'s
  messages hard-code `SKYOAUTH_DATABASE_URL` today (`config.rs:130-170`);
  they name the variable actually read, and still repeat nothing from the
  URL. `Debug` (`config.rs:345-358`) gains a `purpose` field (`migrate` or
  `runtime`) and still omits the password and the URL. The pool variables
  keep their meaning; `migrate` already runs on one dedicated connection
  (`service/src/persistence/mod.rs:94-104`).
- **R5 (lead pick): same-role detection is by privilege, not by URL.** Two
  URLs can name different login roles that share ownership through
  membership, and one role can be reached through two URLs, so comparing
  user names proves nothing. The server checks its own privileges in the
  database at start (R8) and refuses an owner. `migrate`'s refusals of R3
  catch the same mistake from the other side.
- **R6 (open user question): a development opt-out.** Whether the server
  may start as an owner or superuser at all, for local development, behind
  an explicit variable (for example `SKYOAUTH_DATABASE_ALLOW_OWNER_ROLE=true`)
  that turns R8's role refusal into a WARN at every start. The config has
  no development mode to key it on (the server's one variable today is
  `SKYOAUTH_ADDR`, `main.rs:68`). Recommendation: allow it, with the WARN;
  never for the schema check.

## 3. Who migrates, and what the server checks at start

- **R7 (no change; lead pick on the shape).** `migrate` stays an explicit
  step and the server never migrates on start; that is already the rule
  (`persistence/mod.rs:6-7`, `main.rs:76-77`) and this proposal does not
  reopen it. Deployments run it as an operator step or a pre-deploy job with
  the migrate URL, before the server rollout. The server's environment
  should not carry the migrate URL: the server logs a WARN when
  `SKYOAUTH_MIGRATE_DATABASE_URL` is set in its environment (refusing was
  considered; it would break a shared environment file for no gain the
  WARN does not give).
- **R8 (lead pick): the start checks.** Once, before serving, on one
  runtime connection, the server runs two checks and refuses to start on
  either failure, with a message that names the step to run or the
  privilege to remove:
  - **Schema.** The applied rows of `_sqlx_migrations` against the embedded
    `MIGRATOR`: an embedded version not applied or not successful, a
    checksum mismatch, or an applied version the binary does not know is a
    refusal, the same three conditions `migrate` refuses
    (`persistence/mod.rs:9-15`). Needs `SELECT` on `_sqlx_migrations`.
  - **Role.** A refusal when the role is a superuser; owns, or is a member
    of the owner of, any table or function in the schema; has `CREATE` on
    the schema; has `TRUNCATE`, `TRIGGER` or `REFERENCES` on any table; has
    any `INSERT`, `UPDATE` or `DELETE` that section 4 does not list; lacks
    one that it lists (a write would fail later with `42501`); or may `SET`
    `session_replication_role` (`has_parameter_privilege`, PostgreSQL 15 or
    later), which turns off the foreign keys. An extra `SELECT` is a WARN
    only. The `has_*_privilege` functions count inherited privileges, so
    membership is covered.

  The checks land as a library function now and are wired by the first
  slice that gives `serve()` a pool.

## 4. Runtime-role privileges

From the migrations and the code that writes each table. "Writers" are the
only callers in a normal build; "tests only" marks registry writers that
are `#[cfg_attr(not(feature = "test-support"), expect(dead_code))]`, whose
production callers are later slices. Every `UPDATE` column list includes
`revision` where the table has one. Every table gets `SELECT` except
`consumed_assertion`. No table gets `TRUNCATE`, `TRIGGER` or `REFERENCES`
(foreign key checks run as the table owner, README :1032-1034).

| Table                              | INSERT | UPDATE (columns)                                                                                                                    | DELETE | Writers (code)                                                                                                                     |
| ---------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `_sqlx_migrations`                 | no     | none                                                                                                                                | no     | `migrate` only (migrate role); `SELECT` for R8                                                                                     |
| `schema_info`                      | no     | none                                                                                                                                | no     | none (no code reads it); no `SELECT` needed either                                                                                 |
| `tenant`                           | yes    | `name`, `status`                                                                                                                    | no     | `admin::workload` (`tenant.rs:43`, `:106-108`); locks `FOR SHARE` (`admin/workload.rs:284`), `FOR KEY SHARE` (`events.rs:521`)     |
| `principal`                        | yes    | `name`, `status`                                                                                                                    | no     | `admin::workload` (`tenant.rs:135`, `:202-204`)                                                                                    |
| `instance_security_policy`         | yes    | `widening_second_approver`; with the S8 mirror also `single_actor_mode`, `audit_sink_config_digest`, `audit_sink_validated_at` (F2) | no     | bootstrap (`bootstrap.rs:268`, lock `FOR UPDATE` :259); the toggle (`operation.rs:383-391`); locks `FOR SHARE`/`FOR NO KEY UPDATE` |
| `egress_allowlist_entry`           | yes    | `status`                                                                                                                            | no     | `admin::egress` (`instance.rs:107`, `:143-145`); locked `FOR SHARE` by `trust::source` (`source.rs:472`) and the `0011` guard (F1) |
| `audit_chain_head`                 | no     | `sequence`, `head_hash`                                                                                                             | no     | `registry::events` only (`events.rs:529` `FOR UPDATE`, `:542`)                                                                     |
| `audit_event`                      | yes    | **none**                                                                                                                            | **no** | `registry::events` only (`events.rs:536`); the `0005` guards read `id`, `tenant_id`; `verify_audit_chain` reads all (`:768`)       |
| `resource_server`                  | yes    | `name`, `allowed_profiles`, `scopes`, `constraint_versions`, `status`                                                               | no     | `admin::workload` (`audience.rs:52`, `:106-108`; `admin/workload.rs:323`)                                                          |
| `audience_tenant_assignment`       | yes    | `allowed_profiles`, `allowed_scopes`, `constraint_versions`, `status`                                                               | no     | `admin::workload` (`audience.rs:129`, `:195-197`; `admin/workload.rs:327`); locked by the `0010` guard (F1)                        |
| `resource_server_checker`          | yes    | `public_mtls_identity`, `status`                                                                                                    | no     | `admin::workload` (`audience.rs:217`, `:268-270`, `:299`, `:333`)                                                                  |
| `resource_server_checker_tenant`   | yes    | none                                                                                                                                | yes    | `admin::workload` (`audience.rs:303`, `:339`)                                                                                      |
| `resource_action`                  | yes    | `required_scopes`, `accepted_profiles`, `required_resource_dimensions`, `live_check_required`, `status`                             | no     | `admin::workload` (`audience.rs:361`, `:417-420`)                                                                                  |
| `trust_keyset`                     | yes    | `name`, `status`                                                                                                                    | no     | tests only (`trust.rs:48`, `:105`); locked `FOR NO KEY UPDATE` by `trust::keyset` (`keyset.rs:479`)                                |
| `trust_keyset_version`             | yes    | `status`                                                                                                                            | no     | `trust::keyset` only (`trust.rs:154`, `:316-318`)                                                                                  |
| `trust_source`                     | yes    | the 15 mutable columns of `trust.rs:443-449`, `name` to `status`                                                                    | no     | `trust::source` only (`trust.rs:356`, `:443-449`; lock `source.rs:463`)                                                            |
| `principal_binding`                | yes    | `name`, `profile`, `claim_match_policy`, `status`                                                                                   | no     | tests only (`grant.rs:172`, `:243-245`); no hard delete in code (F6)                                                               |
| `service_identity`                 | yes    | `name`, `max_scopes`, `max_resource_constraints`, `status`                                                                          | no     | tests only (`grant.rs:282`, `:353-355`; list bumps `:76-125`)                                                                      |
| `service_identity_resource_server` | yes    | none                                                                                                                                | yes    | tests only (`grant.rs:286`, `list_add!`/`list_remove!`)                                                                            |
| `service_grant`                    | yes    | `name`, `scopes`, `default_scopes`, `resource_constraints`, `max_ttl`, `valid_until`, `status`, `activation_state`                  | no     | tests only (`grant.rs:479`, `:568-571`); the `0004` check locks it, the `0009` guard reads `id`, `mode`, `xmin`                    |
| `service_grant_binding`            | yes    | lock-only `grant_id` (F5)                                                                                                           | yes    | tests only (`grant.rs:485`, list macros)                                                                                           |
| `service_grant_resource_server`    | yes    | none                                                                                                                                | yes    | tests only (`grant.rs:489`, list macros)                                                                                           |
| `admin_identity`                   | yes    | `status`                                                                                                                            | no     | bootstrap, recovery (`operator.rs:633`); `disable_admin_identity` (`:670`)                                                         |
| `admin_credential`                 | yes    | `status`, `revoked_at`                                                                                                              | no     | bootstrap, recovery (`operator.rs:691`, `recovery.rs:613`); `revoke_admin_credential` (`operator.rs:735`)                          |
| `admin_role_binding`               | yes    | `status`                                                                                                                            | no     | bootstrap (`operator.rs:761`); update tests only (`:602`, `:802`); locked `FOR SHARE` (`operation.rs:401`)                         |
| `recovery_state`                   | yes    | `recovery_public_key`, `recovery_key_epoch`                                                                                         | no     | bootstrap (`bootstrap.rs:271`), restore (`recovery.rs:619`)                                                                        |
| `administrative_operation`         | yes    | `consumed_at`, `revoked_at`, `revocation_operation_id`, `outcome`                                                                   | no     | `registry::operation` (`operation.rs:301`, `:362`, `:366`), recovery (`recovery.rs:570`, `:580`, `:626`)                           |
| `consumed_assertion`               | yes    | **none**                                                                                                                            | **no** | `registry::assertion` only (`assertion.rs:147`, `:223`), no conflict target, so `INSERT` alone (README :1034-1039); no `SELECT`    |

**Must not hold.** `UPDATE`, `DELETE` or `TRUNCATE` on `audit_event`;
`INSERT`, `DELETE` or `TRUNCATE` on `audit_chain_head`; `UPDATE` on
`consumed_assertion`; `DELETE` on any table that the `0001`, `0002` and
`0006` guards keep undeletable (every table above marked "no", except
`_sqlx_migrations` and the two below); `DELETE` on `principal_binding` and
`service_grant`, which ADR-008 item 3 allows when disabled but no code
does; `UPDATE` on any column the `0002` to `0004` immutability guards
protect, except the lock-only grant of F5. The guards refuse most of these
anyway (`SK001`); the privileges make the refusal a `42501` that does not
depend on the triggers being enabled.

**Findings: where the code needs more, or the README promises more.**

- **F1. The lock-only column grants close nothing with one runtime role.**
  The README prescribes `UPDATE (id)` on `audience_tenant_assignment`
  (:2286-2301) and `egress_allowlist_entry` (:2478-2485), and
  `UPDATE (instance_id)` on `instance_security_policy` (:1148-1154), so that
  a list-row writer, a destination writer or a policy-row locker can lock
  but not change the row, and says each "takes effect once the migrate and
  runtime roles are split". It does not: the same runtime role runs
  `admin::workload`'s assignment update and disable (`UPDATE ... status`),
  `admin::egress`'s enable and disable (`UPDATE ... status`), and the
  toggle (`UPDATE ... widening_second_approver`). The test
  `a_table_level_update_lets_a_destination_writer_flip_an_entry`
  (`service/tests/schema_trust_source_egress_guard.rs:1340`) shows the
  path that stays open. Closing it needs a second runtime role (an
  exchange role without the admin writers); see Q-roles under "Decisions
  requested". The README sentences need correcting either way.
- **F2. The mirror writes from the runtime role.** The S8 startup mirror
  (`docs/proposals/mirror-revision-rule.md`, O7) runs in the server, so the
  runtime role needs `UPDATE` on `single_actor_mode` and the sink columns.
  IR-053's "an online operator write MUST NOT change them" stays a service
  rule; the database cannot tell the mirror from an online write (`0002`
  comment at :129-134). Running the mirror as the migrate role would put
  the owner credential in the server, which R7 avoids.
- **F3. The split does not stop forged appends.** The runtime role can
  insert operator rows (bootstrap and recovery need it) and append
  correctly chained audit events (every audited write needs it). A stolen
  runtime credential can therefore enroll an operator and record a
  plausible event for it with raw SQL. What the split stops is rewriting or
  deleting history, disabling guards and shadowing the chain head.
- **F4. Row locks need `UPDATE` on a column.** Locks not in the README:
  `tenant` `FOR SHARE` and `FOR KEY SHARE`, `trust_keyset` and
  `trust_source` `FOR NO KEY UPDATE`, the operator rows and
  `recovery_state` `FOR SHARE`, bootstrap's policy `FOR UPDATE`. Each is
  covered by the table's own `UPDATE` columns above, so none needs a
  lock-only grant.
- **F5. `service_grant_binding` under `REPEATABLE READ`.** The `0004` check
  locks the grant's binding rows `FOR KEY SHARE` only above
  `READ COMMITTED` (`0004`:640-644; README :796-801). Every wired write
  runs at `READ COMMITTED` (`trust/write.rs:44-50`, `admin/mod.rs:14`,
  `operation/mod.rs:77`), but the registry list writers take any executor
  (lead pick: grant the lock-only `UPDATE (grant_id)`; every column of the
  row is immutable, `0004` `service_grant_binding_immutable`).
- **F6. Not granted until a writer exists.** `DELETE` on
  `consumed_assertion` (pruning, README :1038), `SELECT` on it (the
  retired-version check, README :1283-1285), and `DELETE` on
  `principal_binding` and `service_grant` (ADR-008 item 3). Each is added to
  the grants file by the PR that adds its writer.
- **R9 (lead pick): grant the registry surface, tests-only writers
  included.** Least privilege would leave out the binding, service
  identity, grant and keyset writers that no production code calls yet.
  The pick grants them now: the runtime role is the role of the whole M1a
  registry, the tests run those writers as it (section 6), and the grants
  file is the one place to narrow later. `trust_keyset` and
  `admin_role_binding` would need lock-only grants without it.

## 5. The guard functions' `search_path`

- **R10 (lead pick): no SQL change.** Every function the migrations create
  already pins `search_path` in its definition: the schema between
  `pg_catalog` and `pg_temp` for the chain functions of `0002` (:320-378),
  the `0004` binding-set check (:618-620) and the `0009` list guard
  (:133-135); `pg_catalog, pg_temp` for the others (`0002`, `0005`, `0006`,
  `0009`, `0010`:81-84, `0011`:96-99), the table readers among them naming
  their tables with the schema resolved at migrate time. The one exception
  is `skyoauth_reject_mutation()` of `0001`, which resolves no names and is
  unpinned by design (README :78-82). None is `SECURITY DEFINER`; `0005`,
  `0010` and `0011` say `SECURITY INVOKER` explicitly. So there is no
  in-place amendment and no `ALTER FUNCTION ... SET search_path`.
- **The proof exists for a non-owner role.** The catalog test
  `assert_functions_pin_search_path` (`service/tests/schema_foundation.rs:196-259`)
  checks every function, and the shadow tests run as a non-superuser,
  non-owner login role: temporary tables named after the real ones in
  `audit_chain_guards_ignore_the_callers_search_path`
  (`schema_foundation.rs:1113`), the `jsonb` type shadow (:1234) and
  `grant_binding_check_ignores_the_callers_search_path`
  (`schema_trust_binding_grant.rs:2245`), and operators put ahead of
  `pg_catalog` (`schema_foundation.rs:1332`, `schema_operator.rs:2892`,
  `schema_registry_guards.rs:907`). Section 6 reruns the temporary-table
  shadow tests as the real runtime role and adds a catalog check that no
  function of the schema is `SECURITY DEFINER` (today only three files
  read `prosecdef`).
- **`TEMP` stays (lead pick).** The runtime role keeps `PUBLIC`'s default
  `TEMPORARY` privilege; the pin is the control. Revoking it is a
  deployment hardening that needs the database owner, documented as
  optional.

## 6. Tests and rollout

The coding session owns production code, migrations, code comments and the
root and migrations READMEs; the test session owns `service/tests/*`,
`tests/*`, the harnesses, CI and `docs/testing/conformance-layout.md`
(ownership as in the second-approver proposal's PR decomposition).

- **The existing privilege tests stay as they are.** Each proves the
  minimum one guard needs, with an ad-hoc login role:
  `grant_binding_check_needs_the_callers_privileges`
  (`schema_trust_binding_grant.rs:2155`),
  `list_row_writers_need_select_on_service_grant`
  (`schema_reserved_ids_and_dormant_grants.rs:1078`),
  `list_row_writers_need_select_and_update_on_the_assignment`
  (`schema_assignment_write_guard.rs:1322`),
  `destination_writers_need_select_and_update_on_the_entries` and
  `a_table_level_update_lets_a_destination_writer_flip_an_entry`
  (`schema_trust_source_egress_guard.rs:1279`, `:1340`),
  `proof_consumption_needs_only_insert` (`schema_operator.rs:2958`),
  `registry_consumption_needs_only_insert` (`registry_assertion.rs:1030`),
  `the_guards_read_with_the_writers_privileges` and
  `the_policy_row_lock_needs_the_prescribed_grant`
  (`schema_operation_approval_guard.rs:1308`, `:1438`), and A24's
  `INSERT`-only role (`tests/security/a24.rs:799`). They keep using
  `create_login_role` (`service/tests/common/mod.rs:118`,
  `tests/src/pg.rs:187`).
- **New: the real runtime role.** Both harnesses (kept in step, as
  `tests/src/pg.rs:53-58` requires) apply the grants file when they build
  the template, to a cluster-wide `NOLOGIN` group role of the harness's
  own name, created if absent; the template digest covers the grants file.
  `TestDb::runtime_pool()` returns a pool of a fresh login role that is a
  member of it. That needs `CREATEROLE` for every database test, which CI's
  superuser has; the root `README.md` test-role table says so. New tests:
  the role's privileges equal section 4 (a catalog comparison over
  `has_table_privilege` and `has_column_privilege`); each writer of
  section 4 runs once as the runtime role; the temporary-table shadow tests
  rerun as it; R8's refusals, one case each; `migrate` with two URLs and
  with the fallback (`service/tests/cli.rs`); the redaction tests for the
  new variable (`service/tests/redaction.rs`).
- **Rollout, each PR green on its own:**
  1. **coding:** the grants file and its apply step, the `migrate`
     variables and refusals of R3, R4's error and `Debug` changes with
     their unit tests, the root README's variable table, and the migrations
     README (section "Reconciliation"). Nothing changes unless
     `SKYOAUTH_MIGRATE_DATABASE_URL` is set, so no existing test moves.
  2. **test:** the harness group role, `runtime_pool()` and the new tests
     above except R8's.
  3. **coding:** R8's checks as a library function, not wired, with unit
     tests.
  4. **test:** R8's database tests.
  5. **coding, in the slice that gives `serve()` a pool:** the server reads
     the runtime URL, runs R8 before binding, and warns per R7.

## Neighbouring note: S6 trust-anchor enforcement

Not part of the role split; recorded here at the lead's request. The
requirement comes from the test session; which of its two forms S6 takes
is not picked here.

D5 rules that "the certificate chain anchor must equal the credential's
`trust_anchor_ref`" (tasks :1021). Nothing enforces it yet:

- `AdminPeer` (`service/src/admin_http/peer.rs:31-33`) holds only
  `public_identity`; its one production constructor,
  `from_peer_spki` (:52), takes the SPKI DER alone. Its docs (:39-44)
  state the anchor duty but give it no carrier.
- The merged read path compares only the key: the handler passes
  `peer.public_identity()` (`service/src/admin_http/operations.rs:113`) to
  `authorize_reader` (`service/src/operation/read.rs:241`), whose lookups
  are `AUTHORIZE_OPERATOR` and `AUTHENTICATE_OPERATOR`, both
  `c.public_identity = $1` (`service/src/persistence/registry/operator.rs:555-565`).
  `trust_anchor_ref` is stored (`operator.rs:691`) and never compared; the
  registry says it does not check the anchor (`operator.rs:148-152`).

So the S6 acceptor must verify the chain against the credential's
`trust_anchor_ref` before it builds an `AdminPeer`, or `AdminPeer` must grow
an anchor field that the lookups compare with `c.trust_anchor_ref`.

- **Lead picks for the split:** S5 owns enrolment and the credential state
  (`public_identity`, `trust_anchor_ref`, status); S6 owns the handshake and
  the chain verification against the trust anchor; S7 owns the
  canonicalization of the presented key (tasks :1024).

## Risks and open items

- **Shared clusters.** Roles are cluster-wide. Two instances in one
  cluster must use different runtime role names, or one instance's runtime
  role holds the other's grants; R3's default makes the collision easy.
- **Unknown applied version.** R8 refuses an applied migration the binary
  does not know, so an old replica restarting after a new `migrate` does
  not start. Acceptable before the first tagged release (no upgrade path); to
  revisit with the upgrade contract.
- **PostgreSQL 15.** `has_parameter_privilege` exists from 15; the service
  states no minimum version (only the tests do, root `README.md:114`).
- **`REVOKE ALL` and column privileges.** R2 relies on a table-level
  `REVOKE` also removing column grants; PR 1 tests it.
- **F1, F2, F3** are limits of one runtime role, not bugs; the README text
  must stop promising more.
- **Not verified.** No statement here was run against PostgreSQL; the
  privilege rules used (row locks need `UPDATE` on a column, `RETURNING`
  needs `SELECT`, foreign key checks run as the owner) are the README's and
  are pinned by the existing tests only for the cases they cover. The
  writer lists come from reading `service/src` (the `#[cfg(test)]` modules
  left out); a statement built at run time from another table name would
  have been missed (none was found: the two dynamic `UPDATE`s,
  `admin/workload.rs:321-329`, pick from two fixed strings).

## What this does not do

No code, migration, test or contract changes in this PR; no new
dependency; no endpoint. It does not change the rule that the server never
migrates (R7), does not add row-level security, does not move the S8 mirror
(F2), and does not split the runtime role further (Q-roles).

## Decisions requested

- **R1 (lead pick):** migrate role owns everything; runtime role is a
  `NOLOGIN` group role, the server logs in as a member.
- **R2 (lead pick):** grants in one embedded, re-applied SQL file, not in
  the migrations.
- **R3 (open user question):** `SKYOAUTH_MIGRATE_DATABASE_URL`,
  `SKYOAUTH_DATABASE_RUNTIME_ROLE` (default `skyoauth_runtime`), and the
  fallback to `SKYOAUTH_DATABASE_URL` without grants.
- **R4 (lead pick):** same parsing and strict TLS per URL, errors name the
  variable, `Debug` gains `purpose`.
- **R5 (lead pick):** same-role detection by privilege in the database.
- **R6 (open user question):** a development opt-out from R8's role
  refusal, with a WARN.
- **R7 (lead pick):** `migrate` as an operator step or pre-deploy job; the
  server warns when it sees the migrate URL.
- **R8 (lead pick):** the server refuses to start on pending or unknown
  migrations and on an over- or under-privileged role.
- **R9 (lead pick):** grant the full registry surface, tests-only writers
  included.
- **R10 (lead pick):** no SQL change for the pin; prove it as the real
  runtime role; keep `TEMP`.
- **F5 (lead pick):** lock-only `UPDATE (grant_id)` on
  `service_grant_binding`.
- **Q-roles (open user question):** one runtime role (F1's closures stay
  open), or an exchange role and an admin role.
- **S5/S6/S7 split (lead picks):** see the neighbouring note.

## Reconciliation

When accepted, PR 1 updates: the migrations README "Limits" (:2548-2556),
the grant sentences at :1150-1154, :2296-2301 and :2480-2485 (F1), the
runtime-role follow-up at :2668-2698, and the root `README.md` variable
table and migration notes; PR 5 updates the `persistence` module docs
(`service/src/persistence/mod.rs:6-7`) and `main.rs`'s usage text. The
`0002` comment at :129-134 stays true (F2).
