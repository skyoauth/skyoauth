# Proposal: a read-only `status` operation on the local socket, and a bound on the restore reply

Status: Proposed. Drafted 2026-11-27 for the lead's review, and for the
user where a question below is the user's. It answers two rulings of the
user (2026-11-27, relayed by the lead), recorded in tasks §13 under "Other
rulings of the user, 2026-11-27": "Read-only socket operation" (a
read-only operation is added to the local socket; proposal first, then the
implementation) and "Restore reply bound" (the `restore` reply's list of
revoked IDs is bounded by a service change, a count cap with the full list
available elsewhere or paginated IDs, worked out in the same proposal).
Nothing here is implemented: this text changes no code, no contract, no
fixture and no test. Each choice is labelled **recommended** (the author's,
for the lead to pick), **(inferred)** where no source fixes it, or **(not
verified)** where the author did not check it by running anything. Line
numbers refer to `main` at `662deca`.

## Problem

### 1. Nothing on the socket reads (Q18)

The local transport (`service/src/local_transport/`, design §7.2, T13.4,
T13.5) takes one JSON line, then the client's end of stream, and answers
one line (`mod.rs:200-228`). Its four operations are `bootstrap`,
`issue_challenge`, `preview` and `restore` (`wire.rs:13-18`;
`mod.rs:232-237`). Three of them write. Every write can end with an
outcome the client cannot know:

- no reply: the transaction timeout or shutdown cut the request during its
  commit (`mod.rs:352-355`), or the reply could not be written
  (`mod.rs:357-359`);
- `auth_unavailable` or `server_error` from a failed `COMMIT`
  (`mod.rs:287-292`);
- a request the client gave up on while it waited in the listen queue,
  which may still run once accepted (`mod.rs:364-373`).

The service's rule is "reconcile, then retry" (`mod.rs:291-302`;
identity-registry :406-418), and the operator client classifies these
outcomes faithfully: `CallError::Unknown` and
`UnknownOutcome::UncertainCommit` (`operator/src/local/exchange.rs:292-304`,
`:469`), `Retry::ReconcileFirst` for the three writes and `Retry::Safe` for
`preview` only (`exchange.rs:192-216`). But it cannot reconcile:
"The transport has no operation that reads state, so this crate cannot
reconcile: the only readers are the admin HTTP API and the database (open
question Q18 of the T13.10 plan ...)" (`exchange.rs:306-309`). The admin
HTTP API is served nowhere yet (tasks §13 D5), and in a break-glass
recovery it is the very path that has failed.

What each write leaves the client holding, and what it lacks:

| Write             | The client knows                                         | Lost with the reply                                                         | What would decide it                                                                    |
| ----------------- | -------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `bootstrap`       | `instance_id`, the mTLS key, the recovery key (it sent them) | `admin_id`, `credential_id`, `binding_id` (the transport generates them, `ops.rs:274-277`) | whether the recovery state exists for this instance, and whether this key is enrolled |
| `issue_challenge` | the replacement's key and anchor                        | `operation_id` and `M` (`ops.rs:361-365`)                                    | nothing needs deciding: a lost challenge expires unused (`mod.rs:399-404`)              |
| `restore`         | `operation_id`, the signature                            | the replacement's IDs, the revoked IDs, the new epoch                        | whether that challenge was consumed by a restore                                       |

A retry is today the only probe, and it misleads: a retried `bootstrap` is
`conflict` and a retried `restore` is `not_restorable` once the first one
committed, "the repeat's answer looks like a refusal and hides the first
call's success" (`operator/src/local/mod.rs:75-82`). `not_restorable` is
also every other reason a restore fails (expired, retired, bad signature;
`mod.rs:443-444`), so it cannot tell "your restore committed" from "your
challenge expired".

### 2. The restore reply has no bound

The `restore` reply carries `revoked_credential_ids`, every credential the
restore revoked (`wire.rs:117-124`; `ops.rs:518-525`). The restore revokes
every unrevoked credential in one statement and returns all their IDs
(`service/src/persistence/registry/recovery.rs:1547-1552`). Nothing bounds
the number of operator credentials, so nothing bounds the reply. The client
caps what it reads at `MAX_REPLY_BYTES`, 4 MiB, and calls a longer reply an
unknown outcome (`operator/src/local/mod.rs:111-127`); its doc leaves the
bound as "Open question for the service and the design" (:123-126). A
restore that committed and revoked enough credentials would therefore
always look unknown to the client, by construction.

## Part A: the read-only operation

### Options

| Option | Shape | Reconciles | Trade-offs |
| ------ | ----- | ---------- | ---------- |
| **A1. `status`** (recommended) | One op; three nullable keys: `operation_id`, `credential_spki`, `revoked_after`. One fixed reply shape. | `bootstrap` (by the instance and the mTLS key) and `restore` (by the operation ID); pages the revoked IDs (Part B) | One more op and one reply with nullable members; the reply reveals the recovery state, a challenge's state, and whether a key is enrolled. |
| A2. `operation_outcome` | One op keyed by `operation_id` only. | `restore` only | Narrowest. Bootstrap writes no operation row (`bootstrap.rs:51`), so a lost bootstrap reply stays unreconcilable through the socket; and the bootstrap's generated IDs stay lost. |
| A3. Reuse an existing read | (a) `preview` answers its refusal reasons; (b) reconcile through the admin HTTP API (D4 operation reads, operator reads); (c) keep the retry as the probe. | (a) and (c) partly; (b) not in break-glass | (a) breaks "a refusal is `{"error":"<code>"}` and nothing else" (`mod.rs:415-418`) and tells every preview caller which check refused (`mod.rs:443-444` chose not to); a consumed challenge needs a signature to ask about. (b) needs the admin listener (served nowhere until S6/S7, tasks §13 D5) and a working operator credential, the thing a restore replaces. (c) is today's gap. |

**Recommended: A1.** It is the only option that reconciles both writes that
matter. The rest of Part A specifies it.

### Request

```text
{"op":"status","operation_id":<string|null>,"credential_spki":<hex|null>,"revoked_after":<string|null>}
```

- Every member is present, in this order (the encoder's order fixes the
  golden lines, `operator/src/local/wire.rs:29-35`); a missing member is
  `invalid_request`, as for the other ops (`mod.rs:219-224`). (Serde's
  derive treats a missing `Option` member as `None` by default, so the
  implementation needs a deserializer that requires it; not verified
  beyond serde's documented default.)
- `operation_id`: as `preview` and `restore` take it; a NUL is
  `invalid_request` (`ops.rs:129-136`).
- `credential_spki`: lowercase hex of a DER `SubjectPublicKeyInfo`, from
  which the transport derives the public identity as bootstrap and issue
  do (`ops.rs:95-100`); never an identity string.
- `revoked_after`: the last revoked credential ID the client already holds;
  only with an `operation_id`, else `invalid_request`.

### Reply

All members, always, in this order; `null` where the reply has nothing to
say. Times are whole microseconds since the Unix epoch, as elsewhere on the
wire (`mod.rs:225-227`).

| Member | Type | Value |
| ------ | ---- | ----- |
| `server_time` | integer | the transport's `now`, from the injected clock the writes use |
| `instance_id` | string or null | the `RecoveryState` row's; null when there is none (bootstrap not closed; identity-registry :296-297) |
| `recovery_key_epoch` | integer or null | the row's |
| `recovery_state_revision` | integer or null | the row's |
| `operation_state` | string or null | null when no `operation_id` was asked; else one of the states below |
| `expires_at` | integer or null | the challenge's, when found |
| `restored_at` | integer or null | its `consumed_at`, when `restored` |
| `admin_id`, `credential_id`, `binding_id` | string or null | the replacement the restore enrolled (from the consumed plan), when `restored` only |
| `revoked_credential_count` | integer or null | when `restored`: how many credentials that restore revoked (Part B) |
| `revoked_credential_ids` | array of strings or null | when `restored`: at most 1000 of them, in byte order, after `revoked_after` |
| `enrolled_state` | string or null | null when no `credential_spki` was asked; else `not_found`, `enabled`, `disabled` or `revoked` for the credential with that public identity |
| `enrolled_admin_id`, `enrolled_credential_id` | string or null | that credential's operator and ID, when found |

Operation states, decided in this order against the state the transaction
read (inferred names):

| State | Condition | Final? |
| ----- | --------- | ------ |
| `not_found` | no row with that ID, or a row that is not an `operator_restoration` of no tenant by `deployment_operator` with `challenge_hash` and `expires_at` set (the filter of restore step 3, `recovery.rs:166-171`) | yes (inferred: an ID the client holds came from a committed issue) |
| `revoked` | `revoked_at` set | yes |
| `restored` | consumed, outcome `restored` | yes |
| `retired` | unconsumed, but the plan's instance or epoch, or `expected_revision`, is no longer the state's | yes: the epoch never decreases (`0005_operator.sql:217-234`) and the library's one write of the row, the rotation, advances epoch and revision together (`recovery.rs:619-623`; inferred for writes by other means), so the consume (`recovery.rs:580-599`) can never match again |
| `issued` | unconsumed, bound, `server_time < expires_at` | no |
| `expiring` | unconsumed, bound, `expires_at <= server_time < expires_at + transaction_timeout` | no: no new restore can consume it, but one that took its `now` before the expiry may still be running |
| `expired` | unconsumed, bound, `server_time >= expires_at + transaction_timeout` | yes, for restores through this transport (below) |
| (any other combination, e.g. consumed with outcome `issued`, which only a write by other means leaves) | `server_error` (inferred) | |

`expired` waits for the transaction timeout because the restore takes `now`
after `BEGIN` (`ops.rs:500-507`), and the transaction timeout bounds
everything from `BEGIN` to the end of the commit (`mod.rs:337-340`): a
restore that took its `now` before the expiry has ended by
`expires_at + transaction_timeout`. A transport on the same database with a
longer transaction timeout, or a library caller with any clock (the registry
trusts its caller's `now`, identity-registry :419-428), is outside that
bound (question Q3).

### What it does not reveal

It returns no `M`, no plan member other than the replacement's three IDs
(and those only once restored), no request digest, no challenge hash, no
signature, no recovery public key, no audit event, and nothing about an
operation that is not a recovery challenge: an approval or a pending gated
write by that ID is `not_found`, the same as no row. It reveals the
recovery state (which `issue_challenge` already reads to build its plan,
`ops.rs:416-420`) and whether a key is enrolled (which an issue already
answers with `conflict`, `mod.rs:270-275`, a lead pick that the channel
"tells it nothing it could not read"). The audit chain's head (IR-055) was
considered and left out: the restore's events do not name the operation
(`recovery.rs:226-229`; identity-registry :379-381), so the sequence tells
the client nothing about its own request.

This changes one lead ruling: "No registry getter returns the operation
row" (identity-registry :358-359; `recovery.rs:165-166`). The read is a
query private to the transport, or a new registry function returning the
closed projection above, not the row (recommended; question Q1).

### Transaction, order and the barrier

- One `READ COMMITTED` transaction with the transport's timeouts, always
  rolled back, as `preview` (`ops.rs:455-486`). It draws no ID.
- It takes the transport's mutex like every request (`connection.rs:160-164`;
  `mod.rs:304-321`), so in one process it runs after any earlier request
  has ended, a cut one included.
- **Barrier (recommended).** It reads the `recovery_state` row
  `FOR SHARE` first. A restore holds that row `FOR NO KEY UPDATE` from its
  step 2 to its commit (`recovery.rs:1521-1524`), and `FOR SHARE` conflicts
  with `FOR NO KEY UPDATE` (PostgreSQL's row-lock table; not tested here),
  so `status` waits for any restore, from any process, that has locked the
  state, including one whose client connection was discarded while
  PostgreSQL still finishes its `COMMIT`. Every later statement takes a
  new snapshot at `READ COMMITTED` and sees that restore's result. The wait
  is bounded by `lock_timeout` (`auth_unavailable`). `FOR SHARE` is what
  an issue and the access-adding operator writes take (`recovery.rs:127-133`;
  identity-registry :382-388), so `status` delays only restores, and only
  while it runs. An uncommitted bootstrap's row is invisible and is not
  waited for (inferred).
- Then the challenge row (no lock), the credential by public identity, and
  the revoked page (Part B).

### Finality, the 100 s wait, and the reconcile procedure

`status` is one more request with the same bounds: at most 100 s from the
accept on a default server (`mod.rs:361-364`;
`DEFAULT_TOTAL_WAIT`, `exchange.rs:41-45`). It cannot see the listen queue,
where a request the client gave up on may still wait (`mod.rs:364-373`). So
only the states marked final above are final; `issued`, `expiring` and a
null `instance_id` are not. The procedure the operator crate documents (the
client still never retries on its own, `operator/src/local/mod.rs:75`):

- **restore, outcome unknown:** `status` with its `operation_id`.
  `restored`: it committed; the reply has the replacement's IDs, and the
  revoked IDs page by `revoked_after`. `expired`, `retired`, `revoked`: it
  did not commit and never will; issue a new challenge. `issued`: repeat the
  same restore, which is single use (LT-107; identity-registry :334-346):
  it restores, or is `not_restorable` because the first one committed, which
  the next `status` shows. `expiring`: ask again later.
- **bootstrap, outcome unknown:** `status` with the bootstrap's
  `credential_spki`. `instance_id` equal to the one sent and the key
  enrolled: it committed (`enrolled_admin_id`, `enrolled_credential_id`;
  the binding ID is not returned, question Q8). `instance_id` null: repeat
  the same bootstrap, which the database closes once (`mod.rs:313-317`).
  Another `instance_id`, or the key not enrolled while an instance exists:
  another bootstrap won; stop.
- **issue_challenge, outcome unknown:** nothing to reconcile: issue again;
  a stray challenge expires unused and any restore retires the others
  (`mod.rs:399-404`). Whether `Op::retry` should say so is question Q5.

### Peer check, limits and audit

- **Peer:** the service UID or root only, checked before a byte is read
  (`mod.rs:448-456`), unchanged. Who reaches the socket reaches bootstrap
  and recovery already (OQ-TM-9).
- **Limits:** no new limit. `max_connections`, the mutex and the statement
  timeout bound it as they bound `preview`. A flood of `status` calls can
  delay a restore by queueing on the mutex; the peer is root-equivalent, so
  no rate limit is proposed (inferred).
- **Replay:** it carries no signature and runs no consume, so it cannot
  replay, extend or spend a challenge; the TTL, single use and the binding
  of `C` are untouched (LT-107).
- **Audit (recommended): not audited.** It writes nothing, so it appends no
  event and cannot fail on the audit append. The admin read router does not
  audit reads either (no `append_audit_event` under
  `service/src/admin_http/`, checked). The transport logs nothing today
  (`mod.rs:44-47`, TM-15); whether a local read should be logged is
  question Q7.

### Errors

| Cause | Code |
| ----- | ---- |
| peer refused | `forbidden` |
| malformed request, a missing or mistyped member, bad hex, a DER that is not one SPKI, a NUL in an ID, `revoked_after` without `operation_id` | `invalid_request` |
| a store failure, the barrier's `lock_timeout` | `auth_unavailable` |
| a challenge row in no state above, an unreadable time | `server_error` |

Never `conflict` or `not_restorable`; a missing row is a state, not an
error. Since `status` writes nothing, every code is a plain refusal, as
for `preview`: the operator client must not treat `status` as a write
(`exchange.rs:469` today tests `!matches!(op, Op::Preview)`, which would
make a new op a write; mutant M9).

### Determinism and wire versioning

- For a given database state and clock, the reply bytes are fixed:
  members in a fixed order, `null` for absent values, revoked IDs in byte
  order (`ORDER BY id COLLATE "C"`, matching Rust's `String` order, which
  is byte-wise), a page size of exactly `min(1000, remaining)`. With the
  fixture's fixed clock and `SequentialIds` the golden lines are
  reproducible as today's are.
- The wire has no version member. An old server answers an unknown `op`
  with `invalid_request` (`mod.rs:219-224`). The transport is served nowhere
  (`mod.rs:23-27`) and `skyoauth-operator` is `publish = false`
  (`operator/Cargo.toml:9`), so no deployed peer exists: **recommended**,
  change `tests/conformance/fixtures/_wire/local_transport.v1.json` in place
  (its `status` is still "proposed") rather than start a `v2` (question Q6).

## Part B: the restore reply bound

### Options

| Option | Reply | Trade-offs |
| ------ | ----- | ---------- |
| B1. Count only | `revoked_credential_count`; no IDs | Smallest; every reply needs a `status` call to see any ID. |
| **B2. Count and capped list** (recommended) | `revoked_credential_count` (exact), and `revoked_credential_ids`: the first `min(count, 1000)` in byte order | The usual reply (well under 1000 operators, inferred) stays complete in one line; the rest pages through `status`. |
| B3. Paginated restore | The restore returns a page and a cursor | A restore runs once; its later pages need a read, which is B2 with `status`. |

**Recommended: B2.** New `restore` reply, members in this order:

```text
{"admin_id":…,"credential_id":…,"binding_id":…,"revoked_credential_count":N,"revoked_credential_ids":[…≤1000…],"recovery_key_epoch":…,"recovery_state_revision":…}
```

The list is complete exactly when its length equals the count. The rest:
`status` with the operation ID and `revoked_after` set to the last ID held,
until the count is reached.

### The cap: 1000

- A generated credential ID is `cred_` and 26 characters, 31 bytes (tasks
  §13 D1; `service/src/ids.rs:185`), 33 as a JSON string, 34 with its comma.
  Today's golden `restored` line is 255 bytes with one ID (fixture
  `golden_replies`, case `restored`). With 1000 generated IDs and the count
  member the line is about 34 KB (computed from the fixture line), under the
  64 KiB request limit.
- The database allows a credential ID of up to 255 bytes with any
  character (`0005_operator.sql:112-114`). `serde_json` writes a control
  character as a six-byte `\u` escape, so the worst ID is 1532 bytes as a
  JSON string; 1000 of them, with the other members at their worst, are
  about 1.54 MB, 37% of the client's 4 MiB. The cap keeps the reply under
  the client's cap whatever the IDs are; 2700 would be the most (about
  99%).
- 1000 is round, far above any plausible number of operator credentials
  (inferred), and the same page size serves `status`.

The client keeps `MAX_REPLY_BYTES` at 4 MiB as a defence against a
misbehaving peer, and its doc (`operator/src/local/mod.rs:111-126`) drops
the open question: the service now bounds every reply.

### Atomicity and audit

- **Atomicity: unchanged.** The restore still revokes every unrevoked
  credential in one statement in its one transaction (`recovery.rs:190-197`,
  step 6). The cap applies to the reply only, after the commit; a truncated
  list is a success, not an unknown outcome.
- **Where the cap lives (recommended):** in the transport (`ops.rs:518-525`).
  The library's `Restored` keeps every ID (`recovery.rs:775-789`), so no
  registry test changes. The service still holds every ID in memory
  (`fetch_all`, `recovery.rs:1548`); that is bounded by the table, not by
  the wire, and could move into SQL later (inferred: not needed at operator
  scale).
- **Audit: unchanged.** Neither event lists the revoked IDs or their count
  (step 10, `recovery.rs:217-229`; the envelope has no such member, IR-056).
  The durable record is each credential's `revoked_at`, which is set once
  (`admin_credential_set_once`, `operator.rs:59-60`).

### Which credentials `status` lists, and one caveat

The restore writes `revoked_at` and the challenge's `consumed_at` from the
same `now`: `restore_operator` computes it once (`recovery.rs:1488`) and
`restore_steps` binds it to the consume (`CONSUME_CHALLENGE`, :580-581) and
to the revocation (:1548-1549). So `status` lists the credentials whose
`revoked_at` equals the operation's `consumed_at`, and counts them the same
way. Caveat: a credential that another writer revoked at the identical
microsecond, before the restore locked the credentials, is listed too
(over-inclusion only; `revoke_admin_credential`, `operator.rs:727-745`, has
no online caller yet, inferred). The count in a restore reply comes from
the revoke statement itself and is exact; if the two differ, the
difference is that tie. An exact record needs a column naming the revoking
operation, a schema change (question Q4).

## Contract and code impact

### Contract amendments (proposed wording; not edited here)

The break-glass points of identity-registry §5.2 carry no IR number
(checked); the lead places the text or numbers it.

1. **identity-registry §5.2, a new bullet after "Errors and uncertain
   commits" (:406-418):**

   > - **Reading the recovery state.** The deployment-local transport serves
   >   one read-only operation, `status`, under the peer check of bootstrap
   >   and restoration. It writes nothing, appends no audit event, consumes,
   >   extends and grants nothing. It reports the `RecoveryState` (instance,
   >   key epoch, revision); for a named operation ID, the state of an
   >   `operator_restoration` challenge (not found, revoked, restored,
   >   retired, issued, expiring or expired), its expiry and restoration
   >   time, and, once restored, the replacement's IDs and the credentials
   >   the restoration revoked, in pages of at most 1000; and, for a named
   >   mTLS key, whether a credential with its public identity exists, its
   >   operator and its state. It returns no challenge, plan member other
   >   than the replacement's IDs, digest, hash, signature or recovery
   >   public key, and does not distinguish another kind of operation from
   >   a missing one. It is the reconcile step of the uncertain-commit rule
   >   above.

2. **identity-registry :358-359**, after "No registry getter returns the
   operation row (lead ruling)": "; the transport's `status` reports only
   the projection of 'Reading the recovery state'".
3. **identity-registry "Restoration" (:370-381)**, appended: "The local
   transport's reply carries the number of revoked credentials and at most
   1000 of their IDs, the first in byte order; `status` returns the rest."
4. **public-api §7.1, the local row (:491)**, its third column: "Bootstrap,
   and the recovery restoration, which verifies the signed response
   (ADR-013 item 7); a read-only `status` that writes and grants nothing;
   challenge bound to instance, operation, arguments and revision".

API-152 (:515) is unchanged: `status` is not a break-glass kind. The wire
bytes stay out of the contracts: the service says no contract text fixes
them (`mod.rs:216`, `:227-228`), and the fixture pins them.

### Service (`service/src/local_transport/`)

- `wire.rs`: `Request::Status(StatusWire)`; `Reply::Status { … }`;
  `Reply::Restored` gains `revoked_credential_count` before the IDs.
- `ops.rs`: `status()` as above; `restore()` truncates to 1000 and counts.
- `mod.rs` docs: "Operations" (:232-275), "Transactions" (:294-302:
  reconcile with `status`), "Errors" (:413-444), "Crashes" (:399-404 stays
  true: no op reads an issue's `M` back).
- A constant for the page size, shared by both uses.

### Operator (`operator/src/local/`)

- **C1 codec** (`wire.rs`): encode `status`, with `null` (the encoder
  writes strings only today, :44-88); parse its reply (the reader has no
  `null` yet, :278-443); parse the new `restored` member. Check that
  `revoked_credential_ids` has exactly `min(count, 1000)` entries in
  strictly increasing byte order, else `Malformed` (an unknown outcome).
- **C4** (the operator slice that uses the socket end to end; its scope is
  not recorded in the repository, `docs/proposals/demo-walkthroughs.md:360`,
  not verified): `Op::Status` with `Retry::Safe`; the write test at
  `exchange.rs:469` becomes an explicit list of the three writes;
  `LocalClient::status`, a page iterator for the revoked IDs, and the
  reconcile procedure above in the docs, replacing `exchange.rs:306-309`.

## Tests

The fixture is checked by both crates (`operator/src/local/mod.rs:36-40`):
`operator/tests/local_wire` and `tests/harness/local_transport_wire.rs`.

**Fixture (`local_transport.v1.json`):** `ops.status`; a `status` reply
shape and the new `restored` shape; golden requests (all keys null; an
operation ID; a `credential_spki`; with `revoked_after`); the `exchange`
steps regenerated with a `status` after `bootstrap` (instance, key
enrolled) and after `restore` (`restored`, IDs, count 1); `unknown_replies`:
a `status` reply missing a member, a string where `null` belongs, a
`restored` reply whose list is longer than its count, unsorted, or longer
than 1000 when the count is larger.

**Service (`service/tests/local_transport.rs`, the PR's own):** every
operation state, each from a real sequence: `not_found` (unknown ID, and
an approval row by its ID); `issued`; `expiring` and `expired` by moving
the injected clock past `expires_at` and past `expires_at` plus the
transaction timeout; `retired` (restore another challenge); `restored` with
the replacement's IDs; `status` before bootstrap (all null), after it (key
`enabled`), after the restore (old key `revoked`); 999, 1000, 1001 and 2001
credentials: the restore reply's count and first page, then pages via
`revoked_after` that join to the full set without repeats; `status` writes
nothing (row counts and audit head unchanged); `status` waits for a restore
blocked before commit and then sees `restored`, and sees `issued` after a
rollback (the barrier; as A32's blocked tests, `scenarios.toml` A32 rows);
request refusals of the table above; a unit test that a `Reply::Restored`
with 1000 worst-case IDs (255 control characters each) is under 4 MiB.

**Mutants** (to run by hand, as the 2026-11-23 check in
`docs/testing/conformance-layout.md:212`; each must turn a test red):

- M1 `expired` at `expires_at` without the transaction-timeout margin;
- M2 the kind, tenant and actor filter removed (an approval row shows a
  state);
- M3 the barrier removed (`FOR SHARE` dropped);
- M4 the cap at 999 or 1001;
- M5 the first page taken from the end, or unsorted;
- M6 the count taken from the truncated list;
- M7 `revoked_after` inclusive;
- M8 `retired` folded into `issued`;
- M9 (C4) `status` classed as a write, so a store failure becomes
  `UncertainCommit`;
- M10 the replacement's IDs returned for `issued`;
- M11 (C1) a `restored` list longer than its count accepted.

A32's scenario tests (`tests/security/a32.rs`) are the test session's;
reconcile cases there would add test IDs to `scenarios.toml`, which
`gen-conformance-registry.mjs --check` then pins. None is proposed here.

## Implementation slices

1. **Contract amendment** (the lead's): the four texts above, with or
   before PR 2.
2. **Service PR:** `status`, the restore cap, module docs, the fixture, and
   the matching C1 codec change in `operator/src/local/wire.rs`. The codec
   lands here because both crates check the same fixture: a fixture change
   alone turns `operator/tests/local_wire` red.
3. **Operator C4 PR:** `LocalClient::status`, `Op::Status` and its retry
   class, the explicit write list, the revoked-ID pages and the reconcile
   docs.

## Not verified

- The serde default for a missing `Option` member, and the deserializer
  that refuses it: from serde's documentation, not tried.
- That `FOR SHARE` waits for `FOR NO KEY UPDATE`, and that a `COMMIT`
  received before the client connection is discarded keeps the row lock
  until it ends: PostgreSQL's documented behaviour, not tested here.
- The size figures: computed from the fixture's golden line and from
  `serde_json`'s escape rules (as `operator/src/local/wire.rs:162-185`
  restates them), not by serializing 1000 IDs.
- That no online path revokes a credential yet (the tie of Part B).
- C4's scope.

## Open questions

- **Q1 (lead).** Does a closed projection keep the ruling "no registry
  getter returns the operation row", or does `status` need a new ruling?
- **Q2 (lead).** The `credential_spki` key: needed only to reconcile a
  bootstrap. Keep it, or accept that a lost bootstrap reply is reconciled by
  repeating the bootstrap (`conflict` once closed) and an admin read later?
- **Q3 (lead).** `expired` is final for restores through this transport's
  own transaction timeout. Accept that bound, or never report `expired` and
  leave finality after the expiry to the client?
- **Q4 (lead, maybe the user).** The revoked list by `revoked_at =
  consumed_at`, with the same-microsecond tie documented; or an exact
  column (a schema change, `0005` in place before beta or a new
  migration)?
- **Q5 (lead).** With `status`, should `issue_challenge` become
  `Retry::Safe`, since its only reconcile is "issue again"? The operator
  crate says today that no write is safe to repeat (`mod.rs:81-82`).
- **Q6 (lead).** Edit `local_transport.v1.json` in place (recommended) or
  add a `v2`?
- **Q7 (lead).** Leave `status` unlogged, as every local request is today,
  or log reads separately when the transport gets logging (TM-15)?
- **Q8 (lead).** Return the bootstrap's `binding_id` too (the credential's
  operator's enabled instance `security_admin` binding)? Not needed to
  connect; the reply would grow by one member.

## Decisions requested

- Part A: option **A1** (`status`), its members and states, the barrier,
  no audit event (recommended); Q1 to Q3, Q5 to Q8.
- Part B: option **B2**, the cap of 1000, the cap in the transport, the
  list by `consumed_at` (recommended); Q4.
- The four contract texts, and the slice order: contract, service PR with
  the C1 codec, then C4.
