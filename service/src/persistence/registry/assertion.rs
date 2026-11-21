//! Consumed single-use WIF proofs (`consumed_assertion`, `0005`): the
//! atomic consume primitive of a `single_use` source (T10.9; ADR-016 items 6
//! and 7; lifetimes §9).
//!
//! A proof is consumed by inserting its row. The primary key
//! `(tenant_id, trust_source_id, replay_key_digest)` makes the consumption
//! atomic across replicas and grants: of several attempts with the same
//! key, exactly one inserts and is [`Consumption::Consumed`]; every other is
//! [`Consumption::Replay`]. A replay is a normal outcome, not an error. Rows
//! are insert-only (`0005` rejects every `UPDATE`), and neither function
//! here ever updates one.
//!
//! # What the caller does
//!
//! The registry stores what it is given and decides nothing else. The
//! service (T11.11, T21.6; migrations README, "The service rules"):
//!
//! - computes `replay_key_digest`, the keyed digest of
//!   `(tenant, source_id, exact_issuer, verified_jti)`, and chooses the
//!   digest-key versions; the registry never sees the key or the `jti`;
//! - computes `retain_until` (the proof's `exp` plus skew) and, for a row
//!   under a retiring digest-key version, its cap at that version's
//!   `drain_until` (the drain protocol of the migrations README);
//! - supplies `consumed_at`; the registry does not read the clock;
//! - consumes only for a `single_use` source that is enabled: the registry
//!   reads neither `trust_source.replay_mode` nor its `status`;
//! - treats [`Consumption::Replay`] and every error as a deny. A missing
//!   `jti`, a store failure or a replay denies (ADR-016 item 6).
//!
//! A crash after the insert commits and before the token is issued burns
//! the proof: it stays consumed, and a retry needs a fresh assertion
//! (ADR-016 item 6).
//!
//! # Concurrency
//!
//! The "exactly one wins" claims hold under `READ COMMITTED`, PostgreSQL's
//! default: a concurrent attempt on the same key waits for the first one's
//! transaction and then sees its row. In a caller transaction at
//! `REPEATABLE READ` or `SERIALIZABLE` the loser may instead fail with
//! `40001` (`serialization_failure`), [`RegistryError::Retry`], which is a
//! deny too until the whole transaction is retried. [`consume_assertion`]
//! fails so when the winner committed after the loser's snapshot.
//! [`consume_assertion_set`] fails so only under `SERIALIZABLE`, and only
//! when both transactions are serializable and both read the key's range
//! first; otherwise its plain `INSERT` sees the committed key and gets
//! `23505`, which is a [`Consumption::Replay`]. Both outcomes deny. So
//! does a `40P01` (`deadlock_detected`) of a caller transaction that
//! consumes several keys in separate calls in an order another transaction
//! reverses.
//!
//! The functions take the tenant and source as given and filter nothing
//! by tenant: whether the source may be used is the caller's decision, and
//! the composite foreign key refuses a source of another tenant.
//!
//! # Errors
//!
//! A source that does not exist in the row's tenant (another tenant's
//! source included) is `Invariant { kind: ForeignKey, constraint:
//! Some("consumed_assertion_trust_source_id_fkey") }`; the retention check
//! (`retain_until > consumed_at`), the range and length checks map by name
//! the same way. As elsewhere in the registry, the bounds the schema checks
//! are left to the database: a `replay_key_digest` outside 32 to 64 bytes is
//! `Invariant { kind: Check, constraint:
//! Some("consumed_assertion_replay_key_digest_octet_length_check") }`.
//! `40001` and `40P01` are [`RegistryError::Retry`]; anything else, a
//! connection or store failure included, is [`RegistryError::Other`]. The
//! caller denies on every error.

use std::time::SystemTime;

use sqlx::PgExecutor;

use super::{RegistryError, model::since_epoch};

/// The most rows one [`consume_assertion_set`] call writes (inferred: a
/// proof has a row per digest-key version, the current one and the few
/// retiring ones still draining).
pub const MAX_ASSERTION_SET: usize = 8;

/// The primary key, whose `23505` is a replay in [`consume_assertion_set`].
const PRIMARY_KEY: &str = "consumed_assertion_pkey";

/// `unique_violation`.
const UNIQUE_VIOLATION: &str = "23505";

/// One consumed proof under one digest-key version, the input of
/// [`consume_assertion`] and [`consume_assertion_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConsumedAssertion {
    pub tenant_id: String,
    /// A source of `tenant_id`; the composite foreign key refuses another
    /// tenant's.
    pub trust_source_id: String,
    /// The keyed digest the service computes, 32 to 64 bytes (the database
    /// checks the bound).
    pub replay_key_digest: Vec<u8>,
    /// The digest-key version, an opaque non-empty string of at most 255
    /// bytes.
    pub digest_key_version: String,
    /// When the proof was consumed, supplied by the caller.
    pub consumed_at: SystemTime,
    /// Until when the row is kept: after `consumed_at`, computed by the
    /// service (the proof's `exp` plus skew, capped at `drain_until` under a
    /// retiring digest-key version).
    pub retain_until: SystemTime,
}

/// The outcome of a consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Consumption {
    /// This call inserted the row (or, for a set, every row): the proof was
    /// not consumed before, and the caller may issue.
    Consumed,
    /// A row with the same key exists: the proof was consumed before, and
    /// the caller denies. Nothing was written.
    Replay,
}

/// Consumes one proof under one digest-key version: a single-row `INSERT …
/// ON CONFLICT DO NOTHING`. One row inserted is [`Consumption::Consumed`],
/// none is [`Consumption::Replay`]; the existing row of a replay is left as
/// it is (`DO NOTHING` never updates).
///
/// The clause names no conflict target: naming one needs `SELECT` on the
/// table, and the runtime role has only `INSERT` on `consumed_assertion`
/// (migrations README, "Privileges"). The primary key is the table's only
/// unique index, so today every conflict is a replay of the key. A unique
/// index added later would also read as [`Consumption::Replay`], which is
/// still a deny.
///
/// A `consumed_at` or `retain_until` outside the range the registry writes
/// is an encode error, [`RegistryError::Other`], before the statement runs.
/// The row's checks run before the conflict is looked for, so a replay
/// with an invalid row (for example `retain_until` not after `consumed_at`)
/// is that check's error, not a replay.
///
/// For the rows of one proof under several digest-key versions, which must
/// be consumed all or none, use [`consume_assertion_set`]: separate calls
/// of this function would keep the rows that did not conflict.
pub async fn consume_assertion<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewConsumedAssertion,
) -> Result<Consumption, RegistryError> {
    let consumed_at = since_epoch(new.consumed_at)?;
    let retain_until = since_epoch(new.retain_until)?;
    let result = sqlx::query(
        "INSERT INTO consumed_assertion \
         (tenant_id, trust_source_id, replay_key_digest, digest_key_version, consumed_at, \
         retain_until) VALUES ($1, $2, $3, $4, timestamptz 'epoch' + $5::interval, \
         timestamptz 'epoch' + $6::interval) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&new.tenant_id)
    .bind(&new.trust_source_id)
    .bind(&new.replay_key_digest)
    .bind(&new.digest_key_version)
    .bind(consumed_at)
    .bind(retain_until)
    .execute(executor)
    .await?;
    Ok(if result.rows_affected() == 1 {
        Consumption::Consumed
    } else {
        Consumption::Replay
    })
}

/// Consumes a set of rows all or none, typically one proof under the
/// current digest-key version and each retiring version still draining
/// (migrations README, the drain protocol): one plain multi-row `INSERT`,
/// without `ON CONFLICT`. Every row inserted is [`Consumption::Consumed`].
/// A `23505` on `consumed_assertion_pkey`, from any row, is
/// [`Consumption::Replay`], and the failed statement writes none of the
/// rows. `INSERT … ON CONFLICT DO NOTHING` is not used here because it would
/// keep the rows that did not conflict.
///
/// - On a pool or a bare connection the statement commits on its own, all
///   or none.
/// - Inside a caller transaction the `23505` of a replay aborts the
///   transaction, as any PostgreSQL error does: the caller must roll it
///   back, which also undoes its earlier statements.
/// - A key twice in the set is an encode error, [`RegistryError::Other`],
///   before any statement runs: it is not a replay of a proof that was
///   never consumed.
/// - The rows are inserted sorted by the primary key, bytewise
///   (`tenant_id`, then `trust_source_id`, then `replay_key_digest`),
///   whatever the order of `set`. Two sets that share keys therefore take
///   their row locks in the same order and do not deadlock: the loser
///   waits on its first shared key while holding no later one.
///
/// An empty set, one of more than [`MAX_ASSERTION_SET`] rows, or one with a
/// key twice, is an encode error, [`RegistryError::Other`], before any statement runs, as is
/// a time outside the range the registry writes. Any other `23505` or error
/// maps as for every registry write.
pub async fn consume_assertion_set<'e>(
    executor: impl PgExecutor<'e>,
    set: &[NewConsumedAssertion],
) -> Result<Consumption, RegistryError> {
    if set.is_empty() {
        return Err(sqlx::Error::Encode("empty assertion set".into()).into());
    }
    if set.len() > MAX_ASSERTION_SET {
        return Err(sqlx::Error::Encode("assertion set too large".into()).into());
    }
    let mut rows: Vec<&NewConsumedAssertion> = set.iter().collect();
    rows.sort_by(|a, b| {
        (&a.tenant_id, &a.trust_source_id, &a.replay_key_digest).cmp(&(
            &b.tenant_id,
            &b.trust_source_id,
            &b.replay_key_digest,
        ))
    });
    if rows.windows(2).any(|pair| same_key(pair[0], pair[1])) {
        return Err(sqlx::Error::Encode("duplicate key in assertion set".into()).into());
    }
    let mut consumed_at = Vec::with_capacity(rows.len());
    let mut retain_until = Vec::with_capacity(rows.len());
    for row in &rows {
        consumed_at.push(since_epoch(row.consumed_at)?);
        retain_until.push(since_epoch(row.retain_until)?);
    }
    let result = sqlx::query(
        "INSERT INTO consumed_assertion \
         (tenant_id, trust_source_id, replay_key_digest, digest_key_version, consumed_at, \
         retain_until) \
         SELECT tenant_id, trust_source_id, replay_key_digest, digest_key_version, \
         timestamptz 'epoch' + consumed_at, timestamptz 'epoch' + retain_until \
         FROM unnest($1::text[], $2::text[], $3::bytea[], $4::text[], $5::interval[], \
         $6::interval[]) WITH ORDINALITY AS r (tenant_id, trust_source_id, \
         replay_key_digest, digest_key_version, consumed_at, retain_until, position) \
         ORDER BY position",
    )
    .bind(
        rows.iter()
            .map(|row| &row.tenant_id[..])
            .collect::<Vec<_>>(),
    )
    .bind(
        rows.iter()
            .map(|row| &row.trust_source_id[..])
            .collect::<Vec<_>>(),
    )
    .bind(
        rows.iter()
            .map(|row| &row.replay_key_digest[..])
            .collect::<Vec<_>>(),
    )
    .bind(
        rows.iter()
            .map(|row| &row.digest_key_version[..])
            .collect::<Vec<_>>(),
    )
    .bind(consumed_at)
    .bind(retain_until)
    .execute(executor)
    .await;
    match result {
        Ok(_) => Ok(Consumption::Consumed),
        Err(error) if is_replay(&error) => Ok(Consumption::Replay),
        Err(error) => Err(error.into()),
    }
}

/// Whether `a` and `b` have the same primary key.
fn same_key(a: &NewConsumedAssertion, b: &NewConsumedAssertion) -> bool {
    (&a.tenant_id, &a.trust_source_id, &a.replay_key_digest)
        == (&b.tenant_id, &b.trust_source_id, &b.replay_key_digest)
}

/// Whether `error` is a `23505` on the primary key, a replay.
fn is_replay(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|error| {
        error.code().as_deref() == Some(UNIQUE_VIOLATION) && error.constraint() == Some(PRIMARY_KEY)
    })
}
