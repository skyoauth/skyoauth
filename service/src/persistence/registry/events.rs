//! The audit event writer and chain verifier (identity-registry IR-055 to
//! IR-059, OQ-IR-14, OQ-IR-15; design section 7; T10.1; migrations README,
//! "Audit chain" and "append audit events in this order").
//!
//! # Appending
//!
//! [`append_audit_event`] is the last step of the audited transaction: the
//! caller writes the domain rows first, then appends the event, then
//! commits. The exception is a write that creates an
//! `administrative_operation`, which follows steps 1 to 3 of the migrations
//! README for it: lock the rows it references or updates
//! `FOR NO KEY UPDATE`, append the event, insert the operation, then make
//! the other updates. The event precedes the operation because
//! `administrative_operation.audit_id` is an immediate (not deferrable)
//! foreign key to it.
//!
//! The append locks the event's `tenant` row first, for a tenant-scope
//! event, with `SELECT … FOR KEY SHARE`, the lock the insert's foreign-key
//! check takes; then the chain head (`SELECT … FOR UPDATE`). An
//! instance-scope event locks no tenant row. It takes `sequence` = head + 1
//! and `prev_hash` = head hash from the locked head, computes the event
//! hash in Rust, inserts the event and advances the head to it. The head
//! lock is the append's last lock so that a transaction never holds it
//! while it waits for another row (migrations README): with the tenant
//! locked only by the insert, an appender holding the head would wait for a
//! transaction that holds the tenant row `FOR UPDATE` and then waits for
//! the head, and one of them would fail with `40P01`. Never lock the
//! event's tenant row `FOR UPDATE`; lock it `FOR NO KEY UPDATE` (README
//! step 1: the foreign-key check of an `administrative_operation` insert,
//! after the head lock, takes `FOR KEY SHARE` on its tenant too). A caller
//! that locked a tenant row `FOR UPDATE` before appending is still
//! consistent with the tenant-then-head order; one that locks the head
//! first and then a tenant row is not. Concurrent appenders queue on the
//! head lock and each gets the committed head, so under `READ COMMITTED`
//! every one of them succeeds. Under `REPEATABLE READ` or `SERIALIZABLE` a
//! writer whose snapshot predates another's committed append fails with
//! `40001` ([`RegistryError::Retry`]): retry the whole transaction.
//!
//! It takes a [`Transaction`] (inferred): an append is four statements, five
//! for a tenant-scope event, that must commit together with the audited
//! write, and the type makes an open transaction a precondition. The `0002`
//! triggers would also refuse an append outside one: the deferred
//! `audit_event_head_reached` check fails an insert that commits before the
//! head reaches it. That constraint must stay deferred until the head is
//! advanced, so before the insert the append runs
//! `SET CONSTRAINTS <schema>.audit_event_head_reached DEFERRED`, with the
//! schema of `audit_event` as the transaction's `search_path` resolves it
//! (read by the head lock statement and quoted by PostgreSQL): a caller
//! that ran `SET CONSTRAINTS ALL IMMEDIATE` still appends, and the
//! constraint stays deferred, its initial mode, for the rest of the
//! transaction. The name is schema-qualified because an unqualified one
//! sets only the first schema on the `search_path` with a constraint of
//! that name (inferred).
//!
//! Before any statement it rejects, as an encode error
//! ([`RegistryError::Other`]):
//!
//! - an action that does not have the `<resource>.<verb>` syntax of IR-059
//!   or is not in [`AUDIT_ACTIONS`](super::AUDIT_ACTIONS), a closed list
//!   (lead decision, 2026-11-21, provisional until the maintainer ratifies
//!   the ADRs, T00.8 to T00.17, Gate M0);
//! - an operator actor with an empty ID (inferred);
//! - a revision above `2^53 - 1` (see "Envelope");
//! - a timestamp outside the years `0000` to `9999` (see "Envelope"), a
//!   narrower range than the one the `0007` check
//!   `audit_event_timestamp_range_check` holds, as every registry time
//!   (module docs, "Timestamps"). A time is truncated toward the past to a
//!   whole microsecond, the precision PostgreSQL stores, before it is
//!   hashed, so the stored row hashes as the written one.
//!
//! Other bad input fails at a statement. A missing tenant fails at the
//! tenant lock, before the head lock, with the error the insert's foreign
//! key gave: [`RegistryError::Invariant`] naming
//! `audit_event_tenant_id_fkey` (inferred: the same value; the transaction
//! is not aborted). A NUL character fails the first statement that binds it
//! (`22021`, [`RegistryError::Other`]), a revision below 1 fails the insert
//! (`23514`, [`RegistryError::Invariant`]), and a `sequence` above
//! `2^53 - 1` is an encode error after the head lock.
//!
//! The ID, the timestamp and every other field come from the caller
//! (registry module docs: T10.2 generates IDs); no clock is read here.
//!
//! # Hash
//!
//! The hash is IR-056's: SHA-256 over the ASCII bytes `skyoauth.audit.v1`
//! and one zero byte; then `prev_hash` as 32 raw bytes, "or zero bytes for
//! the first event of a chain, whose stored `prev_hash` is null" (IR-056),
//! read as no bytes at all, the empty input, not 32 zero-valued bytes (lead
//! decision, 2026-11-21, provisional); then the envelope below. It is not
//! stored: the next event's `prev_hash` and the head's `head_hash` record it,
//! and verification recomputes it (OQ-IR-15, no own-hash column).
//!
//! # Envelope
//!
//! The envelope is a JSON object with one member per `AuditEvent` field of
//! tasks section 3 but `prev_hash` (IR-056 leaves out `hash` and
//! `prev_hash`): `id`, `tenant_id`, `sequence`, `timestamp`, `actor`,
//! `action`, `object_id`, `previous_revision`, `new_revision` and `outcome`,
//! serialized as RFC 8785 (JCS) canonical JSON in UTF-8. Lead decision,
//! 2026-11-21, provisional until the maintainer ratifies the ADRs (T00.8 to
//! T00.17, Gate M0; OQ-IR-15):
//!
//! - Every member is always present; an absent value (`tenant_id`,
//!   `previous_revision`, `new_revision`) is an explicit JSON `null`, so an
//!   absent and a present value hash differently.
//! - `timestamp` is RFC 3339 in UTC with `Z` and exactly six fractional
//!   digits, the stored microseconds, for example
//!   `2026-11-21T09:30:00.000000Z`, from `0000-01-01T00:00:00.000000Z` to
//!   `9999-12-31T23:59:59.999999Z`. Another year, which RFC 3339 cannot
//!   write but the `0007` range allows, has no envelope: the writer rejects
//!   it and the verifier reports a stored row with one as
//!   [`ChainBreak::Unencodable`] (lead decision, 2026-11-21, provisional).
//! - `actor` is IR-058's `{type, id}` object; JCS sorts `id` before `type`.
//!   The `actor` column stores the canonical JSON text of the same object,
//!   so the column and the envelope agree byte for byte. The system actor is
//!   `{"id":"system","type":"system"}`.
//! - `sequence` and the revisions are JSON integers. JCS writes numbers as
//!   IEEE 754 doubles, exact only up to `2^53 - 1`, so the writer rejects a
//!   larger revision or sequence (inferred).
//!
//! The serializer is hand-written for exactly these types (inferred: no JCS
//! crate). Member names are ASCII, so their fixed order is JCS's UTF-16
//! order. Strings are escaped as RFC 8785 section 3.2.2.2 requires: `\b`,
//! `\t`, `\n`, `\f`, `\r`, `\"` and `\\`, any other control character below
//! U+0020 as `\u00xx` with lowercase hex, and every other character as is.
//!
//! # Verifying
//!
//! [`verify_audit_chain`] reads the head and, in the same statement, whether
//! any event lies past it; then the events up to the head in sequence order,
//! a page at a time. Events up to a committed head are committed and
//! append-only, so the pages read them unchanged under any isolation level,
//! and an append committed meanwhile is not read. For each event it checks
//! that the sequences run from 1 without a gap, that its `prev_hash` is the
//! hash recomputed for the event before (`NULL` for the first), and
//! recomputes its hash from the stored columns exactly as the writer did.
//! Finally the head must be at the last event, with its recomputed hash, and
//! no event may lie past the head. The verdict names the first broken
//! sequence and why ([`ChainBreak`]). An edited event `k` breaks the link of
//! event `k + 1` (its `prev_hash` no longer matches), or the head when `k`
//! is the last event: no own hash is stored, so the edit shows where the
//! chain next records the hash.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, FromRow, PgConnection, Postgres, Row, Transaction, postgres::PgRow};

use super::{
    InvariantKind, RegistryError,
    event_actions::{is_audit_action, is_audit_action_syntax},
    micros,
    model::since_epoch,
};

/// The domain-separation prefix of IR-056: `skyoauth.audit.v1` and one zero
/// byte.
pub const AUDIT_HASH_PREFIX: &[u8] = b"skyoauth.audit.v1\0";

/// The largest integer JCS writes exactly, `2^53 - 1`.
pub const MAX_ENVELOPE_INTEGER: i64 = (1 << 53) - 1;

/// `0000-01-01T00:00:00.000000Z` in microseconds from the Unix epoch: the
/// earliest time an envelope writes.
const EARLIEST_ENVELOPE_MICROSECONDS: i64 = -62_167_219_200_000_000;

/// `9999-12-31T23:59:59.999999Z` in microseconds from the Unix epoch: the
/// latest time an envelope writes.
const LATEST_ENVELOPE_MICROSECONDS: i64 = 253_402_300_799_999_999;

/// The encode error for a time outside the years `0000` to `9999`.
const YEAR_OUT_OF_RANGE: &str = "audit timestamp outside the years 0000 to 9999";

/// Whether `microseconds` from the Unix epoch lies in the years `0000` to
/// `9999`, the ones RFC 3339 writes (see the module docs, "Envelope"). The
/// range lies inside the one [`since_epoch`] writes.
fn in_envelope_years(microseconds: i64) -> bool {
    (EARLIEST_ENVELOPE_MICROSECONDS..=LATEST_ENVELOPE_MICROSECONDS).contains(&microseconds)
}

/// Events read per statement by [`verify_audit_chain`] (inferred).
const VERIFY_PAGE: i64 = 500;

/// The microseconds [`since_epoch`] gives for `time`: truncated toward the
/// past, or an encode error outside the `0007` range.
fn microseconds_since_epoch(time: SystemTime) -> Result<i64, sqlx::Error> {
    Ok(since_epoch(time)?.microseconds)
}

/// The time `microseconds` from the Unix epoch, when it is in the range
/// [`since_epoch`] writes, so that it reads back as itself.
fn time_of_microseconds(microseconds: i64) -> Option<SystemTime> {
    let offset = Duration::from_micros(microseconds.unsigned_abs());
    let time = if microseconds >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    }?;
    (microseconds_since_epoch(time).ok()? == microseconds).then_some(time)
}

/// The actor of an audit event (IR-058; lead decision, 2026-11-21,
/// provisional until the maintainer ratifies the ADRs, T00.8 to T00.17,
/// Gate M0). There is no variant for bootstrap or break-glass recovery yet;
/// their reserved IDs are written as [`Operator`](Self::Operator) actors
/// (identity-registry IR-058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditActor {
    /// The reserved system actor `{"type": "system", "id": "system"}`, for
    /// events the service writes on its own (IR-058). Never a principal or
    /// an operator identity.
    System,
    /// An operator identity (`admin_identity`, T13.1), by ID, as
    /// `{"type": "operator", "id": …}` (inferred type name). The ID must not
    /// be empty.
    Operator(String),
}

impl AuditActor {
    /// The type member of the actor object.
    fn kind(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Operator(_) => "operator",
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::System => "system",
            Self::Operator(id) => id,
        }
    }

    /// The canonical (JCS) JSON text of the actor object, as stored in the
    /// `actor` column and embedded in the envelope:
    /// `{"id":…,"type":…}`.
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"id\":");
        push_string(&mut out, self.id());
        out.push_str(",\"type\":");
        push_string(&mut out, self.kind());
        out.push('}');
        out
    }

    /// The actor whose [`canonical_json`](Self::canonical_json) is exactly
    /// `text`, or `None`: another type, a system actor with another ID, an
    /// empty operator ID, or any text that is not the canonical form
    /// (other spacing, member order or escapes).
    pub fn from_canonical_json(text: &str) -> Option<Self> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Object {
            id: String,
            #[serde(rename = "type")]
            kind: String,
        }
        let object: Object = serde_json::from_str(text).ok()?;
        let actor = match (&object.kind[..], object.id) {
            ("system", id) if id == "system" => Self::System,
            ("operator", id) if !id.is_empty() => Self::Operator(id),
            _ => return None,
        };
        (actor.canonical_json() == text).then_some(actor)
    }
}

/// The input of [`append_audit_event`]. The chain assigns `sequence` and
/// `prev_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    /// Caller-generated (T10.2).
    pub id: String,
    /// `None` for an instance-scope event (OQ-IR-14).
    pub tenant_id: Option<String>,
    /// Truncated toward the past to a whole microsecond.
    pub timestamp: SystemTime,
    pub actor: AuditActor,
    /// A name of [`AUDIT_ACTIONS`](super::AUDIT_ACTIONS).
    pub action: String,
    /// The audited object's ID; the `instance_id` for an instance-scope
    /// event (IR-057).
    pub object_id: String,
    /// `None` when there is no such revision, for example on a create.
    pub previous_revision: Option<i64>,
    pub new_revision: Option<i64>,
    pub outcome: String,
}

/// A stored audit event, with its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: Option<String>,
    pub sequence: i64,
    /// `None` for the first event.
    pub prev_hash: Option<[u8; 32]>,
    pub timestamp: SystemTime,
    pub actor: AuditActor,
    pub action: String,
    pub object_id: String,
    pub previous_revision: Option<i64>,
    pub new_revision: Option<i64>,
    pub outcome: String,
    /// The event's own hash (IR-056); not a column.
    pub hash: [u8; 32],
}

impl AuditEvent {
    /// The RFC 8785 canonical JSON of the event's envelope (see the module
    /// docs). An encode error ([`RegistryError::Other`]) for a sequence or
    /// revision above `2^53 - 1` or a timestamp outside the years `0000` to
    /// `9999`.
    pub fn envelope(&self) -> Result<String, RegistryError> {
        Ok(self.fields().envelope()?)
    }

    /// The event's hash recomputed from its fields and `prev_hash`, as
    /// [`append_audit_event`] and [`verify_audit_chain`] compute it. It
    /// ignores [`hash`](Self::hash).
    pub fn compute_hash(&self) -> Result<[u8; 32], RegistryError> {
        Ok(event_hash(self.prev_hash.as_ref(), &self.envelope()?))
    }

    fn fields(&self) -> Fields<'_> {
        Fields {
            id: &self.id,
            tenant_id: self.tenant_id.as_deref(),
            sequence: self.sequence,
            timestamp: Timestamp::Time(self.timestamp),
            actor: &self.actor,
            action: &self.action,
            object_id: &self.object_id,
            previous_revision: self.previous_revision,
            new_revision: self.new_revision,
            outcome: &self.outcome,
        }
    }
}

/// The timestamp of an envelope: a time, or the microseconds a row holds.
#[derive(Clone, Copy)]
enum Timestamp {
    Time(SystemTime),
    Microseconds(i64),
}

/// The envelope members of an event.
struct Fields<'a> {
    id: &'a str,
    tenant_id: Option<&'a str>,
    sequence: i64,
    timestamp: Timestamp,
    actor: &'a AuditActor,
    action: &'a str,
    object_id: &'a str,
    previous_revision: Option<i64>,
    new_revision: Option<i64>,
    outcome: &'a str,
}

fn encode_error(message: &'static str) -> sqlx::Error {
    sqlx::Error::Encode(message.into())
}

impl Fields<'_> {
    /// The canonical JSON of the envelope. The members are written in JCS
    /// order (their names are ASCII, so UTF-16 order is byte order).
    fn envelope(&self) -> Result<String, sqlx::Error> {
        let microseconds = match self.timestamp {
            Timestamp::Time(time) => microseconds_since_epoch(time)?,
            Timestamp::Microseconds(microseconds) => microseconds,
        };
        // Inside the range since_epoch writes, so a row reads as written.
        if !in_envelope_years(microseconds) {
            return Err(encode_error(YEAR_OUT_OF_RANGE));
        }
        let mut out = String::with_capacity(256);
        out.push_str("{\"action\":");
        push_string(&mut out, self.action);
        out.push_str(",\"actor\":");
        out.push_str(&self.actor.canonical_json());
        out.push_str(",\"id\":");
        push_string(&mut out, self.id);
        out.push_str(",\"new_revision\":");
        push_integer(&mut out, self.new_revision)?;
        out.push_str(",\"object_id\":");
        push_string(&mut out, self.object_id);
        out.push_str(",\"outcome\":");
        push_string(&mut out, self.outcome);
        out.push_str(",\"previous_revision\":");
        push_integer(&mut out, self.previous_revision)?;
        out.push_str(",\"sequence\":");
        push_integer(&mut out, Some(self.sequence))?;
        out.push_str(",\"tenant_id\":");
        match self.tenant_id {
            Some(tenant_id) => push_string(&mut out, tenant_id),
            None => out.push_str("null"),
        }
        out.push_str(",\"timestamp\":");
        push_string(&mut out, &rfc3339_microseconds(microseconds));
        out.push('}');
        Ok(out)
    }
}

/// Appends `value` as a JCS integer, or `null`.
fn push_integer(out: &mut String, value: Option<i64>) -> Result<(), sqlx::Error> {
    match value {
        None => out.push_str("null"),
        Some(value) if (-MAX_ENVELOPE_INTEGER..=MAX_ENVELOPE_INTEGER).contains(&value) => {
            out.push_str(&value.to_string());
        }
        Some(_) => return Err(encode_error("audit integer above 2^53 - 1")),
    }
    Ok(())
}

/// Appends `value` as a JCS string (RFC 8785 section 3.2.2.2).
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if control < '\u{20}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// `microseconds` from the Unix epoch as RFC 3339 in UTC with six
/// fractional digits and `Z`. The caller keeps it in the years `0000` to
/// `9999` ([`in_envelope_years`]).
fn rfc3339_microseconds(microseconds: i64) -> String {
    const PER_DAY: i64 = 86_400_000_000;
    let days = microseconds.div_euclid(PER_DAY);
    let of_day = microseconds.rem_euclid(PER_DAY);
    // Howard Hinnant's civil_from_days, proleptic Gregorian, year 0 = 1 BC.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let seconds = of_day / 1_000_000;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        seconds / 3_600,
        seconds / 60 % 60,
        seconds % 60,
        of_day % 1_000_000
    )
}

/// IR-056's hash of an envelope after `prev_hash`.
fn event_hash(prev_hash: Option<&[u8; 32]>, envelope: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_HASH_PREFIX);
    if let Some(prev_hash) = prev_hash {
        hasher.update(prev_hash);
    }
    hasher.update(envelope.as_bytes());
    hasher.finalize().into()
}

/// The stored columns of an event, the timestamp as [`micros!`] gives it.
macro_rules! event_columns {
    () => {
        concat!(
            "id, tenant_id, sequence, prev_hash, ",
            micros!("timestamp"),
            ", actor, action, object_id, previous_revision, new_revision, outcome"
        )
    };
}

/// Locks a tenant-scope event's tenant row before the head, as strongly as
/// the insert's foreign-key check does (see the module docs).
const LOCK_TENANT: &str = "SELECT 1 FROM tenant WHERE id = $1 FOR KEY SHARE";

/// Locks the head and reads the schema of `audit_event`, as the
/// `search_path` resolves it, quoted as an identifier.
const LOCK_HEAD: &str = "SELECT h.sequence, h.head_hash, \
     (SELECT pg_catalog.quote_ident(n.nspname) FROM pg_catalog.pg_class c \
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
      WHERE c.oid = 'audit_event'::pg_catalog.regclass) AS event_schema \
     FROM audit_chain_head h FOR UPDATE";

/// The deferred `0002` constraint trigger the append keeps deferred, after
/// the quoted schema and a dot.
const HEAD_REACHED: &str = "audit_event_head_reached";

const INSERT_EVENT: &str = concat!(
    "INSERT INTO audit_event (id, tenant_id, sequence, prev_hash, timestamp, actor, action, \
     object_id, previous_revision, new_revision, outcome) \
     VALUES ($1, $2, $3, $4, timestamptz 'epoch' + $5, $6, $7, $8, $9, $10, $11) RETURNING ",
    event_columns!()
);

const ADVANCE_HEAD: &str = "UPDATE audit_chain_head SET sequence = $1, head_hash = $2";

/// A stored hash column as 32 bytes, or `None` when it is not 32 bytes.
fn digest(bytes: Vec<u8>) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Appends `event` to the chain in `transaction`, after the domain rows (see
/// the module docs for the order and the `administrative_operation`
/// exception), and returns the stored event with its hash.
pub async fn append_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewAuditEvent,
) -> Result<AuditEvent, RegistryError> {
    if !is_audit_action_syntax(&event.action) {
        return Err(encode_error("audit action is not <resource>.<verb>").into());
    }
    if !is_audit_action(&event.action) {
        return Err(encode_error("audit action is not in the action table").into());
    }
    if event.actor.id().is_empty() {
        return Err(encode_error("audit actor ID is empty").into());
    }
    let interval = since_epoch(event.timestamp)?;
    if !in_envelope_years(interval.microseconds) {
        return Err(encode_error(YEAR_OUT_OF_RANGE).into());
    }
    let mut fields = Fields {
        id: &event.id,
        tenant_id: event.tenant_id.as_deref(),
        // Checked again below with the real sequence; 1 checks the rest.
        sequence: 1,
        timestamp: Timestamp::Microseconds(interval.microseconds),
        actor: &event.actor,
        action: &event.action,
        object_id: &event.object_id,
        previous_revision: event.previous_revision,
        new_revision: event.new_revision,
        outcome: &event.outcome,
    };
    fields.envelope()?;

    if let Some(tenant_id) = &event.tenant_id {
        let tenant = sqlx::query(LOCK_TENANT)
            .bind(tenant_id)
            .fetch_optional(&mut **transaction)
            .await?;
        if tenant.is_none() {
            // What the insert's foreign-key check would have given.
            return Err(RegistryError::Invariant {
                kind: InvariantKind::ForeignKey,
                constraint: Some("audit_event_tenant_id_fkey"),
            });
        }
    }
    let head = sqlx::query(LOCK_HEAD).fetch_one(&mut **transaction).await?;
    let schema: String = head.try_get("event_schema")?;
    // The schema is an identifier PostgreSQL quoted.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "SET CONSTRAINTS {schema}.{HEAD_REACHED} DEFERRED"
    )))
    .execute(&mut **transaction)
    .await?;
    let head_sequence: i64 = head.try_get("sequence")?;
    let prev_hash = match head.try_get::<Option<Vec<u8>>, _>("head_hash")? {
        None => None,
        Some(bytes) => Some(digest(bytes).ok_or_else(|| sqlx::Error::ColumnDecode {
            index: "head_hash".into(),
            source: "audit chain head hash is not 32 bytes".into(),
        })?),
    };
    fields.sequence = head_sequence + 1;
    let hash = event_hash(prev_hash.as_ref(), &fields.envelope()?);

    let row = sqlx::query(INSERT_EVENT)
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(fields.sequence)
        .bind(prev_hash.map(Vec::from))
        .bind(interval)
        .bind(event.actor.canonical_json())
        .bind(&event.action)
        .bind(&event.object_id)
        .bind(event.previous_revision)
        .bind(event.new_revision)
        .bind(&event.outcome)
        .fetch_one(&mut **transaction)
        .await?;
    sqlx::query(ADVANCE_HEAD)
        .bind(fields.sequence)
        .bind(&hash[..])
        .execute(&mut **transaction)
        .await?;
    let stored = StoredEvent::from_row(&row)?;
    let decode = |source: &'static str| sqlx::Error::ColumnDecode {
        index: "audit_event".into(),
        source: source.into(),
    };
    Ok(AuditEvent {
        prev_hash,
        timestamp: time_of_microseconds(stored.timestamp_us)
            .ok_or_else(|| decode("timestamp out of range"))?,
        actor: AuditActor::from_canonical_json(&stored.actor)
            .ok_or_else(|| decode("actor is not canonical"))?,
        id: stored.id,
        tenant_id: stored.tenant_id,
        sequence: stored.sequence,
        action: stored.action,
        object_id: stored.object_id,
        previous_revision: stored.previous_revision,
        new_revision: stored.new_revision,
        outcome: stored.outcome,
        hash,
    })
}

/// An event row as stored, read without interpretation.
struct StoredEvent {
    id: String,
    tenant_id: Option<String>,
    sequence: i64,
    prev_hash: Option<Vec<u8>>,
    timestamp_us: i64,
    actor: String,
    action: String,
    object_id: String,
    previous_revision: Option<i64>,
    new_revision: Option<i64>,
    outcome: String,
}

impl FromRow<'_, PgRow> for StoredEvent {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            sequence: row.try_get("sequence")?,
            prev_hash: row.try_get("prev_hash")?,
            timestamp_us: row.try_get("timestamp_us")?,
            actor: row.try_get("actor")?,
            action: row.try_get("action")?,
            object_id: row.try_get("object_id")?,
            previous_revision: row.try_get("previous_revision")?,
            new_revision: row.try_get("new_revision")?,
            outcome: row.try_get("outcome")?,
        })
    }
}

impl StoredEvent {
    /// The hash the writer computed for this row, or `None` when the writer
    /// could not have written it: an actor that is not canonical, a time
    /// outside the years `0000` to `9999`, or an integer above `2^53 - 1`.
    fn recompute(&self) -> Option<[u8; 32]> {
        // The marker micros! gives for a time outside the readable range is
        // outside those years, so envelope() rejects it.
        let prev_hash = match &self.prev_hash {
            None => None,
            Some(bytes) => Some(digest(bytes.clone())?),
        };
        let actor = AuditActor::from_canonical_json(&self.actor)?;
        let envelope = Fields {
            id: &self.id,
            tenant_id: self.tenant_id.as_deref(),
            sequence: self.sequence,
            timestamp: Timestamp::Microseconds(self.timestamp_us),
            actor: &actor,
            action: &self.action,
            object_id: &self.object_id,
            previous_revision: self.previous_revision,
            new_revision: self.new_revision,
            outcome: &self.outcome,
        }
        .envelope()
        .ok()?;
        Some(event_hash(prev_hash.as_ref(), &envelope))
    }
}

/// Why [`verify_audit_chain`] found the chain broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBreak {
    /// The event with this sequence is missing: the sequences do not run
    /// from 1 without a gap up to the head.
    Gap,
    /// This event's `prev_hash` is not the hash recomputed for the event
    /// before it (`NULL` for the first event): this event or the one before
    /// was changed.
    PrevHashMismatch,
    /// The head's `head_hash` is not the hash recomputed for the last event
    /// (the sequence is the head's), or an event lies past the head (the
    /// sequence is the head's plus one).
    HeadMismatch,
    /// The writer could not have written this event, so it has no hash: an
    /// actor that is not the canonical JSON of a known actor, a time outside
    /// the years `0000` to `9999` (which the `0007` range check allows), a
    /// hash column that is not 32 bytes, or an integer above `2^53 - 1`.
    Unencodable,
}

/// The outcome of [`verify_audit_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainVerdict {
    /// Every event from 1 to the head links and the head records the last
    /// one's hash; `last_sequence` is 0 for an empty chain.
    Intact { last_sequence: i64 },
    /// The first broken sequence and why.
    Broken { sequence: i64, reason: ChainBreak },
}

const READ_HEAD: &str = "SELECT sequence, head_hash, \
     EXISTS (SELECT FROM audit_event WHERE audit_event.sequence > h.sequence) AS past_head \
     FROM audit_chain_head h";

const READ_EVENTS: &str = concat!(
    "SELECT ",
    event_columns!(),
    " FROM audit_event WHERE sequence > $1 AND sequence <= $2 ORDER BY sequence LIMIT $3"
);

/// Verifies the whole chain (see the module docs). A store failure is an
/// error; a broken chain is a [`ChainVerdict::Broken`].
///
/// Deleting the tail and rewinding the head, or deleting every event and
/// resetting the head, verifies as [`ChainVerdict::Intact`]: only the
/// external sink (OQ-TM-12) catches that.
pub async fn verify_audit_chain(
    connection: &mut PgConnection,
) -> Result<ChainVerdict, RegistryError> {
    let head = sqlx::query(READ_HEAD).fetch_one(&mut *connection).await?;
    let head_sequence: i64 = head.try_get("sequence")?;
    let head_hash: Option<Vec<u8>> = head.try_get("head_hash")?;
    let past_head: bool = head.try_get("past_head")?;
    let broken = |sequence, reason| Ok(ChainVerdict::Broken { sequence, reason });

    let mut previous: Option<[u8; 32]> = None;
    let mut last = 0;
    while last < head_sequence {
        let rows = sqlx::query(READ_EVENTS)
            .bind(last)
            .bind(head_sequence)
            .bind(VERIFY_PAGE)
            .fetch_all(&mut *connection)
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let event = StoredEvent::from_row(row)?;
            let expected = last + 1;
            if event.sequence != expected {
                return broken(expected, ChainBreak::Gap);
            }
            if event.prev_hash.as_deref() != previous.as_ref().map(|hash| &hash[..]) {
                return broken(expected, ChainBreak::PrevHashMismatch);
            }
            let Some(hash) = event.recompute() else {
                return broken(expected, ChainBreak::Unencodable);
            };
            previous = Some(hash);
            last = expected;
        }
    }
    if last < head_sequence {
        return broken(last + 1, ChainBreak::Gap);
    }
    if head_hash.as_deref() != previous.as_ref().map(|hash| &hash[..]) {
        return broken(head_sequence, ChainBreak::HeadMismatch);
    }
    if past_head {
        return broken(head_sequence + 1, ChainBreak::HeadMismatch);
    }
    Ok(ChainVerdict::Intact {
        last_sequence: head_sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(value: &str) -> String {
        let mut out = String::new();
        push_string(&mut out, value);
        out
    }

    /// RFC 8785 section 3.2.2.2, with the example string of that section.
    #[test]
    fn strings_escape_as_rfc_8785_requires() {
        assert_eq!(string(""), r#""""#);
        assert_eq!(string("\u{8}\t\n\u{c}\r\"\\"), r#""\b\t\n\f\r\"\\""#);
        assert_eq!(string("\u{0}\u{1}\u{1f}"), r#""\u0000\u0001\u001f""#);
        assert_eq!(string("\u{b}\u{1a}"), r#""\u000b\u001a""#);
        // Not escaped: the solidus, DEL, C1 controls, U+2028 and non-ASCII.
        assert_eq!(string("/\u{7f}\u{80}"), "\"/\u{7f}\u{80}\"");
        assert_eq!(string("\u{2028}\u{2029}"), "\"\u{2028}\u{2029}\"");
        // RFC 8785 section 3.2.2.2's example string.
        assert_eq!(
            string("\u{20ac}$\u{f}\nA'B\"\\\\\"/"),
            "\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\""
        );
        assert_eq!(string("\u{1f600}"), "\"\u{1f600}\"");
    }

    #[test]
    fn integers_are_exact_up_to_two_to_the_53_minus_one() {
        let mut out = String::new();
        push_integer(&mut out, Some(MAX_ENVELOPE_INTEGER)).unwrap();
        push_integer(&mut out, None).unwrap();
        assert_eq!(out, "9007199254740991null");
        assert!(push_integer(&mut String::new(), Some(MAX_ENVELOPE_INTEGER + 1)).is_err());
        assert!(push_integer(&mut String::new(), Some(i64::MAX)).is_err());
    }

    #[test]
    fn timestamps_have_six_digits_and_z() {
        for (microseconds, text) in [
            (0, "1970-01-01T00:00:00.000000Z"),
            (1, "1970-01-01T00:00:00.000001Z"),
            (-1, "1969-12-31T23:59:59.999999Z"),
            (951_782_400_000_000, "2000-02-29T00:00:00.000000Z"),
            (1_795_253_400_123_456, "2026-11-21T09:30:00.123456Z"),
            (-62_135_596_800_000_000, "0001-01-01T00:00:00.000000Z"),
            (-62_135_596_800_000_001, "0000-12-31T23:59:59.999999Z"),
            (-62_162_035_200_000_000, "0000-03-01T00:00:00.000000Z"),
            (-62_162_035_200_000_001, "0000-02-29T23:59:59.999999Z"),
            // The bounds.
            (-62_167_219_200_000_000, "0000-01-01T00:00:00.000000Z"),
            (253_402_300_799_999_999, "9999-12-31T23:59:59.999999Z"),
        ] {
            assert!(in_envelope_years(microseconds), "{microseconds}");
            assert_eq!(rfc3339_microseconds(microseconds), text, "{microseconds}");
        }
    }

    #[test]
    fn only_the_years_0000_to_9999_are_written() {
        for (microseconds, inside) in [
            (-62_167_219_200_000_001, false),
            (-62_167_219_200_000_000, true),
            (253_402_300_799_999_999, true),
            (253_402_300_800_000_000, false),
            // The 0007 bounds, and the marker of an unreadable time.
            (-210_866_803_200_000_000, false),
            (i64::MAX - 1, false),
            (i64::MAX, false),
            (i64::MIN, false),
        ] {
            assert_eq!(in_envelope_years(microseconds), inside, "{microseconds}");
            let actor = AuditActor::System;
            let fields = Fields {
                id: "aud_1",
                tenant_id: None,
                sequence: 1,
                timestamp: Timestamp::Microseconds(microseconds),
                actor: &actor,
                action: "tenant.create",
                object_id: "ten_a",
                previous_revision: None,
                new_revision: None,
                outcome: "success",
            };
            match fields.envelope() {
                Ok(envelope) => assert!(inside, "{envelope}"),
                Err(err) => {
                    assert!(!inside, "{microseconds}");
                    assert_eq!(
                        err.to_string(),
                        format!("{}", encode_error(YEAR_OUT_OF_RANGE))
                    );
                }
            }
        }
    }

    #[test]
    fn actors_serialize_canonically_and_parse_only_the_canonical_form() {
        assert_eq!(
            AuditActor::System.canonical_json(),
            r#"{"id":"system","type":"system"}"#
        );
        let operator = AuditActor::Operator("adm_1\n\"x\"".into());
        assert_eq!(
            operator.canonical_json(),
            r#"{"id":"adm_1\n\"x\"","type":"operator"}"#
        );
        for actor in [AuditActor::System, operator] {
            assert_eq!(
                AuditActor::from_canonical_json(&actor.canonical_json()),
                Some(actor)
            );
        }
        for text in [
            r#"{"type":"system","id":"system"}"#,
            r#"{"id": "system","type":"system"}"#,
            r#"{"id":"system","type":"system"} "#,
            // An escaped "s": the same value, not the canonical text.
            "{\"id\":\"\\u0073ystem\",\"type\":\"system\"}",
            r#"{"id":"other","type":"system"}"#,
            r#"{"id":"","type":"operator"}"#,
            r#"{"id":"adm_1","type":"principal"}"#,
            r#"{"id":"adm_1","type":"operator","x":1}"#,
            r#"{"id":"adm_1"}"#,
            r#""system""#,
            "system",
            "",
        ] {
            assert_eq!(AuditActor::from_canonical_json(text), None, "{text}");
        }
    }

    #[test]
    fn the_first_event_hashes_no_previous_bytes() {
        let envelope = "{}";
        let mut first = Sha256::new();
        first.update(b"skyoauth.audit.v1\0{}");
        assert_eq!(
            event_hash(None, envelope),
            <[u8; 32]>::from(first.finalize())
        );
        let mut next = Sha256::new();
        next.update(b"skyoauth.audit.v1\0");
        next.update([7; 32]);
        next.update(b"{}");
        assert_eq!(
            event_hash(Some(&[7; 32]), envelope),
            <[u8; 32]>::from(next.finalize())
        );
        assert_ne!(
            event_hash(None, envelope),
            event_hash(Some(&[0; 32]), envelope)
        );
    }
}
