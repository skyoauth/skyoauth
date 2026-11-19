# ADR-002: Signer isolation and recovery

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.8 (signer parts). Implementation: T20.2 (public
  signer/JWKS, M2), T32.14 (internal signer group, M3), T50.3, T52.5.
- **Baseline (tasks §11):** "Public signer/JWKS M2; shared internal
  signer-group keys/private set M3 with publication/cache/readiness bounds and
  measured cost. Active plus separately held eligible standby, audited clean
  promotion/degraded replenishment. Live verified-standby-use tripwire
  denies/alerts; offline prepublished key sets cannot enforce instantaneous
  state. Per-replica enrollment remains a future alternative."
- **Contracts:** [token-profiles.md](../contracts/token-profiles.md) §2, §7,
  §8; [public-api.md](../contracts/public-api.md) §5, §7;
  [lifetimes.md](../contracts/lifetimes.md) §8.

## Context

T00.8 asks M0 to ratify "distinct public/internal signer isolation and
separately held eligible standby, live standby-use tripwire with explicit
offline limitation, native comparison/required refresh, signed internal
evidence and minimal dormant-policy preservation". This ADR covers the signer
parts: signer isolation, the standby, the tripwire and signed internal
evidence. Native comparison and required refresh belong to ADR-004 and
dormant-policy preservation to ADR-006 (this split is inferred from the
tasks §11 baselines).

Two signers exist. The public access-token signer signs `wif` and `human_cli`
access JWTs (design §6). The internal signer signs short-lived `human_session`
assertions that the gateway forwards to backends (design §6, §6.2). Design §9
names signer compromise as a threat; design §12 lists signer custody and
recovery among the decisions requiring ratification.

## Decision

### Public access-token signer

1. Signing keys are asymmetric, bridge-owned, isolated and versioned with kid
   and overlap. Retired public keys are retained through the maximum issued
   TTL plus skew. There are no upstream signing keys and no plaintext key
   export (design §6).
2. The public signer's keys and permissions are isolated from public handlers
   and from operator and reviewer credentials. The signer can be separately
   deployed or use a KMS/HSM (design §3.1).
3. M1a defines public-key metadata (`IssuerKeyVersion`); M2/T20 implements the
   public signer and JWKS, with access TTL at most 300 seconds (design §6;
   T20.2). Provider migration does not rotate keys (design §6).

### Internal assertion signer group

4. Public access-token keys and internal assertion keys are distinct key pairs
   with disjoint kid namespaces and non-interchangeable trust sets. The
   gateway's internal assertions never use the public issuer key (design
   §3.1, §6.2; T20.2).
5. The v0.1 model is one versioned key per deployment signer group, shared
   only by that group's authorized auth replicas, not a freshly generated key
   per replica. Scale-out loads the already-published active key from
   protected deployment secret storage or startup unwrapping; it enrolls no
   new trust identity. Replicas have no public access-signing permission. A
   shared compromise affects the whole signer group (design §6.2).
6. Only instance `security_admin`, through audited key administration
   (`/admin/v1/internal-assertion-keys`), enrolls, rotates and disables group
   keys and authorizes private-key distribution. Public clients and auth
   replicas cannot self-register a kid or key (design §6.2; tasks §2
   "Endpoint matrix").
7. Verifiers obtain the internal public set only from the authenticated
   private `/internal/v1/assertion-jwks`, with a version/ETag and at most
   60 seconds of cache freshness, with no stale-on-error extension. An unknown
   kid may trigger one bounded, rate-limited, single-flight refetch of that
   fixed endpoint, with negative caching; failure or a still-unknown or
   disabled key denies. Profile and ingress select the trust set before kid
   lookup (design §6.2).
8. **Publication and readiness.** A new group or key version is published
   before `activate_after`, which is at least the maximum verifier cache
   interval plus allowed skew later. Readiness requires loading a registered
   key, confirming the published set/version and waiting until
   `activate_after`; new verifier processes fetch the current set before
   readiness. Ordinary scale-out of an active group needs no new-key delay.
   Rotation keeps the prior signer through overlap; a failed publication
   prevents activation, not verification (design §6.2).

### Standby, tripwire and compromise recovery

9. **Eligible standby.** Production commissioning and planned-rotation
   completion require one active version plus at least one prepublished,
   unexpired standby per signer group, already past `activate_after`.
   `signing_state=standby` forbids issuing with the key; it is distinct from
   verification eligibility. The standby private key is in separately
   access-controlled encrypted custody: ordinary auth replicas cannot mount,
   unwrap or read it before promotion (design §6.2).
10. **Live standby-use tripwire.** After verifying the signature, live policy
    checks, continuation admission and rechecks consult authoritative key
    state and deny evidence whose admitting key is still an unpromoted
    standby, raising a rate-bounded compromise alert with key and decision
    identifiers, never token bytes. An invalid signature that merely names a
    standby kid does not raise the verified-compromise alert. Offline
    signature verification alone cannot enforce this tripwire, because
    standby public keys are intentionally prepublished; SkyOAuth does not
    claim otherwise (design §6.2).
11. **Clean promotion.** On compromise, instance `security_admin` disables the
    affected version and promotes an eligible unaffected standby through an
    audited, revision-checked key operation, then distributes it only to
    isolated, rebuilt or otherwise verified-clean replicas. A newly enrolled
    key's `activate_after` is never waived. Promotion removes the publication
    wait, not the time needed for containment, key delivery or replica
    recovery (design §6.2).
12. **Degraded replenishment and fail closed.** Promotion may run in an
    alerted degraded-redundancy state while a new standby is enrolled and
    matures; lack of a replacement standby does not block the promoted clean
    signer. With no trusted eligible standby, the group fails closed until
    recovery rather than using compromised material. Promotion cannot
    resurrect contexts admitted under a disabled key (design §6.2).
13. **Retention.** Retired internal verification keys are kept for the
    30-second assertion lifetime plus skew; compromised or disabled keys are
    rejected. Key status and provenance records are kept through all
    dependent continuation deadlines; continuations retain the admitting
    internal kid and deny on its compromise or disable (design §6.2).

### Cost

14. Expected cookie-path work is bounded metadata parsing, a live session and
    policy read, one local asymmetric signature and backend verification. The
    baseline has no per-request KMS/HSM or network signing round trip and no
    cached reusable request assertion. A separately mandated remote internal
    signer is an explicit deployment variant whose availability and latency
    must be measured; its failure denies. T32.14 benchmarks the cost; no
    unmeasured performance claim is made (design §6.2).

## Consequences and requirements

- Contract requirements: TP-010, TP-011, TP-014, TP-015 (trust-set selection
  and key lookup), TP-061 (retention of retired keys), TP-082 (standby-use
  tripwire), API-090, API-091 (`/internal/v1/assertion-jwks`), API-151 (key
  enrollment by `security_admin` only), LT-070, LT-071 and the lifetimes §8
  table (cache, `activate_after`, retention), IR-012 (no key rotation on a
  provider switch).
- A compromised internal signer can forge internal evidence within its trusted
  boundary and stays high-impact, but cannot mint public access tokens; live
  checks additionally compare identity fields to the session and
  authentication records (design §6.2).
- An offline verifier can lag an internal key disable by at most its remaining
  cache freshness, 60 seconds at most; previously granted stream leases keep
  only their stated bound (design §6.2; lifetimes §8).
- Zero static application secrets does not mean zero privileged keys: signer
  trust still needs protection (design §9).
- Conformance rows: A62 (signer scale-out, rotation, compromise and standby),
  A19 (issuer-key rotation), A55 (key-purpose and profile
  separation), A21 (residual offline TTL).

## Alternatives considered

- **Per-replica internal keys.** Remains a future alternative that requires a
  separate enrollment design, not an ambiguous second baseline (design §6.2;
  tasks §11).
- **A freshly generated key per replica at scale-out.** Rejected: scale-out
  reuses the published group key and enrolls no new trust identity (design
  §6.2; tasks §3 "Key separation").
- **A remote internal signer (KMS/HSM per request).** Not the baseline; an
  explicit deployment variant that must be measured (design §6.2).
- **Signing internal assertions with the public issuer key.** Rejected (design
  §3.1, §6.2; T20.2).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-3** — no operator endpoint administers public issuer keys (open).
- **OQ-API-12** — who may fetch `/internal/v1/assertion-jwks`: only
  registered checkers and gateway trust consumers, or other verifying
  backends (open; lead lean recorded, not decided).
- **OQ-TP-3** — allowed JWS algorithm set (open).
- **OQ-LT-11** — unknown-kid refetch rate limit and negative-cache duration
  (open).
- **OQ-TP-10 / OQ-LT-16** — clock skew. Decided (lead decision, 2026-11-19):
  default 60 s, ceiling 120 s; used by every "plus skew" retention above.

New questions raised by this ADR:

- **OQ-ADR002-1 — Standby for the public signer.** Design §6.2 defines the
  eligible standby, tripwire and clean promotion for the internal signer
  group. T50.3 ("Isolate public/internal signers ... Provision eligible
  standby in separate custody, audited clean promotion and replenishment") and
  A62 ("Signer scale-out/rotation, compromise/standby promotion") do not say
  which signer they mean. Whether the public access-token signer also needs a
  separately held standby is not stated.
- **OQ-ADR002-2 — Public key compromise.** Design §6 bounds the retention of
  retired public keys, and design §6.2 bounds the internal key-set cache at
  60 seconds. No cache freshness bound is given for verifiers of the issuer
  JWKS, and no procedure is given for removing a compromised public signing
  key before its retention ends.

## Tests

- A62 — eligible standby prepublished with separate custody; audited clean
  promotion; tripwire denies and alerts on valid unpromoted-standby evidence;
  invalid-signature kid spoof raises no verified alert; offline limitation
  explicit; disabled active key with no eligible standby fails closed.
- A19 — public key rotation through overlap.
- A55 — key-purpose and profile separation.
- Task tests: T32.14 (scale-out, cache, outage, unknown-kid flood, provenance,
  benchmark), T50.3, T52.5 (signer separation, rotation, disable, standby
  misuse).
