# ADR-006: Grant modes and dormant impersonation

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.9 (RFC 8693 direct exchange versus the private
  service-delegation actor grant) and with the dormant-policy parts of T00.8
  and T00.16 (inferred: tasks §2 names no ADR in these tasks).
  Implementation: T10.11, T12.4, T12.5, T12.10, T21.4.
- **Baseline (tasks §11):** "Required direct/delegation; retain disabled
  impersonation policy only, active subsystem/approval machinery deferred".
- **Contracts:** [public-api.md](../contracts/public-api.md) §2.1, §7.2,
  [identity-registry.md](../contracts/identity-registry.md) §5.1,
  [token-profiles.md](../contracts/token-profiles.md) §5.

## Context

v0.1 requires direct workload access and attributed service delegation; it
does not require active true impersonation (tasks §0; design §1.3). Stored WIF
policy, including grants of a mode the release does not support, must survive
human-provider migrations, and schema migrations/upgrades between tagged public
releases, without reset (design §1 "Unsupported impersonation policy remains
disabled, including after a capability upgrade", §2 C06). No upgrade is
supported before the first beta release: an earlier database is recreated, not
migrated (wording amendment per the user's ruling of 2026-11-24: "Amend the
design to clarify that only migration across tagged public releases are
supported, i.e, there is no need to do migration before the first beta
releases. The db migration mechanism must be there and tested."; design §1.1
goal 4; `service/migrations/README.md`, "Conventions").
Design §5.6 defines the modes; design §5.7 defines the two wire profiles that
carry them. T00.9 asks M0 to specify "RFC 8693 direct subject exchange versus
private service-delegation actor grant ... and unsupported two-token
delegation". Selection, binding evaluation, scope defaults and errors are
ADR-015.

## Decision

### Required modes

1. **Direct workload.** The grant's workload actor becomes `sub`; the target
   service is null; audience, scope and resource ceilings still apply (design
   §5.6). Wire profile: RFC 8693
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with
   `subject_token` of type `urn:ietf:params:oauth:token-type:jwt`; an
   `actor_token` is not accepted (design §5.7 table).
2. **Delegation.** The preapproved service becomes `sub` and the workload
   becomes RFC 8693 `act.sub`; source and run provenance and the effective
   revision are retained in audit (design §5.6). Wire profile: the private
   `grant_type=urn:skyoauth:params:oauth:grant-type:service-delegation` with
   `actor_token` of type `urn:ietf:params:oauth:token-type:jwt`; a
   `subject_token` is not accepted (design §5.7 table).
3. **Why two grant types.** RFC 8693 distinguishes subject and actor proofs. A
   single workload assertion is not a service subject token. The private
   extension uses administrator-owned target authorization and is not
   advertised as standard two-token delegation or as an IANA-registered grant
   (design §5.7; T00.9).
4. **Grant shape.** Direct grants require a null target service; delegated
   grants require a same-tenant service (tasks §3 "Ownership"). Tenant
   `trust_admin` enables supported direct and delegation grants (design §7.2).
5. **Token claims.** Both modes issue the `wif` profile with signed
   `skyoauth_mode` (`direct` or `delegation`) and `skyoauth_grant`; only
   delegation carries `act` (design §6).

### Impersonation: preservation only

6. True impersonation is a conditional high-risk mode that omits a
   target-visible actor. It is not required for v0.1 and is never a fallback
   for another mode (design §5.6).
7. An unsupported impersonation grant has a defined write path: authorized
   create or import accepts it only with `status: disabled` and
   `activation_state: requires_reapproval`, storing its full desired
   constraints and provenance in the existing grant record. An enabled or
   approved unsupported record is rejected, not silently activated or treated
   as delegation (design §5.6; T10.11).
8. Feature availability, import, ordinary PATCH or provider migration cannot
   enable such a record. A release that gains the capability leaves it
   disabled and requiring approval (design §5.6).
9. v0.1 implements no activation: no `GrantActivationApproval` table, no
   activation endpoint, no two-person ceremony and no active-impersonation
   release gate. Every attempt to enable or issue this mode denies.
   Startup and import validation reject active unsupported records without
   silently rewriting or deleting them (design §5.6; tasks §2 note under the
   endpoint matrix; T10.11, T12.10).
10. A later feature-specific ADR must specify fresh revision-bound approval
    and activation and their tests before the mode can ship (design §5.6;
    tasks §8 note under the matrix).

## Consequences and requirements

- Contract requirements: the grant-mode table in identity-registry §5.1,
  IR-045 (direct null target, delegation same-tenant service), the
  identity-registry §12 row "Unsupported grant mode (impersonation) at
  issuance: deny; never fall back"; TP-040, TP-041, TP-042, TP-043, TP-046
  (`skyoauth_mode`, `act`, `act.iss`); the public-api §2.1 grant-profile
  table, API-015 (no mode override), API-018 (no standard or IANA claim for
  the private grant), API-124 (impersonation-activation endpoints absent).
- Preservation is a compatibility rule, not an activation subsystem (design
  §1.3); C06 requires unsupported impersonation records to stay unchanged and
  inactive.
- Conformance rows: A16, A25, A38, A45, A53.

## Alternatives considered

- **Standard RFC 8693 two-token delegation** (`subject_token` plus
  `actor_token`). Not supported in v0.1; the single-proof private grant is
  used instead (design §5.7; T00.9).
- **Active true impersonation** with an approval subsystem. Deferred to a
  later feature-specific ADR (design §1.3, §5.6; tasks §8 note).
- **Treating an unsupported impersonation grant as delegation, or deleting
  it.** Rejected (design §5.6).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-8** — whether the private grant URI appears in
  `grant_types_supported` (open).
- **OQ-IR-6** — export names `act_as` and `mode` versus the model
  `target_service_id` and `mode` (open).
- **OQ-TP-5** — `act.iss`. Decided (lead decision, 2026-11-19): required and
  equal to the canonical issuer (TP-046).
- **OQ-ERR-3** — OAuth error codes for mode mismatch and other denials.
  Decided for the WIF exchange profiles (lead decision, 2026-11-19): a
  profile mismatch is `invalid_request`; any source, grant, binding or proof
  failure is one uniform `invalid_grant`, which covers a selected grant of the
  wrong mode (inferred) (ADR-015 item 9). Other `/oauth/token` denials
  (refresh overrides, unknown clients, revoked or expired families) stay open
  under OQ-ERR-3. The errors-retry contract now decides the WIF exchange codes
  (ERR-024, OQ-ERR-3).

New questions raised by this ADR:

- **OQ-ADR006-1 — Stored shape of a dormant impersonation grant.** Decided
  (lead decision, 2026-11-19): the record uses `mode: impersonation`,
  `activation_state` takes `not_required` or `requires_reapproval`, and an
  impersonation grant requires a same-tenant target service. Original question:
  design §5.6 fixes `status: disabled` and `activation_state:
requires_reapproval`, but the sources give neither the `ServiceGrant.mode`
  literal for impersonation nor the other `activation_state` values (for
  example the value an ordinary enabled direct or delegation grant carries),
  nor whether an impersonation record requires `target_service_id`.

## Tests

- A16 — migration preserves direct and delegation bindings, grants and
  dormant impersonation unchanged and disabled.
- A25 — the generated grant selector chooses the authorized actor and target;
  mode override or wrong mode denies.
- A38 — device and impersonation not advertised or accepted for issuance.
- A45 — direct grant with no target service works with a registered checker.
- A53 — disabled/reapproval record round-trips; enabled unsupported input
  rejects; capability upgrade, PATCH and import cannot activate.
- Task tests: T12.4, T12.5, T12.10, T21.4, T51.6.
