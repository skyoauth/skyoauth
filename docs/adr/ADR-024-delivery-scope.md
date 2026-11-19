# ADR-024: Delivery scope and milestone order

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.17 ("M1a/M1b dependencies ... deferring active
  impersonation and optional UX/subsystems") (inferred: tasks §2 names no ADR in
  T00.17). Implementation: the milestone order of tasks §9 and the definitions
  of done in tasks §10.
- **Baseline (tasks §11):** "M1a -> usable M2; parallel M1b before M3; full v0.1
  still both clients/migration/isolation, active impersonation machinery
  deferred"
- **Contracts:** all M0 contracts (T00.1–T00.6) assume this order; none defines
  it.

## Context

The central outcomes are secretless GitHub Actions to cluster-API WIF and human
IdP migration with no client change and no WIF reset (tasks §0). Building every
human, browser, native and gateway subsystem before the first workload token
would delay the workload outcome, while shipping a narrow workload product as
v0.1 would drop the required client libraries and migration guarantee (design
§1.3). The logical model therefore has to be designed once in M0 and implemented
in slices whose dependencies are explicit. This ADR fixes that order and the
v0.1 boundary.

## Decision

### Order

1. **M0.** Contracts, ADRs, threat model and the complete logical model are
   reviewed together before implementation (tasks §9; design §11).
2. **M1a then usable M2.** M1a delivers workload principals, trust, grants,
   tenant, audience and checker authority, independent operator bootstrap and
   recovery with the portable `skyoauth-operator` client, and durable replay. M2
   (signer and JWKS, direct and delegated exchange, the Rust workload library,
   bearer Envoy and WIF live action checks) needs M1a only, not M1b, and ships a
   usable WIF slice (design §1.3; tasks §9).
3. **M1b in parallel, before M3.** M1b adds human providers and enrollment,
   origin, route, bundle and client policy, browser, native, refresh and
   continuation state and the sole provider transition. It may run alongside M2
   and must be complete before M3 (design §1.3; tasks §9).
4. **M3, M4, M5.** M3 (browser, route enforcement, internal signer, TypeScript
   SPA) needs M1b and M2; M4 (native OAuth and the Rust CLI crate) needs M2, M3
   and the M1b OAuth state; M5 (deployment, migration tooling, conformance)
   follows (tasks §9).
5. **No premature dependencies.** Human tables, browser or native UX and a
   tenant-management UI are not prerequisites of the first workload token (tasks
   §0, §9). A spec amendment that a lead decision requires before a milestone
   gates the start of that milestone, not its completion (lead decision,
   2026-11-19, OQ-ADR024-2).

### Full v0.1 is unchanged

6. v0.1 still requires M0, M1a, M1b and M2–M5: direct and attributed delegation
   WIF, opaque SPA sessions, both client libraries, usable native login and
   renewal and zero-reset human-provider migration, with explicit tenant and
   audience isolation even in a one-tenant installation (design §1.3, §11; tasks
   §0).
7. The usable M2 milestone is weaker than full v0.1 acceptance; all
   unconditional A01–A64 rows are demonstrable before v0.1 (design §1.3; tasks
   §10).

### Deferred

8. Active true impersonation machinery (activation approval, endpoints, ceremony
   and release gate) is deferred to a later feature-specific ADR; v0.1 keeps
   only disabled, reapproval-required preservation (design §5.6; ADR-006).
9. Device flow, admin UI, self-service tenant onboarding, invitations, cloud
   STS, alternate gateways and issuers, upstream exchange and vault and
   TypeScript workload helpers are conditional or later and are not substitutes
   for required controls (design §1.3, §11; tasks §9; ADR-009).

## Consequences and requirements

- A release that ships only M1a and M2 is a usable workload slice, not v0.1
  (design §1.3).
- Model and restore invariants become release-blocking when their slice first
  lands and are all exercised before v0.1 (tasks §9).
- New package CI and consumer tests land with their code, not in M5 (tasks §9;
  T50.8).
- Conformance rows: every unconditional row of tasks §8; A53 for disabled-only
  impersonation.

## Alternatives considered

- **Build all human state before M2.** Rejected; M2 needs M1a only (design
  §1.3).
- **A workload-only v0.1.** Rejected; v0.1 still needs both clients and
  migration (design §1.3).
- **Active impersonation in v0.1.** Deferred (design §5.6).
- **A single-tenant-only distribution without tenant checks.** A separate
  reviewed scope choice, not a reason to omit tenant checks (design §1.3).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-TM-12** — audit sink. Decided (lead decision, 2026-11-19): security
  events are also emitted to an append-only external sink: an
  operator-configured hash-chained JSONL stream forwarded to a syslog-over-TLS
  or OTLP-logs endpoint (tasks Gate M1a), implemented under T50.6.
- **OQ-TM-13** — secret references and egress approval. Decided (lead decision,
  2026-11-19): the amendment had to land before M1a; it has landed with the
  M1a spec amendments (T11.2, T11.8, T23.2 and the tasks §3 schema).
- **OQ-TM-14** — bulk session revocation. Decided (lead decision, 2026-11-19):
  the operation must be specified before M1b and M3.

New questions raised by this ADR:

- **OQ-ADR024-1 — Status of the usable M2 slice.** The sources call M2 a "usable
  WIF slice" that "can ship" after M1a, but do not say whether it is published
  as a versioned release, which conformance rows gate it, or whether its token
  endpoint and Rust workload library are covered by the v0.1 compatibility
  contract (design §2) from that point. Open; deferred (lead decision,
  2026-11-19).
- **OQ-ADR024-2 — Spec amendments before slices.** Decided (lead decision,
  2026-11-19): amendments gate the start of a milestone (item 5). Original
  question: Several lead decisions (OQ-TM-12, OQ-TM-13, OQ-TM-14) require design
  or task amendments before M1a, M1b or M3. The sources do not say whether those
  amendments gate the start or the completion of each milestone.

## Tests

- Tasks §8 — every unconditional row before v0.1; workload rows (for example
  A01–A07) are demonstrable after M2 (inferred from tasks §9).
- A53 — disabled-only impersonation round-trips; no activation.
- Task tests: T50.8 (CI lands with code), T52.8 (independent review of staged
  provisioning).
