# ADR-009: Optional upstream provider exchange

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.8, which keeps "provider vault/exchange ...
  separately scoped future features" (inferred: tasks §2 names no ADR in T00.8).
  Implementation: T41.1–T41.4 (T41.2 deferred), T30.5.
- **Baseline (tasks §11):** "Optional compatible provider operation server-side,
  normalize downstream credential"
- **Contracts:** [token-profiles.md](../contracts/token-profiles.md) §1, §3;
  [identity-registry.md](../contracts/identity-registry.md) §1, §5.2.

## Context

Zitadel is the first human adapter, not the canonical API issuer (design §5.5).
An upstream human provider can sometimes exchange its own tokens for other
upstream credentials, and an upstream administration API may need its own
credential. Passing upstream tokens through to applications would make
downstream APIs depend on the provider and would undo the provider-independence
that migration relies on (design §2, §8). Design §11 lists "upstream
exchange/vault" under conditional/later work, and T41.2 is deferred "until a
release explicitly includes ADR-009 upstream exchange" (tasks §9). This ADR
fixes the boundary that holds whether or not the feature ships.

## Decision

1. **Optional.** Upstream provider exchange is optional and not part of the
   required v0.1 gates; it ships only in a release that explicitly includes this
   ADR (design §11; tasks §9; T41.2).
2. **Server-side and compatible only.** Where included, exchange of
   Zitadel-issued tokens runs server-side after checking the actual deployed
   provider capabilities and subject, actor, audience and scope restrictions
   (design §5.5; T41.1, T41.2).
3. **No assumed WIF-to-provider exchange.** SkyOAuth does not assume arbitrary
   GitHub or Kubernetes assertions can be exchanged into Zitadel administrator
   credentials or administrative audiences; local WIF is required independently
   (design §5.5; T41.3).
4. **Normalize downstream.** Downstream credentials are normalized to SkyOAuth's
   public profile. An upstream token is never passed through as the default
   application credential (design §5.5; ADR-019).
5. **Vault only behind a feature.** An upstream token may be retained only in
   the explicit encrypted vault, for an approved upstream operation, behind an
   explicit feature; by default upstream tokens are discarded (design §5.5;
   T30.5). The vault is not in required v0.1 scope: T30.5 keeps only the feature
   flag and the default discard (lead decision, 2026-11-19, OQ-ADR009-2).
6. **Separate administration adapter.** Upstream administration uses a
   separately isolated, restricted service adapter. It is neither SkyOAuth
   operator authority nor a target of public WIF delegation, and an upstream
   admin token is never returned through generalized delegation (design §5.5;
   T41.4).
7. **Trait boundary now.** The human-login trait carries the optional
   provider-exchange capability with explicit deployed-capability checks,
   independent of operator authority, so that adding exchange later does not
   change the login adapter contract (T41.1).
8. **No effect on the stable contract.** Replacing the provider keeps TypeScript
   and Rust contracts, metadata, profiles, constraints, gateway transport and
   registered clients and origins unchanged (design §2; T41.5).

## Consequences and requirements

- No v0.1 endpoint or grant exposes upstream exchange; the public token endpoint
  issues only SkyOAuth profiles (design §5.5; ADR-019).
- Applications and the TypeScript and Rust libraries never receive upstream
  tokens (design §10.2).
- Upstream outage affects only what depends on the upstream provider; WIF and
  operator recovery stay independent (design §8).
- Conformance rows: A14, A15 and A42 cover provider replacement without client
  change (inferred: no conformance row tests exchange itself, because the
  feature is deferred).

## Alternatives considered

- **Pass the upstream token through as the application credential.** Rejected
  (design §5.5).
- **Exchange arbitrary WIF assertions into upstream administrator credentials.**
  Rejected (design §5.5; T41.3).
- **Use upstream administration as operator authority or a WIF delegation
  target.** Rejected (design §5.5; T41.4).
- **Keep upstream tokens by default.** Rejected; default discard (T30.5).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-TM-13** — external secret references and egress approval. Decided (lead
  decision, 2026-11-19): secret references resolve only within a per-tenant
  provisioned namespace, and egress destinations come from a
  `security_admin`-approved allowlist. This would also bound an upstream
  exchange adapter's egress (inferred).

New questions raised by this ADR:

- **OQ-ADR009-1 — Exchange surface.** The sources define no endpoint, grant
  type, token profile or operator role for upstream exchange or for an "approved
  upstream operation". Which of these a release including this ADR must add, and
  through which contract, is not stated. Open; deferred (lead decision,
  2026-11-19).
- **OQ-ADR009-2 — Vault milestone.** Decided (lead decision, 2026-11-19): the
  vault is not in required v0.1 scope; T30.5 keeps only the feature flag and
  default discard (item 5). Original question: T30.5 places the optional
  encrypted provider-token vault in M3, while design §11 lists "upstream
  exchange/vault" as conditional/later. Whether the vault feature may ship in
  v0.1 without exchange, or only together with it, is not stated.
- **OQ-ADR009-3 — Vault key and retention.** The vault is "explicit encrypted"
  (design §5.5), but its key custody, retention bound and the effect of a
  provider switch or session revocation on vaulted tokens are not stated. Open;
  deferred (lead decision, 2026-11-19).

## Tests

- No release-blocking conformance row covers exchange while it is deferred
  (tasks §8).
- T41.5 — replacement-provider tests preserve client contracts, metadata,
  profiles, constraints, gateway transport and registrations.
- When a release includes this ADR, T41.2 adds its exchange tests (inferred).
