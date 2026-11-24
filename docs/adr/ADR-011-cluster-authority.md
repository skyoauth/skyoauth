# ADR-011: Cluster authority

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Questions still marked open under Open questions stay open: ratification closes none of them.
- **Tasks:** ratified with T00.11 (inferred: tasks §2 names no ADR in T00.11,
  which asks for "nonunique issuer strings and same-issuer cross-tenant/cluster
  fixtures"). Implementation: T11.1, T11.7, T11.10, T23.4, T10.8.
- **Baseline (tasks §11):** "One bridge issuer, registered source IDs
  disambiguate clusters, not issuer alone".
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md)
  §2, §4, [public-api.md](../contracts/public-api.md) §2.1.

## Context

Kubernetes clusters, including k3s, issue projected service-account tokens.
Several independently keyed clusters can use the same issuer string, for
example `https://kubernetes.default.svc.cluster.local` (design §5.4, §5.7
example). Design §9 lists issuer, key and cluster confusion as threats, and
tasks T00.7 asks for them in the threat model. The migration rehearsal uses
two independently keyed shared-issuer clusters (design §8 step 6).

## Decision

1. **One bridge issuer.** Protected services trust SkyOAuth's issuer, not the
   clusters' issuers (design §2 C08). A workload's cluster proof is exchanged
   at SkyOAuth for a SkyOAuth credential (design §1, §5.4). The issuer is
   ADR-001.
2. **Each source selects exactly one cluster.** A `kubernetes_token_review`
   source carries a stable cluster ID and a fixed endpoint, CA, reviewer
   reference, audiences and timeout (design §5.4; tasks §3 `TrustSource`). The
   sources do not decide the reverse cardinality, how many sources may name one
   cluster; the lead decision on OQ-ADR011-1 lets several tenants enroll the
   same physical cluster through their own sources. The fixed
   `token_review_endpoint` must be a destination on the instance egress
   allowlist that `security_admin` approves (OQ-TM-13). The adapter details are
   ADR-005.
3. **Source ID, not issuer, disambiguates.** The required generated source ID
   selects exactly one registered verifier. Multiple clusters may share an
   issuer, so the issuer is not a unique lookup key. SkyOAuth does not probe
   clusters until one accepts, does not use unverified claims to select a
   server and does not accept client-supplied endpoints, CAs or credentials
   (design §5.4; T11.1, T11.7).
4. **The selector is not authority.** The source ID is not proof of a tenant
   or cluster. A source selector chooses only a candidate verifier; verified
   evidence plus the selected same-tenant grant establishes authority (design
   §5.4, §7.1).
5. **Evidence is bound to the selected cluster.** The returned
   service-account identity/UID and supported bound-Pod evidence are bound to
   the selected cluster and source (design §5.4; T23.3).
6. **Shared signing authorities.** Clusters that share a signing authority
   cannot provide independent cluster isolation (design §5.4).
7. **No cross-cluster fallback.** A denial at the selected cluster is final;
   no other cluster or verification mode is tried (design §5.4; T11.7, T23.4,
   T23.6).

## Consequences and requirements

- Contract requirements: IR-010, IR-011 (one issuer, distinct from
  upstream), IR-032 (issuer strings are not unique), IR-033 (WIF tenant from
  the selected source and grant), API-011, API-012, API-013 (generated
  selectors, untrusted candidates, verification only at the selected source
  with no fallback).
- Cluster configurations survive provider migration unchanged: IDs, issuer,
  endpoint, cluster, CA and reviewer references (design §2 C05; T23.7).
- Conformance rows: A06, A07, A15, A28, A29.

## Alternatives considered

- **Issuer-based verifier lookup or probing clusters until one accepts.**
  Rejected (design §5.4).
- **Kubernetes local JWT validation as a fallback** after a failed
  TokenReview. Rejected; local validation is a separately enrolled mode
  (design §5.4; T23.6).
- **Backends trusting cluster or CI issuers directly.** Rejected by design §2
  C08.

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-6** — export names `issuer` and `api_server` versus model
  `exact_issuer` and `token_review_endpoint` (open).
- **OQ-TM-13** ([threat model](../threat-model.md) §6) — external secret
  references and egress approval. Decided (lead decision, 2026-11-19):
  TokenReview endpoints come from a `security_admin`-approved egress
  allowlist, and the CA and reviewer-credential references resolve only within
  the tenant's provisioned secret namespace (item 2).

New questions raised by this ADR:

- **OQ-ADR011-1 — `cluster_id` identity.** Decided (lead decision,
  2026-11-19): `cluster_id` is an opaque, server-generated ID owned by the
  tenant's source. Several tenants may enroll the same physical cluster, each
  through its own source and ID. It is a separate identifier from the
  route-control `cluster_id`. Original question: `TrustSource.cluster_id` is a
  model
  field and the design §5.7 export shows a generated-looking
  `cluster_40ef...` value, but the logical model has no cluster entity. The
  sources do not say whether `cluster_id` is server-generated, tenant-scoped
  or shared by several tenants' sources for the same cluster, whether one
  cluster may have several sources, or whether it shares an identifier space
  with the route-control `cluster_id` in `CredentialDependency` and
  `CredentialProtectionScope` (tasks §3).
- **OQ-ADR011-2 — Cluster in the issued token.** Decided (lead decision,
  2026-11-19), deferred: the `wif` profile has no cluster claim in v0.1. A
  resource server that must distinguish clusters defines a constraint
  dimension in its schema (IR-141). Original question: A06 expects a "scoped
  token
  for selected tenant/cluster", but the `wif` claim set (token-profiles §5,
  TP-045) has no cluster or source claim. The cluster is recorded only through
  the selected source in the `PolicyRevision` dependencies (tasks §3 "Policy
  revisions") and whatever allowlist dimensions the resource server defines
  (inferred). Whether a backend is expected to distinguish clusters from the
  token, and how, is not stated.

## Tests

- A28 — independently keyed clusters share an issuer; only the selected
  cluster validates its proof; no cross-cluster probing or fallback.
- A06, A07 — scoped token for the selected tenant/cluster; wrong cluster,
  service account or audience denies.
- A15 — migration keeps two shared-issuer TokenReview clusters' configurations
  and decisions.
- A29 — tenants sharing an issuer coexist without crossover.
- The same-issuer cross-tenant and cluster fixtures that T00.11 asks for are
  the A28 and A29 rows of the
  [conformance layout scenario map](../testing/conformance-layout.md#2-scenario-map).
- Task tests: T10.8 (same-issuer cluster property tests), T11.10, T23.4,
  T52.2.
