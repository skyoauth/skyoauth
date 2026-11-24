# SkyOAuth architecture decision records

These records expand the proposed baselines in the
[tasks plan's ADR table](../skyoauth-tasks.md#11-adr-decisions-to-ratify)
(tasks §11), which design §12 indexes as the decisions requiring
ratification. The maintainer ratified all 24 records directionally on
2026-11-24 (see [Status values](#status-values)): the direction of each
record is accepted, and its details stay changeable through ordinary review.
A record states decided behavior, not implemented behavior; what is
implemented is tracked per conformance stage in
[tests/conformance](../../tests/conformance/README.md).

## Index

The tasks plan names an ADR inside a T00 task only for T00.6 (ADR-010,
ADR-020) and T00.13 (ADR-017). Every other entry in the T00 column is read from
the wording of the T00 task and the ADR baseline (inferred).

| ADR                                                   | Decision                         | Status                                                | T00 task             |
| ----------------------------------------------------- | -------------------------------- | ----------------------------------------------------- | -------------------- |
| [ADR-001](ADR-001-issuer-discovery.md)                | Issuer/discovery                 | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.1, T00.4         |
| [ADR-002](ADR-002-signer-recovery.md)                 | Signer/recovery                  | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.8                |
| [ADR-003](ADR-003-sessions-state.md)                  | Sessions/state                   | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.6, T00.16        |
| [ADR-004](ADR-004-native-oauth.md)                    | Native OAuth                     | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.8, T00.17        |
| [ADR-005](ADR-005-wif-adapters.md)                    | WIF adapters                     | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.11, T00.12       |
| [ADR-006](ADR-006-modes.md)                           | Modes                            | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.9, T00.8, T00.16 |
| [ADR-007](ADR-007-backend-identity.md)                | Backend identity                 | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.5                |
| [ADR-008](ADR-008-policy-writes.md)                   | Policy writes                    | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.10               |
| [ADR-009](ADR-009-upstream-exchange.md)               | Upstream exchange                | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.8                |
| [ADR-010](ADR-010-live-revocation.md)                 | Live revocation                  | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.6, T00.2         |
| [ADR-011](ADR-011-cluster-authority.md)               | Cluster/authority                | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.11               |
| [ADR-012](ADR-012-migration.md)                       | Migration                        | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.16               |
| [ADR-013](ADR-013-operator-trust-provisioning.md)     | Operator trust/provisioning      | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.10               |
| [ADR-014](ADR-014-tenant-scope.md)                    | Tenant scope                     | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.11               |
| [ADR-015](ADR-015-exchange-semantics.md)              | Exchange semantics               | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.9                |
| [ADR-016](ADR-016-replay-constraints.md)              | Replay/constraints               | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.12               |
| [ADR-017](ADR-017-clients-layout.md)                  | Clients/layout                   | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.13, T00.14       |
| [ADR-018](ADR-018-resource-servers.md)                | Resource servers                 | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.15, T00.4        |
| [ADR-019](ADR-019-human-credentials-private-types.md) | Human credentials/private types  | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.3, T00.15        |
| [ADR-020](ADR-020-browser-routing-binding.md)         | Browser routing/binding          | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.5, T00.6, T00.16 |
| [ADR-021](ADR-021-exclusive-provider-writes.md)       | Exclusive provider writes        | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.16               |
| [ADR-022](ADR-022-identifier-binding-lifecycle.md)    | Identifier and binding lifecycle | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.16, T00.9        |
| [ADR-023](ADR-023-enrollment-continuity.md)           | Enrollment and continuity        | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.16               |
| [ADR-024](ADR-024-delivery-scope.md)                  | Delivery scope                   | Ratified, M0 — directionally (maintainer, 2026-11-24) | T00.17               |

With the ratification, T00.8–T00.17 are ticked in the tasks plan; Gate M0
stays open until the lead's separate gate PR. T00.1–T00.7 (the contracts and
the threat model) were ticked earlier, when those documents were reviewed and
before any record was ratified. ADR-001, ADR-007 and ADR-010 pair only with
those earlier tasks: ADR-001 with T00.1 and T00.4 (inferred), ADR-007 with
T00.5 (inferred), ADR-010 with T00.6 (which names it) and T00.2 (inferred).
No T00 box records their ratification; the maintainer's decision of
2026-11-24, which covers all 24 records, does. The other pairings in the
T00 column stay as read above: named for T00.6 and T00.13, inferred
otherwise.

## Format

Every record has the same sections:

- **Header:** status, the T00 task that ratifies it and the implementation
  tasks, the tasks §11 baseline quoted verbatim and the related contracts.
- **Context:** the problem, citing design and tasks sections.
- **Decision:** the tasks §11 baseline expanded from the design and tasks
  text. A record adds no design; text marked "(inferred)" is the record's
  reading of the sources, not a statement they make directly.
- **Consequences and requirements:** the contract requirement IDs (`API-`,
  `ERR-`, `TP-`, `IR-`, `GW-`, `LT-`) that implement the decision and the
  conformance rows (tasks §8) that depend on it.
- **Alternatives considered:** only alternatives the sources name.
- **Open questions:** existing contract and threat-model questions
  (`OQ-API-`, `OQ-ERR-`, `OQ-TP-`, `OQ-IR-`, `OQ-GW-`, `OQ-LT-`, and `OQ-TM-`
  from the [threat model](../threat-model.md) §6) that touch the decision,
  and new questions found while writing the record, numbered
  `OQ-ADR<nnn>-<n>` (for example OQ-ADR001-1). Lead decisions are recorded
  as "Decided (lead decision, 2026-11-19)"; an answered new question is
  marked decided and keeps its ID and original text. Where the sources are
  ambiguous or disagree and no lead decision exists, the record lists the gap
  and does not choose.
- **Tests:** the conformance rows and task tests that exercise the decision.

## Status values

- **Ratified, M0 — directionally (maintainer, 2026-11-24):** the maintainer
  accepted the direction of the record on 2026-11-24, in one decision that
  covers all 24 records and ticks T00.8–T00.17 (see the Index). Its
  details are not frozen sentence by sentence: the lead decisions, the text
  marked "(inferred)" and the provisional lead picks that
  the records, the contracts and the proposals carry (for example D1–D29 of
  [the second-approver proposal](../proposals/second-approver-gated-writes.md)
  and the picks of
  [the recovery proposal](../proposals/recovery-verified-response.md)) are
  accepted as implementation choices that ordinary review can change under
  design §12. A question still marked open stays open: ratification decides
  none. Every record has this status.
- **Proposed, M0 — ratification pending maintainer review:** the record is
  written and awaits review. Every record had this status until 2026-11-24;
  none has it now.

## Changing a decision

Design §12 applies: ratifying or changing a decision updates the design, the
tasks plan, the contracts, the shared fixtures and the affected tests
together. Protocol behavior must not depend on pull-request discussion.
