# SkyOAuth architecture decision records

These records expand the proposed baselines in the
[tasks plan's ADR table](../skyoauth-tasks.md#11-adr-decisions-to-ratify)
(tasks §11), which design §12 indexes as the decisions requiring
ratification. They are proposals for review, not implemented behavior and not
maintainer approval.

## Index

The tasks plan names an ADR inside a T00 task only for T00.6 (ADR-010,
ADR-020) and T00.13 (ADR-017). Every other entry in the T00 column is read from
the wording of the T00 task and the ADR baseline (inferred).

| ADR                                               | Decision                         | Status                                                | T00 task             |
| ------------------------------------------------- | -------------------------------- | ----------------------------------------------------- | -------------------- |
| [ADR-001](ADR-001-issuer-discovery.md)            | Issuer/discovery                 | Proposed, M0 — ratification pending maintainer review | T00.1, T00.4         |
| [ADR-002](ADR-002-signer-recovery.md)             | Signer/recovery                  | Proposed, M0 — ratification pending maintainer review | T00.8                |
| ADR-003                                           | Sessions/state                   | planned (PR 5)                                        | T00.6, T00.16        |
| ADR-004                                           | Native OAuth                     | planned (PR 5)                                        | T00.8, T00.17        |
| [ADR-005](ADR-005-wif-adapters.md)                | WIF adapters                     | Proposed, M0 — ratification pending maintainer review | T00.11, T00.12       |
| [ADR-006](ADR-006-modes.md)                       | Modes                            | Proposed, M0 — ratification pending maintainer review | T00.9, T00.8, T00.16 |
| ADR-007                                           | Backend identity                 | planned (PR 5)                                        | T00.5                |
| ADR-008                                           | Policy writes                    | planned (PR 5)                                        | T00.10               |
| ADR-009                                           | Upstream exchange                | planned (PR 5)                                        | T00.8                |
| ADR-010                                           | Live revocation                  | planned (PR 5)                                        | T00.6, T00.2         |
| [ADR-011](ADR-011-cluster-authority.md)           | Cluster/authority                | Proposed, M0 — ratification pending maintainer review | T00.11               |
| ADR-012                                           | Migration                        | planned (PR 5)                                        | T00.16               |
| [ADR-013](ADR-013-operator-trust-provisioning.md) | Operator trust/provisioning      | Proposed, M0 — ratification pending maintainer review | T00.10               |
| [ADR-014](ADR-014-tenant-scope.md)                | Tenant scope                     | Proposed, M0 — ratification pending maintainer review | T00.11               |
| [ADR-015](ADR-015-exchange-semantics.md)          | Exchange semantics               | Proposed, M0 — ratification pending maintainer review | T00.9                |
| [ADR-016](ADR-016-replay-constraints.md)          | Replay/constraints               | Proposed, M0 — ratification pending maintainer review | T00.12               |
| ADR-017                                           | Clients/layout                   | planned (PR 5)                                        | T00.13, T00.14       |
| ADR-018                                           | Resource servers                 | planned (PR 5)                                        | T00.15, T00.4        |
| ADR-019                                           | Human credentials/private types  | planned (PR 5)                                        | T00.3, T00.15        |
| ADR-020                                           | Browser routing/binding          | planned (PR 5)                                        | T00.5, T00.6, T00.16 |
| ADR-021                                           | Exclusive provider writes        | planned (PR 5)                                        | T00.16               |
| ADR-022                                           | Identifier and binding lifecycle | planned (PR 5)                                        | T00.16, T00.9        |
| ADR-023                                           | Enrollment and continuity        | planned (PR 5)                                        | T00.16               |
| ADR-024                                           | Delivery scope                   | planned (PR 5)                                        | T00.17               |

The T00 boxes in the tasks plan stay unchecked until the records are reviewed
and ratified.

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
- **Open questions:** existing contract questions (`OQ-API-`, `OQ-ERR-`,
  `OQ-TP-`, `OQ-IR-`, `OQ-GW-`, `OQ-LT-`) that touch the decision, with lead
  decisions marked **Decided**, and new questions found while writing the
  record, numbered `OQ-ADR<nnn>-<n>` (for example OQ-ADR001-1). Where the
  sources are ambiguous or disagree, the record lists the gap and does not
  choose.
- **Tests:** the conformance rows and task tests that exercise the decision.

## Status values

- **Proposed, M0 — ratification pending maintainer review:** the record is
  written and awaits review.
- **planned (PR 5):** the record is not written yet; the tasks §11 row is the
  only statement of the baseline.

## Changing a decision

Design §12 applies: ratifying or changing a decision updates the design, the
tasks plan, the contracts, the shared fixtures and the affected tests
together. Protocol behavior must not depend on pull-request discussion.
