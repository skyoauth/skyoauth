# SkyOAuth M0 contracts

These documents extract the public and operator contracts that M0 freezes
from the [design](../skyoauth-design.md) and the
[tasks plan](../skyoauth-tasks.md). They are proposals for review, not
implemented behavior. The bootstrap service and TypeScript health helper do
not implement any of them.

| Document                                     | Task  | Status       | Contents                                                                                                                                                      |
| -------------------------------------------- | ----- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [public-api.md](public-api.md)               | T00.1 | Proposed, M0 | Listener classes, public issuer, app-origin, private gateway, policy, trust and control endpoints, operator API, approval boundaries, route-gate independence |
| [errors-retry.md](errors-retry.md)           | T00.2 | Proposed, M0 | Status classes and reason strings, OAuth errors, check results, `no-store`, cancellation, retry budgets                                                       |
| [token-profiles.md](token-profiles.md)       | T00.3 | Proposed, M0 | `skyoauth-access+jwt` and `skyoauth-internal+jwt`, `wif`, `human_cli` and `human_session` claim sets, rejection rules                                         |
| [identity-registry.md](identity-registry.md) | T00.4 | Proposed, M0 | Issuer, IDs, principal kinds, operator roles, audience registry, scopes, constraints, actions, claim namespace, unknown-means-deny                            |

## Conventions

- MUST, MUST NOT, SHOULD and MAY follow BCP 14 (RFC 2119, RFC 8174) when in
  capitals.
- Each normative requirement has a stable ID (`API-`, `ERR-`, `TP-`, `IR-`)
  that tests and reviews can cite.
- Each requirement cites the design or tasks section it comes from. The
  contracts add no behavior beyond those sources, except where an open
  question is marked **Decided**.
- Where the sources are ambiguous or disagree, the contract does not choose.
  The gap is listed under **Open questions** (`OQ-API-`, `OQ-ERR-`, `OQ-TP-`,
  `OQ-IR-`) for maintainers to resolve.
- An open question marked **Decided** records a lead decision with its date.
  The normative text cites it as "lead decision". The design and tasks
  documents still need the matching follow-up under design §12.
- Text marked "(inferred)" is the contract's reading of the sources, not a
  statement they make directly.
- A requirement ID that is withdrawn (for example a duplicate) stays in place
  as "Withdrawn" with a pointer to the canonical requirement, so that the ID
  is never reused.
- Tables write every path in full; the tasks matrix's grouped-path shorthand
  is not used. A row expanded from a grouped tasks-matrix entry names the
  reading it uses, sibling or child (OQ-API-11).

## Changing a contract

Design §12 applies: ratifying or changing a decision updates the design, the
tasks plan, these contracts, the shared fixtures and the affected tests
together. Protocol behavior must not depend on pull-request discussion. The
T00 checkboxes in the tasks plan stay unchecked until the contracts are
reviewed.

Other T00 tasks (T00.5–T00.17: credential containment and route admission,
lifetimes, threat model, ADRs) are not covered here.
