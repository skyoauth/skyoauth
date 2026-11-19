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
  contracts add no behavior beyond those sources.
- Where the sources are ambiguous or disagree, the contract does not choose.
  The gap is listed under **Open questions** (`OQ-API-`, `OQ-ERR-`, `OQ-TP-`,
  `OQ-IR-`) for maintainers to resolve.

## Changing a contract

Design §12 applies: ratifying or changing a decision updates the design, the
tasks plan, these contracts, the shared fixtures and the affected tests
together. Protocol behavior must not depend on pull-request discussion. The
T00 checkboxes in the tasks plan stay unchecked until the contracts are
reviewed.

Other T00 tasks (T00.5–T00.17: credential containment and route admission,
lifetimes, threat model, ADRs) are not covered here.
