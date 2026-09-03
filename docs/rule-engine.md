# Rule Engine

How a policy decision is computed. The authoritative implementation is
`safeguard-core` (`evaluator`, `rules/*`, `evaluation`); the property tests
there pin everything this document claims, so prose and code cannot drift.

## The evaluation request

The engine is storage-agnostic. Callers (the contract, `safeguard-hooks`,
SDKs) resolve every piece of external state and hand over a fully
materialized snapshot:

```text
EvaluationRequest
├── account_status        structural: active/restricted/frozen/suspended/unknown
├── allowlist             present iff the policy enables an allowlist rule
│   ├── rule_id, action   the configured rule
│   └── member            resolved membership
├── denylist              present iff enabled (rule_id, action, matched)
├── sanctions             present iff enabled (rule_id, action, matched)
└── jurisdiction          present iff enabled (rule_id, action, region)
```

A category absent from the request is skipped. The request alone — with no
storage, registries or network — determines the decision.

## Precedence

Checks run in a fixed, documented order. The first decisive outcome wins;
later checks never run:

```text
1. Account status      (structural, never configurable)
2. Allowlist           (required but not a member)
3. Denylist            (listed subject)
4. Sanctions           (screening match)
5. Jurisdiction        (restricted/prohibited/unknown region)
6. otherwise           APPROVE
```

This order is part of the public contract of the engine: two implementations
of the same policy cannot disagree about a contested case because the
precedence is pinned by tests, not left to interpretation.

## Per-category semantics

### Account status (structural)

| Status | Outcome | Reason code |
| ------ | ------- | ----------- |
| Active | pass | — |
| Restricted | FLAG | `account_restricted` |
| Frozen | BLOCK | `account_frozen` |
| Suspended | BLOCK | `account_suspended` |
| Unknown | FLAG | `account_status_unknown` |

Status is structural because the semantics are (and must stay) uniform: a
frozen account is blocked regardless of policy wording. Freezing mechanics
themselves live in SAC-compatible controls in the contract layer; the engine
only decides what a status means.

### Allowlist

A rule with `type: allowlist` is satisfied only by membership. A non-member
triggers the rule action with reason `allowlist_required`. A member passes.

### Denylist

A listed subject triggers the rule action with reason `denylist_match`.
An unlisted subject passes.

### Sanctions

A screening match triggers the rule action with reason `sanctions_match`.
Crucially, **a match under a blocking policy can never evaluate as APPROVE** —
this is enforced by construction and by property tests. Unmatched subjects
pass.

### Jurisdiction

Region classification is resolved off-chain (attestation, registry, adapter)
and passed in as a snapshot. The rule's action applies to **restricted**,
**prohibited** and **unknown** regions:

| Region | action `block` | action `flag` |
| ------ | -------------- | ------------- |
| Permitted | pass | pass |
| Restricted | BLOCK | FLAG |
| Prohibited | BLOCK | FLAG |
| Unknown | BLOCK | FLAG |

Unknown regions fail closed: missing jurisdiction information can never
silently approve a restricted-flow token operation.

## Decisions and reasons

Every evaluation resolves to `APPROVE`, `BLOCK` or `FLAG` with a stable
`reason_code` and, when a rule produced the outcome, the rule id:

```text
{ decision: BLOCK, policy_id: "institutional-default", policy_version: 1,
  rule_id: "SANCTIONS-001", reason_code: "sanctions_match" }
```

Codes and labels are explicitly assigned, tested for round-trip stability,
and shared with the JSON decision schema — renumbering them would corrupt
audit history.

## Determinism

The engine is a pure function of its request:

- no randomness, no wall-clock time, no hidden state, no network calls;
- identical input + identical policy state = identical decision;
- the full request space (statuses × presence flags × regions × actions) is
  brute-forced in tests for repeatability.

## Fail-closed posture

Missing information never silently approves:

- unknown account status → FLAG;
- unknown jurisdiction → rule action (BLOCK under a blocking rule);
- unbound token or absent active policy → evaluation refused with an error;
- unknown status/region codes sent by a caller map to the `Unknown` variants,
  so junk input flags instead of widening outcomes.

## See also

- [`policy-model.md`](policy-model.md) — what a policy contains
- [`contract-interface.md`](contract-interface.md) — how the contract assembles requests
- `../policy-schema/decision.schema.json` — the decision document shape