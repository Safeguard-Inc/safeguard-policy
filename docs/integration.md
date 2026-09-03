# Integration

How the other two Safeguard repositories (and external integrators) consume
`safeguard-policy`. The contract surface is documented in
[`contract-interface.md`](contract-interface.md); this document describes
the flows end to end.

```text
safeguard-policy  ──▶  safeguard-hooks  ──▶  safeguard-audit
   defines rules       enforces on ops        proves what happened
```

## For safeguard-hooks: enforcing

### 1. Mirror policy state

Read the active configuration before or at evaluation time:

- `get_active_version(policy_id)` → rule set, status, config hash;
- `get_version(policy_id, version)` → any specific version;
- `bound_tokens(policy_id)` → token scope.

Consumers must gate on `schema_version()` and ignore unknown properties
(additive-only schema evolution).

### 2. Resolve facts

The hook owns the identity/sanctions/jurisdiction lookups (via adapters and
attestations, see [`adapters.md`](adapters.md)) and produces the
`EvaluationInput` facts: account status, allowlist membership, denylist and
sanctions match flags, jurisdiction code.

### 3. Evaluate

```text
evaluate(policy_id, token, input)
    → EvaluationResult { policy_version, decision, reason_code, rule_id }
```

The hook **enforces** the decision: `BLOCK` refuses the operation, `FLAG`
routes it to review, `APPROVE` allows it. Enforcement is the hook's job — the
policy contract never moves tokens.

### 4. Publish transfer-level events

The hook emits the operation-level events (`transfer_approved`,
`transfer_blocked`, `transfer_flagged`) that audit consumes. The policy
contract emits only configuration-change events (`policy_created`, …).

## For safeguard-audit: proving

Audit consumes two event streams plus on-chain state:

| Source | What it proves |
| ------ | -------------- |
| Lifecycle events from the policy contract | Which policy configuration was in force when. |
| Transfer-level events from the hook | Which decision was applied to which operation. |
| `get_version` / `get_active_version` queries | The exact rule set and config hash behind a decision. |

Decisions can be written as documents validating against
`policy-schema/decision.schema.json`, linking `decision`, `reason_code`,
`rule_id`, `policy_id`, `policy_version` and an RFC 3339 timestamp.

## Versioned interface

Everything crossing the boundary is versioned:

- decision/reason/type/action codes: stable, never renumbered;
- JSON schemas: additive-only, versioned `$id`, echoed by
  `schema_version()`;
- policy versions: append-only, per-policy monotonic.

See [`versioning.md`](versioning.md) for the compatibility contract.

## Example flow (allowlist + sanctions policy)

```text
1. Admin:  register_version(policy, 1, hash, [ALLOWLIST-001, SANCTIONS-001])
2. Admin:  activate_version(policy, 1)
3. Authy:  bind_token(authority, policy, token)
4. Hook:   facts = { status: active, member: true, matched: false, ... }
5. Hook:   evaluate(policy, token, facts) → APPROVE
6. Hook:   transfer proceeds; emits transfer_approved
7. Audit:  records decision doc { decision: "APPROVE", ... }
```

If the subject is later sanctions-matched (`matched: true`), the same policy
evaluates to `BLOCK` (reason `sanctions_match`, rule `SANCTIONS-001`), the
hook refuses the transfer and audit records the denial.

## Compatibility testing (planned)

Phase 6 adds compatibility tests that pin the interface between this repo and
`safeguard-hooks` (policy ids, versions, decisions, rule ids, registry
references, reason codes) so the two repositories cannot drift apart.

## See also

- [`contract-interface.md`](contract-interface.md) — entrypoint reference
- [`rule-engine.md`](rule-engine.md) — decision semantics
- [`registries.md`](registries.md) — where facts come from
- `../policy-schema/README.md` — the machine-readable contract