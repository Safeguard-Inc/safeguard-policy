# CLI

`crates/safeguard-cli` builds the `safeguard` binary: offline policy
tooling for authors and operators. It is a **developer/operator tool, not a
replacement for on-chain enforcement** — activating a policy, binding a
token, or evaluating live subjects happens against the contract, never
through this binary.

## What the CLI shares with the contract

The CLI runs the exact engine the contract runs. `validate` and `inspect`
use the SDK document model; `evaluate` calls
`safeguard_core::evaluator` through the SDK. A policy that the CLI approves
is a policy the contract approves, given the same facts — offline results
cannot drift from on-chain results.

## Commands

```
safeguard version
safeguard validate <policy.json>
safeguard inspect  <policy.json>
safeguard evaluate <policy.json> <facts.json>
```

### `version`

Prints the binary version and the policy-schema version it understands
(mirrors the contract's `schema_version` entrypoint). Use this to check
that a deployed contract and a local CLI speak the same schema.

### `validate`

Loads a policy document, checks it against `policy.schema.json` semantics
and the repository invariants:

- non-empty `policy_id`, ASCII, at most 32 bytes (the on-chain id width);
- integer `version >= 1`;
- at least one rule; unique rule ids; at most one rule per type;
- jurisdiction rules carry well-formed region lists (uppercase ISO alpha-2,
  no duplicates, no cross-list classification); other rules carry none.

Exits 0 on success, 1 with a diagnostic list on failure.

### `inspect`

Prints a human-readable summary of a policy document: id, version, rule
count and each rule's type/action/regions. Useful for a quick review before
registering a policy version on-chain.

### `evaluate`

Runs one subject through the engine offline:

```bash
safeguard evaluate policies/default/policy.json facts.json
# APPROVE  reason=no_reason
```

`facts.json` is the resolved subject state, matching `EvaluationFacts`:

```json
{
  "account_status": "active",
  "allowlist_member": true,
  "denylist_matched": false,
  "sanctions_matched": false,
  "jurisdiction": "US"
}
```

`jurisdiction` accepts either a region code (`"US"`, classified against
the policy's region lists) or an explicit classification
(`permitted` | `restricted` | `prohibited` | `unknown`). The exit code is 0
for `APPROVE`/`FLAG` and non-zero for `BLOCK`, so the CLI composes with
shell pipelines and CI. See [`docs/how-to-evaluate.md`](how-to-evaluate.md)
for the worked cases.

## Relationship to other tools

| Tool | Scope |
| ---- | ----- |
| `safeguard` CLI | Offline authoring/validation/dry-run evaluation |
| `scripts/validate_policy.py` | Same invariants, Python (used in CI for the shipped policies) |
| contract `evaluate` | On-chain, live evaluation (read-only, no enforcement) |
| `safeguard-hooks` | Actual enforcement at transfer time (separate polyrepo) |

The CLI and `validate_policy.py` enforce the same rules so contributors can
use whichever they prefer; the CI gate runs the Python one over the shipped
reference policies.