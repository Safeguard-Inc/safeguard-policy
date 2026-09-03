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
`EvaluationInput` facts: account status, allowlist membership, denylist
match, a sanctions-match **claim**, a jurisdiction code, plus the `subject`
hash and `account` that key the on-chain registries.

Where a deployment maintains the registries, the hook may **read** them
instead of resolving every fact itself:

- `sanctions_entry(subject_hash)` → authoritative screening status;
- `jurisdiction(account)` → stored region classification;
- `identity(account)` → verification record (status, attestation ref).

The contract resolves the sanctions and jurisdiction facts from those
registries when entries exist, so even a hook that sends a clean-screen
claim cannot hide a listed subject.

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
| Registry + authority events | What compliance data changed, and who held the authority role when. |
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

## Example flow (allowlist + sanctions policy, with registries)

```text
1.  Admin:  register_version(policy, 1, hash, [ALLOWLIST-001, SANCTIONS-001])
2.  PolicyA: activate_version(operator, policy, 1)   ← policy authority, not the admin
3.  Authy:  bind_token(authority, policy, token)
4.  Authy:  set_sanctions_entry(authority, subject_hash, "OFAC-SDN", active, ...)
5.  Hook:   evaluate(policy, token, { status: active, member: true, ... })
           → BLOCK (sanctions_match, SANCTIONS-001)   ← registry, not the hook's claim
6.  Hook:   refuses the transfer; emits transfer_blocked
7.  Audit:  records decision doc { decision: "BLOCK", reason_code: "sanctions_match", ... }
```

The hook's clean-screen claim cannot override the active on-chain entry —
step 5 blocks because the registry is authoritative for the subject hash. A
retired entry (`retire_sanctions_entry`) lifts the block, and the
`SanctionsEntryUpdated` event lets audit prove the dataset change.

## Compatibility testing

The interface between this repository and `safeguard-hooks` is pinned in
several layers, all run by `./scripts/ci.sh`:

- `safeguard-contract` tests register the **shipped policy documents** and
  assert the documented evaluation cases at the contract level, so a policy
  JSON and the on-chain semantics cannot drift;
- `the_stable_numeric_interface_is_pinned` asserts every code hooks and audit
  observe — schema version, the thirteen error codes, decision/reason/type/
  action codes, registry statuses, input status/region codes — in one place;
- `safeguard-sdk` golden fixtures hold the expected decision documents for
  the worked cases, so serialization drift fails loudly;
- the proptest suites sample unbounded input spaces (arbitrary rule sets,
  arbitrary facts over shipped policies, arbitrary u32 codes at the contract
  boundary) for determinism and fail-closed invariants.

`safeguard-hooks` consuming these tests should treat the contract client,
the stable codes and the golden fixtures as its compatibility contract; when
that repository exists, cross-repo CI will run this gate against it.

## See also

- [`contract-interface.md`](contract-interface.md) — entrypoint reference
- [`rule-engine.md`](rule-engine.md) — decision semantics
- [`registries.md`](registries.md) — where facts come from
- `../policy-schema/README.md` — the machine-readable contract