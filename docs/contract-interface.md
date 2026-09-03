# Contract Interface

The on-chain surface of `safeguard-contract`. This is the reference for
`safeguard-hooks`, SDKs and operators; the entrypoints are implemented in
`src/contract.rs` and delegate to the functional modules.

## Entrypoints

### Bootstrap and roles

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `initialize(admin)` | declared admin | Sets the administrator. Fails with `AlreadyInitialized` if called twice. |
| `admin() -> Address` | public | Read the current admin. |
| `set_admin(new_admin)` | current admin + new admin | Rotate the admin (both sides authenticate). |
| `authorities() -> Vec<Address>` | public | Read registry authorities. |
| `add_authority(authority)` / `remove_authority(authority)` | admin | Manage registry authorities. |

### Policy lifecycle

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `register_version(policy_id, version, config_hash, rules)` | admin | Create a `Draft` version. Rejects existing versions (`VersionExists`) and invalid rule sets (`InvalidRuleSet`). |
| `activate_version(policy_id, version)` | admin | Promote a draft to `Active`; the previous active version becomes `Superseded`. Fails on non-drafts (`VersionNotDraft`) and missing versions (`VersionNotFound`). |
| `deactivate_version(policy_id, version)` | admin | Disable the active version; clears the active pointer. Only the active version may be deactivated (`VersionNotActive`). |
| `get_version(policy_id, version) -> PolicyVersionRecord` | public | Read a specific version record. |
| `get_active_version(policy_id) -> PolicyVersionRecord` | public | Read the active version. Fails `PolicyNotActive` when none. |

### Token registry

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `bind_token(operator, policy_id, token)` | admin or authority | Add a token to a policy's scope. Idempotent. Unauthorized operators get `Unauthorized`. |
| `unbind_token(operator, policy_id, token)` | admin or authority | Remove a token from a policy's scope. Idempotent. |
| `bound_tokens(policy_id) -> Vec<Address>` | public | List tokens covered by a policy. |

### Evaluation

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `evaluate(policy_id, token, input) -> EvaluationResult` | public | Evaluate a subject against the active version for a bound token. Read-only and deterministic. |

`EvaluationInput` carries the caller-resolved facts (account status code,
allowlist membership, denylist/sanctions match flags, jurisdiction code);
`EvaluationResult` returns the active policy version, decision code, reason
code and the triggering rule id. Unknown status/region codes fail closed to
the core `Unknown` variants. Errors are scope/configuration only:
`PolicyNotActive`, `TokenNotBound`, `InvalidRuleSet`.

`schema_version() -> u32` returns the policy-schema version this contract
speaks — the gate consumers should check before relying on serialization.

## Error codes

Stable, never renumbered (see [`versioning.md`](versioning.md)):

| Code | Name | Meaning |
| ---- | ---- | ------- |
| 1 | `Unauthorized` | Caller not in the required role. |
| 2 | `AlreadyInitialized` | `initialize` called twice. |
| 3 | `NotInitialized` | Admin not set (only reachable internally). |
| 4 | `PolicyNotFound` | No such policy (reserved; version records are the current truth). |
| 5 | `VersionNotFound` | No version with this number. |
| 6 | `VersionNotDraft` | Activation attempted on a non-draft. |
| 7 | `InvalidRuleSet` | Duplicate category/id or unknown codes. |
| 8 | `PolicyNotActive` | No active version. |
| 9 | `TokenNotBound` | Token not in the policy's scope. |
| 10 | `InvalidPolicyId` | Reserved/invalid policy id. |
| 11 | `VersionExists` | Append-only registration violated. |
| 12 | `VersionNotActive` | Deactivation of a non-active version. |

## Storage layout

Instance: `Admin → Address`, `Authorities → Vec<Address>`.
Persistent (TTL-extended on every read/write):

```text
Version(VersionKey{policy_id, version}) → PolicyVersionRecord
ActiveVersion(policy_id)                → u32
TokenBindings(policy_id)                → Vec<Address>
```

All multi-byte ids are fixed 32-byte `BytesN<32>` values.

## Events

Typed `contractevent`s, published by the lifecycle:

| Event | Payload |
| ----- | ------- |
| `policy_created` | policy_id, version, config_hash |
| `policy_activated` | policy_id, version, config_hash |
| `policy_deactivated` | policy_id, version |

These are the **configuration-change** events audit consumes. Transfer-level
events (`transfer_approved`, `transfer_blocked`) belong to `safeguard-hooks`.

Note for tests: in soroban-sdk 27 testutils, recorded events are scoped to
the invocation that emitted them; query `env.events().all()` immediately
after the emitting call.

## See also

- [`rule-engine.md`](rule-engine.md) — what `evaluate` computes
- [`integration.md`](integration.md) — how hooks and audit use this surface
- [`security.md`](security.md) — auth model behind every entrypoint