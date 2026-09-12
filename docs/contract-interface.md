# Contract Interface

The on-chain surface of `safeguard-contract`. This is the reference for
`safeguard-hooks`, SDKs and operators; the entrypoints are implemented in
`src/contract.rs` and delegate to the functional modules.

## What the contract does — and does not

The contract **stores policy configuration and evaluates subjects** against
the active version of a bound policy. It never fetches external data: every
fact a decision needs is represented through contract state (registered
registries, attestation references, or caller-supplied claims resolved
against those registries). There is no network access in the evaluation
path, and evaluation never consults wall-clock time — decisions are
functions of contract state plus the caller's input, nothing else.

Operations (`operation_rules`) are **not** modeled on-chain: rule categories
are allowlist, denylist, sanctions and jurisdiction (see
`docs/rule-engine.md`). Operation-specific gating (e.g. "this rule applies
to transfers but not to mints") belongs to `safeguard-hooks`, which decides
*when* to invoke `evaluate` for a given token operation.

## Entrypoints

### Bootstrap and roles

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `initialize(admin)` | declared admin | Sets the administrator, emitting `admin_set`. Fails with `AlreadyInitialized` if called twice. |
| `admin() -> Address` | public | Read the current admin. |
| `set_admin(new_admin)` | current admin + new admin | Rotate the admin (both sides authenticate), emitting `admin_set` on a real rotation. |
| `authorities() -> Vec<Address>` | public | Read registry authorities. |
| `add_authority(authority)` / `remove_authority(authority)` | admin | Manage registry authorities. |
| `policy_authorities() -> Vec<Address>` | public | Read policy authorities. |
| `add_policy_authority(authority)` / `remove_policy_authority(authority)` | admin | Manage policy authorities (may activate/deactivate versions). |

### Policy lifecycle

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `register_version(policy_id, version, config_hash, rules)` | admin | Create a `Draft` version. Rejects existing versions (`VersionExists`) and invalid rule sets (`InvalidRuleSet`). |
| `activate_version(operator, policy_id, version)` | admin or policy authority | Promote a draft to `Active`; the previous active version becomes `Superseded`. Fails on non-drafts (`VersionNotDraft`) and missing versions (`VersionNotFound`). |
| `deactivate_version(operator, policy_id, version)` | admin or policy authority | Disable the active version; clears the active pointer. Only the active version may be deactivated (`VersionNotActive`). |
| `get_version(policy_id, version) -> PolicyVersionRecord` | public | Read a specific version record. |
| `get_active_version(policy_id) -> PolicyVersionRecord` | public | Read the active version. Fails `PolicyNotActive` when none. |

### Token registry

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `bind_token(operator, policy_id, token)` | admin or authority | Add a token to a policy's scope, emitting `token_bound`. Idempotent. Rejects a policy id that was never registered with `PolicyNotFound`; unauthorized operators get `RegistryAuthorityRequired`. |
| `unbind_token(operator, policy_id, token)` | admin or authority | Remove a token from a policy's scope, emitting `token_unbound`. Idempotent. Same `PolicyNotFound` guard as bind. |
| `bound_tokens(policy_id) -> Vec<Address>` | public | List tokens covered by a policy. |

### Compliance registries

Deterministic snapshots of external compliance information (see
[`registries.md`](registries.md)); all writes require admin or a registry
authority, reads are public.

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `set_identity(operator, account, status, attestation_ref, expires_at)` | admin or authority | Write/replace an account's verification record. Unknown status codes fail `InvalidRegistryData`. `expires_at` is a ledger-seconds epoch after which `is_authorized` treats the record as `Unknown` (fail closed); `0` means no expiry. |
| `remove_identity(operator, account)` | admin or authority | Remove an account's verification record. |
| `identity(account) -> Option<IdentityRecord>` | public | Read the stored record. |
| `set_sanctions_entry(operator, subject_hash, list_id, status, dataset_version, effective_at, source)` | admin or authority | Upsert a normalized entry. Status must be a known `SanctionsStatus` and `dataset_version >= 1`. |
| `retire_sanctions_entry(operator, subject_hash)` | admin or authority | Flip an entry to inactive — never deletes, so history stays readable. |
| `sanctions_entry(subject_hash) -> Option<SanctionsEntryRecord>` | public | Read the stored entry. |
| `set_jurisdiction(operator, account, region)` | admin or authority | Set/replace an account's region code. Unknown codes fail `InvalidRegistryData`. |
| `clear_jurisdiction(operator, account)` | admin or authority | Remove an account's region code. |
| `jurisdiction(account) -> Option<u32>` | public | Read the stored region code. |

### Evaluation

| Function | Auth | Description |
| -------- | ---- | ----------- |
| `evaluate(policy_id, token, input) -> EvaluationResult` | public | Evaluate a subject against the active version for a bound token. Read-only and deterministic. |
| `is_authorized(account, token) -> bool` | public | Enforcement wire entry point: decide `account` on `token` from on-chain state alone. Never reverts; `true` only on an explicit approve (see below). |

`EvaluationInput` carries the caller-resolved facts (account status code,
allowlist membership, denylist match flag, sanctions match claim,
jurisdiction code, and the `subject` hash + `account` that key the
on-chain registries). `EvaluationResult` returns the active policy version,
decision code, reason code and the triggering rule id.

**`is_authorized` — the ENFORCE seam.** This is the `is_authorized(account,
token) -> bool` wire function the `safeguard-hooks` policy-client calls
(see `interfaces/policy/policy.md` in that repo). The wire carries only an
account and a token, so the decision is derived exclusively from this
contract's on-chain state: the policy governing the token (resolved through
the registry's reverse index, and required to be bound and active), the
account's identity record (an account with no record is `Unknown` → denied;
an account whose record carries an **elapsed `expires_at` is likewise
`Unknown` → denied** — a verification with a stated lifetime ends when that
lifetime ends, and only `expires_at == 0` means "no expiry"), and the
sanctions/jurisdiction registries via the same override as
`evaluate`. Allowlist/denylist/sanctions *membership* are caller-supplied
facts in the richer `evaluate` flow and are treated as absent here — a
deployment wiring ENFORCE to this contract must use a rule set decidable
from on-chain state. Only an explicit `approve` authorizes: block and flag
decisions (unknown identity, restricted jurisdiction, review outcomes) all
answer `false`, and any evaluation error answers `false` (fail closed).

**Registry resolution.** When the compliance registries hold an entry, the
sanctions match and the jurisdiction classification are resolved from the
registry — an active sanctions entry always matches, a stored region always
wins — and the caller's claims are used only as the no-entry fallback.
Unknown status/region codes still fail closed to the core `Unknown`
variants. Errors are scope/configuration only: `PolicyNotActive`,
`TokenNotBound`, `InvalidRuleSet`.

`schema_version() -> u32` returns the policy-schema version this contract
speaks — the gate consumers should check before relying on serialization.

## Error codes

Stable and never renumbered (see [`versioning.md`](versioning.md)). Codes are
**non-dense after the completeness audit**: the removed codes 1
(`Unauthorized`) and 10 (`InvalidPolicyId`) are never reissued; the single
generic authorization code was split into the two distinct authority gates
(14, 15), and `PolicyNotFound` (4) is now produced by the registry layer.
Every code is reachable by a real path — pinned by
`every_error_code_is_reachable` and the code-table test.

| Code | Name | Meaning |
| ---- | ---- | ------- |
| 2 | `AlreadyInitialized` | `initialize` called twice. |
| 3 | `NotInitialized` | Admin not set (admin-only ops before `initialize`). |
| 4 | `PolicyNotFound` | No version was ever registered under this policy id (bind/unbind to a ghost policy). |
| 5 | `VersionNotFound` | No version with this number. |
| 6 | `VersionNotDraft` | Activation attempted on a non-draft. |
| 7 | `InvalidRuleSet` | Duplicate category/id or unknown codes. |
| 8 | `PolicyNotActive` | No active version. |
| 9 | `TokenNotBound` | Token not in the policy's scope. |
| 11 | `VersionExists` | Append-only registration violated. |
| 12 | `VersionNotActive` | Deactivation of a non-active version. |
| 13 | `InvalidRegistryData` | Registry write carried an unknown status/region code or `dataset_version == 0`. |
| 14 | `RegistryAuthorityRequired` | Caller is not the admin or a declared registry authority. |
| 15 | `PolicyAuthorityRequired` | Caller is not the admin or a declared policy authority. |

## Storage layout

Instance: `Admin → Address`, `Authorities → Vec<Address>`.
Persistent (TTL-extended on every read/write):

```text
Version(VersionKey{policy_id, version}) → PolicyVersionRecord
ActiveVersion(policy_id)                → u32
TokenBindings(policy_id)                → Vec<Address>
Identity(account)                       → IdentityRecord{status, attestation_ref, expires_at}
SanctionsEntry(subject_hash)            → SanctionsEntryRecord{list_id, status, dataset_version, effective_at, source}
Jurisdiction(account)                   → u32 (RegionStatus code)
```

All multi-byte ids are fixed 32-byte `BytesN<32>` values. Sanctions entries
are keyed by subject hash — never raw identifiers or PII.

## Events

Typed `contractevent`s published by the lifecycle and registries:

| Event | Payload |
| ----- | ------- |
| `admin_set` | admin |
| `token_bound` | policy_id, token |
| `token_unbound` | policy_id, token |
| `policy_created` | policy_id, version, config_hash |
| `policy_activated` | policy_id, version, config_hash |
| `policy_deactivated` | policy_id, version |
| `identity_updated` | account, status, attestation_ref, expires_at |
| `identity_removed` | account |
| `sanctions_entry_updated` | subject_hash, status, dataset_version |
| `jurisdiction_updated` | account, region |
| `jurisdiction_cleared` | account |
| `authority_added` | authority |
| `authority_removed` | authority |
| `policy_authority_added` | authority |
| `policy_authority_removed` | authority |

These are the **configuration-change** events audit consumes: `admin_set`
proves who held the administrator role at any point (genesis on
`initialize`, the successor on every real `set_admin`);
`token_bound`/`token_unbound` prove which tokens a policy governed at any
point (the same guarantee the hooks polyrepo's binding events give the
enforcement layer); the `registry_updated` family covers compliance-data
mutations; and the
`authority_added`/`authority_removed` pair is the
`registry_authority_changed` family proving who held the registry-authority
role when. The `policy_authority_added`/`policy_authority_removed` pair does
the same for who could promote policy versions to active. All fire only on
real changes (idempotent role calls and no-op registry writes stay silent).
Transfer-level events (`transfer_approved`, `transfer_blocked`) belong to
`safeguard-hooks`.

Note for tests: in soroban-sdk 27 testutils, recorded events are scoped to
the invocation that emitted them; query `env.events().all()` immediately
after the emitting call.

## See also

- [`rule-engine.md`](rule-engine.md) — what `evaluate` computes
- [`integration.md`](integration.md) — how hooks and audit use this surface
- [`security.md`](security.md) — auth model behind every entrypoint