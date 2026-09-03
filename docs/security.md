# Security Model

Compliance enforcement must be **deterministic** and **fail-closed**.
This document states the model explicitly so it is a design requirement, not
an accident of implementation. Threat-by-threat analysis lives in
[`threat-model.md`](threat-model.md).

## Principles

1. **Fail closed, never open.** When compliance-relevant information is
   missing — account status unknown, jurisdiction unknown, dataset stale —
   the outcome is conservative (flag at minimum, block where the rule
   blocks). Missing data can never produce APPROVE.
2. **Deterministic evaluation.** Identical input plus identical policy state
   always produces the identical decision: no randomness, no wall-clock
   time, no network calls inside the evaluation path.
3. **Append-only policy state.** Policies change by creating and activating
   new versions; existing versions never mutate. History cannot be rewritten
   or silently downgraded.
4. **Least privilege.** Distinct roles for lifecycle changes and registry
   changes; every state change authenticates the actor.
5. **No external dependencies in the execution path.** The contract never
   fetches internet data; external compliance data enters through reviewed
   adapters and deterministic registries.

## Roles

| Role | Can do | Auth |
| ---- | ------ | ---- |
| Admin | Initialize; rotate admin; manage authorities; register/activate/deactivate policy versions; bind tokens | `require_auth` on the admin address |
| Registry authority | Bind/unbind tokens to policies | Declared address verified as admin or authority, then `require_auth` |
| Everyone else | Read queries; subject to evaluation | none (public reads) |

Role changes are admin-only. There is deliberately no single unrestricted
superuser beyond the admin, and the registry-authority role exists so token
scope updates do not require the full policy-admin trust domain.

## Fail-open vs fail-closed

The choice is made **per rule category** and documented:

| Situation | Behavior |
| --------- | -------- |
| Account status unknown | FLAG (`account_status_unknown`) |
| Region unknown | triggers the jurisdiction rule action (BLOCK under a blocking rule) |
| Unbound token / no active policy | evaluation refused (`TokenNotBound` / `PolicyNotActive`) |
| Invalid status/region code from a caller | mapped to the `Unknown` variants → flags |
| Corrupt rule records | registration rejected; evaluation returns `InvalidRuleSet` |

Silently failing open is never an implementation detail here; every path is
tested.

## Access control

All state-changing entrypoints authenticate before touching storage:

- `initialize` — caller must be the declared admin; guarded against
  re-initialization.
- Lifecycle (`register_version`, `activate_version`, `deactivate_version`) —
  admin only.
- Registry (`bind_token`, `unbind_token`) — admin or registry authority.
  The declared operator is checked against the role set **before**
  `require_auth`, so a non-member cannot even attempt authorization.
- Reads (`get_version`, `get_active_version`, `bound_tokens`, `admin`,
  `authorities`, `evaluate`) — public; auditors can always read state.

## Storage

- Instance storage holds the admin and authorities (contract lifetime).
- Persistent storage holds version records, the active-version pointer and
  token bindings, with TTL extension on every read/write so long-lived
  compliance state cannot silently expire.
- Multi-byte ids are stored as fixed 32-byte values (`BytesN<32>`), matching
  the engine's identifier width, so arbitrary (non-UTF-8) ids are
  representable and serialize deterministically.

## Upgrades

Contract code, policy schema, policy versions and SDKs are **separate**
version axes; see [`versioning.md`](versioning.md). Upgrades are designed as
controlled, reviewable transitions:

- contract upgrades: new deployed instance + migration of state by admin
  tooling (testnet rehearsal first);
- policy changes: always a new version, activated explicitly;
- schema changes: additive only (see `../policy-schema/README.md`).

## See also

- [`threat-model.md`](threat-model.md) — concrete threats and mitigations
- [`versioning.md`](versioning.md) — version axes and compatibility
- [`contract-interface.md`](contract-interface.md) — entrypoint-level details
- `../SECURITY.md` — reporting vulnerabilities