# Versioning

Safeguard has **four separate version axes** that are easy to confuse.
They are versioned independently and intentionally:

| Axis | What changes | Where it lives | Versioned by |
| ---- | ------------ | -------------- | ------------ |
| Contract code | The deployed wasm artifact | `safeguard-contract` | Cargo package version (`0.x.y`) |
| Policy schema | The machine-readable shapes hooks/audit consume | `policy-schema/*.schema.json` | `$id` query string (`?version=N`) |
| Policy versions | Rule sets in force per token | contract persistent storage | Monotonic `version` per policy |
| SDK (future) | Client libraries | `sdk/` | crate/package version |

Example of the axes evolving independently:

```text
Contract v1                Contract v2
├── Policy schema v1   ──▶ ├── Policy schema v2
├── Policy v1              ├── Policy v3
└── SDK v1                 └── SDK v2
```

## Contract version vs policy version

- **Contract version**: a deployment/upgrade of the contract code. Changing
  rule semantics, entrypoints or storage layout requires a contract upgrade
  (new instance + state migration by admin tooling, rehearsed on testnet).
- **Policy version**: a change to a rule set, applied through the lifecycle
  (`register_version` → `activate_version`). This is the normal, frequent
  kind of change and never requires a contract upgrade.

## Schema version

The policy schema is the **stable interface** between the polyrepos, so it
has its own compatibility rules (see `../policy-schema/README.md`):

- additive-only: new optional properties or enum extensions allowed;
  removals/renames/renumberings are breaking;
- the current schema version is `1`, encoded in every `$id` and echoed by
  the contract's `schema_version` entrypoint so consumers can gate on it;
- a breaking schema change must be announced alongside the core release that
  implements it.

## Compatibility guarantees

- Decision and reason codes, rule type/action codes, and status/region codes
  are explicitly numbered and **never renumbered** — audit history and
  on-chain records depend on it. Additions append new codes.
- Enum labels are stable ASCII strings shared between Rust (`as_str`),
  JSON schemas and decision documents.
- `policy_id` and rule ids are ASCII, 1–32 bytes everywhere; the schema
  enforces the width so off-chain documents cannot silently truncate.

## Migration and rollback

**Policy change (routine).** Register the new version as a draft, validate
it (`scripts/validate_policy.py`), activate it, verify with `evaluate`.
Rollback is a new version too — activate the previous configuration again;
the old record still exists (status `Superseded`) and can be re-registered
as a new draft if its number is free.

**Schema change (additive).** New optional properties ship in the same
release as the consumers that understand them. `schema_version` stays
compatible; consumers must ignore unknown properties.

**Contract upgrade (rare).** Deploy a new instance, migrate state with admin
tooling (replay registration/bindings or export/import), run compatibility
tests, switch hooks to the new address. Rollback is re-pointing hooks at the
old instance; on-chain state that used the new layout must be migrated back.
Testnet rehearsal is required — see [`deployment.md`](deployment.md) and
the `scripts/deploy-testnet.sh` / `scripts/rehearse-upgrade.sh` runbooks.

## See also

- [`policy-model.md`](policy-model.md) — policy version lifecycle
- [`contract-interface.md`](contract-interface.md) — `schema_version` and entrypoints
- [`deployment.md`](deployment.md) — testnet deploy and upgrade drills
- `../policy-schema/README.md` — schema compatibility contract
- `../CHANGELOG.md` — per-release changes