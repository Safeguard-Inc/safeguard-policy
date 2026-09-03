# Policy Schema

The **stable machine-readable interface** of `safeguard-policy`. Everything
outside this repository that consumes policies — `safeguard-hooks` when it
mirrors policy state, `safeguard-audit` when it reads decisions, SDKs and
CLIs when they build requests — speaks the shapes defined here.

## Files

| File | Defines |
| ---- | ------- |
| [`policy.schema.json`](policy.schema.json) | A policy document: id, version, rule set. |
| [`rule.schema.json`](rule.schema.json) | A single rule: id, type, action. |
| [`jurisdiction.schema.json`](jurisdiction.schema.json) | Jurisdiction rule configuration (region classification + action). |
| [`sanctions.schema.json`](sanctions.schema.json) | A normalized sanctions dataset entry (adapter output). |
| [`decision.schema.json`](decision.schema.json) | A policy decision document (produced by hooks/audit). |

All schemas target [JSON Schema draft
2020-12](https://json-schema.org/draft/2020-12/schema) and are validated with
the `jsonschema` Python library (see `../scripts/validate-policy.py`).

## Compatibility contract

The schema is part of the **versioned interface** between the Safeguard
polyrepos. The rules:

- **Additive only.** A schema may add optional properties or extend an enum;
  it may never remove, rename or renumber what is already published.
- **`policy_id` and rule `id`** are ASCII, 1–32 bytes, matching the fixed-width
  identifier contract in `safeguard-core` (longer ids would silently truncate
  on-chain).
- **Enum labels are stable** and mirror the core serialization: rule `type` ∈
  `allowlist | denylist | sanctions | jurisdiction`, rule `action` ∈
  `block | flag`, decision ∈ `APPROVE | BLOCK | FLAG`, reason codes are the
  lowercase labels from `safeguard_core::decision::ReasonCode`.
- A schema version bump is required for any breaking change and must be
  announced alongside the core crate release that implements it. The current
  schema version is `1`, tracked in each file's `$id` query string and echoed
  by the contract's `schema_version` entrypoint.

## Keeping rule definitions in sync

`rule.schema.json` and `policy.schema.json` both define the *rule* shape (the
policy schema embeds it via `$defs`). They are validated to be identical by
`scripts/test-schema.py`; if you edit one, update the other in the same
commit.

## Validating

```bash
# One or more policy documents
python3 scripts/validate-policy.py policies/default/policy.json policies/examples/*.json

# The whole test battery (positive, negative and parity cases)
python3 scripts/test-schema.py
```