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
safeguard fixture validate [fixtures_dir]
safeguard registry inspect <dataset.json>
safeguard policy test <policy.json> [--fixtures-dir DIR] [--strict]
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

### `fixture validate`

Validates the fixture datasets (default `policies/fixtures`) with the same
rules as `scripts/check-fixtures.py`, without needing the Python
toolchain:

- `accounts.json` — well-formed Stellar `G` addresses, known account-status
  labels, jurisdictions in the universe or the `XX` unknown sentinel;
- `jurisdictions.json` — well-formed region lists (uppercase ISO alpha-2,
  no duplicates, no cross-list classification);
- `sanctions.json` — entries parse through the SDK's schema-mirroring model,
  subject hashes are 64 hex chars, dataset versions are >= 1.

Prints an `OK:` summary (counts) or a numbered problem list, exiting 1 on
failure.

### `registry inspect`

Summarizes a normalized registry dataset before it is pushed on-chain. The
kind is auto-detected from the JSON shape:

- **sanctions** entries (a `SanctionsDatasetEntry` array) — entry count,
  active/inactive split, per-list breakdown, dataset versions;
- **identity** records (an `{ "accounts": [...] }` object) — count and
  status histogram;
- the **region universe** (permitted/restricted/prohibited lists) — counts
  per list.

Unrecognized shapes are rejected with a clear message.

### `policy test`

Evaluates every account fixture through a policy offline — the policy
author's acceptance run before anything touches the chain:

```bash
safeguard policy test policies/examples/combined-policy.json
# policy example-combined v1 — 6 fixture subjects
# account          status     region decision reason
# GAAAAA…AAAWHF    active     US     APPROVE  no_reason
# ...
# summary: 2 approve, 2 block, 2 flag
```

`--strict` turns any `BLOCK` into a non-zero exit, so the command composes
with CI gates. Account fixtures carry no screening claim, so
`sanctions_matched` is `false` for every subject; inspect the sanctions
dataset separately with `registry inspect`.

### `dataset build`

Runs a provider sanctions snapshot through the adapter pipeline — parse,
normalize, hash — and writes the dataset report an operator reviews before
pushing entries to the contract's `set_sanctions_entry`:

```bash
safeguard dataset build policies/fixtures/snapshots/ofac-sample.txt -o report.json
# source ofac: 5 entries normalized, 1 review items
# review items (operator decision required):
#   - subject="unmapped sample entity" …
#       reason: unmapped provider list code "NONSTANDARD"
```

The snapshot is pipe-delimited `subject|list-code|status|effective-date`
(see [`adapters.md`](adapters.md)). Default OFAC list/status mappings apply;
repeat `--list PROVIDER_CODE=LIST_ID` to extend them. Review items —
unmappable records — are never dropped silently; the command reports them
and exits zero so the operator decides.

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