# Registries

How external compliance information becomes something the policy engine can
consume deterministically. This is the **data boundary** of the repository:
facts enter on-chain state only in normalized, referenced forms.

## The boundary in one picture

```text
External Source (sanctions data, KYC/attestation providers, geo providers)
        │  adapters (off-chain, reviewed)
        ▼
Normalized datasets / attestations   ← schemas in policy-schema/
        │  deterministic representation
        ▼
Registries (on-chain or caller-resolved facts)
        │
        ▼
Policy engine snapshot (EvaluationRequest)
```

The contract **never fetches internet data** during evaluation. Everything
required for a deterministic on-chain decision is either stored on-chain or
passed in as a resolved fact by the caller (hooks).

## Registry types

| Registry | Holds | Current state |
| -------- | ----- | ------------- |
| Identity | Account → verification status, attestation reference, expiry. No PII: references, hashes, provider ids. | **On-chain today**: `set_identity` / `remove_identity` / `identity` (admin or registry authority). Read by hooks/audit; verification status is not an engine input. |
| Sanctions | Subject hash, list id, status, dataset version, effective time, source. | **On-chain today**: `set_sanctions_entry` / `retire_sanctions_entry` / `sanctions_entry` plus `evaluate` resolution — an active entry for the subject hash makes the sanctions rule fire regardless of the caller's claim. |
| Jurisdiction | Account → region code. | **On-chain today**: `set_jurisdiction` / `clear_jurisdiction` / `jurisdiction` plus `evaluate` resolution — a stored classification wins over the caller's claim. |
| Token | Policy → bound Confidential Tokens. | **On-chain today**: `bind_token` / `unbind_token` / `bound_tokens`. `evaluate` refuses unbound tokens. |

## Why registries are not a centralized database

The registries are on-chain because snapshots must be verifiable and
shared, but they are **deterministic snapshots or attestations**, not a
live central database: entries are normalized, versioned and replaceable
by the registry authority, and nothing in the evaluation path depends on a
network round-trip or on a registry being present — with no entry,
`evaluate` falls back to the caller's resolved facts.

## Authoritativeness in `evaluate`

Where an entry exists, the registry is authoritative and the caller's
claim is ignored for that fact:

| Fact | Registry lookup | Authoritative value |
| ---- | --------------- | ------------------- |
| Sanctions match | `SanctionsEntry(subject_hash)` | `true` when the entry is active, `false` when retired |
| Jurisdiction | `Jurisdiction(account)` | the stored `RegionStatus` code |
| Identity | (storage only — no engine input) | hooks/audit read it; evaluation is unaffected |

No entry → caller-claim fallback, so deployments without registries behave
identically to the pre-registry contract. The identity registry stores
verification status for hooks and audit rather than feeding the engine,
which keeps the engine free of semantics the policy does not own.

## Privacy

Registries store references, not personal data:

- sanctions entries are keyed by a subject hash (SHA-256 of the normalized
  subject identifier);
- identity data enters via attestations and provider references;
- region classification is a coarse code, not a location.

## Dataset freshness

Sanctions entries carry a monotonic `dataset_version`. Adapters re-publish
on refresh; consumers and operators can detect stale data by comparing
versions. On-chain entries get TTL extension on every read/write so they do
not silently expire (see [`security.md`](security.md)).

## See also

- [`adapters.md`](adapters.md) — how external data becomes normalized entries
- [`rule-engine.md`](rule-engine.md) — how registry facts feed decisions
- [`contract-interface.md`](contract-interface.md) — registry entrypoints and storage layout
- [`security.md`](security.md) — registry authority role and data hygiene
- `../policy-schema/sanctions.schema.json`, `jurisdiction.schema.json`