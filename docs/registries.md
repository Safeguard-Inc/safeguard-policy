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
| Identity | Account → identity reference, verification status, jurisdiction, attestation reference, expiry. No PII: references, hashes, provider ids. | Caller-resolved facts (`EvaluationInput`) — the contract receives resolved status/membership flags. On-chain identity registry is Phase 4. |
| Sanctions | Subject hash, list id, status, dataset version, effective time, source. | Normalized dataset shape defined (`policy-schema/sanctions.schema.json`); matching is caller-resolved today; on-chain screening registry is Phase 4. |
| Jurisdiction | Account/region classification. | Region classification defined (`jurisdiction.schema.json`); resolved per subject and passed in. |
| Token | Policy → bound Confidential Tokens. | **On-chain today**: `bind_token` / `unbind_token` / `bound_tokens`. `evaluate` refuses unbound tokens. |

## Why registries are not a centralized database

The token registry is on-chain because scope must be verifiable and shared.
The identity/sanctions/jurisdiction registries are represented on-chain
(Phase 4) as **deterministic snapshots or attestations**, not as a live
central database: entries are normalized, versioned and replaceable, and
nothing in the evaluation path depends on a network round-trip.

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
- [`contract-interface.md`](contract-interface.md) — the token registry entrypoints
- `../policy-schema/sanctions.schema.json`, `jurisdiction.schema.json`