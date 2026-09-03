# Adapters

The off-chain integration boundary. Adapters convert external compliance
data — sanctions lists, identity/KYC attestations, jurisdiction
classification — into Safeguard's normalized, deterministic representations
so the policy engine can consume them without ever touching a live external
endpoint.

## The adapter pipeline

```text
External Source
      │
      ▼
Source Adapter   (one per provider; fetch, parse, map)
      │
      ▼
Normalizer       (canonical field mapping, hashing, validation)
      │
      ▼
Safeguard Dataset / Attestation   (validated against policy-schema)
      │
      ▼
Registry / Caller facts           (consumed by the policy engine)
```

## Sanctions adapters

Responsibility: convert a provider's records into normalized entries that
validate against `policy-schema/sanctions.schema.json`:

```json
{
  "subject_hash": "…64 hex…",
  "list_id": "OFAC-SDN",
  "status": "active",
  "dataset_version": 42,
  "effective_at": "2023-06-01T00:00:00Z",
  "source": "ofac"
}
```

Requirements:

- deterministic: the same provider snapshot must produce the same entries;
- keyed by subject hash so no personal data is stored (see
  [`registries.md`](registries.md));
- carries `dataset_version` so stale data is detectable;
- runs off-chain and publishes a dataset; the contract never calls the
  adapter.

## Identity adapters

Abstract the KYC/attestation provider. The policy layer consumes normalized
results, never provider-specific shapes:

```text
VERIFIED   UNVERIFIED   REVOKED   EXPIRED   UNKNOWN
```

plus the derived facts the engine needs (account status, allowlist
membership, jurisdiction). Adapters map provider state to these stable
outcomes; the engine's fail-closed rules handle `UNKNOWN` (flag, never
approve).

## Jurisdiction adapters

Convert provider/geo data into the normalized classification
(`permitted`/`restricted`/`prohibited`/`unknown`) defined by
`jurisdiction.schema.json`, mapped per account or transaction context.
Unknown classifications fail closed in the engine.

## What an adapter must never do

- Never be called from inside the Soroban execution path.
- Never pass raw provider data through unmapped (normalize first, then
  validate).
- Never guess: if a source field cannot be normalized, mark the record
  `unknown`/skip and surface it for operator review rather than inventing a
  value.

## Testing adapters

Adapters should ship with golden tests: provider sample input → expected
normalized output, validated against the schema. The fixtures in
`policies/fixtures/` model normalized output (`sanctions.json`, `accounts.json`)
and are cross-checked by `scripts/check-fixtures.py`.

## See also

- [`registries.md`](registries.md) — where normalized data lands
- [`security.md`](security.md) — the fail-closed stance on missing data
- `../policy-schema/README.md` — the schemas adapters validate against