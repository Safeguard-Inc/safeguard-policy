# Adapters

The off-chain integration boundary. Adapters convert external compliance
data — sanctions lists, identity/KYC attestations, jurisdiction
classification — into Safeguard's normalized, deterministic representations
so the policy engine can consume them without ever touching a live external
endpoint.

**Implemented in `crates/safeguard-adapters`** and exposed to operators as
`safeguard dataset build <snapshot>` (see [`cli.md`](cli.md)).

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

Crate modules map onto the stages:

| Stage | Module | What it owns |
| ----- | ------ | ------------ |
| Source | `sanctions::source::SanctionsSource` | One trait per provider: parse snapshot → `ProviderRecord`s. `fetch` (transport) is optional; offline fixtures exercise the same deterministic `parse`. Ships `PipeDelimitedSource` for OFAC-style files. |
| Normalizer | `sanctions::normalizer` | Canonical subject normalization → SHA-256 hash; list-code and status mapping (`NormalizerConfig`); date normalization to RFC 3339 UTC. Never-guess: unmappable records become `Review` items. |
| Dataset | `dataset::DatasetReport` | The operator artifact: registry-ready entries + review items, written as JSON for review before anything is pushed on-chain. |
| Identity | `identity::IdentitySource` | Maps provider facts to the five normalized `IdentityStatus` outcomes with a shared, injected-clock expiry rule. |
| Jurisdiction | `jurisdiction::RegionUniverse` | Classifies region codes into `permitted`/`restricted`/`prohibited`/`unknown` (unknown fails closed), with provider-alias normalization to ISO alpha-2. |

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

Requirements (all implemented and test-pinned in `safeguard-adapters`):

- **deterministic**: the same provider snapshot must produce the same
  entries (subject hashing, mapping and ordering are pure);
- **keyed by subject hash** so no personal data is stored (see
  [`registries.md`](registries.md)) — `canonicalize_subject` + `hash_subject`
  reduce a provider subject to a 64-hex SHA-256 before it leaves the
  adapter;
- carries `dataset_version` so stale data is detectable (set by the
  publisher; entries are compared by version on-chain);
- runs off-chain and publishes a dataset; the contract never calls the
  adapter.

A concrete run looks like (the shipped sample is
`policies/fixtures/snapshots/ofac-sample.txt`):

```bash
safeguard dataset build policies/fixtures/snapshots/ofac-sample.txt -o report.json
# source ofac: 5 entries normalized, 1 review items
```

Review items name the raw record and the reason — an unmapped list code,
an unparseable date, an empty subject — and require an operator decision.
Records are never silently dropped or guessed through.

## Identity adapters

Abstract the KYC/attestation provider. The policy layer consumes normalized
results, never provider-specific shapes:

```text
VERIFIED   UNVERIFIED   REVOKED   EXPIRED   UNKNOWN
```

plus the derived facts the engine needs (account status, allowlist
membership, jurisdiction). `identity::resolve_status` applies the shared
rule — provider says unverified stays `Unverified`; verified but expired
becomes `Expired`; only verified-and-current is `Verified` — with the clock
injected so tests and replay are deterministic. The engine's fail-closed
rules handle anything else (flag, never approve). Providers implement
`IdentitySource` and map their state onto `ProviderFacts`; the module turns
those into PII-free `AttestationRecord`s matching the on-chain
`set_identity` surface.

## Jurisdiction adapters

Convert provider/geo data into the normalized classification
(`permitted`/`restricted`/`prohibited`/`unknown`) defined by
`jurisdiction.schema.json`, mapped per account or transaction context.
`RegionUniverse` classifies codes case-insensitively against a policy's
lists and maps common provider aliases (`us`/`USA`/`840`) onto ISO alpha-2;
anything outside the universe is `unknown` and fails closed in the engine.

## What an adapter must never do

- Never be called from inside the Soroban execution path.
- Never pass raw provider data through unmapped (normalize first, then
  validate).
- Never guess: if a source field cannot be normalized, mark the record
  `unknown`/skip and surface it for operator review rather than inventing a
  value (enforced by the `Review` item path in `safeguard-adapters`).

## Testing adapters

Adapters ship with golden tests: provider sample input → expected
normalized output, validated against the SDK's schema-mirroring model (the
same shape `scripts/check-fixtures.py` validates against the schemas). The
fixtures in `policies/fixtures/` model normalized output (`sanctions.json`,
`accounts.json`); `policies/fixtures/snapshots/ofac-sample.txt` models
adapter *input* and its 5-entries + 1-review-item output is pinned by the
CLI's dataset-build end-to-end test.

## See also

- [`registries.md`](registries.md) — where normalized data lands
- [`security.md`](security.md) — the fail-closed stance on missing data
- [`cli.md`](cli.md) — `safeguard dataset build`
- `../policy-schema/README.md` — the schemas adapters validate against
- `crates/safeguard-adapters` — the implementation