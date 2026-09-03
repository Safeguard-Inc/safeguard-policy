# Threat Model

Threats to a compliance policy layer, and the mitigations built into this
repository. The security principles are stated in
[`security.md`](security.md); this document walks concrete attack scenarios.

Assumed adversaries:

- **Unauthorized actors** — anyone without admin or authority role trying to
  change policy or registry state.
- **Compromised operators** — a legitimate admin or authority acting
  maliciously or after compromise.
- **Malicious callers** — arbitrary accounts invoking `evaluate` or reads
  with crafted inputs.
- **Broken data pipelines** — adapters, attestation providers or datasets
  feeding stale or malicious compliance data.

## Threat table

| # | Threat | Impact | Mitigation | Status |
| - | ------ | ------ | ---------- | ------ |
| T1 | **Policy manipulation** — an unauthorized party registers or activates a policy version. | Rule set swapped; restricted actors approved. | Role-split lifecycle: registration is admin-only, activation requires admin or policy authority, both `require_auth`; registration validated before persistence; append-only (no overwrite). | Mitigated |
| T2 | **Policy downgrade** — replace active v3 with v1. | Re-enabled legacy rules or disabled checks. | Versions are immutable records; only drafts activate; re-registering an existing version is rejected (`VersionExists`); downgrade requires an explicit new version + activation. | Mitigated |
| T3 | **Registry poisoning** — malicious compliance data (sanctions/identity) enters evaluation. | Bad subjects approved or legitimate subjects blocked. | Data enters only through reviewed adapters normalized against schemas (`sanctions.schema.json`); on-chain records validated at registration; dataset versions let stale data be detected. Partially mitigated by operator review; full registry on-chain wiring is Phase 4. | Partially mitigated |
| T4 | **Privilege escalation** — a non-admin gains admin or authority powers. | Full control. | Role changes admin-only; `require_auth` on the acting address; declared-operator check precedes auth so non-members cannot even attempt; no anonymous mutations. | Mitigated |
| T5 | **Silent fail-open** — missing compliance data approves by accident. | Sanctioned/unknown actors transact. | Unknown status/region map to FLAG or the rule action; unbound tokens and absent active policies error; enforced by property tests over the request space. | Mitigated |
| T6 | **Stale compliance data** — sanctions or identity datasets outdated. | Recently-listed subjects approved. | Dataset version on every sanctions entry; TTL extension keeps on-chain state live; adapters must re-publish on refresh. Operationally, screening latency is a deployment decision documented in the default policy. | Partially mitigated |
| T7 | **Denial of service** — registry unavailable or malformed input floods evaluation. | Legitimate operations blocked or flagged. | Evaluation is a pure read with no network; malformed input codes fail closed (flag) rather than panic; storage access is bounded. | Mitigated |
| T8 | **Replay/re-entrancy on lifecycle** — replayed admin calls. | Duplicate versions or double activation. | Append-only registration; activation idempotence via status transitions (only drafts activate); Soroban auth covers the invocation. | Mitigated |
| T9 | **Spec/implementation drift across polyrepos** — hooks interprets a decision differently than this repo defines it. | Enforcement contradicts policy. | Stable serialized codes/labels with round-trip tests; decision schema shared; parity tests keep schema copies identical; compatibility tests against hooks are Phase 6 work. | Partially mitigated |
| T10 | **Identifier collisions** — two rules/policies share an id after truncation. | Wrong rule attributed. | 32-byte ASCII id constraint enforced in schema and validator; unique-id invariant per policy. | Mitigated |
| T11 | **Storage expiry** — persistent policy records expire. | Active policy vanishes; evaluations fail (fail-closed, but availability loss). | TTL extension on every read/write (`TTL_EXTEND_TO` ≈ 9.5 months); monitoring of record TTL is operator responsibility. | Mitigated |
| T12 | **Privacy** — on-chain registries leak personal data. | Regulatory exposure. | Registries store hashes/references, not PII (sanctions entries are subject hashes); identity data enters via attestations/references. | Mitigated by design |

## Residual risks and open work

- **Compromised admin** (T1/T4 with a legitimate admin): mitigated by
  multi-sig-style operations only if the deployment uses one; documented as
  operator responsibility. Future work: authority quorums.
- **Registry poisoning** (T3): the on-chain registry layer (Phase 4) will
  make dataset provenance and rotation explicit on-chain; until then
  screening data quality is an operator/adapter responsibility.
- **Cross-polyrepo drift** (T9): addressed by compatibility tests against
  `safeguard-hooks` scheduled for Phase 6.

## When evaluating a change

Ask: does this change (1) make any path silently approve when information is
missing, (2) allow policy or registry state to mutate without admin/authority
auth, (3) introduce nondeterminism or external calls into evaluation, or
(4) weaken the append-only version model? If yes, the change needs a security
review before merge.