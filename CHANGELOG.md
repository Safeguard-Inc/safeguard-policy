# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial repository structure for the `safeguard-policy` polyrepo:
  - `crates/safeguard-core`: `no_std` policy engine (decision model, rule
    primitives, versioning, deterministic evaluation).
  - `crates/safeguard-contract`: Soroban policy contract with role-based
    administration, policy lifecycle, token registry binding and an on-chain
    `evaluate` entrypoint.
  - `policy-schema`: JSON Schema definitions for policies, rules, decision
    documents, jurisdiction configuration and normalized sanctions data.
  - `policies`: default, example and fixture policy documents.
  - `scripts`: policy validation and fixture cross-reference checking.
  - Reference documentation (architecture, policy model, rule engine,
    security model) and CI.

### Added (docs & tooling)

- Full reference documentation set under `docs/`: architecture, policy
  model, rule engine, security model, threat model, versioning, contract
  interface, registries, adapters, integration, a worked evaluation example
  and a design-decisions record.
- `scripts/ci.sh` — the shared local/CI gate (fmt, clippy, tests, wasm build,
  schema battery) with `rust`/`schema` subcommands; `rust-toolchain.toml`
  pins the stable toolchain and components.
- CI: full Rust gate (fmt, clippy, tests, wasm artifact on `wasm32v1-none`)
  added to the existing schema job; dependabot for Cargo and GitHub Actions.
- Contribution tooling: pull request template and issue forms for bugs,
  features, policy changes and integrations.
- `crates/safeguard-sdk`: off-chain Rust SDK with a policy document model,
  invariant validation mirroring the Python validator, and offline
  evaluation through the same core engine compiled into the contract.
- `crates/safeguard-cli`: the `safeguard` operator CLI (`version`, `validate`,
  `inspect`, `evaluate`) for offline policy authoring and dry-run decisions.
- `sdk/typescript`: `@safeguard/policy-sdk` with types mirroring
  `policy-schema/`, invariant validation and decision-document helpers;
  tested via Node's built-in test runner.
- CI: TypeScript SDK job (typecheck + tests) and dependabot coverage for
  the npm ecosystem.
- `docs/sdk.md` and `docs/cli.md`: reference documentation for the SDKs and
  the operator CLI.
- On-chain compliance registries in `safeguard-contract` (identity
  verification, normalized sanctions entries keyed by subject hash,
  jurisdiction classification) with role-authenticated entrypoints, typed
  events for audit, and `evaluate` resolving sanctions/jurisdiction facts
  authoritatively from registry entries with a caller-claim fallback.
- Property testing with proptest (dev-only): engine invariants over
  arbitrary rule sets, arbitrary facts against every shipped policy, and
  arbitrary u32 codes at the contract input boundary — determinism and
  fail-closed guarantees with shrinking counterexamples.
- Compatibility surface for `safeguard-hooks`: the shipped combined policy
  registered on-chain and asserted against the documented cases, a single
  test pinning every stable numeric code, and golden decision documents for
  the worked cases committed under `crates/safeguard-sdk/tests/fixtures/`.
- Registry dataset models in both SDKs mirroring `sanctions.schema.json`
  (Rust `registry` module; TypeScript `registry.ts`).
- Reference docs updated for the registry layer and the compatibility
  gates (`registries.md`, `contract-interface.md`, `integration.md`,
  `how-to-evaluate.md`).
- `registry_authority_changed` event family (`AuthorityAdded`/`AuthorityRemoved`):
  role changes now emit typed events for audit, with contract tests and
  interface documentation.
- Operator CLI expansions: `fixture validate`, `registry inspect`
  (auto-detecting sanctions/identity/token/jurisdiction datasets), and
  `policy test` (fixture-driven acceptance runs with per-subject
  decisions); the facts-file model moved into the SDK and is shared with
  the CLI.
- Fixture datasets for identity verification records and policy→token
  registry bindings, validated by `scripts/check-fixtures.py` and the CLI
  fixture gate (including a shipped-policy cross-check).
- Dependency supply-chain gate: `deny.toml` (cargo-deny: advisories,
  allowlist-only licenses, wildcard bans, sources) and npm audit, run by
  `.github/workflows/security.yml` nightly and on dependency PRs, and
  locally via `./scripts/ci.sh security`.
- Tag-driven release pipeline (`.github/workflows/release.yml`) building
  the contract wasm, CLI binary, schemas + policies tarball and the
  TypeScript SDK package into a GitHub release, plus `docs/release.md`
  describing the version model, checklist and rollback.
- TypeScript SDK identity registry types (`IdentityRecord`,
  `isIdentityRecord`) mirroring the on-chain verification surface.
- Schema battery extended to 39 checks with standalone sanctions-entry
  and decision-document positive/negative cases.
- Adapter pipeline implementations in the new `crates/safeguard-adapters`
  workspace member: sanctions source + normalizer (canonicalize-then-hash
  subjects, deterministic list/status/date mapping, never-guess review
  items), the identity provider boundary with a shared injected-clock
  expiry rule, and jurisdiction universe classification with provider
  alias normalization.
- `safeguard dataset build` CLI command running a provider snapshot through
  the adapter pipeline into a registry-ready dataset report, plus
  `registry inspect` support for those reports (entries + review items).
- A shipped sample snapshot (`policies/fixtures/snapshots/ofac-sample.txt`)
  whose 5-entries + 1-review-item output is pinned by tests and the local
  gate.
- Testnet deployment runbooks: `scripts/deploy-testnet.sh` (deploy +
  initialize + smoke, opt-in `--load-policy` deriving payloads from the
  policy JSON) and `scripts/rehearse-upgrade.sh` (offline lifecycle gate
  plus the on-chain register/activate/deactivate drill), documented in
  `docs/deployment.md`.
- TypeScript SDK `DatasetReport`/`ReviewItem` types mirroring the adapter
  output shape, with structural validation.
- Fixed: the local gate had lost its TypeScript gate in the security-batch
  edit, silently breaking `./scripts/ci.sh all`; restored, and a new
  `scripts` gate dry-runs the runbooks and rebuilds the sample dataset.
- Docs: `adapters.md` and `cli.md` document the implemented pipeline;
  roadmap, versioning and design-decisions records updated (D13-D15).

## [Unreleased] — 100%-spec batch

### Added

- `rule_registered` lifecycle event: one typed event per rule in every
  `register_version` call, so audit can reconstruct the exact rule set of
  any registered version from events alone (§26).
- Policy Authority role: a dedicated role (managed by the admin) that may
  activate and deactivate policy versions, separating *creating* versions
  (admin) from *promoting* them; `policy_authority_added` /
  `policy_authority_removed` events make role changes auditable (§24).
- Contributor issue taxonomy (SC/SDK/CLI/TEST/INFRA/DOCS/SECURITY) in
  `CONTRIBUTING.md`, a "Contributor task" issue template, and aligned
  feature-template labels (§30).
- Registry publishing: crates.io (core → sdk → adapters → cli, token-gated)
  and npm (`@safeguard/policy-sdk`) jobs in the release workflow, a
  publishable npm package, and a local publish-readiness gate in `ci.sh`
  (§29).
- Negative contract tests: unknown account reads `None` and fails closed to
  FLAG; expired attestations are stored unmutated and require an authorised
  registry authority to replace (§18).
- Documentation closures: policy-schema README tables what the JSON document
  carries versus on-chain lifecycle state (§10), and the contract interface
  documents the no-external-data, no-wall-clock evaluation boundary (§3).

### Changed

- `activate_version` / `deactivate_version` now take an `operator` argument
  and require the admin or a policy authority (was: admin only); deploy and
  upgrade-rehearsal runbooks pass the admin.
