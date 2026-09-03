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
