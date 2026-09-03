# Contributing to Safeguard Policy

Thanks for contributing. This repository is part of a three-repository
"Safeguard" family:

```
SAFEGUARD
   ├── safeguard-policy   DEFINE  ← you are here
   ├── safeguard-hooks    ENFORCE
   └── safeguard-audit    VERIFY
```

`safeguard-policy` decides what the rules are. `safeguard-hooks` enforces
those rules. `safeguard-audit` proves what happened.

## Code of conduct

Read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be excellent.

## Getting started

Requires Rust 1.91+ (stable) and the `wasm32v1-none` target for contract
builds (the Soroban environment does not support `wasm32-unknown-unknown`
on Rust 1.82+):

```bash
rustup toolchain install stable
rustup target add wasm32v1-none
cargo test --workspace          # unit + contract tests
cargo fmt --all -- --check      # formatting
cargo clippy --workspace --all-targets -- -D warnings
```

## Repository layout

- `crates/safeguard-core` — the policy engine. Pure, deterministic, `no_std`,
  no Soroban dependency. All rule logic and precedence lives here so it can be
  unit-tested at speed and reused off-chain.
- `crates/safeguard-contract` — the on-chain policy contract built on
  `soroban-sdk`. Thin: it stores policy state and calls the core engine.
- `policy-schema/` — machine-readable JSON Schema for policies, rules and
  decisions (the stable interface other Safeguard repos consume).
- `policies/` — reference policies: a `default/` configuration plus
  `examples/` and `fixtures/`.
- `docs/` — architecture, policy model, rule engine, security model.

## What belongs here — and what does not

This repository **defines policy**: rule types, registries, versions,
evaluation. It does **not** enforce token transfers (that is
`safeguard-hooks`), and it is not a wallet, dashboard, auditor UI, KYC
provider, or centralized sanctions database.

## Issue taxonomy

Issues and PRs are tagged with one of the following categories so the issue
pool stays filterable (use the "Contributor task" template for scoped tasks):

| Label | Covers |
| ----- | ------ |
| `SC` | Smart contract work: policy registry, policy versioning, allowlist/denylist contracts, jurisdiction rules, sanctions registry, account-status rules, the evaluation engine, policy precedence |
| `SDK` | Rust policy client, TypeScript policy client, registry helpers, error types, policy serialization |
| `CLI` | Policy validation, policy inspection, fixture generation, policy testing |
| `TEST` | Allowlist/sanctions/jurisdiction tests, fuzz tests, regression tests, compatibility tests |
| `INFRA` | CI, release automation, package publishing, contract deployment automation |
| `DOCS` | Policy specification, threat model, integration guide, contributor guide, examples |
| `SECURITY` | Threat modeling, access-control review, policy-downgrade tests, malicious-registry tests |

## Making changes

1. Open an issue describing the change (policy changes and contract changes
   both deserve review). Scoped tasks use the "Contributor task" template;
   tag them with the category above.
2. Keep commits small and self-contained: one improvement per commit, each
   leaving the workspace green.
3. Every behavioral change ships with tests:
   - Pure logic: unit tests next to the code in `safeguard-core`.
   - Contract behavior: integration tests in `safeguard-contract`.
   - Determinism-sensitive changes: property tests asserting identical inputs
     produce identical decisions.
4. Run the full gate locally before opening a PR:
   `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Pull request checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Schema changes include a version bump note in `policy-schema/README.md`
- [ ] Policy behavior changes update `docs/rule-engine.md` precedence docs
- [ ] User-visible changes update `CHANGELOG.md`

## Commit conventions

Follow the repository style: imperative subject lines that describe *why*,
with a body that explains context. See recent history for examples. Changes
are committed one logical improvement at a time rather than bundled.

## License

Apache-2.0. By contributing you agree your contributions are licensed under
the same terms.
