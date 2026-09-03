# 🛡️ Safeguard Policy

**Safeguard** is compliance infrastructure for [Stellar Confidential
Tokens](https://stellar.org/blog/developers/developer-preview-confidential-tokens-on-stellar).
It is organized as three repositories with a strict separation of duties:

```
             SAFEGUARD
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
    POLICY      HOOKS     AUDIT
    DEFINE     ENFORCE    VERIFY
```

| Repository      | Role     | Responsibility                                  |
| --------------- | -------- | ----------------------------------------------- |
| `safeguard-policy` | **Define** | What the rules are: policy model, rule primitives, registries, versions, evaluation. **← you are here** |
| `safeguard-hooks`  | **Enforce** | That the rules run on token operations: authorization, blocking, flagging. |
| `safeguard-audit`  | **Verify** | What happened: compliance events, investigation, reporting. |

The dependency chain is one-way and versioned:

```
safeguard-policy
       │  versioned policy interfaces (schemas + SDK)
       ▼
safeguard-hooks
       │  versioned compliance events
       ▼
safeguard-audit
```

This repository answers:

> "Given this account, token, jurisdiction, operation and policy version,
> what compliance rules apply — and what is the decision?"

It does **not** block token transfers. Enforcement belongs to
`safeguard-hooks`.

---

## Why this exists

Stellar's Confidential Token design keeps transaction amounts and balances
private while preserving compliance surface area: addresses stay visible,
and the protocol preview already exposes policy contracts, allow/block-list
identity registries, account freezing, SAC passthrough and auditor
functionality. The missing piece — and the original Safeguard proposal's
central finding — is a **reusable, versioned compliance policy layer** that
issuers and integrators do not have to re-implement per deployment.

`safeguard-policy` is that layer: a policy contract + engine that deployments
bind to their tokens, plus the stable machine-readable schema that the rest
of the ecosystem consumes.

## What this repository defines

- **Policy model** — policies, versions, activation state, configuration
  hashes. Policies never mutate silently; they evolve as explicit versions.
- **Rule primitives** — allowlist, denylist, sanctions, jurisdiction and
  account-status checks, each with a deterministic contract.
- **Registries** — on-chain representations of identity, sanctions,
  jurisdiction and token scope that the policy engine consumes.
- **Evaluation** — a deterministic engine resolving every request to one of
  `APPROVE`, `BLOCK` or `FLAG`, with documented rule precedence.
- **Schemas** — a stable machine-readable policy format (`policy-schema/`)
  that `safeguard-hooks` and `safeguard-audit` consume.
- **Events** — policy lifecycle events (`policy_created`,
  `policy_activated`, …) that make compliance configuration auditable.

### What it deliberately does **not** contain

No token transfer contract, no wallet, no dashboard, no auditor UI, no KYC
provider, no centralized sanctions database, no generic explorer, no payment
processor, and no transfer hook. Those belong to the other Safeguard repos or
to the wider ecosystem.

---

## Decision model

Every evaluation resolves to a standardized decision:

```
APPROVE
BLOCK
FLAG
```

with supporting metadata — policy id, policy version, rule reference, reason
code and (off-chain) timestamp. Serialization is deterministic and versioned.

```text
Policy Decision
├── decision        APPROVE | BLOCK | FLAG
├── policy_id
├── policy_version
├── rule_id         (when a rule produced the outcome)
├── reason_code     machine-readable cause
└── timestamp       (recorded by the caller)
```

### Rule precedence

Precedence is explicit, documented in
[`docs/rule-engine.md`](docs/rule-engine.md) and enforced by tests, so two
contributors cannot implement contradictory interpretations of one policy.
The default evaluation order is:

```text
Account status  (frozen/suspended/restricted → block/flag)
    ↓
Allowlist       (required but not a member → block/flag)
    ↓
Denylist        (matched → block/flag)
    ↓
Sanctions       (matched → block/flag)
    ↓
Jurisdiction    (prohibited/restricted → block/flag)
    ↓
APPROVE
```

Every step is deterministic: identical input + identical policy state =
identical decision. No network calls, no randomness, no hidden state.

---

## Repository layout

```text
.
├── crates/
│   ├── safeguard-core/       # Policy engine — pure, no_std, no Soroban dep
│   │   └── src/
│   │       ├── decision.rs   # Decision, ReasonCode, PolicyDecision
│   │       ├── error.rs      # PolicyError
│   │       ├── rule.rs       # RuleType, RuleAction, Rule
│   │       ├── rules/        # allowlist, denylist, sanctions, jurisdiction, account_status
│   │       ├── version.rs    # PolicyVersion, VersionStatus
│   │       ├── policy.rs     # PolicyConfig, activation state
│   │       ├── evaluation.rs # EvaluationRequest/Response
│   │       └── evaluator.rs  # Deterministic precedence engine
│   └── safeguard-contract/   # Soroban policy contract (thin, on-chain)
│       └── src/
│           ├── lib.rs        # #[contract] PolicyContract
│           ├── error.rs      # ContractError
│           ├── storage.rs    # DataKey + state accessors
│           ├── admin.rs      # Role-based administration
│           ├── lifecycle.rs  # register / activate / deactivate
│           ├── registry.rs   # Policy ↔ token bindings
│           ├── evaluate.rs   # On-chain evaluation entrypoint
│           └── test.rs       # Contract integration tests
├── policy-schema/            # JSON Schema: policy, rule, decision
├── policies/                 # default + example policies, test fixtures
├── docs/                     # architecture, policy model, rule engine, security
├── scripts/                  # Off-chain validation tooling
└── .github/workflows/        # CI
```

The two crates exist so the **policy engine is testable at native speed and
reusable off-chain** (CLI, SDKs, `safeguard-hooks`) while the **contract stays
a thin on-chain shell** around it.

## Getting started

```bash
# Requires Rust 1.91+ (stable); the toolchain is pinned in rust-toolchain.toml
rustup target add wasm32v1-none

# The full local gate (same as CI): fmt, clippy, tests, wasm build,
# schema battery, fixture checks
./scripts/ci.sh

# Or just the Rust part / schema part
./scripts/ci.sh rust
./scripts/ci.sh schema
```

## Using policies

Reference policies live under [`policies/`](policies/):

```bash
# Validate a policy document against the JSON Schema
python3 scripts/validate_policy.py policies/default/policy.json
```

- [`policies/default/policy.json`](policies/default/policy.json) — the
  recommended default configuration.
- [`policies/examples/`](policies/examples/) — annotated example policies
  (allowlist-only, denylist-only, sanctions screening, jurisdiction
  restricted, combined).
- [`policies/fixtures/`](policies/fixtures/) — fixtures used by tests.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — Define → Enforce → Verify and the role of this repo
- [`docs/policy-model.md`](docs/policy-model.md) — policies, versions, activation, registries
- [`docs/rule-engine.md`](docs/rule-engine.md) — rule semantics and precedence
- [`docs/security.md`](docs/security.md) — the security model and roles
- [`docs/threat-model.md`](docs/threat-model.md) — threats and mitigations
- [`docs/versioning.md`](docs/versioning.md) — the four version axes and compatibility
- [`docs/contract-interface.md`](docs/contract-interface.md) — the on-chain surface
- [`docs/registries.md`](docs/registries.md) — how compliance data reaches the engine
- [`docs/adapters.md`](docs/adapters.md) — the off-chain integration boundary
- [`docs/integration.md`](docs/integration.md) — how hooks and audit consume this repo
- [`docs/how-to-evaluate.md`](docs/how-to-evaluate.md) — a worked evaluation example
- [`docs/decisions.md`](docs/decisions.md) — design decisions and rationale

## Roadmap

The build order follows the phases in [`docs/architecture.md`](docs/architecture.md):

1. **Foundation** — policy types, schema, policy contract, versioning ✅
2. **Core rules** — allowlist, denylist, sanctions, jurisdiction, account status ✅
3. **Evaluation** — deterministic APPROVE/BLOCK/FLAG engine ✅
4. **Registries** — identity, sanctions, jurisdiction, token scope (contract wiring)
5. **Developer tooling** — Rust/TypeScript SDKs, CLI, fixture generation
6. **Hardening** — reference docs, CI, security model ✅; fuzzing, compatibility tests against `safeguard-hooks`, testnet deployment pending

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report security issues per
[`SECURITY.md`](SECURITY.md). This project follows
[Semantic Versioning](https://semver.org/); see
[`CHANGELOG.md`](CHANGELOG.md).

## License

Apache-2.0.
