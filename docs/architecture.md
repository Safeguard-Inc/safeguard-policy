# Architecture

## Safeguard: Define → Enforce → Verify

Safeguard is compliance infrastructure for Stellar Confidential Tokens,
organized as three repositories with a strict separation of duties:

```text
             SAFEGUARD
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
    POLICY      HOOKS     AUDIT
    DEFINE     ENFORCE    VERIFY
```

| Repository | Role | Responsibility |
| ---------- | ---- | -------------- |
| `safeguard-policy` (this repo) | **Define** | What the rules are: policy model, rule primitives, registries, versions, evaluation. |
| `safeguard-hooks` | **Enforce** | That the rules run on token operations: authorization, blocking, flagging. |
| `safeguard-audit` | **Verify** | What happened: compliance events, investigation, reporting. |

The dependency chain is one-way and versioned:

```text
safeguard-policy
       │  versioned policy interfaces (policy-schema + SDK)
       ▼
safeguard-hooks
       │  versioned compliance events
       ▼
safeguard-audit
```

**This repository never enforces a transfer.** It answers the question:

> "Given this account, token, jurisdiction, operation and policy version,
> what compliance rules apply — and what is the decision?"

## Evaluation flow

```text
                    STELLAR / SOROBAN
                           │
                 Confidential Token
                           │
                           ▼
                  ┌─────────────────┐
                  │ safeguard-hooks │
                  │    ENFORCE      │
                  └────────┬────────┘
                           │  evaluate(policy_id, token, facts)
                           ▼
                  ┌─────────────────┐
                  │ safeguard-policy│
                  │     DEFINE      │
                  └────────┬────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Allow/Deny       Jurisdiction      Sanctions /
       Rules             Rules          Risk Rules
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                   Policy Decision
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
          APPROVE        BLOCK          FLAG
```

The decision is returned to the hook, which is what actually stops or
flags the operation. The audit repo then records the decision and the
policy state that produced it.

## Repository structure

```text
.
├── crates/
│   ├── safeguard-core/       # Policy engine — pure, no_std, no Soroban dep
│   └── safeguard-contract/   # Soroban policy contract (thin on-chain shell)
├── policy-schema/            # Machine-readable policy/decision/sanctions schemas
├── policies/                 # default + example policies, test fixtures
├── scripts/                  # Validation tooling and the local CI gate
├── docs/                     # This documentation set
└── .github/workflows/        # CI
```

### Why the engine and the contract are separate crates

`safeguard-core` holds **all** rule semantics and is:

- `no_std` and dependency-free, so it compiles into the wasm contract
  artifact and stays auditable;
- pure (no storage, no network, no time), so it is fast to test natively,
  reusable off-chain (CLI, SDKs, `safeguard-hooks`), and deterministic by
  construction.

`safeguard-contract` owns what only a contract can own: state, authorization,
scope (which tokens a policy covers) and the boundary translation between
Soroban values and core snapshot types. It never interprets rule semantics
itself — the engine decides.

## Decision model

Every evaluation resolves to exactly one of:

```text
APPROVE   the operation is permitted
BLOCK     the operation is denied (enforcement by safeguard-hooks)
FLAG      needs review: neither clearly permitted nor clearly denied
```

with stable machine-readable metadata (policy id, policy version, triggering
rule, reason code). Serialization is deterministic and versioned; numeric
codes and labels are pinned by tests and must never be renumbered (see
[`versioning.md`](versioning.md)).

## Rule precedence

Precedence is explicit, documented in [`rule-engine.md`](rule-engine.md), and
enforced by the engine's property tests:

```text
Account status  (structural; always first)
    ↓
Allowlist → Denylist → Sanctions → Jurisdiction
    ↓
APPROVE (when nothing decisive fired)
```

## Build phases

The repository follows the phased plan from the original proposal:

| Phase | Scope | Status |
| ----- | ----- | ------ |
| 1 | Foundation: policy types, schema, policy contract, versioning | ✅ |
| 2 | Core rules: allowlist, denylist, sanctions, jurisdiction, account status | ✅ |
| 3 | Evaluation: deterministic APPROVE/BLOCK/FLAG engine | ✅ |
| 4 | Registries: identity, sanctions, jurisdiction, token scope (contract wiring) | ✅ |
| 5 | Developer tooling: Rust/TypeScript SDKs, CLI, fixture generation | ✅ |
| 6 | Hardening: fuzzing, compatibility gates, dependency security, release pipeline | ✅ |
| 7 | Adapters: sanctions/identity/jurisdiction pipelines + `dataset build` CLI | ✅ |
| 8 | Deployment: testnet runbooks + upgrade rehearsal drill | ✅ (offline-validated; live run requires network) |
| 9 | Cross-repo: `safeguard-hooks` CI, mainnet rollout | pending (needs the hooks polyrepo) |

## Where each concept lives

| Concept | Definition | Implementation |
| ------- | ---------- | -------------- |
| Decisions and reason codes | [`policy-model.md`](policy-model.md) | `safeguard-core::decision` |
| Rules and precedence | [`rule-engine.md`](rule-engine.md) | `safeguard-core::rule`, `::evaluator` |
| Policy versions | [`policy-model.md`](policy-model.md) | `safeguard-core::version` |
| Registries | [`registries.md`](registries.md) | contract storage + adapters |
| Contract interface | [`contract-interface.md`](contract-interface.md) | `safeguard-contract` |
| Security model | [`security.md`](security.md) | roles + fail-closed rules |
| Threats | [`threat-model.md`](threat-model.md) | — |
| Polyrepo integration | [`integration.md`](integration.md) | schemas + events |