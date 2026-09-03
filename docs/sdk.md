# SDKs

The developer-facing surface for working with Safeguard policy documents.
Two SDKs ship from this repository:

| SDK | Location | Audience | Status |
| --- | -------- | -------- | ------ |
| Rust | `crates/safeguard-sdk` | Backend services, the CLI, Rust tooling | Available (`0.1.0`) |
| TypeScript | `sdk/typescript` (`@safeguard/policy-sdk`) | Web dashboards, compliance UIs, backend services | Available (`0.1.0`, private) |

## The one rule both SDKs follow

> **Neither SDK reimplements the decision engine.**

Decisions are produced by `safeguard_core::evaluator` — the same code
compiled into the wasm contract. Offline evaluation (CLI, Rust SDK) calls
that engine directly, so an offline result is exactly what the contract
would return for the same inputs. The TypeScript SDK deliberately stops at
types, validation and decision-document helpers: it has no engine, because
a second, drifting implementation is the failure mode this architecture
exists to prevent.

## Rust SDK (`safeguard-sdk`)

### Crate layout

| Module | Purpose |
| ------ | ------- |
| `model` | `PolicyDocument`, `Rule`, `RegionLists`, `DecisionDoc` — the machine-readable policy surface |
| `validation` | `validate_policy_document` — schema + invariants (mirrors `scripts/validate_policy.py`) |
| `evaluate` | `evaluate_policy` / `EvaluationFacts` — offline evaluation through `safeguard_core` |
| re-exports | `Decision`, `PolicyDecision`, `ReasonCode`, `EvaluationRequest`, `RuleType`, `AccountStatus`, `RegionStatus` from core |

### Typical flow

```rust
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::validation::validate_policy_document;
use safeguard_sdk::evaluate::{evaluate_policy, EvaluationFacts};

let doc: PolicyDocument = serde_json::from_str(policy_json)?;
let problems = validate_policy_document(&doc);
assert!(problems.is_empty(), "{problems:?}");

let facts = EvaluationFacts {
    account_status: AccountStatus::Active,
    allowlisted: true,
    denylisted: false,
    sanctions_match: false,
    jurisdiction: Some(RegionStatus::Permitted),
    // ...
};
let decision = evaluate_policy(&doc, &facts)?;
assert_eq!(decision.decision, Decision::Approve);
```

### Why no contract client here

Deploying, registering policies, binding tokens, and calling `evaluate`
against a live contract are done through the generated Soroban client from
`safeguard-contract` (see [`docs/contract-interface.md`](contract-interface.md)).
The SDK stays a pure, dependency-light library (`no_std`-compatible core,
serde for documents) so downstream services can embed it without pulling in
the Soroban runtime.

## TypeScript SDK (`@safeguard/policy-sdk`)

Package documentation: [`sdk/typescript/README.md`](../sdk/typescript/README.md).

### Surface

- `types.ts` — literal unions mirroring the JSON Schema enums exactly
  (`RuleType`, `RuleAction`, `Decision`, `ReasonCode`, `AccountStatus`,
  `RegionStatus`); `PolicyDocument`, `Rule`, `RegionLists`, `DecisionDoc`
- `validate.ts` — `validatePolicyDocument`, `validatePolicyJson`, `isRule`;
  invariants match the Rust validator byte-for-byte in behavior
- `decision.ts` — `buildDecisionDoc`, `nowTimestamp` — audit-ready decision
  documents matching `decision.schema.json` (RFC 3339 timestamps, stable
  serialization for storage)

### Usage

```ts
import { validatePolicyJson, buildDecisionDoc } from "@safeguard/policy-sdk";

const problems = validatePolicyJson(policyJson);
if (problems.length > 0) throw new Error(problems.join("\n"));

const doc = buildDecisionDoc({
  decision: "BLOCK",
  policy_id: "institutional-default",
  policy_version: 1,
  rule_id: "SANCTIONS-001",
  reason_code: "sanctions_match",
});
```

### Development

```bash
cd sdk/typescript
npm ci
npm test          # typecheck + build + node --test (10 tests)
```

The SDK depends only on TypeScript for development (Node's built-in test
runner is used), so consumers get zero runtime dependencies.

## Keeping the three surfaces in lockstep

`policy-schema/` (JSON Schema), the Rust SDK, and the TypeScript SDK must
not drift. The guards are:

1. `scripts/test-schema.py` asserts the embedded rule definition in
   `policy.schema.json` is byte-identical to the standalone `rule.schema.json`;
2. Rust SDK validation tests mirror the documented invariants;
3. TypeScript SDK tests mirror the same invariants;
4. `docs/versioning.md` defines when each surface may change and how
   compatibility is declared (schema version vs crate version vs package
   version).

Adding a value to any enum (for example a new `ReasonCode`) requires
touching all three surfaces plus the schemas in the same change, with tests
updated in the same commit.