# @safeguard/policy-sdk

TypeScript SDK for Safeguard policy documents: typed policy/decision
documents, invariant validation, and audit-ready decision helpers.

This SDK **does not reimplement the decision engine.** Decisions come from
the contract (or the offline CLI/Rust SDK), which run the same
`safeguard_core::evaluator` compiled into the wasm artifact. This package
is the typed surface for building on top of those decisions.

## Install

```bash
npm install @safeguard/policy-sdk
```

The package has **zero runtime dependencies**; TypeScript is a dev-only
dependency and tests run on Node's built-in test runner.

## Usage

### Validate a policy document

```ts
import { validatePolicyJson } from "@safeguard/policy-sdk";

const problems = validatePolicyJson(policyJson);
if (problems.length > 0) {
  throw new Error(problems.join("\n"));
}
```

`validatePolicyDocument` enforces the same invariants as the Rust SDK and
`scripts/validate_policy.py`: non-empty ASCII ids at most 32 bytes, unique
rule ids, at most one rule per type, jurisdiction rules carrying
well-formed region lists, and no regions on other rule types.

### Build a decision document for audit

```ts
import { buildDecisionDoc } from "@safeguard/policy-sdk";

const doc = buildDecisionDoc({
  decision: "BLOCK",
  policy_id: "institutional-default",
  policy_version: 1,
  rule_id: "SANCTIONS-001",
  reason_code: "sanctions_match",
});
// { decision: "BLOCK", policy_id: "...", policy_version: 1,
//   rule_id: "SANCTIONS-001", reason_code: "sanctions_match" }
```

`buildDecisionDoc` output matches `decision.schema.json`, and
`nowTimestamp()` produces RFC 3339 timestamps for the optional
`timestamp` field.

## Types

- `PolicyDocument`, `Rule`, `RegionLists` — mirror `policy.schema.json`
- `DecisionDoc` — mirrors `decision.schema.json`
- `Decision`, `ReasonCode`, `RuleType`, `RuleAction`, `AccountStatus`,
  `RegionStatus` — literal unions matching the schema enums exactly

## Development

```bash
npm ci
npm test   # typecheck + build + node --test (10 tests)
```

The CI gate runs this suite (`.github/workflows/ci.yml`) and the local gate
(`scripts/ci.sh typescript`).

## Keeping surfaces in lockstep

The JSON Schema, Rust SDK and TypeScript SDK must not drift. Every value
shared across the boundary is asserted bidirectionally: this package's
tests mirror the invariants, `crates/safeguard-sdk/tests/schema_parity.rs`
pins the Rust labels against the schemas, and `scripts/test-schema.py`
guards the schemas themselves. See `docs/versioning.md` for the
compatibility rules.

## License

Apache-2.0.