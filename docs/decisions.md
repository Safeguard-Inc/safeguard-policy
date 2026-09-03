# Design Decisions

A record of the significant decisions made while building `safeguard-policy`
and why. Add an entry when a choice shapes the interface or the security
model; link it from the code when the rationale is not obvious.

## D1: Two-crate workspace (engine vs contract)

**Decision.** `safeguard-core` (pure, `no_std`, dependency-free) and
`safeguard-contract` (Soroban, thin).

**Why.** All rule semantics live in the core so they are natively testable at
speed, reusable off-chain (CLI, SDKs, hooks), and auditable without the
Soroban dependency tree. The contract owns only state, auth and boundary
translation. The split is what keeps the engine deterministic by
construction (no storage/network/time in the crate).

## D2: One rule per category, fixed precedence

**Decision.** A policy version enables at most one rule per category
(allowlist, denylist, sanctions, jurisdiction), evaluated in pinned order.

**Why.** The precedence must be unambiguous. With multiple rules per
category there is no principled tie-break; with the order pinned and
property-tested, two implementations of the same policy cannot disagree
about a contested case.

## D3: Append-only policy versions

**Decision.** Policies change only by registering and activating new
versions; existing versions never mutate; re-registration is rejected.

**Why.** Auditability: safeguard-audit must be able to prove which
configuration was in force. Also prevents silent downgrades (see
[`threat-model.md`](threat-model.md) T2).

## D4: Fail-closed unknowns

**Decision.** Missing or invalid compliance data (unknown account status,
unknown region, invalid input codes) flags or blocks; it never approves.

**Why.** Financial/compliance enforcement must not accidentally fail open.
This is a design requirement, not an implementation detail — enforced by
property tests over the whole request space.

## D5: Stable numeric codes and labels

**Decision.** Decision/reason/type/action/status/region codes are explicitly
assigned, tested for round-trip, and never renumbered; labels are stable
ASCII strings shared between Rust, JSON schemas and decision documents.

**Why.** These values cross the polyrepo boundary into on-chain events and
audit records; renumbering would silently corrupt history
([`versioning.md`](versioning.md)).

## D6: Fixed-width 32-byte ids

**Decision.** `policy_id` and rule ids are ASCII, 1–32 bytes; on-chain they
are `BytesN<32>`.

**Why.** Fixed width serializes deterministically without allocation, and the
schema enforces the width so off-chain documents cannot silently truncate
against the on-chain identifier.

## D7: 32-byte subject hashes in sanctions data

**Decision.** Sanctions dataset entries are keyed by subject hash, never raw
identifiers or PII.

**Why.** Privacy by reference ([`registries.md`](registries.md)); the policy
layer needs matchability, not personal data.

## D8: Typed contract events over raw publish

**Decision.** Lifecycle events use `#[contractevent]` types, not
`env.events().publish` (deprecated in soroban-sdk 27).

**Why.** Type safety plus inclusion in the contract spec so tooling and
audit understand the events.

## D9: wasm32v1-none target

**Decision.** Contract artifacts build for `wasm32v1-none`, not
`wasm32-unknown-unknown`.

**Why.** The Soroban environment rejects `wasm32-unknown-unknown` on Rust
1.82+ (reference-types/multi-value features); `wasm32v1-none` is the
supported target.

## D10: JSON Schema as the cross-repo contract, validated by scripts

**Decision.** The machine-readable interface is hand-authored JSON Schema
(draft 2020-12) validated by small Python scripts, rather than generated from
the Rust types.

**Why.** The schema must be stable and readable by non-Rust consumers
(hooks, audit, SDKs). The parity and negative-case tests
(`scripts/test-schema.py`) keep the two rule-definition copies from
drifting and the validator from going permissive.

## D11: Events are scoped per invocation in tests

**Decision.** Contract tests assert events immediately after the emitting
call.

**Why.** soroban-sdk 27 testutils records events per invocation; asserting
across calls would be flaky and misleading (observed empirically, encoded in
`src/test.rs`).

## D12: Python tooling with jsonschema, no other deps

**Decision.** Validation scripts use the stdlib + `jsonschema` only.

**Why.** Keeps tooling installable and auditable; the schema layer must not
depend on heavyweight or fragile dependencies.