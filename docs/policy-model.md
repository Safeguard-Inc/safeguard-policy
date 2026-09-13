# Policy Model

This document defines the policy model: what a policy is, how it is
versioned, what its configuration contains, and how it maps onto on-chain
state and off-chain policy documents. The authoritative semantics live in
`safeguard-core` (`policy`, `version`, `rule` modules) and in the JSON
Schema (`../policy-schema/`); this document is the prose that ties them
together.

## What a policy is

A policy is a **named, versioned set of compliance rules** that applies to a
specific set of tokens:

```text
Policy ──▶ versions (append-only chain)
Policy ──▶ tokens   (registry binding)
```

It answers "what compliance rules apply to this account, token and
jurisdiction" — it does not move tokens.

## Policy configuration

The configuration of a policy version is its **rule set**, normalized to at
most one rule per category:

```text
Allowlist    (membership required or sufficient)
Denylist     (listed subjects excluded)
Sanctions    (screening matches excluded or flagged)
Jurisdiction (region classification enforced)
```

Invariants, enforced at registration and by the validator:

- at most one rule per category (the engine evaluates categories in fixed
  precedence order, so more than one rule per category would be ambiguous);
- rule ids are unique within the version;
- rule ids and policy ids are ASCII, 1–32 bytes (the fixed-width on-chain
  identifier width — longer ids would silently truncate);
- `jurisdiction` rules must carry a region classification
  (`permitted`/`restricted`/`prohibited`, ISO alpha-2 codes);
- non-jurisdiction rules must not carry a region classification.

Every rule has a stable `type` and a per-rule `action` (`block` or `flag`).
The same data can therefore mean different things under different policies:
a sanctions match may block under one policy and flag for review under
another.

## Composing documents

The invariants above are properties of **one** document. A policy set is
assembled from many — the reference policies in `policies/default` and
`policies/examples`, a vendor bundle, a deployment's override directory —
and that assembly has a failure mode no single-document check can see:

> two sources claiming the same identity, `(policy_id, version)`.

Nothing downstream can tell them apart. A binding that names only a
`policy_id` resolves to whichever document the loader happened to reach
last, so **which rule parameters apply becomes an accident of read order**.
The pair `(policy_id, version)` is therefore treated as an identity that at
most one source may own, and composition reports a contest rather than
overwriting silently: it names the id, the version, and both origins.

The identity is the *pair*, which keeps version history intact — a second
version under the same `policy_id` is the append-only chain above, not a
collision.

Composition also validates each document as it loads, so an invalid source
is rejected instead of being admitted into a set whose lookup would then
depend on it. [`safeguard_sdk::composition`](../crates/safeguard-sdk/src/composition.rs)
is the implementation; `safeguard policy compose` is the CLI surface, and
`scripts/check-fixtures.py` and `safeguard fixture validate` run the same
identity check over the shipped policies.

## Versions: append-only

**A policy never silently mutates.** Every change is a new version:

```text
Policy v1 ─▶ Policy v2 ─▶ Policy v3
```

A version records:

| Field | Meaning |
| ----- | ------- |
| `policy_id` | The policy it belongs to. |
| `version` | Monotonic version number within the policy. |
| `status` | Lifecycle state (below). |
| `config_hash` | Hash of the serialized rule set; lets audit prove exactly which configuration produced a decision. |

### Lifecycle

```text
Draft ──activate──▶ Active ──supersede──▶ Superseded
   │                    │
   └───deactivate───────┘──────────────▶ Disabled
```

- **Registration** creates a `Draft` (admin only, append-only: re-registering
  an existing version is rejected).
- **Activation** promotes a `Draft` to `Active` (admin only). Any previously
  active version becomes `Superseded` — there is exactly one active version
  per policy, recorded as the active-version pointer.
- **Deactivation** moves the active version to `Disabled` and clears the
  pointer; the policy then has **no active version** until a new one is
  activated.

Only drafts can be activated. An active version can never be silently
replaced or downgraded: changing a rule set always requires a new version.

## Token scope

A policy applies only to tokens explicitly bound to it (admin or registry
authority):

```text
Policy A ──▶ Token X, Token Y
Policy B ──▶ Token Z
```

`evaluate` refuses subjects whose token is not bound to the policy
(`TokenNotBound`), preventing one policy from accidentally governing
unrelated assets.

## On-chain records vs off-chain documents

The same policy exists in two forms:

| Form | Location | Purpose |
| ---- | -------- | ------- |
| Policy document (JSON) | `policies/` or operator tooling | Authoring, review, validation (`scripts/validate_policy.py`), schema-checked. |
| Policy version record | contract persistent storage | What the contract evaluates against; created by `register_version`, queried via `get_version` / `get_active_version`. |

The `config_hash` links the two: the on-chain record stores the digest of the
configuration, so the document that produced a given on-chain state can be
proven later.

## See also

- [`rule-engine.md`](rule-engine.md) — how the rule set is evaluated
- [`versioning.md`](versioning.md) — schema/contract/policy version interplay
- [`contract-interface.md`](contract-interface.md) — the lifecycle entrypoints
- `../policy-schema/README.md` — the machine-readable contract