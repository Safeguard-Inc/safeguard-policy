# How to Evaluate: A Worked Example

This document walks evaluation end to end using the reference policies and
fixtures in `policies/`. Everything here is deterministic and reproducible:
given the policy document and the account facts, the decision is fixed.

## Setup

Deploy and initialize the contract, then register and activate the
**combined policy** (`policies/examples/combined-policy.json`):

| Rule | Type | Action | Id |
| ---- | ---- | ------ | -- |
| ALLOWLIST-001 | allowlist | block | — |
| DENYLIST-001 | denylist | block | — |
| SANCTIONS-001 | sanctions | **flag** | — |
| JURISDICTION-001 | jurisdiction | block | regions below |

```text
permitted: AU CA CH DE FR GB JP NL SG US
restricted: BY RU
prohibited:  CU IR KP SY VE
```

Bind the token, then evaluate subjects from `policies/fixtures/accounts.json`.

## Case 1 — everything passes → APPROVE

Subject: active account, US jurisdiction, allowlisted, nothing matched.

```text
facts = { status: active, member: true, deny: false, sanction: false, region: US }
```

1. Account status: Active → pass.
2. Allowlist: member → pass.
3. Denylist: not listed → pass.
4. Sanctions: not matched → pass.
5. Jurisdiction: US is permitted → pass.
6. → **APPROVE** (`no_reason`), `policy_version = 1`.

## Case 2 — non-member → BLOCK by allowlist

Facts: `member: false` (all else passing).

1. Account status: pass. 2. Allowlist: **not a member** → rule action `block`.

→ **BLOCK** (`allowlist_required`, rule `ALLOWLIST-001`).

Note precedence: even if the subject were also sanctions-matched, the
allowlist failure shadows it — the first decisive check wins.

## Case 3 — sanctions match → FLAG (not BLOCK)

Facts: `sanction: true`, member, active, US.

1. Account status: pass. 2. Allowlist: pass. 3. Denylist: pass.
4. Sanctions: matched → rule action is **flag** under this policy.

→ **FLAG** (`sanctions_match`, rule `SANCTIONS-001`).

The same match under the default policy (`policies/default/policy.json`,
action `block`) would evaluate to **BLOCK**. This is the per-rule severity
model: data is shared, severity is policy-owned.

## Case 4 — frozen account → BLOCK regardless of rules

Facts: `status: frozen`, member, US, nothing matched.

1. Account status: **frozen** → structural BLOCK.

→ **BLOCK** (`account_frozen`), **no rule id** — status is structural, not a
policy rule.

## Case 5 — prohibited region → BLOCK by jurisdiction

Facts: active, member, region `IR` (prohibited), nothing matched.

1–4 pass. 5. Jurisdiction: IR is prohibited → rule action `block`.

→ **BLOCK** (`jurisdiction_prohibited`, rule `JURISDICTION-001`).

## Case 6 — unknown region → fail-closed BLOCK

Facts: active, member, region `XX` (unknown), nothing matched.

1–4 pass. 5. Jurisdiction: unknown → **triggers the rule action** (`block`).

→ **BLOCK** (`jurisdiction_unknown`, rule `JURISDICTION-001`).

Unknown never silently approves.

## Case 7 — scope guards

- Token not bound to the policy → evaluation fails `TokenNotBound`.
- No active version → evaluation fails `PolicyNotActive`.
- Invalid status code (e.g. `99`) → mapped to `unknown` → **FLAG**
  (`account_status_unknown`), fail-closed.

## Deciding for yourself

1. Resolve the facts for the subject (account status, membership, matches,
   region).
2. Walk the precedence order; the first decisive check wins.
3. Map the outcome: status structural table, then rule action per category
   (see [`rule-engine.md`](rule-engine.md)).

The contract's `evaluate` entrypoint performs exactly this walk against the
active version — see [`contract-interface.md`](contract-interface.md).