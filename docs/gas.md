# Gas usage per transaction

Measured cost of every public policy-contract function, in **stroops**
(1 stroop = 1e-7 XLM; 1 XLM = 10,000,000 stroops). The number a caller
actually pays is the **fee charged** for a real transaction, which includes
CPU instructions, ledger footprint, storage rent and transaction size.

Measured on Testnet, 2026-09-08, against the deployment recorded in
`deployments/testnet.json`, using `scripts/bench-gas.sh` (repeat runs vary
by a few percent).

## Current (gas-optimized wasm)

| Function | Stroops | XLM |
| -------- | ------: | ---: |
| `schema_version` | 3,187 | 0.000319 |
| `admin` | 3,350 | 0.000335 |
| `bound_tokens(policy)` | 4,172 | 0.000417 |
| `get_active_version` (1-rule policy) | 5,797 | 0.000580 |
| `get_active_version` (4-rule policy) | 8,176 | 0.000818 |
| `is_authorized(account, token)` — **hot enforcement path** | 6,718–6,759 | ~0.000674 |
| `evaluate(policy, token, input)` — compliant subject | 8,588 | 0.000859 |
| `register_version` / `bind_token` / `set_identity` (writes) | ~5–8k + storage rent | — |

`is_authorized` is the function `safeguard-hooks` calls once per screened
party per operation, so it is the number that dominates token-operation
cost end to end: **≈ 0.00067 XLM (~0.0002 USD) per party screened.**

## What was optimized (2026-09-08) and why

| Function | Before | After | Δ |
| -------- | -----: | ----: | --: |
| `is_authorized` (enforcement-default policy) | 7,984 | 6,718–6,759 | **−15%** |
| `is_authorized` (institutional-default policy) | 8,540* | 7,397 | **−13%** |

\* baseline not measured separately; the closest before-number is the
`evaluate` fee of 8,540, which shares the same evaluation core.

Two metered-read savings, both behavior-identical:

1. **No full binding-list read per authorization.** `is_authorized` used to
   re-read the policy's entire token-binding `Vec` to confirm the token was
   bound (twice — once in its own check and once inside `evaluate`). The
   registry's reverse index (`TokenPolicy(token) → policy id`) is
   maintained atomically with the bindings — set on bind, cleared on
   unbind — so its presence is the coverage proof. The hot path now reads
   the index and the active version instead of the (potentially large)
   binding list, via `evaluate::evaluate_active`, which skips the scope
   re-check. The public `evaluate` keeps its full scope checks unchanged.

2. **No registry reads for rules the policy does not enable.** `assemble`
   previously resolved the sanctions entry and the jurisdiction
   classification unconditionally, even when the active policy had no
   sanctions or jurisdiction rule — the common enforcement shape. Those
   lookups now happen only when the policy enables the rule that consumes
   them; the caller's claim is used otherwise, exactly as before.

## Methodology

```bash
bash scripts/bench-gas.sh testnet     # prints the table (requires the
                                      # deployment record + stellar CLI)
```

Each row is a real signed transaction sent with `--cost --send=yes`; the
reported number is `Fee Charged` from the CLI's fee table. Read-only
functions are sent too, so the table reflects the full on-chain cost of
executing the function, not a local estimate. Pass/fail of the call is
irrelevant — only the fee matters.

### Caveats

* Fees drift with network pricing (`stellar network settings --network
  <net>`); re-run the script for current numbers.
* Storage **rent** is charged on writes and on TTL extension. A read that
  happens to bump an entry's TTL (entries are extended when their TTL
  drops below the contract's threshold) can show a one-off spike — e.g.
  `token_is_bound` measured once at 57,587 stroops (≈0.006 XLM) and 3,930
  on every other run. Steady-state reads are the stable numbers above.
* `evaluate` with a policy that *does* enable sanctions/jurisdiction rules
  still pays those registry reads — that is the cost of the rules, and the
  read is the mechanism that makes the on-chain registry authoritative.