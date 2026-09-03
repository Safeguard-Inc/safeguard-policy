# Testnet deployment and upgrade drills

How a Safeguard policy contract gets deployed to a Stellar test network,
how the shipped policy is loaded, and how version upgrades are rehearsed
before they touch anything live.

## Prerequisites

- The [Stellar CLI](https://github.com/stellar/stellar-cli) on `PATH`
  (`stellar`), which provides `contract deploy`/`invoke` and network and
  identity management.
- A configured network, e.g.:

  ```bash
  stellar network add --global testnet \
    --rpc-url https://soroban-testnet.stellar.org \
    --network-passphrase "Test SDF Network ; September 2015"
  ```

- A funded identity that will become the contract admin:

  ```bash
  stellar keys fund admin        # testnet gives free funds
  stellar keys address admin     # the account that initialize() stores
  ```

## Deploying the contract

[`scripts/deploy-testnet.sh`](../scripts/deploy-testnet.sh) is the runbook.
Its default path performs only calls with address/string arguments, so it
can be rehearsed confidently:

```bash
./scripts/deploy-testnet.sh --dry-run   # print every command first
./scripts/deploy-testnet.sh             # deploy + initialize + smoke test
```

The smoke test reads `schema_version` back from the deployed contract,
proving the instance answers. The contract id is kept under the
`safeguard-policy` alias and printed at the end for follow-on steps
(hooks wiring, registry pushes).

### Loading the default policy

```bash
./scripts/deploy-testnet.sh --load-policy
```

This additionally registers and activates the shipped
`policies/default/policy.json` and binds its fixture tokens. The payloads
bash cannot compute — the 32-byte zero-padded policy id, the sha256 of the
policy document, and the numeric rule records — are derived
deterministically from the JSON file, so the same policy file always
produces the same invocation. **Rehearse this stage on testnet before any
mainnet use** (see [`versioning.md`](versioning.md)); the fixture token
addresses are placeholders, not deployable token contracts.

## Rehearsing an upgrade

Policy changes are the routine kind of upgrade and must never mutate state
silently. [`scripts/rehearse-upgrade.sh`](../scripts/rehearse-upgrade.sh)
drills the register → activate → deactivate cycle:

```bash
./scripts/rehearse-upgrade.sh                        # offline lifecycle gate
./scripts/rehearse-upgrade.sh --network testnet --dry-run
./scripts/rehearse-upgrade.sh --network testnet      # on-chain drill
```

- **Stage 1** runs the contract's own register/activate/evaluate suite in
  the Soroban test harness — no network needed — so rule-semantics
  regressions fail before anything is deployed.
- **Stage 2** (with `--network`) registers the example combined policy as
  a draft, confirms its version record is *not* active, activates it, then
  deactivates it. The drill leaves no permanent state behind.

On-chain `evaluate` requires a token bound to the policy and the full
`EvaluationInput` struct (subject hash + account), so live reads are
exercised after real token bindings exist rather than fabricated with
placeholder values.

## Publishing registry datasets

The contract's registries are populated from the datasets the adapter
pipeline produces. Build and review a dataset before pushing:

```bash
safeguard dataset build policies/fixtures/snapshots/ofac-sample.txt -o report.json
safeguard registry inspect report.json     # summary before the push
```

The review items in the report (unmapped list codes, unparseable dates)
require an operator decision before their entries are pushed; entries
never leave the adapter unscreened. See [`adapters.md`](adapters.md) and
[`registries.md`](registries.md).

## Rollback

- **Policy-level** problems roll back by activating a previous policy
  version — no redeploy needed (append-only versions make this safe).
- **Contract-level** problems roll back by pointing `safeguard-hooks` at
  the previous contract instance and migrating state back if the new
  layout was written (rehearse on testnet first).
- **Schema-level** problems cannot roll back silently; consumers must
  support the previous schema version or migrate (additive compatibility).

See [`versioning.md`](versioning.md) for the full migration and rollback
procedure.

## See also

- [`versioning.md`](versioning.md) — version axes, migration, rollback
- [`release.md`](release.md) — when and how releases are tagged
- [`adapters.md`](adapters.md) — producing registry datasets
- `scripts/deploy-testnet.sh`, `scripts/rehearse-upgrade.sh` — the runbooks