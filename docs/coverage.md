# Coverage

## Guarantee

Overall line coverage of the Rust workspace is **≥ 80%**, enforced by the
`coverage` CI job (`.github/workflows/ci.yml`) via
[`scripts/coverage.sh`](../scripts/coverage.sh). The gate fails the build if
the TOTAL line-cover of `cargo llvm-cov --workspace --summary-only` drops
below 80%.

Measured on `main` (error-code audit, September 2026): **95.1%** line
coverage overall — the contract crate (`safeguard-contract`) and every
workspace crate are individually above the threshold. The error-code audit
added two reachability tests, so every one of the 13 contract error codes is
pinned by a test that asserts it is produced by a real path.

## How to run

```bash
rustup component add llvm-tools-preview   # one-time
bash scripts/coverage.sh                  # prints the table and enforces 80%
bash scripts/coverage.sh 90               # raise the bar locally
```

The script installs `cargo-llvm-cov` on first use. CI uses a prebuilt binary
(`taiki-e/install-action`) so the gate stays fast.

## Reading the numbers

Line coverage is the primary metric; the gate keys off the TOTAL row's
line-cover column. Region and branch numbers are informational. Coverage is
measured on the full workspace including integration tests, so a regression
in any crate — including the soroban contract — fails CI before it reaches
review.

To see per-module gaps:

```bash
cargo llvm-cov --workspace --summary-only | sort -t'%' -k1
```