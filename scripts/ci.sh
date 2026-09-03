#!/usr/bin/env bash
# Local full-gate runner: everything CI enforces, in one command.
#
#   ./scripts/ci.sh          # everything (rust + schema + typescript)
#   ./scripts/ci.sh rust      # fmt, clippy, tests, wasm artifact build
#   ./scripts/ci.sh schema    # schema battery, fixtures, reference policies
#   ./scripts/ci.sh typescript # TS SDK typecheck + tests
#
# Exits non-zero on the first failing step.

set -euo pipefail

cd "$(dirname "$0")/.."

rust_gate() {
    echo "==> cargo fmt (check)"
    cargo fmt --all -- --check

    echo "==> cargo clippy (deny warnings)"
    cargo clippy --workspace --all-targets -- -D warnings

    echo "==> cargo test (workspace)"
    cargo test --workspace

    echo "==> wasm artifact (wasm32v1-none, release)"
    if ! rustup target list --installed | grep -q '^wasm32v1-none$'; then
        echo "    installing wasm32v1-none target (once)"
        rustup target add wasm32v1-none
    fi
    cargo build -p safeguard-contract --target wasm32v1-none --release
}

schema_gate() {
    echo "==> schema test battery"
    python3 scripts/test-schema.py

    echo "==> fixture cross-reference check"
    python3 scripts/check-fixtures.py

    echo "==> validate reference policies"
    python3 scripts/validate_policy.py \
        policies/default/policy.json \
        policies/examples/*.json
}

typescript_gate() {
    echo "==> TypeScript SDK (typecheck, build, tests)"
    (cd sdk/typescript && npm ci --no-audit --no-fund && npm test)
}

case "${1:-all}" in
    rust)       rust_gate ;;
    schema)     schema_gate ;;
    typescript) typescript_gate ;;
    all)        rust_gate; schema_gate; typescript_gate ;;
    *)
        echo "usage: $0 [rust|schema|typescript|all]" >&2
        exit 2
        ;;
esac

echo "All gates green."