#!/usr/bin/env bash
# Local full-gate runner: everything CI enforces, in one command.
#
#   ./scripts/ci.sh          # everything (rust + schema + typescript + security + scripts + publish)
#   ./scripts/ci.sh rust      # fmt, clippy, tests, wasm artifact build
#   ./scripts/ci.sh schema    # schema battery, fixtures, reference policies
#   ./scripts/ci.sh typescript # TS SDK typecheck + tests
#   ./scripts/ci.sh security  # cargo-deny + npm audit
#   ./scripts/ci.sh scripts   # runbook syntax, dry-runs, adapter sample
#   ./scripts/ci.sh publish   # publish-readiness (cargo package, npm pack)
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

security_gate() {
    echo "==> cargo-deny (advisories, bans, licenses, sources)"
    if ! command -v cargo-deny >/dev/null 2>&1; then
        echo "    cargo-deny not installed; skipping (CI runs it)" >&2
    else
        cargo-deny check
    fi

    echo "==> npm audit (TypeScript SDK)"
    (cd sdk/typescript && npm audit --audit-level=high)
}

publish_gate() {
    echo "==> cargo package (all workspace crates)"
    for crate in core sdk adapters cli contract; do
        cargo package -p "safeguard-$crate" --list --allow-dirty >/dev/null
        echo "    safeguard-$crate packages cleanly"
    done

    echo "==> npm pack (TypeScript SDK tarball)"
    (cd sdk/typescript && npm pack --dry-run >/dev/null)

    echo "==> npm tarball excludes test artifacts"
    (cd sdk/typescript && npm pack --dry-run --json) | python3 -c "
import json, sys
d = json.load(sys.stdin)[0]
leaked = [f['path'] for f in d['files'] if '/test/' in f['path']]
assert not leaked, f'test artifacts leaked into the npm package: {leaked}'
print('    tarball is publish-clean')
"
}

scripts_gate() {
    echo "==> shell script syntax (bash -n)"
    for script in scripts/*.sh; do
        bash -n "$script"
    done

    echo "==> operator runbooks (deploy + rehearse) dry-run"
    ./scripts/deploy-testnet.sh --dry-run >/dev/null
    ./scripts/rehearse-upgrade.sh --dry-run >/dev/null

    echo "==> adapter sample snapshot builds and validates"
    report=$(mktemp)
    cargo run -q -p safeguard-cli -- dataset build \
        policies/fixtures/snapshots/ofac-sample.txt -o "$report" >/dev/null
    python3 - "$report" <<'EOF'
import json, sys
report = json.load(open(sys.argv[1]))
assert len(report["entries"]) == 5, report
assert len(report["review"]) == 1, report
print("    sample snapshot: 5 entries, 1 review item")
EOF
    rm -f "$report"
}

case "${1:-all}" in
    rust)       rust_gate ;;
    schema)     schema_gate ;;
    typescript) typescript_gate ;;
    security)   security_gate ;;
    scripts)    scripts_gate ;;
    publish)    publish_gate ;;
    all)        rust_gate; schema_gate; typescript_gate; security_gate; scripts_gate; publish_gate ;;
    *)
        echo "usage: $0 [rust|schema|typescript|security|scripts|all]" >&2
        exit 2
        ;;
esac

echo "All gates green."