#!/usr/bin/env bash
# Benchmark per-transaction gas (fee charged, in stroops) for the policy
# contract's public functions against a live network.
#
# Usage:
#   bash scripts/bench-gas.sh [network]        # default: testnet
#
# Requires:
#   - stellar CLI (>= 28) on PATH
#   - the network configured and an identity funding the calls (the admin
#     identity from the deployment record; default name "admin",
#     override with STELLAR_ADMIN)
#   - a deployment record at deployments/<network>.json (scripts/
#     deploy-testnet.sh produces the ids; the live record is committed)
#
# Output: one line per function with the fee actually charged for a real
# transaction, in stroops (1 stroop = 1e-7 XLM). Read-only functions are
# sent with --send=yes so the fee table is printed; nothing here asserts
# pass/fail — only the cost of executing the function is measured.
#
# Methodology note: the fee charged is the authoritative on-chain cost
# (it includes CPU instructions, ledger footprint, storage rent and tx
# size). It is the number a token holder actually pays per operation.
# See docs/gas.md for the measured table and how to read it.

set -euo pipefail

cd "$(dirname "$0")/.."

NETWORK="${1:-testnet}"
RECORD="deployments/$NETWORK.json"
ADMIN="${STELLAR_ADMIN:-admin}"
# The record's network name doubles as the stellar CLI network name
# (added with `stellar network add testnet ...` per docs/deployment.md).
CLI_NETWORK="$(python3 -c "import json,sys; print(json.load(open('$RECORD'))['network'])")"

[ -f "$RECORD" ] || {
    echo "error: no deployment record at $RECORD" >&2
    echo "deploy first (scripts/deploy-testnet.sh) and record the ids" >&2
    exit 1
}

CONTRACT=$(python3 -c "import json; print(json.load(open('$RECORD'))['contract_id'])")
ADMIN_ADDR=$(python3 -c "import json; print(json.load(open('$RECORD'))['admin']['public_key'])")

# Deterministic helper: ASCII policy id -> 32-byte zero-padded hex (the
# on-chain BytesN<32> wire form used by register_version/bind_token/...).
pid_hex() { python3 -c "import sys; print(sys.argv[1].encode('ascii').ljust(32, b'\\0').hex())" "$1"; }

invoke() { # fn args... -> prints the fee charged in stroops
    local out fee
    out="$(stellar contract invoke --id "$CONTRACT" --source-account "$ADMIN" \
        --network "$CLI_NETWORK" --cost --send=yes -- "$@" 2>&1)" || true
    fee="$(printf '%s' "$out" | grep -oE 'Fee Charged: [0-9]+' | tail -1 | grep -oE '[0-9]+')"
    printf '%s' "${fee:-n/a}"
}

echo "== safeguard-policy gas benchmark ($NETWORK) =="
echo "contract: $CONTRACT   admin: $ADMIN"
printf '%-28s %10s\n' "function" "stroops"

# Read-only state reads.
printf '%-28s %10s\n' "schema_version" "$(invoke schema_version)"
printf '%-28s %10s\n' "admin" "$(invoke admin)"

# One row per policy in the deployment record.
python3 - "$RECORD" <<'EOF' | while IFS='|' read -r policy_id token; do
import json, sys
rec = json.load(open(sys.argv[1]))
tokens = {b["policy_id"]: b["token"] for b in rec.get("bound_tokens", [])}
for p in rec.get("policies", []):
    pid = p["policy_id"]
    print(f"{pid}|{tokens.get(pid, '')}")
EOF
    PID=$(pid_hex "$policy_id")
    printf '%-28s %10s\n' "get_active_version($policy_id)" "$(invoke get_active_version --policy_id "$PID")"
    printf '%-28s %10s\n' "bound_tokens($policy_id)" "$(invoke bound_tokens --policy_id "$PID")"
    if [ -n "$token" ]; then
        printf '%-28s %10s\n' "is_authorized(admin,$policy_id)" "$(invoke is_authorized --account "$ADMIN_ADDR" --token "$token")"
    fi
done

echo
echo "Values are fee charged per real transaction on $NETWORK in stroops"
echo "(1 XLM = 10,000,000 stroops). Repeat runs vary by a few percent;"
echo "see docs/gas.md for the recorded table and methodology."