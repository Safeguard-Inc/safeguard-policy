#!/usr/bin/env bash
# Deploy the Safeguard policy contract to a Stellar test network.
#
# Usage:
#   ./scripts/deploy-testnet.sh                # deploy + initialize + smoke test
#   ./scripts/deploy-testnet.sh --network testnet
#   ./scripts/deploy-testnet.sh --admin alice   # admin identity name
#   ./scripts/deploy-testnet.sh --load-policy   # also register/activate default policy
#   ./scripts/deploy-testnet.sh --dry-run       # print commands without running
#
# Prerequisites:
#   - stellar CLI (https://github.com/stellar/stellar-cli) on PATH
#   - a funded identity: `stellar keys fund <name>` on testnet (or
#     `stellar keys add` + fund on a futurenet), and the network configured
#     with `stellar network add`
#
# Default path (deploy → initialize → smoke-read schema_version) performs
# only calls whose arguments are addresses/strings, so it can be rehearsed
# with confidence. `--load-policy` additionally registers and activates the
# shipped default policy; those payloads need 32-byte policy ids and rule
# codes, so they are constructed deterministically from the policy JSON and
# MUST be rehearsed on testnet before any mainnet use (docs/versioning.md).
#
# Env overrides:
#   STELLAR_NETWORK   network name to use (default: testnet)
#   STELLAR_ADMIN     identity name that becomes the contract admin
set -euo pipefail

cd "$(dirname "$0")/.."

NETWORK="${STELLAR_NETWORK:-testnet}"
ADMIN="${STELLAR_ADMIN:-admin}"
WASM="target/wasm32v1-none/release/safeguard_contract.wasm"
LOAD_POLICY=0
DRY_RUN=0
ALIAS="safeguard-policy"

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --network) NETWORK="$2"; shift 2 ;;
        --admin) ADMIN="$2"; shift 2 ;;
        --alias) ALIAS="$2"; shift 2 ;;
        --load-policy) LOAD_POLICY=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

say() { printf '\n==> %s\n' "$*"; }
step() {
    # Run a stellar command (or print it under --dry-run). Every argument is
    # quoted, so values with spaces or shell metacharacters stay intact.
    local description="$1"; shift
    say "$description"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '    '
        for arg in "$@"; do printf '%q ' "$arg"; done
        printf '\n'
        return 0
    fi
    "$@"
}

command -v stellar >/dev/null 2>&1 || {
    echo "error: stellar CLI not found on PATH" >&2
    echo "install: https://github.com/stellar/stellar-cli" >&2
    exit 1
}

if [[ $DRY_RUN -eq 0 ]]; then
    echo "network: $NETWORK"
    echo "admin identity: $ADMIN"
    if ! stellar network ls 2>/dev/null | grep -qE "(^| )$NETWORK($| )"; then
        echo "error: network '$NETWORK' is not configured" >&2
        echo "run: stellar network add --global $NETWORK --rpc-url <rpc> --network-passphrase <passphrase>" >&2
        exit 1
    fi
fi

say "Building the contract wasm (wasm32v1-none, release)"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "    cargo build -p safeguard-contract --target wasm32v1-none --release"
else
    if ! rustup target list --installed | grep -q '^wasm32v1-none$'; then
        rustup target add wasm32v1-none
    fi
    cargo build -p safeguard-contract --target wasm32v1-none --release
fi
[[ -f "$WASM" ]] || {
    echo "error: $WASM not found after build" >&2
    exit 1
}

step "Deploying the policy contract (alias: $ALIAS)" \
    stellar contract deploy \
        --network "$NETWORK" \
        --source-account "$ADMIN" \
        --wasm "$WASM" \
        --alias "$ALIAS"

step "Initializing the contract with admin = $ADMIN" \
    stellar contract invoke \
        --network "$NETWORK" \
        --source-account "$ADMIN" \
        --id "$ALIAS" \
        -- initialize \
        --admin "$ADMIN"

step "Smoke test: read schema_version" \
    stellar contract invoke \
        --network "$NETWORK" \
        --source-account "$ADMIN" \
        --id "$ALIAS" \
        -- schema_version

if [[ $LOAD_POLICY -eq 1 ]]; then
    echo
    echo "==> Loading the default policy (--load-policy)"

    # Compute the 32-byte zero-padded ASCII policy id and the sha256 of the
    # policy JSON deterministically, so the payloads below are reproducible.
    POLICY_FILE="policies/default/policy.json"
    POLICY_ID_HEX=$(python3 - <<'EOF'
import json, sys
policy = json.load(open("policies/default/policy.json"))
raw = policy["policy_id"].encode("ascii")
print(raw.ljust(32, b"\0").hex())
EOF
)
    CONFIG_HASH=$(python3 - <<'EOF'
import hashlib
data = open("policies/default/policy.json", "rb").read()
print(hashlib.sha256(data).hexdigest())
EOF
)
    RULES_JSON=$(python3 - <<'EOF'
import json
policy = json.load(open("policies/default/policy.json"))
TYPE = {"allowlist": 0, "denylist": 1, "sanctions": 2, "jurisdiction": 3}
ACTION = {"block": 0, "flag": 1}
rules = []
for rule in policy["rules"]:
    rid = rule["id"].encode("ascii").ljust(32, b"\0").hex()
    rules.append({
        "rule_id": rid,
        "rule_type": TYPE[rule["type"]],
        "action": ACTION[rule["action"]],
    })
print(json.dumps(rules))
EOF
)

    say "Registering policy version $(python3 -c "import json; print(json.load(open('policies/default/policy.json'))['version'])")"
    step "stellar contract invoke register_version" \
        stellar contract invoke \
            --network "$NETWORK" \
            --source-account "$ADMIN" \
            --id "$ALIAS" \
            -- register_version \
            --policy_id "$POLICY_ID_HEX" \
            --version 1 \
            --config_hash "$CONFIG_HASH" \
            --rules "$RULES_JSON"

    say "Activating policy version 1"
    step "stellar contract invoke activate_version" \
        stellar contract invoke \
            --network "$NETWORK" \
            --source-account "$ADMIN" \
            --id "$ALIAS" \
            -- activate_version \
            --operator "$ADMIN" \
            --policy_id "$POLICY_ID_HEX" \
            --version 1

    say "Binding fixture tokens (policies/fixtures/tokens.json)"
    while IFS= read -r token; do
        [[ -n "$token" ]] || continue
        step "Binding token $token" \
            stellar contract invoke \
                --network "$NETWORK" \
                --source-account "$ADMIN" \
                --id "$ALIAS" \
                -- bind_token \
                --policy_id "$POLICY_ID_HEX" \
                --token "$token"
    done < <(python3 - <<'EOF'
import json
data = json.load(open("policies/fixtures/tokens.json"))
for binding in data["bindings"]:
    if binding["policy_id"] == json.load(open("policies/default/policy.json"))["policy_id"]:
        print(binding["token"])
EOF
)
fi

echo
echo "Deployment complete."
if [[ $DRY_RUN -eq 0 ]]; then
    echo "Contract id: $(stellar contract id --alias "$ALIAS" --network "$NETWORK" 2>/dev/null || echo "see: stellar contract id --alias $ALIAS")"
fi
echo
echo "Next steps:"
echo "  - rehearse the upgrade drill (scripts/rehearse-upgrade.sh --help)"
echo "  - wire safeguard-hooks to the contract id above"
echo "  - push registry datasets built with: safeguard dataset build"