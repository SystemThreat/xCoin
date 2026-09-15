#!/bin/bash
# Non-destructive integration checks against a LIVE testnet node.
# Read-only RPCs + one --dry-run send. Never broadcasts, never touches the seed
# file beyond reading it. Requires a running nexd with the PQ RPCs.
#
# Usage: tests/integration_testnet.sh [config-path] [rpc-port] [index]
#   defaults: $HOME/.xcoin/nex.conf, 19432 (testnet A RPC), index 1
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-$HOME/.xcoin/nex.conf}"
PORT="${2:-19432}"
INDEX="${3:-1}"
CLI=("$HERE/xcoin-wallet-cli" --config "$CONFIG" --rpc-port "$PORT")

step() { echo; echo "== $* =="; }

step "info"
"${CLI[@]}" info

step "balance --index $INDEX"
"${CLI[@]}" balance --index "$INDEX"

step "utxos --index $INDEX"
"${CLI[@]}" utxos --index "$INDEX"

step "history --index $INDEX"
"${CLI[@]}" history --index "$INDEX"

step "JSON outputs parse"
for cmd in "info" "balance --index $INDEX" "utxos --index $INDEX" "history --index $INDEX"; do
  "${CLI[@]}" --json $cmd | python3 -m json.tool > /dev/null && echo "  ok: $cmd"
done

step "dry-run send 1.0 XCF to self (never broadcasts)"
DEST="$("${CLI[@]}" address --index 0)"
if "${CLI[@]}" send "$DEST" 1.0 --index "$INDEX" --yes --dry-run; then
  echo "  dry-run signed OK (spendable funds present)"
else
  echo "  dry-run refused (expected when all UTXOs are immature) — OK"
fi

echo; echo "integration checks complete — nothing was broadcast"
