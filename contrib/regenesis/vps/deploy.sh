#!/usr/bin/env bash
# From the Mac: ship the reviewed commit to the VPS and run the bootstrap there.
#     contrib/regenesis/vps/deploy.sh <vps-ip> <mac-public-ip-or-ddns> [ssh-key]
# Uses the operator's SSH key only; no credential of any kind is copied to the VPS.
set -euo pipefail
VPS="${1:?vps ip}"; MAC="${2:-none}"; KEY="${3:-$HOME/.ssh/id_ed25519_vps}"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD)"
# HEAD is what ships (git archive), so check HEAD, not the working tree. Node two runs testnet A:
# a commit without testnet A's final genesis must not reach it (bootstrap.sh checks the pinned
# hash again on the VPS, before it changes anything there).
HEAD_CHAINPARAMS="$(git -C "$REPO" show HEAD:src/kernel/chainparams.cpp)"
if ! grep -q '^static constexpr bool TESTNET_GENESIS_IS_FINAL = true;' <<<"$HEAD_CHAINPARAMS"; then
  echo "REFUSING: TESTNET_GENESIS_IS_FINAL is not true in $COMMIT (testnet A is not re-mined in it); nothing shipped." >&2
  exit 1
fi
TARBALL="$(mktemp -t xcoin-src).tar.gz"
git -C "$REPO" archive --format=tar.gz --prefix=xcoin-src/ -o "$TARBALL" HEAD
echo "shipping $COMMIT ($(du -h "$TARBALL" | cut -f1)) to root@$VPS"
scp -i "$KEY" "$TARBALL" "root@$VPS:/root/xcoin-src.tar.gz"
scp -i "$KEY" "$REPO/contrib/regenesis/vps/bootstrap.sh" "root@$VPS:/root/bootstrap.sh"
ssh -i "$KEY" "root@$VPS" "bash /root/bootstrap.sh /root/xcoin-src.tar.gz '$MAC' 2>&1 | tee /root/bootstrap.log"
rm -f "$TARBALL"
