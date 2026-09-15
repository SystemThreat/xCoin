#!/usr/bin/env bash
# From the Mac: ship the reviewed commit to the VPS and run the bootstrap there.
#     contrib/regenesis/vps/deploy.sh <vps-ip> <mac-public-ip-or-ddns> [ssh-key]
# Uses the operator's SSH key only; no credential of any kind is copied to the VPS.
set -euo pipefail
VPS="${1:?vps ip}"; MAC="${2:-none}"; KEY="${3:-$HOME/.ssh/id_ed25519_vps}"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD)"
TARBALL="$(mktemp -t xcoin-src).tar.gz"
git -C "$REPO" archive --format=tar.gz --prefix=xcoin-src/ -o "$TARBALL" HEAD
echo "shipping $COMMIT ($(du -h "$TARBALL" | cut -f1)) to root@$VPS"
scp -i "$KEY" "$TARBALL" "root@$VPS:/root/xcoin-src.tar.gz"
scp -i "$KEY" "$REPO/contrib/regenesis/vps/bootstrap.sh" "root@$VPS:/root/bootstrap.sh"
ssh -i "$KEY" "root@$VPS" "bash /root/bootstrap.sh /root/xcoin-src.tar.gz '$MAC' 2>&1 | tee /root/bootstrap.log"
rm -f "$TARBALL"
