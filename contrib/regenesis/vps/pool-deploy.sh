#!/bin/bash
# pool-deploy.sh <vps-ip>: ship xcoin-pool.py, ws-bridge.py and pool-install.sh from this
# checkout to the VPS over the operator's SSH key and run the installer as root.
set -euo pipefail
VPS="${1:?usage: pool-deploy.sh <vps-ip>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
ssh -o BatchMode=yes "root@$VPS" 'install -d -m 700 /root/pool-deploy'
scp -q "$ROOT/xcoin-pool/xcoin-pool.py" "$ROOT/xcoin-pool/ws-bridge.py" "$HERE/pool-install.sh" "root@$VPS:/root/pool-deploy/"
ssh -o BatchMode=yes "root@$VPS" 'cd /root/pool-deploy && bash pool-install.sh'
