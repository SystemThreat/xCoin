#!/bin/bash
# pool-install.sh: the rehearsal pool and its browser bridge on the VPS, next to node two.
# Run as root on the VPS after bootstrap.sh, with xcoin-pool.py and ws-bridge.py in the
# current directory (pool-deploy.sh ships them). Idempotent.
#
#   /opt/xcoin/pool/{xcoin-pool.py,ws-bridge.py}   root:xcoin 640, read by the xcoin user
#   xcoin-pool.service        stratum on 0.0.0.0:3335, RPC through the node's cookie, no secret
#   xcoin-ws-bridge.service   127.0.0.1:3336, published by the superknet tunnel as wss://superknet.com/stratum
#   /var/lib/xcoin/explorer-stats   written by the pool (xcoin), read by the explorer (group xcoin-explorer)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
for f in xcoin-pool.py ws-bridge.py; do [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }; done
id xcoin >/dev/null 2>&1 || { echo "bootstrap.sh first: no xcoin user" >&2; exit 1; }
getent group xcoin-explorer >/dev/null || { echo "explorer not installed: no xcoin-explorer group" >&2; exit 1; }

install -d -o root -g xcoin -m 750 /opt/xcoin/pool
install -o root -g xcoin -m 640 xcoin-pool.py ws-bridge.py /opt/xcoin/pool/
python3 -m py_compile /opt/xcoin/pool/xcoin-pool.py /opt/xcoin/pool/ws-bridge.py

# The pool owns the statistics directory; the explorer's group may read it.
install -d -o xcoin -g xcoin-explorer -m 750 /var/lib/xcoin/explorer-stats
chown xcoin:xcoin-explorer /var/lib/xcoin/explorer-stats/* 2>/dev/null || true
chmod 644 /var/lib/xcoin/explorer-stats/* 2>/dev/null || true

cat > /etc/systemd/system/xcoin-pool.service <<'UNIT'
[Unit]
Description=xCoin solo pool (testnet A rehearsal)
After=network-online.target xcoin-testneta.service
Requires=xcoin-testneta.service

[Service]
User=xcoin
Group=xcoin
WorkingDirectory=/opt/xcoin/pool
Environment=XCOIN_RPC_PORT=19432
Environment=XCOIN_RPC_COOKIE=/var/lib/xcoin/testneta/testneta/.cookie
Environment=XCOIN_ADDRESS_HRP=txa
Environment=XCOIN_STRATUM_HOST=0.0.0.0
Environment=XCOIN_STRATUM_PORT=3335
Environment=XCOIN_NATPMP=0
Environment=XCOIN_STATS_DIR=/var/lib/xcoin/explorer-stats
Environment=XCOIN_EXPLORER_URL=https://superknet.com
ExecStart=/usr/bin/python3 /opt/xcoin/pool/xcoin-pool.py
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/xcoin/explorer-stats

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/xcoin-ws-bridge.service <<'UNIT'
[Unit]
Description=xCoin stratum-over-WebSocket bridge (browser miner)
After=xcoin-pool.service
Requires=xcoin-pool.service

[Service]
User=xcoin
Group=xcoin
WorkingDirectory=/opt/xcoin/pool
ExecStart=/usr/bin/python3 /opt/xcoin/pool/ws-bridge.py --listen 127.0.0.1:3336 --pool 127.0.0.1:3335 --origin https://xcoinminer.com --origin https://www.xcoinminer.com
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

ufw allow 3335/tcp comment 'xcoin rehearsal pool stratum' >/dev/null
systemctl daemon-reload
systemctl enable xcoin-pool.service xcoin-ws-bridge.service >/dev/null 2>&1
# (Re)start both: a re-run after a pool update must load the new file. A restart drops
# connected miners; NerdMiner does not reconnect on its own, so tell the operator.
systemctl restart xcoin-pool.service
sleep 3
systemctl restart xcoin-ws-bridge.service
sleep 1
systemctl --no-pager --lines=0 status xcoin-pool.service xcoin-ws-bridge.service | grep -E "Active|●"
ss -ltnp | grep -E ':3335|:3336' || { echo "pool or bridge not listening" >&2; exit 1; }
curl -fsS http://127.0.0.1:3336/ | grep -q "stratum websocket ok"
echo "pool and bridge installed"
