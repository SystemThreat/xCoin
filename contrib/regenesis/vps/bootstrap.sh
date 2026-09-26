#!/usr/bin/env bash
# xCoin node 2 (testnet A) on a fresh Ubuntu 24.04 VPS: hardening, build, service.
#
# Run as root on the VPS, once, after the operating system is freshly installed and
# the operator's SSH key is in /root/.ssh/authorized_keys:
#
#     bash bootstrap.sh /root/xcoin-src.tar.gz <mac-public-ip-or-ddns>
#
# The source tarball is `git archive` of the reviewed commit, copied in with scp; the
# VPS never holds a GitHub credential. Nothing here needs a secret: RPC uses the
# cookie the node writes into its own data directory, readable by the service user
# only. Idempotent: safe to run again.
set -euo pipefail
SRC_TARBALL="${1:?source tarball path}"
MAC_ADDNODE="${2:-none}"   # the Mac's public IP or DDNS name, or "none" to only listen and let the Mac dial in
XCOIN_USER=xcoin
SRC_DIR=/opt/xcoin/src
DATA_DIR=/var/lib/xcoin/testneta
CONF_DIR=/etc/xcoin
P2P_PORT=19333
RPC_PORT=19432
GENESIS_TESTNET_A=1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9

log() { printf '\n== %s\n' "$*"; }

# Before anything on this machine changes: the tree must carry testnet A's final genesis, and
# it must be the one pinned above. A tree whose TESTNET_GENESIS_IS_FINAL is false has the v1
# genesis as a placeholder; its node refuses to start, and forced, it would open a new chain.
log "preflight: the tarball's testnet A genesis is final and is ${GENESIS_TESTNET_A}"
CHAINPARAMS_SRC=$(tar -xzOf "${SRC_TARBALL}" --wildcards '*/src/kernel/chainparams.cpp' 2>/dev/null || true)
# Here-strings, not pipes: under pipefail a SIGPIPE in the writer would read as a refusal.
if ! grep -q '^static constexpr bool TESTNET_GENESIS_IS_FINAL = true;' <<<"${CHAINPARAMS_SRC}"; then
  echo "REFUSING: TESTNET_GENESIS_IS_FINAL is not true in this tree (testnet A is not re-mined in it)."
  echo "Nothing was changed; the running node and its binary are untouched. See contrib/regenesis/TESTNET-A.md."
  exit 1
fi
if ! grep -q "TESTNET_GENESIS_HASH *= \"${GENESIS_TESTNET_A}\"" <<<"${CHAINPARAMS_SRC}"; then
  echo "REFUSING: this tree's TESTNET_GENESIS_HASH is not ${GENESIS_TESTNET_A}, the hash pinned in bootstrap.sh."
  echo "Nothing was changed. Pin the re-mined genesis here (GENESIS_TESTNET_A) in the same commit."
  exit 1
fi

log "0/7 swap: the build wants about 1.5 GB per compiler; make sure there is 4 GB of swap"
SWAP_TOTAL_KB=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
if [ "${SWAP_TOTAL_KB:-0}" -lt 3500000 ] && [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
free -g | awk '/Swap:/{print "swap now: " $2 " GB"}'

log "1/7 system: updates, time sync, firewall, intrusion ban, no password logins"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential cmake ninja-build pkgconf ccache python3 \
  libevent-dev libboost-dev libsqlite3-dev \
  ufw fail2ban unattended-upgrades chrony ca-certificates
timedatectl set-timezone UTC || true
systemctl enable --now chrony
# sshd: keys only, root by key only
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-xcoin.conf <<'SSHD'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
SSHD
sshd -t && systemctl reload ssh
# firewall: ssh (rate limited) and the testnet A P2P port only; RPC stays on localhost
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow ${P2P_PORT}/tcp comment 'xcoin testnet A p2p'
ufw --force enable
cat > /etc/fail2ban/jail.d/sshd.local <<'F2B'
[sshd]
enabled = true
maxretry = 4
bantime = 1h
F2B
systemctl enable --now fail2ban
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true

log "2/7 service user and directories (no shell, no password)"
id -u ${XCOIN_USER} >/dev/null 2>&1 || useradd --system --home-dir /var/lib/xcoin --shell /usr/sbin/nologin ${XCOIN_USER}
install -d -m 750 -o ${XCOIN_USER} -g ${XCOIN_USER} /var/lib/xcoin "${DATA_DIR}"
install -d -m 750 -o root -g ${XCOIN_USER} "${CONF_DIR}"

log "3/7 source: unpack the reviewed commit"
rm -rf "${SRC_DIR}"
install -d "${SRC_DIR}"
tar -xzf "${SRC_TARBALL}" -C "${SRC_DIR}" --strip-components=1
cat "${SRC_DIR}/contrib/regenesis/vps/SOURCE-COMMIT" 2>/dev/null || true

log "4/7 build: the CI configure, only the node and the CLI"
cd "${SRC_DIR}"
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF -DWITH_CCACHE=ON >/dev/null
JOBS=$(nproc); [ "$(awk '/MemTotal/{print int($2/1048576)}' /proc/meminfo)" -lt 6 ] && JOBS=2
cmake --build build -j"${JOBS}" --target bitcoind bitcoin-cli
install -m 755 build/bin/nexd build/bin/nex-cli /usr/local/bin/
/usr/local/bin/nexd --version | head -1

log "5/7 configuration: ${CONF_DIR}/testneta.conf (no secrets in it)"
cat > "${CONF_DIR}/testneta.conf" <<CONF
# xCoin testnet A, node 2. Written by contrib/regenesis/vps/bootstrap.sh.
testnet=1
server=1
listen=1
daemon=0
natpmp=0
upnp=0
datadir=${DATA_DIR}
# The section name is the chain's config name ("test" for -testnet, src/util/chaintype.cpp);
# a section named anything else is ignored and every option under it does nothing.
[test]
port=${P2P_PORT}
rpcport=${RPC_PORT}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
maxconnections=32
dbcache=512
CONF
if [ "${MAC_ADDNODE}" != "none" ]; then echo "addnode=${MAC_ADDNODE}:${P2P_PORT}" >> "${CONF_DIR}/testneta.conf"; fi
chown root:${XCOIN_USER} "${CONF_DIR}/testneta.conf"; chmod 640 "${CONF_DIR}/testneta.conf"

log "6/7 systemd unit: runs as ${XCOIN_USER}, hardened, restarts on failure"
cat > /etc/systemd/system/xcoin-testneta.service <<UNIT
[Unit]
Description=xCoin node, testnet A (node 2)
After=network-online.target chrony.service
Wants=network-online.target

[Service]
Type=simple
User=${XCOIN_USER}
Group=${XCOIN_USER}
ExecStart=/usr/local/bin/nexd -conf=${CONF_DIR}/testneta.conf
ExecStop=/usr/local/bin/nex-cli -conf=${CONF_DIR}/testneta.conf stop
TimeoutStopSec=120
Restart=on-failure
RestartSec=10
# hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallArchitectures=native
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now xcoin-testneta.service
sleep 8
systemctl --no-pager --lines=5 status xcoin-testneta.service || true

log "7/7 verify: the genesis block is testnet A's"
printf '#!/usr/bin/env bash\nexec sudo -u %s /usr/local/bin/nex-cli -conf=%s/testneta.conf "$@"\n' "${XCOIN_USER}" "${CONF_DIR}" > /usr/local/bin/rcli
chmod 755 /usr/local/bin/rcli
for i in $(seq 1 20); do
  if G=$(rcli getblockhash 0 2>/dev/null); then break; fi
  sleep 3
done
echo "genesis: ${G:-unavailable}"
if [ "${G:-}" = "${GENESIS_TESTNET_A}" ]; then
  echo "OK: testnet A genesis matches"
elif [ -n "${G:-}" ]; then
  echo "MISMATCH: the node reports genesis ${G}, expected ${GENESIS_TESTNET_A}."
  echo "Stopping and disabling xcoin-testneta so it does not build or relay a chain on the wrong genesis."
  systemctl disable --now xcoin-testneta.service || true
  exit 1
else
  echo "NOT READY: the node did not answer getblockhash 0 within 60 s (it may still be loading, or it refused to start)."
  echo "Check: journalctl -u xcoin-testneta -n 50, then run: rcli getblockhash 0"
  exit 1
fi
rcli getblockchaininfo 2>/dev/null | grep -E 'chain|blocks|headers' | head -3 || true
echo
echo "Done. Useful: rcli getconnectioncount | rcli getpeerinfo | journalctl -u xcoin-testneta -f"
