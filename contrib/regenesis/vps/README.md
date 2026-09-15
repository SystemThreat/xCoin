# Node 2 on a VPS (testnet A)

One fresh Ubuntu 24.04 machine, hardened, building the reviewed commit and running
`nexd -testnet` as an unprivileged service. No secret is ever placed on the VPS: RPC
uses the cookie the node writes into its own data directory, the source arrives as a
tarball over the operator's SSH key, and the firewall admits only SSH and the testnet A
P2P port.

1. Reinstall the VPS as Ubuntu 24.04 at the provider's panel and put the operator's
   public key in `/root/.ssh/authorized_keys` (the panel's SSH-key field, or paste it
   over the provider's console). Confirm the new host key fingerprint over that console
   (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) before the first `ssh`.
2. From the Mac, at the reviewed commit:
   `contrib/regenesis/vps/deploy.sh <vps-ip> <mac-public-ip-or-ddns>`
   This ships `git archive` of HEAD and runs `bootstrap.sh` on the VPS: packages as CI
   installs them, `chrony`, `ufw` (22 rate-limited, 19333 open), `fail2ban`,
   unattended upgrades, key-only sshd, the `xcoin` system user, the build
   (`nexd`, `nex-cli`), `/etc/xcoin/testneta.conf`, the hardened
   `xcoin-testneta.service`, and a check that block 0 is testnet A's genesis.
3. On the VPS afterwards: `rcli getconnectioncount`, `rcli getpeerinfo`,
   `journalctl -u xcoin-testneta -f`. Configuration lives in
   `/etc/xcoin/testneta.conf`; data in `/var/lib/xcoin/testneta`.

TESTNET-A.md section 4 is the rehearsal step this implements.

## The rehearsal pool on the same box

`pool-deploy.sh <vps-ip>` ships `xcoin-pool/xcoin-pool.py`, `xcoin-pool/ws-bridge.py` and
`pool-install.sh`, which installs them under `/opt/xcoin/pool` and starts two hardened
services as the `xcoin` user: `xcoin-pool.service` (stratum on `0.0.0.0:3335`, RPC through
the node's cookie, `XCOIN_ADDRESS_HRP=txa`, statistics in `/var/lib/xcoin/explorer-stats`,
which the explorer reads through its group) and `xcoin-ws-bridge.service` (stratum over
WebSocket on `127.0.0.1:3336`, browsers from xcoinminer.com only). `ufw` opens 3335.

The browser endpoint is published by the superknet tunnel as `wss://superknet.com/stratum`:
an ingress rule `superknet.com` path `^/stratum$` -> `http://localhost:3336` placed before
the explorer's rule on the managed tunnel (`pool.superknet.com` is an alias, a proxied CNAME
`pool` -> `<tunnel-id>.cfargotunnel.com` in the superknet.com zone). The pool's TCP port is
not behind the proxy: NerdMiner uses the VPS address directly,
`NerdMiner txa1r… --pool <vps-ip>:3335 --worker <name>`. No secret is involved anywhere:
the pool authenticates to the node with the cookie file, and the tunnel token already on
the box is the only credential.

Checks: `journalctl -u xcoin-pool -f`, `ss -ltnp | grep -E '3335|3336'`,
`curl -s http://127.0.0.1:3336/` (answers `xcoin stratum websocket ok`),
`curl -s http://127.0.0.1:3101/api/network` (the explorer's view of the pool).
