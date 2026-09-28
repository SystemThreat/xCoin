<p align="center">
  <img src="assets/dlt-logo.svg" width="120" alt="Distributed Ledger Technologies"><br>
  <b>xCoin Ӿ (XID)</b><br>
  <i>Post-quantum proof-of-work money. XID is its ticker; Ӿ is its symbol.</i><br><br>
  <sub>100,000,000 XID, all of it mined · the Charter committed in the genesis block · 300-second blocks · MetalDAG</sub>
</p>

<p align="center">
  <b>Mainnet: live since 2026-09-26 00:00 UTC</b> · Testnet A: retired<br>
  <a href="https://distributedledgertechnologies.com">Distributed Ledger Technologies</a> ·
  <a href="https://xcoinproject.com/whitepaper">Whitepaper</a> ·
  <a href="CHARTER.md">Charter</a> ·
  <a href="https://superknet.com">Explorer</a> ·
  <a href="https://xcoinminer.com">Miner</a> ·
  <a href="https://minedifferent.com">Forum</a>
</p>

---

## Mainnet

| | |
|---|---|
| Genesis | 2026-09-26 00:00:00 UTC |
| Genesis hash | `3bc1a36df7d786a5c4584e21d248e0a3785a96aaa60a5b3959dfad50283379f2` |
| Charter hash | `fd9b475afdbe178864f32802726cc60c27290c09efd472d0934b1c733d3b9340` |
| Currency id | `e6e4ae00e1d3b25a7e4c2e94d3216d70f6b6f2e7cbd38bf23acaed391edea060` |
| Genesis message | `Hic experimentum prosperat - 2026-09-26 - 10,000,000,000,000,000 sats, 100M XID` |
| Emission | the Annual Tenth: 6.25 → 12.5 → 25 → 50 XID a block, then 10% less every 110,000 blocks, never below 1.5 XID; exactly 100,000,000 XID |
| Node transport | BIP324 v2 with the hybrid ML-KEM-768 upgrade "HX1" (XIP-4); `-v2hybrid=1` (prefer) by default; see [the post-quantum transport](#the-post-quantum-transport-hx1) |
| Node software | NEX 31.99.1, protocol 70016 (31.99.0 nodes follow the same chain and connect both ways) |
| Ports | P2P 9333, RPC 8332 on localhost ([the 8332 clash](#ports)) |
| DNS seeds | `seed.xcoinproject.com`, `seed.superknet.com`, `seed.xcoinminer.com`, `seed.minedifferent.com`, `seed.movepunk.com` |
| Explorer | [superknet.com](https://superknet.com) |

Check a node: `nex-cli getblockhash 0` and `nex-cli getcharter` (mainnet needs no network
flag) must print the values above.

xCoin is proof-of-work money that can only be spent with post-quantum signatures.
The supply is fixed at 100,000,000 XID and all of it is mined: there is no premine, no
founder allocation and nothing carried in from anywhere. The rules the currency runs
under are written in a short document, the Charter, and the SHA-256 of that text is
committed in the genesis block. The protocol belongs to whoever holds XID. There is no
company behind it, nothing to license and nothing for sale; anyone may build on it.

This repository holds the node (a Bitcoin Core fork), a stratum mining pool, a Metal
miner for macOS, the block explorer and a browser extension.

**Status: mainnet is live.** Its genesis block was mined at 2026-09-26 00:00:00 UTC; the
genesis hash, charter hash and currency id are in the table above. Nodes encrypt their
connections to each other with hybrid post-quantum keys (ML-KEM-768 layered on BIP324,
"HX1", XIP-4); [the transport section](#the-post-quantum-transport-hx1) says when a
connection can still be classical. The 100,000,000 XID cap and the emission schedule
(the Annual Tenth) are final.
Testnet A, the rehearsal chain, is retired and its coins did not carry over; this build
refuses to start on it. Every command below runs against mainnet.

## Table of contents

1. [Run a node](#run-a-node)
2. [Mine](#mine)
3. [Wallet and identity](#wallet-and-identity)
4. [The browser extension](#the-browser-extension)
5. [Repository layout](#repository-layout)
6. [Consensus at a glance](#consensus-at-a-glance)
7. [Charter](#charter)
8. [Sites](#sites)
9. [Contributing and security](#contributing-and-security)
10. [History: testnet A](#history-testnet-a)
11. [License](#license)

## Run a node

A node downloads every block, checks every proof of work and every signature against
the consensus rules, and keeps the full set of unspent outputs. Running one gives you
two things. For yourself: your own copy of the chain, a wallet that talks only to your
own machine, and no need to trust the explorer or anyone else about what the chain
says. For the network: one more independent verifier and relay, which is what keeps
a young chain honest. A node does not need a GPU or the 4 GiB mining DAG; it verifies
proof of work with the light cache (the DAG divided by 128, 32 MiB at epoch 0).

The node builds and runs on macOS with Homebrew and on Ubuntu 24.04. The binaries are
still named `nexd` and `nex-cli`. Their default data directory is
`~/Library/Application Support/NEX` on macOS and `~/.nex` on Linux. The configuration
file is `nex.conf` in that directory, and the mainnet chain (`blocks`, `chainstate`,
`wallets`, `debug.log`) lives directly in it. A `testneta` subdirectory, if you have one,
is left over from the retired testnet A.

### Dependencies

macOS (Apple Silicon or Intel):

```sh
xcode-select --install
brew install cmake boost pkgconf libevent
```

SQLite ships with macOS; nothing else is needed for the wallet.

Ubuntu 24.04 (the tree's CI list, plus `git`):

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkgconf ccache python3 git \
  libevent-dev libboost-dev libsqlite3-dev
```

### Build

```sh
git clone https://github.com/SystemThreat/xCoin.git
cd xCoin
cmake -B build -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
cmake --build build -j
```

`main` is the current release. Releases are also tagged: `mainnet-genesis-2026-09-26` is
31.99.0, the release mainnet launched with (`git tag -l` lists them; `git checkout <tag>`
before `cmake` builds one exactly).

The compile takes roughly 10 to 20 minutes on a recent Mac and much longer on a small
VPS; a handful of compiler warnings is normal. Each compiler process wants about 1.5 GB
of memory. On a small machine (2 cores, 3 GB) add 4 GB of swap and build with
`cmake --build build -j2`. Leave `-DBUILD_TESTS=OFF` out if you want the unit test
binary `build/bin/test_bitcoin` as well.

The results are `build/bin/nexd` (the node) and `build/bin/nex-cli` (its RPC client).
`build/bin/nexd -version` prints the release: the tag for a build of a tagged commit,
otherwise `v31.99.1`.

### Run a mainnet node

Mainnet is the default chain; no network flag is needed. The node finds its peers
through the DNS seeds compiled into it and talks to them on P2P port 9333.

```sh
build/bin/nexd -server -daemon
```

Or put the same thing in `nex.conf` and start `nexd` with no arguments (mainnet options
go at the top of the file, before any `[section]`):

```
server=1
daemon=1
```

`listen` is on by default. Open TCP 9333 on your firewall or router if you want other
nodes to dial you; the node works without it, and `-listen=0` turns inbound off. Keep
the RPC port closed: it listens on localhost only.

There is no RPC password. On every start the node writes a cookie file, `.cookie`, at
the top of its data directory (`~/Library/Application Support/NEX/.cookie` on macOS,
`~/.nex/.cookie` on Linux), mode 600, and deletes it on shutdown; `nex-cli` reads it
from the same data directory. If you run with `-datadir=<path>`, give the same
`-datadir` to every `nex-cli` call. The log is `debug.log` in the same directory.

### Check that it is syncing, and on the right chain

```sh
build/bin/nex-cli getblockchaininfo        # "chain": "main"; "blocks" climbs to "headers"
build/bin/nex-cli getblockhash 0
build/bin/nex-cli getcharter
build/bin/nex-cli getchaintips
build/bin/nex-cli getconnectioncount
curl -s https://superknet.com/api/network  # the explorer's "height", for comparison
```

What to expect:

- `getblockhash 0` prints `3bc1a36df7d786a5c4584e21d248e0a3785a96aaa60a5b3959dfad50283379f2`,
  the mainnet genesis. A data directory that holds another chain does not get this far:
  `nexd` stops at startup with "Incorrect or no genesis block found". Then move the
  `blocks` and `chainstate` directories out of the data directory (leave `wallets` where
  it is) and start again.
- `getcharter` reports `charter_hash` `fd9b475a…9340`, `currency_id` `e6e4ae00…a060` and
  `genesis_is_final: true`.
- `getconnectioncount` is at least 1 within a minute of starting.
- `getchaintips` shows one tip with `"status": "active"`: the chain your node follows. An
  extra entry with a short `branchlen` is a stale block and harmless.
- The node is in sync when `getblockchaininfo` shows `"initialblockdownload": false` and
  `"blocks"` equals `"headers"`, and both match the explorer's `height`, give or take the
  block in flight. The chain is young; a fresh node caught up in under a minute in
  September 2026.
- The tip must be the explorer's tip. Compare the hash at your height:

  ```sh
  h=$(build/bin/nex-cli getblockcount)
  build/bin/nex-cli getblockhash $h
  curl -s https://superknet.com/api/block/$h   # its "hash" must be the same
  ```

  The explorer is a convenience, not an authority: your node checked every block itself.
  A different hash at the same height means one side is on another branch; look at
  `getchaintips` and at the peers in `getpeerinfo` before you trust either.

### If it finds no peers

If `getconnectioncount` stays at 0 for more than a minute, your resolver is probably not
answering for the DNS seeds. The node then falls back to the fixed seeds compiled into it
(the five public nodes below in 31.99.1; 31.99.0 carried only the first). You can add
them yourself at once:

```sh
build/bin/nex-cli addnode 172.96.186.49:9333 onetry     # New York
build/bin/nex-cli addnode 198.252.107.13:9333 onetry    # Hong Kong
build/bin/nex-cli addnode 103.119.217.105:9333 onetry   # London
build/bin/nex-cli addnode 198.252.101.117:9333 onetry   # Singapore
build/bin/nex-cli addnode 54.20.130.14:9333 onetry      # São Paulo
```

or keep them in `nex.conf`, one `addnode=` line each (`addnode=172.96.186.49` and so on;
the port defaults to 9333), or pass `-addnode=<address>` at start. Any one that answers
is enough; the node learns the rest of the network from it.

### The post-quantum transport (HX1)

Every connection to a peer that speaks v2 uses BIP324 with the HX1 upgrade: an ML-KEM-768
key exchange layered on BIP324's classical one, so recording the traffic today and
breaking elliptic curves later does not reveal it. `-v2hybrid` sets the mode: `1`
(prefer, the default) uses HX1 with every peer that takes part and stays classical with
one that does not; `2` (require) disconnects such peers and never falls back to v1; `0`
turns it off. Leave the default: on a young network `require` can leave a node with
fewer peers.

Check it:

```sh
build/bin/nex-cli getpeerinfo | grep -E '"addr"|"transport_protocol_type"|"transport_hybrid"'
build/bin/nex-cli getnetworkinfo | grep -A8 '"v2hybrid"'
```

A post-quantum session shows `"transport_protocol_type": "v2"` and
`"transport_hybrid": true`; `v2hybrid_counts` counts the handshake outcomes since start.

The first sync may be classical. The DNS and fixed seeds hand out bare addresses that say
nothing about v2, and 31.99.0 treats such an address as v1-only: a brand-new 31.99.0 node
makes its first connections, and its whole first sync, over plain v1, and uses HX1 once it
has met its peers (after its first restart, for example). 31.99.1 tries v2 with HX1 on
seed addresses first and falls back to v1 only for a peer that does not speak v2. On
either version, a peer given with `-addnode` or `addnode` is tried over v2 first.

### Ports

| | mainnet | who else uses it |
|---|---|---|
| P2P | 9333 (open it for inbound peers) | Litecoin's P2P port |
| RPC | 8332 (localhost only; never open it) | Bitcoin Core's RPC port |

If `bitcoind` runs on the same machine, `nexd` cannot take 8332 and stops at startup
("Unable to start HTTP server"), or, if `bitcoind` started second, `nex-cli` reaches
`bitcoind` with the wrong cookie ("Authorization failed: Incorrect rpcuser or
rpcpassword"). The same goes for `litecoind` and 9333. The defaults stay as they are, so
that no running node changes; give xCoin its own ports in `nex.conf` instead:

```
rpcport=29432
port=29333
```

`nex-cli` reads `rpcport` from the same file. If you set it on the command line instead,
pass the same `-rpcport` to every `nex-cli` call, and give a pool `XCOIN_RPC_PORT`.

### Stop and upgrade

Stop the node with `build/bin/nex-cli stop`; it logs "Shutdown done" and exits. The chain
stays in the data directory, and the next start continues from where it left off.

Upgrading from 31.99.0 to 31.99.1 needs no resync and no `-reindex`, and 31.99.0 can be
put back the same way: [doc/release-notes-31.99.1.md](doc/release-notes-31.99.1.md).

### A node on a VPS

On a fresh Ubuntu 24.04 box with 2 cores and 3 GB of memory plus 4 GB of swap, as an
ordinary user:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkgconf ccache python3 git \
  libevent-dev libboost-dev libsqlite3-dev
git clone https://github.com/SystemThreat/xCoin.git && cd xCoin
cmake -B build -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
cmake --build build -j2
sudo ufw allow 9333/tcp            # only if you want inbound peers
build/bin/nexd -server -daemon
build/bin/nex-cli getblockhash 0   # must print 3bc1a36d…79f2
```

Keep RPC on localhost (the default) and never open 8332 on the firewall. The scripts in
`contrib/regenesis/vps/` set up a testnet A node; they are history and refuse to run
([History: testnet A](#history-testnet-a)).

## Mine

The proof of work is MetalDAG: Keccak-based and memory-hard, with a 4 GiB DAG that
grows 128 MiB every 14-day epoch, counted from the genesis time. It is written for the
unified memory of Apple Silicon. SHA-256 ASICs cannot mine it.

Every mining path pays a witness v3 address, `xpa1r…`. Get one from any of these:

- MMM, the Mac miner app, holds a wallet ([below](#mmm-on-a-mac)).
- [xcoin-wallet](#the-standalone-wallet): `xcoin-wallet address`.
- Your node's wallet:

  ```sh
  build/bin/nex-cli createwallet mining
  build/bin/nex-cli getnewaddress            # xpa1r…
  ```

An `xpa1z…` string is a legacy witness v2 form; the pools, the miner and the chain all
refuse it, and an `xid1…` forum identity is not an address at all. Mined coins mature
after 1,000 blocks, about 3.5 days at 300 s; until then `getbalances` lists them under
`immature`.

### The public pools

| Pool | Stratum | Fee | Pays |
|---|---|---|---|
| Solo, New York | `pool.xcoinminer.com:3335` (172.96.186.49) | none | a block you find pays its whole coinbase to you |
| PPLNS, Singapore | `198.252.101.117:3336` | 2.99% | every block's coinbase pays the miners of the last shares, pro rata, plus one fee output |

The stratum user is your `xpa1r…` address, optionally with `.workername`; the password is
ignored. Both pools pay in the coinbase and hold no coins. On the PPLNS pool, a miner
whose part of a block would be under 10,000 sat gets no output in that block.

### MMM on a Mac

MMM (Mac Metal Miner) is the native macOS app: it mines on the Apple GPU, shows the
pool and the chain, and its WALLET tab runs the bundled xcoin-wallet. Source:
[github.com/SystemThreat/MMM](https://github.com/SystemThreat/MMM) (`./build.sh --install`);
instructions at [macmetalminer.com](https://macmetalminer.com). In Setup:

```
Network   Mainnet
Explorer  https://superknet.com
Pool      pool.xcoinminer.com   (or 198.252.101.117 for PPLNS)
Port      3335                  (3336 for PPLNS)
Worker    any name
Password  leave blank
Payout    your xpa1r… address
```

MMM reads the genesis time from the explorer, so it needs no `--base`.

### NerdMiner on the command line

`miner/` is NerdMiner 4.1.0, Swift and Metal, for Apple Silicon Macs. It needs the
Xcode Command Line Tools and enough memory for the 4 GiB DAG.

```sh
cd miner
./build.sh
./NerdMiner xpa1r… --pool pool.xcoinminer.com:3335 --base 1790380800 --worker <name>
```

`--pool 198.252.101.117:3336` mines on the PPLNS pool instead, and `--pool 127.0.0.1:3333`
on a pool of your own (below). `--base 1790380800` is the mainnet genesis time
(2026-09-26 00:00 UTC; `nex-cli getblock $(nex-cli getblockhash 0)` shows it as
`time`), from which the DAG epochs count; pass it, since a NerdMiner that does not carry
it stops on an `xpa1r…` address without it. While it runs, NerdMiner serves its own
statistics on `127.0.0.1:47475` for the browser extension; `--no-stats` turns that off.

### In a browser

Open [xcoinminer.com](https://xcoinminer.com), paste an `xpa1r…` address and press
start. The page speaks stratum over WebSocket to `wss://superknet.com/stratum`, which
`xcoin-pool/ws-bridge.py` relays to the solo pool. It is a learning tool: the hashrate is
low, but a share it finds is a real share.

### Your own pool

`xcoin-pool/` is a stratum pool that stands on your own node (it refuses a non-loopback
RPC host): a thin bridge from `getblocktemplate` to `submitblock`, standard library only,
no accounts. In its default solo mode a block you find pays its whole coinbase, subsidy
plus fees, to your address, and the pool builds no other transaction. Run it next to a
synced mainnet node:

```sh
XCOIN_RPC_COOKIE="$HOME/.nex/.cookie" \
XCOIN_NATPMP=0 \
XCOIN_STATS_DIR="$HOME/.xcoin-pool" \
python3 xcoin-pool/xcoin-pool.py
```

On macOS the cookie is at `"$HOME/Library/Application Support/NEX/.cookie"`. The defaults
are mainnet's: RPC `127.0.0.1:8332` (set `XCOIN_RPC_PORT` if you moved `rpcport`),
stratum on port 3333, `xpa` addresses. Then start NerdMiner with `--pool 127.0.0.1:3333`.
The pool authenticates to the node with the cookie file and warns if it is ever given a
password instead. It reads `getblockchaininfo` at start and refuses to run when
`XCOIN_ADDRESS_HRP` contradicts the chain the node reports. `XCOIN_NATPMP=0` keeps the
stratum port off your router. A mainnet node hands out block templates only while it has
a peer and has finished its initial sync; until then the pool logs `RPC getblocktemplate
error` and keeps polling. `XCOIN_POOL_MODE=pplns` runs it as a PPLNS pool; see
[xcoin-pool/README.md](xcoin-pool/README.md).

The pool's tests run offline:

```sh
python3 xcoin-pool/test_coinbase.py -v
python3 xcoin-pool/test_miner_slots.py -v
python3 xcoin-pool/test_ws_bridge.py -v
```

[superknet.com](https://superknet.com) is the explorer, with a public API at
`/api/stats`, `/api/network` and `/api/block/<height>`. It is a convenience: your node is
the authority, and the checks in [Check that it is
syncing](#check-that-it-is-syncing-and-on-the-right-chain) need only `nex-cli`.

## Wallet and identity

### The node wallet

The node's own wallet makes witness v3 addresses (`xpa1r…`, an ML-DSA-65 leaf and an
SLH-DSA fallback leaf) and signs with ML-DSA-65:

```sh
build/bin/nex-cli createwallet <name>
build/bin/nex-cli -stdin encryptwallet                      # type the passphrase, Enter, Ctrl-D
build/bin/nex-cli -stdinwalletpassphrase walletpassphrase 60   # unlock for 60 s, passphrase from stdin
build/bin/nex-cli getnewaddress
build/bin/nex-cli getbalances
build/bin/nex-cli sendtoaddress <xpa1r…> 1.5
```

A passphrase goes in over stdin, never on the command line where shell history and
`ps` would keep it. Fees are the byte-rate fee alone: the settlement levy exists in
the code but ships at a zero rate and zero cap. No output may be worth less than
10,000 sat. The wallet lives in `wallets/` in the data directory; back it up with
`nex-cli backupwallet <file>`.

### The standalone wallet

[github.com/SystemThreat/xcoin-wallet](https://github.com/SystemThreat/xcoin-wallet) is
the post-quantum wallet without a node: a Python CLI over a native keytool built from
the same ML-DSA-65 and SLH-DSA sources as the node. One 256-bit seed is the whole wallet;
the wallet file (`.mmm`) is encrypted with a passphrase, and signing happens offline in
the keytool. With `--explorer` it needs no node: balances and fees come from the
explorer's API and the explorer relays the signed transaction.

```sh
git clone https://github.com/SystemThreat/xcoin-wallet.git && cd xcoin-wallet
./build.sh && ./install.sh          # Apple Silicon, Xcode CLT; installs xcoin-wallet into ~/.local/bin
xcoin-wallet new --offline
xcoin-wallet address                                              # xpa1r…
xcoin-wallet --explorer https://superknet.com --hrp xpa balance
xcoin-wallet --explorer https://superknet.com --hrp xpa send <xpa1r…> 1.5
```

Pass `--hrp xpa` with `--explorer`: it makes sure the wallet reads and writes mainnet
addresses. The passphrase is typed at a prompt or handed over a pipe with
`--passphrase-fd N`; the wallet refuses to start if it finds one in an environment
variable. MMM's WALLET tab runs this same wallet.

`wallet/` in this tree is an older snapshot of that wallet. It makes legacy witness v2
addresses, which this chain refuses as outputs, and cannot spend witness v3 outputs; do
not use it for coins.

### Your identity

An xCoin identity is a forum handle derived from an ML-DSA-65 key: the SHA-256 of the
public key, written as bech32m under the prefix `xid` with no witness version, 62
characters starting `xid1`. It has no chain prefix, so no node reads it as an address
and nothing can be paid to it. By convention the identity is key index 101 of your
wallet (`xcoin-wallet identity --index 101`).

[minedifferent.com](https://minedifferent.com) is the forum. There are no passwords:
you sign in with `NerdMiner login`, which asks the wallet to sign a one-time
challenge with the index 101 key (the wallet asks for its passphrase) and opens the
resulting link. `XCOIN_WALLET_CLI` tells NerdMiner where the wallet is: the
`xcoin-wallet-cli` launcher in your xcoin-wallet clone.

```sh
XCOIN_WALLET_CLI=<path to xcoin-wallet>/xcoin-wallet-cli ./NerdMiner login --index 101
```

Chat unlocks after one accepted share credited to that identity.

## The browser extension

`extension/nerdminer-md/` is NerdMiner MD: a toolbar popup that shows live statistics
from the NerdMiner running on your Mac (hashrate, shares, blocks, DAG epoch), who is
online at MineDifferent, and the `#rigs` chat. It does not mine. NerdMiner 4.1 admits
the extension on its own; nothing is pasted anywhere. Sign in at minedifferent.com
once and the extension reuses that session.

Chrome, Brave, Edge: open the extensions page, switch on developer mode, choose
"Load unpacked" and pick `extension/nerdminer-md/`.

Firefox: copy the folder, replace its `manifest.json` with `manifest.firefox.json`
(renamed to `manifest.json`), then `about:debugging` → This Firefox → Load Temporary
Add-on and pick that `manifest.json`.

Options: the stats URL (`http://127.0.0.1:47475` unless NerdMiner was started with
`--stats-port`) and the forum origin.

## Repository layout

```
src/, cmake/, CMakeLists.txt, test/   the node: a Bitcoin Core fork. Binaries nexd and nex-cli.
contrib/regenesis/CHARTER.md          the Charter, the text whose hash the genesis commits to
contrib/regenesis/emission.py         turns emission-policy.json into the params.h table and proves it sums to the cap
contrib/regenesis/aserti3_2d_reference.py   independent ASERT reference in exact integer arithmetic
contrib/regenesis/TESTNET-A.md, vps/  history: the retired testnet A runbook and its VPS scripts
contrib/seeds/                        nodes_main.txt, the fixed seeds compiled into src/chainparamsseeds.h
xcoin-pool/                           xcoin-pool.py (solo or PPLNS stratum pool), ws-bridge.py (browser bridge), tests
miner/                                NerdMiner 4.1.0: Swift + Metal for macOS, build.sh, NerdMiner login
wallet/                               an older snapshot of xcoin-wallet (witness v2 only; see above)
explorer/                             xcoin-explorer.py, the explorer behind superknet.com (cookie RPC, tests/)
extension/nerdminer-md/               NerdMiner MD; manifest.json (Chromium), manifest.firefox.json
doc/release-notes-*.md                what each xCoin release changed (doc/ is otherwise inherited from Bitcoin Core)
CHARTER.md                            verbatim copy of contrib/regenesis/CHARTER.md
COPYING                               MIT, from Bitcoin Core
```

Where the numbers live: `src/consensus/params.h` (emission, charter hash, maturity,
output floor, levy), `src/kernel/chainparams.cpp` (P2P ports, prefixes, genesis,
difficulty, MetalDAG sizing, DNS seeds), `src/chainparamsbase.cpp` (RPC ports, data
directories), `src/consensus/consensus.h` and `src/policy/policy.h` (block weight, data
carrier), `src/script/xcoin_v3.h` (witness v3 rules and budget).

## Consensus at a glance

| Rule | Value |
|---|---|
| Unit | 1 XID = 100,000,000 sat |
| Supply cap | 100,000,000 XID exactly; nothing premined, nothing carried in |
| Block reward | the Annual Tenth (charter section 4): 6.25, 12.5, 25 XID for 20,000 blocks each, then 50 XID to block 220,000 <!-- [EMISSION-SHAPE] --> |
| Reduction | 10% less every 110,000 blocks (~382 days), never under 1.5 XID and never more than a tenth of what is left per step; 0.1 XID tail; 65 rows; the last subsidy block (35,375,353) pays 0.1 XID plus the 0.0166 XID remainder, then fees only <!-- [EMISSION-SHAPE] --> |
| Block interval | 300 s target |
| Difficulty | ASERT (aserti3-2d), per block, anchored at genesis, half-life 2 h; no minimum-difficulty blocks |
| Proof of work | MetalDAG (Keccak): 4 GiB DAG at epoch 0, +128 MiB per epoch; an epoch is 14 days from the genesis time; light cache = DAG / 128 |
| Signatures | witness v3 script trees only; leaves ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-128s (FIPS 205); no ECDSA or Schnorr spend path; no witness v2 output may be created |
| Validation budget | per witness v3 input, witness bytes + 50; an ML-DSA-65 check costs 200, an SLH-DSA check 1,080, and hash opcodes cost 1 per byte hashed |
| Coinbase maturity | 1,000 blocks |
| Output floor | 10,000 sat per non-data output; a coinbase with a single spendable output is exempt so every era's subsidy stays mintable |
| Settlement levy | zero rate, zero cap at genesis (the machinery is dormant) |
| Block weight | 64,000,000 WU consensus; 4,000,000 WU mined by default; 16,000,000 WU largest relayable block |
| Data carrier | 8,000 bytes per block: 100 OP_RETURN anchors of 80 bytes |
| Genesis coinbase | one output, `OP_RETURN "XCOIN/charter/1" ‖ CHARTER_HASH`, value 0; block 0 mints nothing |

The chains:

| | mainnet | testnet A (retired) | regtest |
|---|---|---|---|
| Select | default | `-testnet` (refuses to start) | `-regtest` |
| Addresses | `xpa1r…` | `txa1r…` | `nxrt1r…` |
| P2P / RPC port | 9333 / 8332 | 19333 / 19432 | 19444 / 18443 |
| Data subdirectory | (root) | `testneta` | `regtest` |
| Genesis | `3bc1a36d…79f2`, mined 2026-09-26 00:00 UTC | last `1dc4131e…ccb9`, not re-mined | local |

Testnet A ran the mainnet rules unchanged, down to the emission table and the DAG
sizing; a unit test in the tree still checks that line by line. Only its identity
differed.

## Charter

The Charter (`CHARTER.md`, verbatim from `contrib/regenesis/CHARTER.md`) is the text
that defines the currency: its name and units, the 100,000,000 XID cap, the emission
schedule (section 4, the Annual Tenth, final since 2026-09-25), what ownership means,
how history is kept, how rules may change and what the chain is for. Software, proof of
work and signature algorithms are its current implementation and may be replaced;
sections 1 through 9 of the text may not.

Its SHA-256 is compiled into the node as `CHARTER_HASH` in `src/consensus/params.h`
and written into the genesis coinbase's only output:

```
fd9b475afdbe178864f32802726cc60c27290c09efd472d0934b1c733d3b9340
```

Check it yourself against a running mainnet node:

```sh
shasum -a 256 CHARTER.md             # sha256sum on Linux
build/bin/nex-cli getcharter         # charter_hash, currency_id, genesis_hash, genesis_is_final: true
```

Editing the Charter, by one byte, changes that hash, and a chain whose genesis commits
to a different hash is a different currency: the unit suite fails until the constant is
changed on purpose, and the genesis has to be mined again. Sections 2 (supply) and 4
(emission) carry a veto and cannot be changed by any process. Later versions may only
add sections 10 and beyond, and take force when their hash is committed in a block
under the Charter's own section 7.

## Sites

- [xcoinproject.com](https://xcoinproject.com): the whitepaper and the Charter.
- [xcoinminer.com](https://xcoinminer.com): mine in a browser.
- [superknet.com](https://superknet.com): the explorer and its public API.
- [minedifferent.com](https://minedifferent.com): the forum; sign in with your xCoin identity.
- [macmetalminer.com](https://macmetalminer.com): MMM, the Mac miner.
- [distributedledgertechnologies.com](https://distributedledgertechnologies.com).

## Contributing and security

Read the code before the prose: if this file and `src/consensus/params.h` disagree,
the source is right and this file needs a fix. Bug reports and pull requests are
welcome for every part of the tree. Run the relevant tests first:

```sh
build/bin/test_bitcoin                                  # node unit tests (build with BUILD_TESTS on)
build/bin/test_bitcoin -t regenesis_testnet_a_tests     # testnet A rules equal mainnet rules
test/functional/test_runner.py                          # node functional tests
python3 xcoin-pool/test_coinbase.py -v                  # pool
```

Changes to consensus are not made by pull request alone. The Charter's section 7 sets
the process: additions by fork with miner signalling and a published review period;
removals by hard fork with a supermajority of node operators and a migration window of
at least four years. Sections 2 and 4 cannot be changed at all.

Security: if you find a way to mint, to spend what you do not own, to split the chain
or to crash a node from the network, do not open a public issue. [SECURITY.md](SECURITY.md)
says where to report it.

No secrets, anywhere. This tree is written so that no secret is ever placed in an
environment variable: RPC uses the cookie the node writes into its own data
directory; the pool and the explorer read that cookie file; wallet passphrases are
typed at a prompt or passed over a pipe. Keep it that way in anything you add, and
never paste a seed, a passphrase or a cookie into an issue, a log or the chat.

## History: testnet A

Testnet A was the rehearsal chain that ran the mainnet rules before genesis. It is
retired: its coins have no value and did not carry over. This build refuses
`nexd -testnet` with "Refusing to start on testnet A: this build's testnet A genesis is
not final"; that is expected and does not mean the build is broken.
`contrib/regenesis/TESTNET-A.md` (its runbook) and `contrib/regenesis/vps/` (its VPS and
pool scripts) are kept as a record; `deploy.sh` and `bootstrap.sh` stop before changing
anything, and none of it sets up a mainnet node.

## License

MIT. The node inherits Bitcoin Core's license, see [COPYING](COPYING); `miner/` and
`wallet/` carry their own MIT `LICENSE` files.
