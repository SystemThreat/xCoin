<p align="center">
  <img src="assets/dlt-logo.svg" width="120" alt="Distributed Ledger Technologies"><br>
  <b>xCoin (XCF)</b><br>
  <i>Post-quantum proof-of-work money. XCF is xCoin Finality.</i><br><br>
  <sub>21,000,000 XCF, all of it mined · the Charter committed in the genesis block · 300-second blocks · MetalDAG</sub>
</p>

<p align="center">
  <b>Testnet A rehearsal: running</b> · Mainnet genesis: not mined<br>
  <a href="https://distributedledgertechnologies.com">Distributed Ledger Technologies</a> ·
  <a href="https://xcoinproject.com/whitepaper">Whitepaper</a> ·
  <a href="CHARTER.md">Charter</a> ·
  <a href="https://superknet.com">Explorer</a> ·
  <a href="https://xcoinminer.com">Miner</a> ·
  <a href="https://minedifferent.com">Forum</a>
</p>

---

xCoin is proof-of-work money that can only be spent with post-quantum signatures.
The supply is fixed at 21,000,000 XCF and all of it is mined: there is no premine, no
founder allocation and nothing carried in from anywhere. The rules the currency runs
under are written in a short document, the Charter, and the SHA-256 of that text is
committed in the genesis block. The protocol belongs to whoever holds XCF. There is no
company behind it, nothing to license and nothing for sale; anyone may build on it.

This repository holds the node (a Bitcoin Core fork), a solo mining pool, a Metal miner
for macOS, a standalone post-quantum wallet and a browser extension.

**Status: the testnet A rehearsal is running. The mainnet genesis block has not been
mined and has no date.** Coins on testnet A have no value. Everything below runs
against the rehearsal chain unless it says otherwise.

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
10. [License](#license)

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
`~/Library/Application Support/NEX` on macOS and `~/.nex` on Linux; the configuration
file is `nex.conf` in that directory, and the testnet A chain lives in the `testneta`
subdirectory.

### Dependencies

macOS (Apple Silicon or Intel):

```sh
xcode-select --install
brew install cmake boost pkgconf libevent
```

SQLite ships with macOS; nothing else is needed for the wallet.

Ubuntu 24.04 (the same list the tree's CI installs):

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkgconf ccache python3 \
  libevent-dev libboost-dev libsqlite3-dev
```

### Build

From the root of this repository:

```sh
cmake -B build -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
cmake --build build -j
```

Each compiler process wants about 1.5 GB of memory. On a small machine (the VPS
scripts below assume 2 cores and 3 GB) add 4 GB of swap and build with
`cmake --build build -j2`. Leave `-DBUILD_TESTS=OFF` out if you want the unit test
binary `build/bin/test_bitcoin` as well.

The results are `build/bin/nexd` (the node) and `build/bin/nex-cli` (its RPC client).

### Run against the rehearsal

Testnet A is selected with `-testnet`. Node two of the rehearsal is reachable as
`testnet.superknet.com` (P2P port 19333); the same name is the chain's DNS seed, so a
node finds it on its own, and `-addnode` makes that immediate. If your resolver still
answers with a cached older address, use `-addnode=172.96.186.49` instead.

```sh
build/bin/nexd -testnet -server -listen -daemon -addnode=testnet.superknet.com
```

Or put the same thing in `nex.conf` and start `nexd` with no arguments (network
options for a non-mainnet chain go under that chain's section, which for testnet A
is `[test]`):

```
testnet=1
server=1
listen=1
daemon=1
[test]
addnode=testnet.superknet.com
```

There is no RPC password. On every start the node writes a cookie file,
`testneta/.cookie` inside its data directory, mode 600, and deletes it on shutdown;
`nex-cli` reads it from the same data directory. If you run with `-datadir=<path>`,
give the same `-datadir` to every `nex-cli` call.

### Check that it is syncing

```sh
build/bin/nex-cli -testnet getblockchaininfo        # "chain": "test", "blocks" rising
build/bin/nex-cli -testnet getblockhash 0
build/bin/nex-cli -testnet getcharter
build/bin/nex-cli -testnet getconnectioncount
build/bin/nex-cli -testnet getpeerinfo | grep -E '"addr"|"synced_blocks"'
```

What to expect:

- `getblockhash 0` prints `1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9`.
  Anything else is a data directory from a different genesis: stop the node, delete the
  `testneta` subdirectory and start again.
- `getcharter` reports `charter_hash`
  `415b1dbc7ff2cd14b747b300ecd95862540e12305a801bb2bfed8b93c5d84689` and
  `genesis_is_final: true`.
- `getconnectioncount` is at least 1. Opening TCP 19333 on your firewall or router
  lets other nodes dial you as well; the node works without it.

Stop the node with `build/bin/nex-cli -testnet stop`. The chain stays in the data
directory and the next start continues from where it left off.

### A node on a VPS

`contrib/regenesis/vps/` sets up a hardened node on a fresh Ubuntu 24.04 box with two
cores and 3 GB of memory (it adds 4 GB of swap). From your own machine, with your SSH
key already in the VPS's `/root/.ssh/authorized_keys`:

```sh
contrib/regenesis/vps/deploy.sh <vps-ip> <your-public-ip-or-ddns> [ssh-key]
```

The third argument is the SSH key for the VPS; it defaults to `~/.ssh/id_ed25519_vps`.

`deploy.sh` ships `git archive` of your checkout over SSH and runs `bootstrap.sh` on
the VPS: the CI package list, `chrony`, `ufw` (SSH rate-limited, 19333 open, RPC on
localhost only), `fail2ban`, unattended upgrades, key-only sshd, an unprivileged
`xcoin` system user, the build, `/etc/xcoin/testneta.conf` with no secret in it, a
hardened `xcoin-testneta.service`, and a check that block 0 is the testnet A genesis.
Pass `none` as the second argument to only listen. Afterwards, on the VPS:

```sh
rcli getconnectioncount            # rcli wraps nex-cli with the service's conf
rcli getpeerinfo
journalctl -u xcoin-testneta -f
```

`pool-deploy.sh <vps-ip>` adds the solo pool and its WebSocket bridge to the same
box as two more hardened services (see [Mine](#mine)).

## Mine

The proof of work is MetalDAG: Keccak-based and memory-hard, with a 4 GiB DAG that
grows 128 MiB every 14-day epoch. It is written for the unified memory of Apple
Silicon. SHA-256 ASICs cannot mine it.

Every mining path pays a witness v3 address, `txa1r…` on testnet A. Make one in your
node's wallet:

```sh
build/bin/nex-cli -testnet createwallet mining
build/bin/nex-cli -testnet getnewaddress            # txa1r…
```

A `txa1z…` string is a legacy witness v2 form; the pool, the miner and the chain all
refuse it. Mined coins mature after 1,000 blocks, about 3.5 days at 300 s; until then
`getbalances` lists them under `immature`.

### NerdMiner on a Mac

`miner/` is NerdMiner 4.1.0, Swift and Metal, for Apple Silicon Macs. It needs the
Xcode Command Line Tools and enough memory for the 4 GiB DAG.

```sh
cd miner
./build.sh
./NerdMiner txa1r… --pool 172.96.186.49:3335 --worker <name>
```

The address is the stratum user; `--worker` names the rig. `172.96.186.49:3335` is
the rehearsal pool next to node two; `--pool 127.0.0.1:3335` points at a pool of your
own (below). While it runs, NerdMiner serves its own statistics on `127.0.0.1:47475`
for the browser extension; `--no-stats` turns that off.

### In a browser

Open [xcoinminer.com](https://xcoinminer.com), paste a `txa1r…` address and press
start. The page speaks stratum over WebSocket to `wss://superknet.com/stratum`, which
`xcoin-pool/ws-bridge.py` relays to the rehearsal pool. It is a learning tool: the
hashrate is low, but a share it finds is a real share.

### Your own pool

`xcoin-pool/` is a solo, coinbase-only stratum pool: a thin bridge from
`getblocktemplate` to `submitblock` on your own node, standard library only, no
accounts and no fee. A block you find pays its whole coinbase, subsidy plus fees, to
your address, and the pool builds no other transaction. Run it against your node:

```sh
XCOIN_RPC_PORT=19432 \
XCOIN_RPC_COOKIE="$HOME/.nex/testneta/.cookie" \
XCOIN_ADDRESS_HRP=txa \
XCOIN_STRATUM_PORT=3335 \
XCOIN_NATPMP=0 \
XCOIN_STATS_DIR="$HOME/.xcoin-pool" \
python3 xcoin-pool/xcoin-pool.py
```

On macOS the cookie is at `"$HOME/Library/Application Support/NEX/testneta/.cookie"`.
The environment carries paths and ports only; the pool authenticates to the node with
the cookie file and warns if it is ever given a password instead. It reads
`getblockchaininfo` at start and refuses to run when `XCOIN_ADDRESS_HRP` contradicts
the chain the node reports. `XCOIN_NATPMP=0` keeps the stratum port off your router.
Then start NerdMiner with `--pool 127.0.0.1:3335`.

The pool's tests run offline:

```sh
python3 xcoin-pool/test_coinbase.py -v
python3 xcoin-pool/test_ws_bridge.py -v
```

[superknet.com](https://superknet.com) is the explorer, with a public API at
`/api/stats` and `/api/network`. It is a convenience: your node is the authority, and
the daily check in `contrib/regenesis/TESTNET-A.md` (section 7) needs only `nex-cli`.

## Wallet and identity

### The node wallet

The node's own wallet is the one that spends on this chain today. It makes witness v3
addresses and signs with ML-DSA-65:

```sh
build/bin/nex-cli -testnet createwallet <name>
build/bin/nex-cli -testnet -stdin encryptwallet                      # type the passphrase, Enter, Ctrl-D
build/bin/nex-cli -testnet -stdinwalletpassphrase walletpassphrase 60   # unlock for 60 s, passphrase from stdin
build/bin/nex-cli -testnet getnewaddress
build/bin/nex-cli -testnet getbalances
build/bin/nex-cli -testnet sendtoaddress <txa1r…> 1.5
```

A passphrase goes in over stdin, never on the command line where shell history and
`ps` would keep it. Fees are the byte-rate fee alone: the settlement levy exists in
the code but ships at a zero rate and zero cap. No output may be worth less than
10,000 sat.

### The standalone wallet

`wallet/` is a small, readable post-quantum wallet: a Python CLI (`wallet_cli.py`,
launched by `xcoin-wallet-cli`) over a native keytool (`xcoin-wallet.cpp`) built from
this tree's own ML-DSA-65 sources. One 256-bit seed is the whole wallet; the wallet
file (`.mmm`) is encrypted with a passphrase, and signing happens in the keytool,
offline, with the seed passed over a pipe and never to the node.

```sh
cd wallet
NEX=.. ./build.sh          # builds ./xcoin-wallet, the keytool (Xcode CLT, Apple Silicon)
./xcoin-wallet-cli new --offline
./xcoin-wallet-cli identity --index 101
```

`./install.sh` symlinks the tools into `~/.local/bin` as `xcoin-wallet`; put that
directory on your PATH if you want to call it from anywhere.

Where it stands: its addresses are still legacy witness v2 strings, which this chain
does not accept as outputs, and it cannot yet spend witness v3 outputs. Use it today
for identities and message signing; keep coins in the node wallet until the standalone
wallet has moved to witness v3. Its offline tests run with
`python3 -m unittest discover -s tests` from `wallet/`; the card-wallet tests need the
`cryptography` package, and two history tests still describe the old wallet and fail
until the wallet moves to witness v3.

The passphrase is typed at a prompt or handed over a pipe with `--passphrase-fd N`.
The wallet refuses to start if it finds a passphrase in an environment variable.

### Your identity

An xCoin identity is a forum handle derived from an ML-DSA-65 key: the SHA-256 of the
public key, written as bech32m under the prefix `xid` with no witness version, 62
characters starting `xid1`. It has no chain prefix, so no node reads it as an address
and nothing can be paid to it. By convention the identity is key index 101 of your
wallet.

[minedifferent.com](https://minedifferent.com) is the forum. There are no passwords:
you sign in with `NerdMiner login`, which asks the wallet to sign a one-time
challenge with the index 101 key (the wallet asks for its passphrase) and opens the
resulting link.

```sh
./NerdMiner login --index 101
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
contrib/regenesis/TESTNET-A.md        the rehearsal runbook: two nodes, a pool, a miner, daily checks
contrib/regenesis/emission.py         prints the emission table and proves it sums to the cap
contrib/regenesis/aserti3_2d_reference.py   independent ASERT reference in exact integer arithmetic
contrib/regenesis/vps/                bootstrap.sh, deploy.sh, pool-install.sh, pool-deploy.sh (Ubuntu 24.04)
xcoin-pool/                           xcoin-pool.py (solo stratum pool), ws-bridge.py (browser bridge), tests
miner/                                NerdMiner 4.1.0: Swift + Metal for macOS, build.sh, NerdMiner login
wallet/                               wallet_cli.py, xcoin-wallet.cpp (keytool), build.sh, install.sh, tests/
explorer/                             xcoin-explorer.py, the explorer behind superknet.com (cookie RPC, tests/)
extension/nerdminer-md/               NerdMiner MD; manifest.json (Chromium), manifest.firefox.json
CHARTER.md                            verbatim copy of contrib/regenesis/CHARTER.md
COPYING                               MIT, from Bitcoin Core
```

Where the numbers live: `src/consensus/params.h` (emission, charter hash, maturity,
output floor, levy), `src/kernel/chainparams.cpp` (P2P ports, prefixes, genesis,
difficulty, MetalDAG sizing), `src/chainparamsbase.cpp` (RPC ports, data directories), `src/consensus/consensus.h` and `src/policy/policy.h`
(block weight, data carrier), `src/script/xcoin_v3.h` (witness v3 rules and budget).

## Consensus at a glance

| Rule | Value |
|---|---|
| Unit | 1 XCF = 100,000,000 sat |
| Supply cap | 21,000,000 XCF exactly; nothing premined, nothing carried in |
| Block reward | 14 XCF per block from block 1, for 750,000 blocks (era 0) |
| Halving | every 750,000 blocks, rounded down to a whole sat; 31 eras; the last subsidy block (23,250,000) pays 1 sat plus the 0.09 XCF rounding remainder, then fees only |
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

The three chains:

| | mainnet | testnet A | regtest |
|---|---|---|---|
| Select | default | `-testnet` | `-regtest` |
| Addresses | `xpa1r…` | `txa1r…` | `nxrt1r…` |
| P2P / RPC port | 9333 / 8332 | 19333 / 19432 | 19444 / 18443 |
| Data subdirectory | (root) | `testneta` | `regtest` |
| Genesis | not mined | `1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9` | local |

Testnet A runs the mainnet rules unchanged, down to the emission table and the DAG
sizing; a unit test in the tree checks that line by line. Only its identity differs.

## Charter

The Charter (`CHARTER.md`, verbatim from `contrib/regenesis/CHARTER.md`) is the text
that defines the currency: its name and units, the 21,000,000 XCF cap, the emission
schedule, what ownership means, how history is kept, how rules may change and what
the chain is for. Software, proof of work and signature algorithms are its current
implementation and may be replaced; sections 1 through 9 of the text may not.

Its SHA-256 is compiled into the node as `CHARTER_HASH` in `src/consensus/params.h`
and written into the genesis coinbase's only output:

```
415b1dbc7ff2cd14b747b300ecd95862540e12305a801bb2bfed8b93c5d84689
```

Check it yourself:

```sh
shasum -a 256 CHARTER.md
build/bin/nex-cli -testnet getcharter
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
python3 -m unittest discover -s tests                   # wallet, from wallet/ (see the note above)
```

Changes to consensus are not made by pull request alone. The Charter's section 7 sets
the process: additions by fork with miner signalling and a published review period;
removals by hard fork with a supermajority of node operators and a migration window of
at least four years. Sections 2 and 4 cannot be changed at all.

Security: if you find a way to mint, to spend what you do not own, to split the chain
or to crash a node from the network, do not open a public issue. Use the repository's
private vulnerability report so the maintainers see it first, and include the exact
commit and the steps to reproduce.

No secrets, anywhere. This tree is written so that no secret is ever placed in an
environment variable: RPC uses the cookie the node writes into its own data
directory; the pool and the explorer read that cookie file; the wallet's passphrase
is typed at a prompt or passed over a pipe; the VPS receives the source as a tarball
over your SSH key and holds no credential. Keep it that way in anything you add, and
never paste a seed, a passphrase or a cookie into an issue, a log or the chat.

## License

MIT. The node inherits Bitcoin Core's license, see [COPYING](COPYING); `miner/` and
`wallet/` carry their own MIT `LICENSE` files.
