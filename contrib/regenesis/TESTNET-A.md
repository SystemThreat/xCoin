# The rehearsal chain — the founder's runbook

The rehearsal is the consensus rules exactly as mainnet will run them, on a private chain with its own
identity: `-testnet` / `-chain=test` on the `regenesis` branch (the code calls it "testnet A"; the chain
type is `TESTNET`). It is **private**: run it between your own two nodes, your pool and your own miner.
It is not announced, it has no seeds, and it is never called a public testnet. Coins on it have no value.

REGENESIS.md section 9 requires **at least three quiet days** of it, with both nodes, the pool and the
miner, before mainnet genesis. Start it and leave it alone; the point is the days, not the blocks.

The binaries are `build/bin/nexd`, `nex-cli`, `test_bitcoin` and `xcoin-genesis` of this worktree.

---

## 0. Three rules, before anything else

1. **Its own ports.** The rehearsal uses 19333 (P2P) and 19432 (RPC) for the node and 3335 for the
   pool, and nothing else. Never point it at another node's ports.
2. **`-natpmp=0 -upnp=0` on every node command line.** The rehearsal must not open a router mapping.
   Both flags are in every block below; if you retype a command, keep them.
3. **Everything under `$HOME/.xcoin-rehearsal/` (mode 700).** The node's datadir, the pool's stats
   directory and the pool's log live there, never under `build/`, which gets deleted. `XCOIN_STATS_DIR`
   is on every pool command line so a rehearsal pool can never write into another pool's directory.

---

## 1. Identity

| | rehearsal chain | mainnet (for comparison) |
|---|---|---|
| Select | `-testnet` (or `-chain=test`) | default |
| Magic | `'X','T','A',0x02` | `'X','P','A',0x03` |
| P2P port | 19333 | 9333 |
| RPC port | 19432 | 8332 |
| Data dir | `<datadir>/testneta` | `<datadir>` |
| bech32 HRP | `txa`, witness v3 only: addresses read `txa1r…`; a `txa1z…` string is refused | `xpa` (`xpa1r…`) |
| Seeds | `testnet.superknet.com` (node two; `-addnode` / `-connect` also work) | five hostnames, DNS records still to be created |
| Genesis hash | `1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9` | not mined yet (`GENESIS_IS_FINAL = false`) |
| Genesis time | `1789379971` = 2026-09-14 09:59:31 UTC (also `metaldagBaseTime`) | TBD |
| Genesis nonce / bits | `166982` / `0x1e0fffff` | TBD |
| Genesis merkle root | `b49ffb666442033ee8908bd83f4e458e1ccafcb620f844acff6b7dbde727d0f8` | TBD |
| MetalDAG PoW hash of the genesis | `000003ae512afefde0e58261f26308e2822b3f73f1beb8e67ff448d12c8c78e8` | TBD |
| Coinbase message | `xCoin testnet A - 2026-09-14 - 2,100,000,000,000,000 sats, 21M XCF` | `Hic experimentum prosperat II - <date> - 21,000,000 XCF - charter <first 16 hex of CHARTER_HASH>` |
| Charter output | `OP_RETURN "XCOIN/charter/1" ‖ CHARTER_HASH`, the coinbase's only output, value 0 | same |
| CHARTER_HASH | `415b1dbc7ff2cd14b747b300ecd95862540e12305a801bb2bfed8b93c5d84689` | same |
| CURRENCY_ID (`getcharter`) | `fb9c965c9b2c61d9f1f3471d96a775f764389142b838f63c183913b38b71029e` | TBD |
| `genesis_is_final` | `true` | `false` |
| Block 1 | an ordinary block: 14 XCF plus fees to whoever mines it. Nothing is carried in, no premine, nothing inscribed | same |
| Witness v2 outputs | none, and none can be created: `bad-txout-not-pq` after the genesis block | same |
| Coinbase maturity | 1,000 blocks (~3.5 days at 300 s) | same |
| Settlement levy | none at genesis: zero rate, zero cap (machinery dormant; a later soft fork can switch it on) | same |
| Output value floor | 10,000 sat; a coinbase with exactly one spendable output is exempt (any value from 1 sat), so every era's subsidy stays mintable | same |
| Checkpoint signers | none; only release checkpoints exist | same |

Consensus that is identical to mainnet (the unit test `regenesis_testnet_a_tests/testnet_a_rules_are_mainnet_rules`
proves each line): the emission table (14 XCF per block from height 1, halved every 750,000 blocks in
whole satoshis, 31 eras, closing remainder on the last subsidy block), the 8,000-byte data-carrier
budget per block, 4,000,000 WU blocks, 300 s target spacing, anchored ASERT with a 2 h half-life from
block 1, no min-difficulty blocks, `powLimit` `0x1e0fffff`, MetalDAG at the mainnet sizing (4 GiB
launch DAG, +128 MiB per 14-day epoch, cache = DAG/128) with epoch 0 starting at the rehearsal genesis
time, the settlement levy schedule, coinbase maturity 1,000 and the multi-algorithm header bits (must
be 0).

MetalDAG note: the epoch seed depends only on the epoch number, so the rehearsal chain's epoch-0 DAG is
byte for byte mainnet's epoch-0 DAG. Epoch 1 begins 14 days after the genesis time.

---

## 2. Build (once, on each machine)

```sh
cd $HOME/xCoin                               # your clone of this repository
cmake -B build -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF   # once; BUILD_TESTS stays on for test_bitcoin
cmake --build build -j8 --target bitcoind bitcoin-cli test_bitcoin xcoin-genesis
build/bin/test_bitcoin -t 'regenesis_testnet_a_tests'
```

On the VPS: the same commit, the same configure; only `bitcoind` and `bitcoin-cli` are needed there.
The binaries are named `nexd` and `nex-cli`. The package list for Ubuntu 24.04 is the one CI installs
(`.github/workflows/build.yml`).

---

## 3. Step 1 — node 1, the Mac

```sh
cd $HOME/xCoin && \
mkdir -p -m 700 $HOME/.xcoin-rehearsal/node && \
build/bin/nexd -testnet -server -listen -daemon -natpmp=0 -upnp=0 \
  -datadir=$HOME/.xcoin-rehearsal/node \
  -port=19333 -rpcport=19432
```

No RPC password exists anywhere in the rehearsal. The node writes `$HOME/.xcoin-rehearsal/node/testneta/.cookie`
(mode 600, owner only) on every start and deletes it on shutdown; `nex-cli` reads it from the same `-datadir`, and the
pool reads it through `XCOIN_RPC_COOKIE`. Environment variables carry paths and ports only, never a secret
(`contrib/regenesis/WALLET-SECRETS.md`).

Then check it, and keep this alias for the rest of the rehearsal:

```sh
alias rcli='$HOME/xCoin/build/bin/nex-cli -testnet -datadir=$HOME/.xcoin-rehearsal/node -rpcport=19432'
rcli getblockchaininfo | head -5      # chain "test"
rcli getblockhash 0                   # 1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9
rcli getcharter                       # genesis_is_final true, currency_id fb9c965c…029e
```

Add `-addnode=<VPS-ip>:19333` to dial the VPS from here (then no port needs opening on your router), or
open TCP 19333 on the router and let the VPS dial in. Either way `-natpmp=0 -upnp=0` stays.

---

## 4. Step 2 — node 2, the VPS

```sh
mkdir -p -m 700 $HOME/.xcoin-rehearsal/node && \
nexd -testnet -server -listen -daemon -natpmp=0 -upnp=0 \
  -datadir=$HOME/.xcoin-rehearsal/node -port=19333 -rpcport=19432 \
  -addnode=<Mac-public-ip-or-DDNS>:19333
```

```sh
alias rcli='nex-cli -testnet -datadir=$HOME/.xcoin-rehearsal/node -rpcport=19432'
rcli getblockhash 0        # must print 1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9
rcli getconnectioncount    # 1 once either side reaches the other
```

Open TCP 19333 on the VPS firewall (`ufw allow 19333/tcp`) so the Mac can dial in; then on the Mac
`rcli addnode "<VPS-ip>:19333" onetry` if it has not connected yet. Either side can add the other
later over RPC: `rcli addnode "<host>:19333" add`.

Two nodes on one machine prove relay and agreement, not independence; the VPS is what makes the
rehearsal a two-machine test, so bring it in on day 1.

---

## 5. Step 3 — the pool

```sh
cd $HOME/xCoin && \
mkdir -p -m 700 $HOME/.xcoin-rehearsal/pool && \
XCOIN_RPC_PORT=19432 XCOIN_RPC_COOKIE=$HOME/.xcoin-rehearsal/node/testneta/.cookie \
XCOIN_ADDRESS_HRP=txa XCOIN_STRATUM_PORT=3335 XCOIN_NATPMP=0 \
XCOIN_STATS_DIR=$HOME/.xcoin-rehearsal/pool \
python3 xcoin-pool/xcoin-pool.py 2>&1 | tee -a $HOME/.xcoin-rehearsal/pool/pool.log
```

`XCOIN_NATPMP=0` keeps 3335 off the router. The pool refuses to start if `XCOIN_ADDRESS_HRP`
contradicts the chain the node reports, so a copy-paste that points it at the wrong node stops rather
than mining the wrong rules. Every block, block 1 included, pays `OP_3 <root>` of the worker's
`txa1r…` address the whole reward.

---

## 6. Step 4 — the miner

Make the payout address in the node wallet first; the pool pays only witness v3 addresses:

```sh
rcli createwallet rehearsal
rcli getnewaddress mining        # txa1r…
```

Then point the miner at the pool with that address as the stratum user, worker name after a dot:

```sh
<miner> txa1r…  --pool 127.0.0.1:3335 --worker rehearsal1
```

Block 1 at `powLimit` is about 2^20 MetalDAG hashes: under a second for a GPU miner, about five hours
for a single CPU thread. Watch the pool log for `BLOCK FOUND` and then run the day-1 checks in section 7.

A `txa1z…` or `xpa1z…` string is refused by the pool: this chain has no witness v2 output.

---

## 7. What to look at each day

One block, pasted daily on the Mac (add the same on the VPS for the two-node view):

```sh
echo "=== $(date -u) ==="; \
rcli getblockchaininfo | grep -E '"chain"|"blocks"|"bestblockhash"|"difficulty"'; \
rcli getconnectioncount; \
rcli getcharter; \
rcli getmininginfo | grep -E '"blocks"|"difficulty"|"networkhashps"'; \
rcli gettxoutsetinfo | grep -E '"height"|"txouts"|"total_amount"'; \
tail -3 $HOME/.xcoin-rehearsal/node/testneta/debug.log
```

**Day 1 — that it started right.** Both nodes on `1dc4131e…ccb9`; `getconnectioncount` ≥ 1 on both;
`getcharter` reporting `currency_id fb9c965c…029e` and `genesis_is_final true`; block 1 in, paying
**14.00000000 XCF** to your address and nothing else:

```sh
rcli getblock $(rcli getblockhash 1) 2 | python3 -c "
import json,sys; print([(o['value'], o['scriptPubKey'].get('address')) for o in json.load(sys.stdin)['tx'][0]['vout']])"
```

**Day 2 — that it keeps going.** The height rising on both nodes and the two `bestblockhash` values
equal; every block paying 14 XCF plus fees; `getdifficulty` moving as ASERT reacts to the block rate;
`~/.xcoin-rehearsal/pool/pool_stats.json` moving; the miner showing accepted shares.

**Day 4 or later — that the money moves.** A coinbase matures after 1,000 blocks, about 3.5 days at
300 s, so the first spendable coin appears on day 4. Send one transaction through the node's wallet
and watch the fee being set by the relay floor and the estimator alone (no levy is charged on
this chain; the fee is the byte-rate fee):

```sh
rcli getbalances                          # "trusted" > 0 once block 1's coinbase has matured
rcli sendtoaddress $(rcli getnewaddress savings) 1.5
```

Anything that stops the chain, forks it, or makes a node refuse a block its peer accepted is a
**no-go for genesis** and goes in the cutover checklist as a finding.

---

## 8. Stopping, restarting, wiping

```sh
rcli stop                                     # each node; the pool and the miner take Ctrl-C
```

Restart with the same block in section 3: the chain is in the datadir and survives. **Wipe only if you
mean to start the chain over**, which costs you the whole rehearsal:

```sh
rm -rf $HOME/.xcoin-rehearsal/node/testneta      # each machine
```

Any `testneta` directory from before the current genesis (`1dc4131e…ccb9`) holds a different chain and
must be deleted, not reused.

---

## 9. Troubleshooting

| symptom | cause and fix |
|---|---|
| `getblockhash 0` does not print `1dc4131e…ccb9` | A datadir from an earlier genesis. Delete `testneta` in it (section 8) and restart. |
| The pool exits: `Address HRP … contradicts the node's chain` | `XCOIN_ADDRESS_HRP` and `XCOIN_RPC_PORT` disagree. On the rehearsal chain they are `txa` and `19432`. |
| The pool exits: `XCOIN_RPC_COOKIE=…: no such file` | The node is not running, or runs on another `-datadir`. Start it first (section 3); the cookie appears on every start. |
| The miner is refused with a `witness v2` message | Use a `txa1r…` address from the node wallet (section 6). |
| `getbalances` shows everything under `immature` | Coinbase maturity is 1,000 blocks; nothing mined is spendable before that. Expected until day 4. |
| The two nodes are at different tips | Check `getpeerinfo` on both and `getchaintips`; a fork on the rehearsal chain is a finding, not a nuisance — record it. |
