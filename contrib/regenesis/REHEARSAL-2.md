# Rehearsal 2 — the genesis dress rehearsal (one Mac, mainnet identity)

The November 1, 2026 mainnet ceremony (REGENESIS.md section 8), performed
once in advance, end to end, on a single Mac. (The ceremony was planned for
September 30, 2026; it moved to November 1 so that node-to-node connections
get hybrid post-quantum encryption first: ML-KEM-768 layered on BIP324,
"HX1", draft XIP-4.) Because mainnet does not exist
yet, the rehearsal runs the REAL mainnet identity — magic `XPA\x03`, port
9333, HRP `xpa`, witness v3 only, `GENESIS_IS_FINAL = true` — in a build
whose genesis constants are local-only and are NEVER pushed. Testnet A is
not involved and keeps running untouched.

What this rehearses: mining block 0 with `xcoin-genesis`, freezing the
constants, rebuilding, two nodes agreeing on the chain, the pool under the
own-node rule (XIP-2), mining block 1's subsidy (6.25 XID, the first row of the <!-- [EMISSION-SHAPE] -->
Annual Tenth), the 1,000-block coinbase
maturity (~3.5 days at 300 s), and the first spend — signed by the node
wallet's v3 path. What it deliberately does not rehearse: multi-host binary
distribution, DNS seeds, and the public announcement.

## 0. Rules

1. **Loopback only.** Every node runs `-bind=127.0.0.1 -natpmp=0 -upnp=0
   -dnsseed=0`. Nothing listens beyond the Mac; there is nobody to talk to
   anyway — that is the point of rehearsing before mainnet exists.
2. **Everything under `$HOME/.xcoin-rehearsal2/` (mode 700).** Datadirs,
   pool stats, logs. Deleted at teardown.
3. **The rehearsal constants never leave the Mac.** `FINAL_GENESIS_*` from
   this run are pasted locally, built locally, and discarded. The real
   constants are mined once, on November 1, from the announced T.
4. The Mac stays awake for the maturity window: mining holds a power
   assertion, but check System Settings › sleep on power adapter.
5. **Its own build directory, `build-rehearsal2`, configured with
   `-DXCOIN_REHEARSAL_BUILD=ON`.** While the emission shape is provisional,
   `xcoin-genesis` refuses a mainnet genesis without `-allowprovisional`, and
   `GENESIS_IS_FINAL = true` compiles only in a rehearsal build
   (`kernel/chainparams.cpp`); while the constants are pasted, an ordinary build
   of the tree fails to compile, which is the point. `nexd` from the rehearsal
   build warns at startup that it is one. Never configure `build/` with the flag,
   and revert the pasted constants in `src/kernel/chainparams.cpp` before anything
   is committed.

## 1. The ceremony, rehearsed

```sh
cmake -B build-rehearsal2 -DXCOIN_REHEARSAL_BUILD=ON     # rule 5: never build/
cmake --build build-rehearsal2 -j8 --target xcoin-genesis
# T = the rehearsal genesis time (unix seconds, announced only to yourself)
build-rehearsal2/bin/xcoin-genesis -time=<T> -threads=8 -allowprovisional
# → prints REHEARSAL ONLY, then FINAL_GENESIS_MESSAGE/TIME/NONCE/BITS/HASH/MERKLE + CURRENCY_ID.
# Paste into src/kernel/chainparams.cpp, set GENESIS_IS_FINAL = true,
# rebuild (build-rehearsal2 only), and prove it:
cmake --build build-rehearsal2 -j8
build-rehearsal2/bin/test_bitcoin -t "regenesis_tests,ml_dsa_kat_tests,xcoin_v3_tests"
```

## 2. Two nodes, one Mac

```sh
mkdir -p -m 700 $HOME/.xcoin-rehearsal2/{node1,node2,pool}
B=$PWD/build-rehearsal2/bin
$B/nexd -server -daemon -datadir=$HOME/.xcoin-rehearsal2/node1 \
  -bind=127.0.0.1 -port=9333 -rpcport=8332 -natpmp=0 -upnp=0 -dnsseed=0 \
  -allowsolomining=1        # until node2 peers; remove after
$B/nexd -server -daemon -datadir=$HOME/.xcoin-rehearsal2/node2 \
  -bind=127.0.0.1:9433 -port=9433 -rpcport=8432 -natpmp=0 -upnp=0 -dnsseed=0 \
  -connect=127.0.0.1:9333
alias r1='$PWD/build-rehearsal2/bin/nex-cli -datadir=$HOME/.xcoin-rehearsal2/node1 -rpcport=8332'
alias r2='$PWD/build-rehearsal2/bin/nex-cli -datadir=$HOME/.xcoin-rehearsal2/node2 -rpcport=8432'
r1 getcharter          # genesis_is_final true, the rehearsal currency_id
r1 getblockhash 0      # must equal r2 getblockhash 0 — two verifiers agree
```

## 3. Payout, pool, miner

```sh
r1 createwallet rehearsal2 && r1 getnewaddress mining   # xpa1r… (witness v3)
XCOIN_RPC_PORT=8332 XCOIN_RPC_COOKIE=$HOME/.xcoin-rehearsal2/node1/.cookie \
XCOIN_ADDRESS_HRP=xpa XCOIN_STRATUM_PORT=3339 XCOIN_NATPMP=0 \
XCOIN_STATS_DIR=$HOME/.xcoin-rehearsal2/pool \
python3 xcoin-pool/xcoin-pool.py 2>&1 | tee -a $HOME/.xcoin-rehearsal2/pool/pool.log
# own-node rule: the pool starts because its node is loopback — XIP-2, rehearsed.
NerdMiner <xpa1r…> --pool 127.0.0.1:3339 --worker rehearsal2 --base <T>
```

Block 1 pays the first row of the emission table (6.25 XID under the <!-- [EMISSION-SHAPE] -->
Annual Tenth) — the first coin of the rehearsal chain, minted by the
same rule as mainnet's first coin. No premine: block 0 pays nothing.

## 4. The wait, and the spend

Watch daily (both tips equal, ASERT settled near 300 s, subsidy 6.25 XID for blocks 1–20,000 under the Annual Tenth): <!-- [EMISSION-SHAPE] -->

```sh
r1 getblockchaininfo | head -6 && r2 getbestblockhash
r1 getbalances        # immature until height ≥ 1001
```

At 1,000 confirmations on block 1, the dress rehearsal's whole point:

```sh
r1 sendtoaddress "$(r1 getnewaddress spend-test)" 1.0
r2 getrawmempool      # the spend relayed to the second verifier
```

A v3 coinbase, matured, spent with a v3 ML-DSA-65 signature, accepted by an
independent node. That is the full life of a coin, rehearsed before any real
coin exists.

## 5. Teardown

Stop both nodes and the pool; `rm -rf $HOME/.xcoin-rehearsal2`; discard the
constants (`git diff src/kernel/chainparams.cpp` shows nothing of them) and
`build-rehearsal2`. Keep: the timing notes, anything that surprised you, and the
corrections they force on REGENESIS.md section 8 before November 1.
