# xcoin-pool

A minimal **solo** Stratum pool for xCoin (XCF). Point a **MetalDAG-capable**
Stratum miner such as NerdMiner at it: when one of your shares meets the network
target you find a block and receive the full block reward at your own `xpa1r…`
address (`txa1r…` on the rehearsal chain). Ordinary Bitcoin SHA-256d ASICs do not
compute MetalDAG and cannot mine xCoin directly. No accounts, no pool fee.

It's a thin bridge to a local xCoin node (getblocktemplate → build work →
submitblock), standard library only.

> Point this pool only at a node of this chain: it builds witness v3 coinbases and
> refuses everything else.

## Addresses: witness v3 only

Worker addresses are **bech32m witness version 3** (REGENESIS.md sections 3 and 4):
the 32-byte program is a Merkle root over algorithm-tagged leaves and the coinbase
pays `OP_3 <root>`.

- Accepted: `xpa1r…` (mainnet), `txa1r…` (rehearsal), and on regtest `nxrt1r…`
  (plus `nxrt1z…`, since regtest still permits witness v2 outputs).
- **Refused: `xpa1z…` / `txa1z…`.** There is no witness v2 output anywhere on
  these chains; paying one would be rejected as `bad-txout-not-pq`. The refusal
  message tells the miner to use a witness v3 address from the node wallet:

  ```
  txa1z59v2c5z…03pnlk is a legacy witness v2 address; this chain accepts only witness v3
  (post-quantum script tree) addresses. Generate one in the node wallet (getnewaddress).
  ```

## The rehearsal pool

The testnet A rehearsal pool runs this program unchanged: stratum on
`172.96.186.49:3335`, paying `txa1r…` addresses, one node behind it (P2P 19333,
RPC 19432), the node's cookie file for RPC and no secret anywhere. Point a
NerdMiner at it with a `txa1r…` address from the node wallet
(`nex-cli -testnet createwallet`, then `getnewaddress`):

```bash
./NerdMiner txa1r… --pool 172.96.186.49:3335 --worker <name>
```

The browser miner at xcoinminer.com reaches the same pool through the
WebSocket bridge below. `contrib/regenesis/vps/pool-install.sh` is the exact
service definition (`xcoin-pool.service` and `xcoin-ws-bridge.service`, both as
an unprivileged user).

## Run your own against the rehearsal chain

With a node of your own on the rehearsal chain (`contrib/regenesis/TESTNET-A.md`,
datadir `$HOME/.xcoin-rehearsal/node`), from your clone of this repository:

```bash
cd $HOME/xCoin
mkdir -p -m 700 $HOME/.xcoin-rehearsal/pool
XCOIN_RPC_PORT=19432 \
XCOIN_RPC_COOKIE=$HOME/.xcoin-rehearsal/node/testneta/.cookie \
XCOIN_ADDRESS_HRP=txa \
XCOIN_STRATUM_PORT=3335 \
XCOIN_NATPMP=0 \
XCOIN_STATS_DIR=$HOME/.xcoin-rehearsal/pool \
python3 xcoin-pool/xcoin-pool.py
```

Always set `XCOIN_STATS_DIR` for a rehearsal pool so its stats and webhook files never share a directory with another pool's.

Then start a NerdMiner with a `txa1r…` address and `--pool 127.0.0.1:3335`.

`XCOIN_NATPMP=0` keeps the stratum port off your router unless you mean to
publish it. `XCOIN_STRATUM_PORT` must not be 3333 (the mainnet default) and
`XCOIN_RPC_PORT` must not be 8332 (the mainnet node's RPC,
`src/chainparamsbase.cpp`) or 9333 (its P2P port).

## The browser miner: `ws-bridge.py`

The pool speaks newline-delimited JSON over plain TCP. A browser can only open
WebSockets, so `ws-bridge.py` accepts a WebSocket and opens one TCP connection to
the pool per client, forwarding text frames as lines and lines as text frames. It
parses nothing, authenticates nothing and keeps no state; standard library only,
like the pool.

```bash
python3 xcoin-pool/ws-bridge.py --listen 127.0.0.1:3336 --pool 127.0.0.1:3335 \
  --origin https://xcoinminer.com --origin https://www.xcoinminer.com
```

`--origin` (repeatable; or `XCOIN_WS_ORIGINS`, comma-separated) is an allowlist
of browser origins; with none given any origin is accepted. `XCOIN_WS_LISTEN` and
`XCOIN_WS_POOL` are the environment forms of the two addresses. The bridge
listens on loopback and is published by a TLS terminator in front of it (the
rehearsal uses a tunnel ingress pointing at `http://127.0.0.1:3336`, reached as
`wss://superknet.com/stratum`). A plain HTTP `GET /` answers
`xcoin stratum websocket ok`, which is what the tunnel's health check and
`pool-install.sh` look for.

## Numbered browser sessions

A miner that names itself (`txa1r….rig1`) is registered under that name. A browser
tab uses the site's default worker name (`web` or `web-solo`), and the pool turns
every such session into its own numbered rig: `web-solo-00001`, `web-solo-00002`,
… The counter lives in `XCOIN_STATS_DIR/web_session_seq.txt`, survives restarts and
never repeats, so two tabs (or one tab opened twice) are two rigs on the explorer
instead of one merged entry. After `mining.authorize` the pool tells the miner the
name it is registered under with a `client.show_message` notice
(`registered as web-solo-00042`); a miner that ignores the notice loses nothing.

## Run it against mainnet (once mainnet exists)

```bash
export XCOIN_RPC_COOKIE=<datadir>/.cookie      # the node writes it on every start; mainnet datadir root
# defaults: RPC 127.0.0.1:8332, stratum 0.0.0.0:3333, xpa addresses
python3 xcoin-pool.py
```

On mainnet the node serves `getblocktemplate` only while it has at least one peer
and is not in initial block download; otherwise the RPC fails with `-9 ... is not
connected!` or `-10 ... is in initial sync`, the pool logs `RPC getblocktemplate
error` and keeps polling. For a **single-node launch** (mining block 1 before a
second node is peered) or an isolated rehearsal start the node with
`-allowsolomining=1`; it prints a startup warning, and the flag must be removed
once the node has peers. The rehearsal chain (`-testnet`) and regtest are exempt
from the gate, as upstream, and never need it.

## What it handles

- Builds the coinbase paying your `xpa1r…` / `txa1r…` address as `OP_3 <root>`,
  and refuses to build a witness v2 payout on any chain but regtest.
- Every height, block 1 included, is built the same way: nothing is carried in.
- Keeps the coinbase scriptSig inside the consensus 2..100 bytes (`bad-cb-length`)
  and writes exactly one `OP_RETURN` of its own, the 38-byte witness commitment.
- Proper segwit coinbase (witness commitment + reserved value), correct merkle and
  header assembly, and `submitblock` on a network-target solve.
- Vardiff-friendly share target that never rejects a real block on the easy-start
  difficulty.

## Fees and the settlement levy

The pool is **solo and coinbase-only**: it pays the miner the template's whole
`coinbasevalue` (subsidy for the height's emission era **plus** the fees the node
collected) and keeps nothing.

It builds **no non-coinbase transaction**. The chain ships with no settlement
levy (REGENESIS.md section 6: the genesis schedule row is zero rate, zero cap; a
later soft fork can switch one on). If a payout path is ever added here it must
floor its fee at `payout_fee_floor_sats(total_in)` = `max(byte floor,
levy_from_inputs(total_in))`, which under the genesis rule is the byte floor and
under an activated levy is the levy; a transaction paying less than an active
levy is `bad-txns-levy` and cannot be mined at all. `test_coinbase.py::LevyTests` pins those numbers against
`src/consensus/levy.h` and fails if the pool ever grows a transaction-building
RPC call.

## Environment

| Var | Default | Meaning |
|---|---|---|
| `XCOIN_RPC_HOST` / `XCOIN_RPC_PORT` | `127.0.0.1` / `8332` | node JSON-RPC, mainnet's port per `src/chainparamsbase.cpp` (rehearsal: `19432`) |
| `XCOIN_RPC_COOKIE` | — (preferred) | path of the node's cookie file, `<datadir>/<chain>/.cookie`; no password exists anywhere |
| `XCOIN_RPC_USER` / `XCOIN_RPC_PASSWORD` | — (fallback) | a secret in the environment; the pool warns (see `contrib/regenesis/WALLET-SECRETS.md`) |
| `XCOIN_STRATUM_HOST` / `XCOIN_STRATUM_PORT` | `0.0.0.0` / `3333` | where miners connect (use another port for the rehearsal chain) |
| `XCOIN_ADDRESS_HRP` | `xpa` | address prefix: `xpa` mainnet, `txa` rehearsal, `nxrt` regtest |
| `XCOIN_NATPMP` | `1` | `0` disables the NAT-PMP port forward (use `0` on the rehearsal chain) |
| `XCOIN_START_DIFF` | `0.05` | initial share difficulty, sized for an Apple Silicon GPU; shares faster than 5/s double it at once, then EWMA vardiff takes over (set 0.001 for a CPU-only rehearsal) |
| `XCOIN_VARDIFF_TARGET` | `15` | desired seconds per accepted share |
| `XCOIN_VARDIFF_INTERVAL` | `60` | minimum seconds between retunes |
| `XCOIN_VARDIFF_MIN` | `0.000001` | minimum share difficulty |
| `XCOIN_VARDIFF_MAX` | `1000000` | maximum share difficulty |
| `XCOIN_STATS_DIR` | `~/.xcoin` | miner/rig registry and stats files |
| `XCOIN_POLL_SECS` | `3` | template poll interval |
| `XCOIN_EXPLORER_URL` | `https://superknet.com` | explorer the block-found notice links a found block to |
| `XCOIN_WS_LISTEN` / `XCOIN_WS_POOL` / `XCOIN_WS_ORIGINS` | `127.0.0.1:3336` / `127.0.0.1:3335` / any | `ws-bridge.py` only: listen address, pool address, comma-separated origin allowlist |

## Tests

```bash
python3 xcoin-pool/test_coinbase.py -v
python3 xcoin-pool/test_ws_bridge.py -v
```

`test_coinbase.py` (56 tests): address decoding and refusal, the `OP_3 <root>` coinbase,
the scriptSig and data-carrier limits, the stratum authorize path end to end, the numbered
browser sessions, submit input validation (malformed hex, extranonce2 length), user-agent
sanitization, the RPC cookie credential, and the levy arithmetic including the cap.
`test_ws_bridge.py` (4 tests): the WebSocket handshake and round trip against a fake pool,
large and fragmented frames, the origin allowlist and the plain HTTP probe, and the close
code when the pool is down.

## Notes

- This is **solo** mining: you compete for whole blocks; there is no reward sharing.
- **AuxPoW merge-mining is not active.** It is a future consensus upgrade and
  must not be advertised as launch functionality.

## The address prefix is checked against the node

The pool reads `getblockchaininfo` at startup and refuses to run when `XCOIN_ADDRESS_HRP` contradicts the chain the node reports (main uses `xpa`, the rehearsal chain `txa`, regtest `nxrt`). A witness v2 payout is legal only on regtest, so a wrong prefix could otherwise have the pool paying an output type the chain rejects.
