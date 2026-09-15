# xcoin-explorer

The block explorer behind superknet.com: witness v3 outputs, `xpa1r` / `txa1r`
addresses, the exact fee of every transaction and the charter commitment, all
read from the node. One Python file, no framework, no node-side index.

It serves the **testnet A rehearsal** today (label "Rehearsal chain", addresses
`txa1r…`, RPC 19432). Mainnet genesis is not mined; when it is, the same file
serves mainnet (`xpa1r…`, RPC 8332) by RPC port.

## Run it

The default is the rehearsal chain (RPC 19432) on explorer port **3101**. Ports
3001, 3333, 9333 and 9432 are reserved by other services and the program refuses
to bind or dial them.

```sh
cd explorer
export XCOIN_RPC_COOKIE=$HOME/.xcoin-rehearsal/node/testneta/.cookie

# the rehearsal chain, the default
XCOIN_EXPLORER_PORT=3101 python3 xcoin-explorer.py
# -> http://127.0.0.1:3101/

# any other spare port works the same way
XCOIN_EXPLORER_PORT=3105 python3 xcoin-explorer.py

# mainnet, by RPC port, once its genesis is mined
XCOIN_RPC_PORT=8332 XCOIN_EXPLORER_PORT=3101 python3 xcoin-explorer.py
```

It binds `127.0.0.1` unless `XCOIN_EXPLORER_BIND` says otherwise, authenticates
with the node's cookie file (no password in the environment), and refuses to run
against a node with no `getcharter` RPC.

### Chain selector

`XCOIN_CHAIN` picks a profile and `XCOIN_RPC_PORT` overrides its port; the port
then names the chain. The node's own `getblockchaininfo` confirms it at start-up
and sets the address prefix, so a mislabelled port cannot make the explorer print
`xpa1r` strings for a `txa1r` chain.

| Chain       | RPC port | Addresses | Notes                                     |
|-------------|----------|-----------|-------------------------------------------|
| `rehearsal` | 19432    | `txa1r…`  | testnet A, the default; second node 19434 |
| `mainnet`   | 8332     | `xpa1r…`  | once its genesis is mined                 |

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `XCOIN_CHAIN` | `rehearsal` | `rehearsal` or `mainnet` |
| `XCOIN_RPC_PORT` | from the chain | 19432 / 8332 |
| `XCOIN_RPC_HOST` | `127.0.0.1` | |
| `XCOIN_RPC_COOKIE` | — | the node's `.cookie` file (preferred) |
| `XCOIN_RPC_USER` / `XCOIN_RPC_PASSWORD` | — | fallback for local runs only |
| `XCOIN_EXPLORER_PORT` | `3101` | 3001, 3333, 9333, 9432 refused |
| `XCOIN_EXPLORER_BIND` | `127.0.0.1` | |
| `XCOIN_EXPLORER_URL` | `http://localhost:<port>` | canonical / og base URL |
| `XCOIN_ADDRESS_HRP` | from the node | `txa` / `xpa` |
| `XCOIN_MAX_SUPPLY` | `21000000` | the cap the supply card is measured against |
| `XCOIN_LEVY_BP` | `0` | settlement levy in basis points; the chain's rule is 0 |
| `XCOIN_ADDNODE` | chain default | the peer line the home page suggests |
| `XCOIN_STATS_DIR` | `./pool` | the pool's stats directory |
| `XCOIN_WEB_POOL_STATS` | empty | the browser pool's `/stats` URL |
| `XCOIN_EXPLORER_PUBLIC` | off | enables the analytics tag and the chat embed |

## What it shows

Sources of truth, all read-only: `xcoin-regenesis/contrib/regenesis/REGENESIS.md`
sections 3, 4 and 6; `src/script/xcoin_v3.h`; `contrib/regenesis/carry_v3_vector.json`.
The Python mirrors `wallet-cli-regenesis/wallet_cli.py` and NerdMiner's
`nerdminer-regenesis/XcoinAddress.swift`.

- **Witness v3 everywhere.** `OP_3 <32-byte Merkle root>` is decoded from the
  script when the node does not name the address, so block pages, address pages,
  the rich list and the search box all speak `xpa1r` / `txa1r`. Spends are decoded
  too: the control block gives the leaf version (ML-DSA-65 `0xc0`, SLH-DSA `0xc2`)
  and the depth of the path the spender revealed.
- **A witness v2 string is mapped, not paid.** An `xpa1z` / `txa1z` string names
  a bare ML-DSA-65 key hash and is not payable on this chain. It gets its own
  page — the key hash, the two scripts, and the single-leaf witness v3 address of
  the SAME key — and the search box redirects there with `?from=` so the address
  page repeats the note. A mainnet string on the rehearsal chain also names this
  chain's address.
- **The fee, exact.** Every transaction view shows the fee paid, from the
  explorer's own UTXO set (`sum(inputs) − sum(outputs)`), block pages total it and
  the mempool lists it. The settlement levy is **0 bp on every chain**, so no levy
  figure, pill, row or column renders; `/api/stats` reports `levy_bp: 0`. Setting
  `XCOIN_LEVY_BP` for a test chain brings the levy rows back (`ceil(bp × outputs /
  10,000)` satoshis, with a `levy met` / `below the levy` verdict).
- **The network panel** shows `charter_hash`, `currency_id`, the genesis and
  `genesis_is_final` from `getcharter`, the proof of work (MetalDAG, 300 s
  blocks, coinbase maturity 1,000 blocks), the subsidy rule and the output rule.
  `/api/charter` returns the charter, and `/api/stats` carries it.
- **The block reward card** reads the era subsidy at the tip from the chain
  (`getblockstats`): 14 XCF in era 0, halving every 750,000 blocks, 21,000,000 XCF
  cap. No premine.
- **A rich list** at `/richlist`, built from the explorer's own scan of every block
  (it owns the UTXO set, which is also where exact input values, and so fees, come
  from — no node-side `txindex` needed).
- **The front page** names the chain it serves (the testnet A rehearsal; mainnet
  genesis is not mined), the Testnet badge follows the chain, and the pool's rigs,
  the latest blocks and the top miners are all chain truth.
- **Isolation.** Analytics and the forum chat embed are off unless
  `XCOIN_EXPLORER_PUBLIC=1`, so a local run cannot pollute the live site's numbers.

The unit is **XCF** on every page. Function names such as `sats_xat()` and the
cross-site tab script's `XATInstance` global are code names and never render.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

- `tests/test_v3_addresses.py` pins the founder's conversion vector
  (`xpa1z59v2c5z…` → `xpa1rt682c5q…` on mainnet, `txa1rt682c5q…` on the rehearsal
  chain), the node's leaf and branch hashes, the levy arithmetic at an explicit
  5 bp, bech32m and the witness decoder, and recomputes every case in
  `carry_v3_vector.json` when that file is present.
- `tests/test_render.py` renders every page against a stub rehearsal chain
  (14 XCF coinbases, one spend, one pending transaction) and checks what each one
  says: XCF and never the old ticker, no levy text at the chain's 0 bp rule, and
  the levy rows back under a 5 bp override.
