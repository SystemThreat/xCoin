# Proposal: true air-gap signing + network access (incl. Tor) for xcoin-wallet

Status: **proposal / near-future.** Nothing here is implemented yet except where
noted as DONE. This documents the intended direction and answers a recurring
question: *can anyone, from anywhere on a public network (or Tor), use this wallet
on mainnet?*

---

## 1. Where we are today (accurate baseline)

- **Offline signing — DONE.** `send` signs in the native `xcoin-wallet` keytool on
  the local machine. The seed (and, for card wallets, the card factor behind it)
  goes to the keytool over a pipe and **never reaches the node**. Verified
  byte-for-byte against consensus (BIP143 sighash + txid match).
- **The wallet still needs a node** for everything else, over **localhost RPC**:
  `scantxoutset` (balance/UTXOs), `createrawtransaction`,
  `validateaddress`, `testmempoolaccept`, `sendrawtransaction`.
- So today's model is **"self-hosted node on the same machine."** `send` does
  scan → build → sign(offline) → broadcast all in one process on one host.
- There is **no light/SPV mode**: the wallet relies on a fully-synced node's UTXO
  set (`scantxoutset`). No secret ever leaves the machine, but the *machine* is
  online while it signs.

The gap: signing is offline *in software*, but it still happens on a networked
computer. A true air gap puts the seed/cards on a machine that is **never
networked at all**.

---

## 2. Proposed air-gap workflow (split the one command into three)

Split `send` into an online "prepare", an offline "sign", and an online
"broadcast". The data that crosses the gap contains **no secrets** — it is public
transaction data either way.

| Command | Runs on | Secrets? | Does |
|---|---|---|---|
| `prepare <dest> <amt> [--index N] --out bundle.json` | ONLINE (has node) | no | scan, coin-select, fee, build the **unsigned tx + prevouts** → write bundle |
| `sign-bundle bundle.json --out signed.txt` | OFFLINE (cold, holds seed/cards) | **yes, locally only** | unlock (card/passphrase), verify amounts, sign via keytool → signed hex. **No network.** |
| `broadcast signed.txt` | ONLINE (has node) | no | `testmempoolaccept` + `sendrawtransaction` |

- The **bundle** is just: unsigned raw tx, and for each input `{txid, vout,
  scriptPubKey, amount, keyindex}`. All public. Safe to move by USB, QR, or file.
- The **signed output** is the final tx hex. Also public.
- `send` stays as the convenient all-in-one for hot use; the three-step flow is
  the air-gap path.

### Critical security rule for the offline signer

The cold machine **must independently show what it is signing** — destination
address, amount, fee, change — parsed from the bundle, and require confirmation.
Otherwise a compromised online machine could hand the cold signer a bundle that
pays an attacker. The keytool already decodes the tx; `sign-bundle` must print
`To / Amount / Fee / Change` and prompt before signing. This is the whole point
of an air gap and is non-negotiable.

### Watch-only on the online machine (no keys needed)

PQ addresses have no BIP32 xpub, but **addresses are public**: derive them once on
the cold machine and export a plain list.

- `export-watch --count N --out watch.txt` (offline) → the `scriptPubKey`/address
  list for indices `0..N`.
- The online machine scans those scripts with `scantxoutset` — full balance/UTXO
  visibility with **zero key material online**. `prepare` uses this list.

### QR transport (optional, later)

A signed PQ tx is ~5.4 KB — too big for one QR. Propose animated/multi-frame QR
(e.g. chunked with an index header) for both bundle and signed hex, so a
truly-offline laptop with only a camera/screen can round-trip without USB.

---

## 3. Can anyone, from anywhere, use this on mainnet? (the network question)

**Short answer:** architecturally yes — but *how* determines privacy, and mainnet
must first have a real public P2P network (see §5). The seed never leaves the
user's machine in any model, because signing is offline.

### Model A — run your own full node (recommended)

Run `nexd` anywhere — home, laptop, a VPS. The wallet talks to it over
`localhost`. This works **from any location or network**, as long as *your node*
can reach mainnet peers. This is the honest answer to "anyone from anywhere": yes,
if they run a node. Best privacy and trust (you validate your own transactions).

### Model B — point the wallet at a remote/shared node

The wallet already supports `--rpc-host/--rpc-port/--rpc-user/--rpc-password`, so
it can talk to someone else's node from any network.

- **Safe:** the seed still never goes to the remote node — offline signing means
  the node only ever sees the *unsigned* tx (public) and the *signed* tx to
  broadcast (public).
- **Trade-off:** the remote node **sees your addresses** (you send it
  `scantxoutset` queries) and your broadcasts, so it can log or censor you. Lower
  privacy than Model A. Fine for convenience, not for anonymity.

### Model C — light/SPV client

Does not exist. Would need a light-client protocol so the wallet doesn't need a
full node. Out of near-term scope; noted for completeness.

### Tor / onion network

Two independent layers — keep them separate:

1. **Node-level Tor (the important one, and it's node config, not wallet code).**
   `nexd` is Bitcoin-Core-derived and supports Tor: set `proxy=127.0.0.1:9050`,
   `onlynet=onion`, and optionally run the node as a hidden service. Then **all
   P2P traffic — peer connections and, crucially, transaction broadcast — goes
   over Tor**, hiding your IP from the network when you send. The wallet still
   talks to your node over `localhost`; nothing in the wallet changes. This is the
   main anonymity win and is available the moment the node is Tor-configured.

2. **Reaching a *remote* node's RPC over Tor (wallet change needed).** To use
   Model B privately — e.g. reach *your own* home node from anywhere via its onion
   address — the wallet's RPC client (currently plain `urllib`) needs **SOCKS5
   proxy support**. Proposed: a `--tor` / `--socks5 host:port` flag that routes RPC
   over Tor so you can point `--rpc-host <...>.onion`. Note: exposing a node's RPC
   over an onion service is powerful but must be locked down (RPC auth, `rpcallowip`,
   ideally a dedicated onion) — RPC is not a public API.

**Net:** from any public network, with Tor at the node level, a user can operate
on mainnet without revealing their IP, and (with the proposed SOCKS flag) reach
their own node's onion RPC from anywhere. The keys stay on their cold machine
throughout.

---

## 4. Proposed commands summary

```
# online (node host)
xcoin-wallet prepare <dest> <amount> [--index N] [--fee/--feerate] --out bundle.json
xcoin-wallet broadcast signed.txt

# offline (cold machine with seed / cards) — NO network
xcoin-wallet sign-bundle bundle.json --out signed.txt      # shows To/Amount/Fee, confirms
xcoin-wallet export-watch --count N --out watch.txt

# later
--qr on prepare/sign-bundle           # animated QR transport
--socks5 host:port  /  --tor          # route RPC over Tor for remote/onion nodes
```

All of the underlying pieces already exist: coin selection, fee estimation, the
offline keytool signer, and tx decode. `prepare`/`sign-bundle`/`broadcast` are a
refactor of `cmd_send` into three phases with a bundle file between them — no new
crypto.

---

## 5. Prerequisite: mainnet must actually be a public network

"Anyone from anywhere" presumes a reachable mainnet P2P network. Today the Xcoin
mainnet is effectively single-node / LAN. Before this proposal is meaningful on
mainnet, the network needs:

- **Public P2P**: reachable nodes with `listen=1`, port-forwarding or hosting.
- **Seed nodes / DNS seeds** so new nodes can find peers.
- **Onion seeds** (and a few Tor-reachable nodes) for Tor-only users.
- A minimum-chain-work / checkpoint before wide launch.

These are network-deployment tasks, not wallet code, and gate the "from any public
network" answer. The wallet work in §2–§4 can proceed in parallel and is ready to
use the moment the network is public.

---

## 6. Suggested order of work

1. **`prepare` / `sign-bundle` / `broadcast` split** + the offline confirm prompt
   (the core air gap). Reuses existing code; highest value.
2. **`export-watch`** so the online machine holds zero key material.
3. **`--socks5`/`--tor` RPC** for private remote/onion node access.
4. **QR transport** for camera-only air gaps.
5. (Network side, separate track) **public mainnet P2P + seed/onion nodes.**

Non-goal for now: light/SPV client.
