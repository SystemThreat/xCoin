# Running your own node + using xcoin-wallet

This is the operator/user guide: what's in this directory, how to run your own
Xcoin node, and how to drive the wallet against it. If you just want to make a key
and receive coins, you can do that fully offline (no node) — see §3.

## 1. What's in this directory

Everything lives in **`xcoin-wallet/`** (inside the Xcoin source tree):

| File | What it is |
|---|---|
| `xcoin-wallet.cpp` → `xcoin-wallet` | Native keytool: offline key derivation, address, and **offline ML-DSA-65 signing**. No network. |
| `wallet_cli.py` (via `xcoin-wallet-cli`) | Full wallet CLI: balance, utxos, send, history, info — talks to your node's RPC. |
| `card_seed.py` | NTAG 424 DNA hardware-card support (optional). |
| `build.sh` / `install.sh` | Build the native tool / install the CLI to `~/.local/bin`. |
| `tests/` | 78 offline unit tests + integration tests (need a running node). |
| `README.md` | Wallet usage + commands + seed/card security. |
| `PROPOSAL-airgap-and-network.md` | Future: true air-gap, Tor, remote nodes. |
| `RUN-YOUR-OWN-NODE.md` | This file. |

## 2. Build

Requires Xcode Command Line Tools on Apple Silicon, run **inside the Xcoin source
tree** (the native tool builds against the node's own PQClean ML-DSA-65 sources, so
every key/signature is consensus-identical by construction):

```bash
cd xcoin-wallet
NEX=.. ./build.sh          # builds ./xcoin-wallet (native keytool)
./install.sh               # optional: symlinks xcoin-wallet + xcoin-keytool into ~/.local/bin
```

## 3. Make a key / receive coins — no node needed

Key generation, address display, and signing are fully offline:

```bash
./xcoin-wallet new                 # generates + saves your seed (~/.xcoin/wallet.seed)
./xcoin-wallet address             # your receiving address (share this to get paid)
```

That address can receive coins (mining rewards or payments) with **no node running
on your side**. You only need a node when you want to *see* or *spend* those coins.

## 4. Run your own node

The wallet is a full-node client (like `bitcoin-cli` needs `bitcoind`). Point your
miner or your wallet at a node **you** run.

### Config (`~/.xcoin/nex.conf`)

Keep RPC bound to localhost. Never expose it to the internet without the hardening
in §7.

```ini
# mainnet example
server=1
listen=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=CHOOSE_A_USER
rpcpassword=CHOOSE_A_LONG_RANDOM_PASSWORD
# txindex=1        # only if you want full `history` across the chain
```

Start the node (`nexd`), let it sync, then the wallet talks to it over localhost.

### Testnet (what this repo is currently exercised against)

```bash
./xcoin-wallet-cli --config /path/to/testnet/nex.conf --rpc-port 19332 info
```

## 5. Using the wallet against your node

```bash
# handy alias
alias xw='./xcoin-wallet-cli'          # add --config/--rpc-port for testnet

xw info                     # chain height, sync state, peers, mempool
xw address --index 0        # a receiving address (needs the node to derive)
xw balance --index 0        # spendable vs immature (coinbase < 100 confs)
xw utxos --index 0          # per-UTXO maturity countdown
xw history --index 0        # send/receive history
xw send <dest> <amount> --index 0 --dry-run   # build + sign OFFLINE + policy-check, no broadcast
xw send <dest> <amount> --index 0             # the real thing (asks you to type SEND)
```

- **Signing is offline by default** — your seed goes to the local keytool, never to
  the node. There is no node-side signing.
- **Coinbase matures after 100 confirmations.** `balance`/`utxos` show the countdown;
  `send` automatically excludes immature coins. This is the "spendable after 100
  confirmations" rule — mined coins become P2P-spendable cash once 100 blocks are on
  top of them.
- `--json` on any command for scripting.

## 6. Hardware-card wallets

See `README.md` → "Hardware-key wallets". Create with `new --card`, unlock by tapping
the card. Signing is still offline, so the card factor never reaches the node.

## 7. Is it safe to run your own node? (honest answer)

**Running your own node for your own wallet, on your own machine, is the safest
setup** — you validate your own transactions, and offline signing means your seed
never leaves your machine even if the node is remote or compromised. Do this.

**What is NOT safe is exposing your node's RPC to the public internet** casually. RPC
can control the node. If you ever front a node for others (a shared/public RPC):

- Bind RPC to `127.0.0.1` only and reach it through a proxy/tunnel — never bind to
  `0.0.0.0`.
- Use a long random `rpcpassword` and **`-rpcwhitelist`** to allow only the methods
  the wallet needs (scan/build/broadcast/derive/validate/getblock*), nothing that can
  stop or reconfigure the node.
- Put rate-limiting / a WAF in front (`scantxoutset` is heavy and will be abused).
- Understand the privacy trade-off: users of your RPC reveal their addresses to your
  node. Their *seed* stays safe (offline signing); their *privacy* does not.

**Caveat:** this is pre-release software on a young network. Treat mainnet balances as
experimental until the network is publicly established (public peers + seed nodes).

## 8. Getting real coins into a wallet (incl. a card wallet)

A fresh wallet is empty. To hold spendable cash:

1. Point a miner at the wallet's address (`xcoin-wallet address`), or receive a payment
   to it.
2. Mined coinbase becomes spendable after **100 confirmations** (`balance` shows the
   countdown).
3. Then `send` it — offline-signed, and for card wallets, gated by a card tap.

That is the full loop: receive → mature (100 confs) → spend = P2P electronic cash.
