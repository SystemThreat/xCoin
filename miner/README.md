# NerdMiner 4.1.0 — MetalDAG miner + sign in with your xCoin identity

A MetalDAG stratum miner for Apple Silicon Macs (Swift + Metal). Build it with `./build.sh` (Xcode Command Line
Tools); the binary is `./NerdMiner`, and `MacMetalCLI` is a compatibility symlink to it for older scripts.

## What's new in 4.1.0

`NerdMiner login` — log in to **MineDifferent** (the xCoin forum) with your xCoin identity (`xid1…`) by signing a
challenge with your wallet's ML-DSA-65 key. No password exists anywhere. The miner never sees a key: it shells out
to the xCoin wallet CLI, which does the unlock (a passphrase typed at the terminal or handed over a pipe with
`--passphrase-fd`, or an NTAG 424 card tap; never an environment variable) and the signature. The identity (`xid1…`) is a forum handle derived from the same key as your addresses, not a payout address; coins
cannot be sent to it. Payout addresses start `xpa1r` (`txa1r` on testnet A).

```
NerdMiner login --index 101          # make a challenge, sign with the forum key, open a one-time login link
NerdMiner login <challenge-id>       # solve the challenge shown on minedifferent.com/login
   --wallet PATH   .mmm or legacy wallet.seed (default: the wallet CLI's default wallet)
   --index N       key index (default 0; the forum identity convention is index 101)
   --server URL    forum origin (default https://minedifferent.com)
   --no-open       print the link instead of opening it
NerdMiner --version
```

Mining: the testnet A rehearsal is running and the mainnet genesis is not mined yet, so mine with a testnet A
address (`txa1r…`, witness v3 bech32m) against the rehearsal pool:

```
./NerdMiner txa1r... --pool 172.96.186.49:3335 --worker rehearsal1 [--mode solo|shared] [--base <unixtime>]
```

`--base <unixtime>` overrides the MetalDAG epoch base time (the genesis time from the node's `getblock` of
block 0); testnet A has it built in, mainnet will need it once its genesis is mined. An `xpa1r…` mainnet address
is refused until then, and an `xid1…` identity is never a payout address.

### Companion stats server (for the "NerdMiner MD" browser extension)

While mining, the CLI serves live stats over HTTP on **127.0.0.1 only** (never 0.0.0.0), default port 47475.
`--stats-port N` changes the port, `--no-stats` turns it off. `NerdMiner login` never starts it.

Auth: every request needs `Authorization: Bearer <token>` or `?token=<token>`. The token is a random 32-hex
string created on first run at `~/Library/Application Support/NerdMiner/companion-token` (mode 0600). It is
printed once at startup as `Companion token: … (NerdMiner MD extension → Options)` before the dashboard opens.

```
GET /stats    JSON: version, running, address, worker, pool, network, mode, gpu, chip, hashrate_hps,
              hashrate_pretty, total_hashes, uptime_s, shares_found, accepted, rejected, blocks_found,
              last_block_height, difficulty, best_share_bits, dag_epoch, dag_bytes, dag_traffic_gbs,
              system_memory_bytes, last_event, ts
GET /events   text/event-stream: `event: stats` every 2 s, `event: block` when blocks_found increases
GET /health   {"ok":true,"version":"4.1.0"}
OPTIONS *     204 + CORS (Allow-Origin *, Allow-Headers Authorization/Content-Type, Allow-Methods GET/POST/OPTIONS)
```

Unauthorized → 401 `{"error":"unauthorized"}`; unknown path → 404. All responses carry `Cache-Control: no-store`.
Source: `StatsServer.swift`. Test without the GPU: `./NerdMiner __statsdemo [--stats-port N]` serves fake numbers.

## Layout

```
miner/
  NerdMiner            arm64 binary (version: nerdMinerVersion in StatsServer.swift)      build: ./build.sh
  MacMetalCLI          symlink to NerdMiner, a compatibility name for older scripts
  main.swift           miner (login dispatch at the top of main())
  Login.swift          the login flow
  StatsServer.swift    loopback HTTP stats server for the NerdMiner MD extension (/stats, /events, /health)
  MetalDAGEngine.swift, MetalDAGShader.swift, build.sh, Package.swift
```

The wallet is `wallet/` at the root of this repository (`xcoin-wallet-cli` launching `wallet_cli.py`, which has
`signmessage` and `identity`; the native ML-DSA-65 keytool `xcoin-wallet` with the stdin commands `_address`,
`_signmsg` and `_verify`, listed under "Wallet commands used" below; see `wallet/README.md`). `NerdMiner login` looks for `xcoin-wallet-cli` in this order:
`$XCOIN_WALLET_CLI`, then `./wallet/xcoin-wallet-cli` next to the binary (`Login.swift` also tries two older
locations under `~/x-Coin/` last). From a clone at `$HOME/xCoin`, the simplest is:

```
export XCOIN_WALLET_CLI=$HOME/xCoin/wallet/xcoin-wallet-cli
```

## The protocol (MineDifferent login v1)

1. `GET /api/challenge/new` → `{id, expires}` (10-minute TTL). The /login page does this and shows the id.
2. The wallet signs the UTF-8 text (no trailing newline):
   ```
   MineDifferent login v1
   challenge: <id>
   address: <xid1…>
   expires: <unix seconds>
   ```
   `signmessage --template` fills `{address}` in itself with the key's identity (its JSON reply carries it as
   `address`, plus `identity` and `witness_v2_address`), so one unlock covers the identity and the signature.
   The line keeps the name `address:` on the wire; NerdMiner sends exactly the string the wallet signed.
3. `POST /api/challenge/<id>/solve` with JSON `{address, pubkey, sig}` (hex; pubkey 1952 B, sig 3309 B).
4. The server: derives the identity from the pubkey and requires it to equal `address`; verifies the
   ML-DSA-65 signature (FIPS 204) over the rebuilt text; upserts the user; reads superknet.com for blocks/shares
   badges; returns `{ok, login_url}`. The link is one-time and sets the session cookie.

### The xCoin identity (`xid1…`)

A forum identity is an ML-DSA-65 public key. `identity_program = SHA-256(pubkey)` (32 bytes — the same bytes as
the legacy witness v2 program and the input of the witness v3 one-leaf tree). Encoding: bech32m (BIP-350,
constant `0x2bc830a3`), human-readable part `xid`, data = `convertbits(identity_program, 8 → 5, pad)` with **no
witness-version byte**. Result: `xid1` + 52 data chars + 6 checksum chars = 62 lowercase chars. Decoding requires
HRP `xid`, a valid bech32m checksum and exactly 32 bytes after `convertbits(5 → 8, no pad)`. Because there is no
version byte and `xid` is not a chain HRP, no node ever accepts an `xid1…` string as an address: nothing can be
paid to it. That is the point — it is a chat/forum handle, not a payout address.

Older clients may still present an address form of the same key — witness v3 one-leaf `xpa1r…` or legacy
witness v2 `xpa1z…` (`OP_2 <SHA-256(pk)>`, refused on this chain) — and the server derives those from the pubkey
too. New logins present the `xid1…` identity.

Verified 2026-09-04 against the deployed Worker: good signature → session; tampered signature, wrong address,
short pubkey, and replay all rejected.

## Wallet commands used

```
xcoin-wallet-cli [--file W] [--passphrase-fd N] identity [--index N]                 # the xid1… identity (default index 101)
xcoin-wallet-cli [--file W] [--passphrase-fd N] signmessage --template 'text with {address}' [--index N] [--as identity|address]
xcoin-wallet-cli [--file W] [--passphrase-fd N] signmessage --message 'utf8' [--index N]
printf '%s\n' SEEDHEX | ./xcoin-wallet _address --index N                         # keytool: address, identity, key hash
printf '%s\n%s\n' SEEDHEX MSGHEX | ./xcoin-wallet _signmsg --index N               # keytool: address, identity, pubkey, sig
printf '%s\n%s\n%s\n' PUBKEYHEX MSGHEX SIGHEX | ./xcoin-wallet _verify              # keytool: OK / FAIL
```
`signmessage` prints one JSON line `{address, identity, witness_v2_address, pubkey, sig, message_hex, index}`; by
default `{address}` and the `address` field are the `xid1…` identity, which is what `NerdMiner login` posts.
Message signatures never carry the tx-only trailing SIGHASH byte, and a login message is always longer than a
32-byte transaction sighash, so a login signature can never double as a spend.
