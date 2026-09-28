NEX 31.99.1
===========

A maintenance release of the xCoin mainnet node. 31.99.0 (tag
`mainnet-genesis-2026-09-26`) is the release mainnet launched with on 2026-09-26;
31.99.1 changes no rule. A 31.99.1 node and a 31.99.0 node follow the same chain, speak
the same protocol and connect to each other in both directions, with HX1 or without it.
Upgrading is optional, an upgraded node still reaches every 31.99.0 node, and going
back to 31.99.0 is one restart.

Compatibility with 31.99.0
--------------------------

- **Consensus: unchanged.** Same genesis (`3bc1a36d…79f2`), charter hash, currency id,
  emission table, difficulty, proof of work and script rules. No soft fork, no hard
  fork, nothing to activate.
- **Protocol: unchanged.** Protocol version 70016, the same message start, the same
  services, BIP324 v2 and the HX1 hybrid upgrade (XIP-4) byte for byte as in 31.99.0.
  `-v2hybrid` still defaults to `1` (prefer), and `-v2transport` to on. The only new
  thing a peer sees in the version handshake is the user agent: `/NEX:31.99.1/` instead
  of `/NEX:31.99.0/`.
- **Ports, data directory, configuration: unchanged.** P2P 9333, RPC 8332,
  `~/Library/Application Support/NEX` or `~/.nex`, `nex.conf`, the `.cookie` file. Every
  option means what it meant.
- **Data on disk: unchanged.** Blocks, chainstate, wallets, `peers.dat` and
  `settings.json` keep their formats, so moving from 31.99.0 to 31.99.1 and back needs
  no resync and no `-reindex`.
- **RPC: unchanged.** No method, argument or result field was added, removed or renamed.

What changed
------------

- **Five fixed seeds instead of one.** Fixed seeds are the addresses compiled into the
  node that it tries when no DNS seed answers (a filtered resolver, a lapsed domain).
  31.99.0 carried one, `172.96.186.49:9333`. 31.99.1 carries all five public nodes:
  `172.96.186.49` (New York), `198.252.107.13` (Hong Kong), `103.119.217.105` (London),
  `198.252.101.117` (Singapore) and `54.20.130.14` (São Paulo), all on 9333
  (`contrib/seeds/nodes_main.txt`, `src/chainparamsseeds.h`). The DNS seeds are unchanged.
- **A release build.** The version is 31.99.1 and the build is marked as a release, so
  the node no longer shows "This is a pre-release test build - use at your own risk - do
  not use for mining or merchant applications" in `debug.log` or in the `warnings` of
  `getblockchaininfo` and `getnetworkinfo`. That text was the inherited Bitcoin Core
  template and said nothing about the chain. `nexd -version` prints the release tag for
  a build of a tagged commit, otherwise `v31.99.1` with no commit suffix.
- **xcoin-pool: PPLNS mode and miner slots.** `XCOIN_POOL_MODE=pplns` makes the pool pay
  the miners of the last N shares directly in every block's coinbase, pro rata by
  credited difficulty, plus one fee output (`XCOIN_POOL_FEE_BP`, default 299 = 2.99%, to
  `XCOIN_POOL_FEE_ADDRESS`); the pool never holds coins. `XCOIN_POOL_MAX_MINERS` caps the
  miners served at once. Solo stays the default, so a pool that sets neither behaves as
  before. See `xcoin-pool/README.md`.
- **Documentation.** The README is rewritten for mainnet (build, run, check the chain
  against the explorer, peers, the HX1 transport, ports, mining, wallets); SECURITY.md
  is xCoin's own policy instead of Bitcoin Core's; INSTALL.md points at the README; the
  testnet A VPS scripts are marked as history.

Known and unchanged on purpose
------------------------------

- Mainnet's RPC port 8332 is Bitcoin Core's, and its P2P port 9333 is Litecoin's.
  Changing a default port would cut off running nodes, pools and scripts, so the defaults
  stay. On a machine that also runs `bitcoind` or `litecoind`, set `rpcport=` and/or
  `port=` in `nex.conf` (README, "Ports").
- `nexd -testnet` still refuses to start: testnet A is retired.
- **First contact is still classical; this is not the seed-v2 release.** An address from
  a DNS seed or a fixed seed says nothing about v2, and in the default mode 31.99.1, like
  31.99.0, treats it as v1-only: a brand-new node makes its first connections, and its
  whole first sync, over plain v1, and uses HX1 once it has met its peers. Trying v2
  first on seed addresses comes in a later release.
- **Keep `-v2hybrid=2` (require) off on public nodes.** Require mode refuses every inbound
  v1 connection, so a node that newcomers reach through the seeds would turn away every
  new node, on 31.99.0 and on 31.99.1 alike. Leave public nodes on the default
  `-v2hybrid=1` (prefer). This holds even after the seed-v2 release ships, for as long as
  31.99.0 nodes still join: a 31.99.0 node makes its first contact over v1 whatever the
  seed runs.

Upgrade in place
----------------

The node keeps running while you build, and the old binaries stay where they are, so
going back is one restart.

1. Build 31.99.1 into its own directory, next to the 31.99.0 build, from a clone
   updated to the release (`git checkout main && git pull --ff-only`, or
   `git fetch --tags` and `git checkout <tag>`):

   ```sh
   cmake -B build-31.99.1 -DENABLE_IPC=OFF -DWITH_EMBEDDED_ASMAP=OFF -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
   cmake --build build-31.99.1 -j2      # 2 on a 2-core, 3 GB machine; the core count on a big one
   build-31.99.1/bin/nexd -version
   ```

   Always give `-j` a number while the node is running. With no number, the default
   Makefile generator starts every compile at once, about 1.5 GB each, and on a small
   VPS the kernel's out-of-memory killer may pick the node. A 2-core, 3 GB machine needs
   4 GB of swap for `-j2` (README, "Build"). A machine too small to build next to its
   node (1 or 2 GB of memory, for example) gets `nexd` and `nex-cli` built the same way
   on another Ubuntu 24.04 machine with the same packages and copied into
   `build-31.99.1/bin/` on the node.

2. Note where the running node stands: `build/bin/nex-cli getblockcount`.
3. Stop it and wait until it has exited. If the node runs with `-datadir=` or `-conf=`,
   give the same options to every `nex-cli` call in steps 2, 3 and 5:

   ```sh
   build/bin/nex-cli stop
   while pgrep -x nexd >/dev/null; do sleep 1; done   # one nexd on this machine; otherwise wait for "Shutdown done" in its debug.log
   ```

4. Start the new binary with exactly the options, data directory and `nex.conf` the old
   one used, with `-daemonwait` in place of `-daemon`, for example
   `build-31.99.1/bin/nexd -server -daemonwait`. No `-reindex`. `-daemonwait` returns
   once the node is up, or prints "Error during initialization - check debug.log for
   details"; in that case start the old binary again and read the log.
5. Check it:

   ```sh
   build-31.99.1/bin/nex-cli getnetworkinfo | grep -E '"subversion"|"protocolversion"'   # /NEX:31.99.1/, 70016
   build-31.99.1/bin/nex-cli getblockhash 0          # 3bc1a36d…79f2
   build-31.99.1/bin/nex-cli getblockcount           # at least what step 2 showed
   build-31.99.1/bin/nex-cli getconnectioncount      # at least 1 within a minute
   build-31.99.1/bin/nex-cli getpeerinfo | grep -E '"subver"|"transport_hybrid"'
   ```

A node run as a service is upgraded the same way: copy the old `nexd` and `nex-cli`
aside, stop the service, put the new binaries in their place, start the service and
run the checks. A pool on the node needs no change: it reads the new cookie on every
call and keeps polling while the node restarts. If the service manager stops the pool
together with the node (a systemd unit with `Requires=` on the node's unit does), start
the pool again once the node is up, and check that miners are back.

Roll back
---------

Stop 31.99.1 as in step 3 and start the 31.99.0 binaries (`build/bin/nexd`, or the
copies you kept) with the same options and data directory. Nothing is converted in
either direction. The only thing a rolled-back node loses is the 31.99.1 behaviour
above: its fixed-seed list is back to one entry, and it shows the pre-release warning
again.
