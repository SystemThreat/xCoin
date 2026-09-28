Build and run instructions for the xCoin node are in the top-level
[README: Run a node](README.md#run-a-node): dependencies for macOS (Homebrew) and
Ubuntu 24.04, [the build](README.md#build), and
[running a mainnet node](README.md#run-a-mainnet-node).

The `doc/build-*.md` files are inherited from Bitcoin Core. Their commands
(`git clone https://github.com/bitcoin/bitcoin.git`, `bitcoind`, `bitcoin-cli`,
`~/Library/Application Support/Bitcoin`) do not apply to xCoin: here the source is
`https://github.com/SystemThreat/xCoin.git`, the binaries are `nexd` and `nex-cli`, and
the data directory is `~/Library/Application Support/NEX` on macOS or `~/.nex` on Linux.
