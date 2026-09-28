# Security policy

This repository is xCoin (XID), a fork of Bitcoin Core. Report xCoin problems to xCoin.
Bitcoin Core's security team, its security@bitcoincore.org address and its maintainers'
keys have nothing to do with this project: do not send them xCoin reports.

## What to report privately

Do not open a public issue, pull request or forum post for any of these:

- a way to create coins outside the emission schedule, or to spend an output without
  its owner's post-quantum signature;
- a way to make two nodes of the current release disagree about which chain is valid
  (a chain split);
- a way to crash, stall or exhaust a node from the network, including through the HX1
  (XIP-4) or BIP324 handshake;
- a way to read, tamper with or downgrade an HX1 session without the peer noticing;
- a way to extract a seed, key, passphrase or RPC cookie from the node wallet, the pool,
  the explorer or the miner in this tree.

Ordinary bugs, documentation errors and feature requests go to the public issue tracker.

## How to report

Use GitHub's private vulnerability reporting: open
[github.com/SystemThreat/xCoin/security/advisories/new](https://github.com/SystemThreat/xCoin/security/advisories/new),
or the **Security** tab of this repository and then **Report a vulnerability**. Only the
maintainers see the report. You need a GitHub account.

Include in the report:

- the release or commit (`nexd -version`, or `subversion` in `nex-cli getnetworkinfo`);
- the steps to reproduce, and what you expected instead;
- what an attacker gains, and whether it is being exploited on mainnet today.

Never include a seed, a passphrase or a cookie, yours or anyone else's.

## Supported versions

Fixes are made on `main` and ship in the next release. Mainnet runs 31.99.0 (tag
`mainnet-genesis-2026-09-26`) and 31.99.1 side by side; they follow the same chain and
connect to each other. Upgrade to the newest release to receive fixes.

The standalone wallet ([SystemThreat/xcoin-wallet](https://github.com/SystemThreat/xcoin-wallet))
and MMM ([SystemThreat/MMM](https://github.com/SystemThreat/MMM)) live in their own
repositories. Until they publish their own policy, report their security problems
through the channel above.
