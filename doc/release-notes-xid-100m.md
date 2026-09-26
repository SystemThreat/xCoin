XID, a 100,000,000 XID cap, and mainnet on November 1, 2026 (branch `xid-100m`)
===============================================================================

Owner decisions of 2026-09-25. Nothing here is released yet.

Currency
--------

- The ticker is **XID** (it was XCF; before that XAT, retired). The currency symbol Ӿ
  is unchanged. Forum identity handles still start `xid1…`; they are not addresses and
  coins cannot be sent to them. Payout addresses start `xpa1r` (`txa1r` on testnet A).
- The hard cap is exactly **100,000,000 XID** with 8 decimals (1 XID = 100,000,000 sat),
  replacing 21,000,000. `MAX_MONEY` is 10^16 sat and equals the emission cap
  (`consensus/params.h` asserts `MAX_SUPPLY_SAT == MAX_MONEY`).
- The emission shape is **final**, the Annual Tenth (charter section 4): 6.25, 12.5 and 25 XID <!-- [EMISSION-SHAPE] -->
  for 20,000 blocks each, 50 XID to block 220,000, then 10% less every 110,000 blocks (never
  under 1.5 XID, never more than a tenth of what is left per step), a 0.1 XID tail; 65 rows,
  the last subsidy block, 35,375,353, also minting the 0.0166 XID remainder (~2363 at 300 s). The table in
  `consensus/params.h` is generated from `contrib/regenesis/emission-policy.json` by
  `contrib/regenesis/emission.py`; `contrib/regenesis/EMISSION-SHAPE-SPOTS.md` lists every
  place that states the shape.
- Mainnet launches on **November 1, 2026**, moved from September 30, 2026 so that
  node-to-node connections get hybrid post-quantum encryption first (ML-KEM-768 layered
  on BIP324, "HX1", draft XIP-4).

Genesis safety
--------------

- `GENESIS_IS_FINAL = true` does not compile while the emission shape is provisional
  (`Consensus::EMISSION_SHAPE_IS_FINAL`, generated from the policy's `"status"`; true
  only when it starts with `FINAL`). The local dress rehearsal (REHEARSAL-2.md) builds
  with the new CMake option `-DXCOIN_REHEARSAL_BUILD=ON`, which allows it; such a build
  prints a warning at startup and must never leave the machine.
- `xcoin-genesis -chain=main` refuses while charter section 4 carries its PROVISIONAL
  comment or `EMISSION_SHAPE_IS_FINAL` is false. The new `-allowprovisional` flag
  overrides this for the rehearsal only, and the paste block it prints says
  REHEARSAL ONLY.
- A node now refuses to start on **testnet A** while `TESTNET_GENESIS_IS_FINAL` is false
  (the v1 genesis stands in until testnet A is re-mined for the new charter), as it
  already did on mainnet. `-allowunfinalgenesis=1` overrides it for tests and dry runs
  that never peer.
- `contrib/regenesis/vps/deploy.sh` and `bootstrap.sh` refuse a commit whose testnet A
  genesis is not final or not the pinned one, before anything is shipped or changed, and
  `bootstrap.sh` stops and disables the service if the started node reports another
  genesis.
- New ctest entries: `emission_policy_check_params` (the generated table, the cap and the
  charter's PROVISIONAL comment agree with the policy) and `emission_shape_spots` (every
  tagged statement of the shape is listed).

RPC, JSON and clients
---------------------

- `AmountFromValue` accepts amounts up to `100000000.00000000`; one satoshi more fails
  with "Amount out of range". The old 21,000,000 limit no longer applies.
- The node prints amounts in XID as exact decimal numbers. A client that parses them as
  IEEE 754 doubles (the default in Python's `json`, in JavaScript and in most JSON
  libraries) gets them exactly only **below 2^26 XID (67,108,864 XID)**: above that, one
  double step is more than a satoshi, and about a third of amounts come back one sat off.
  The 2^53 limit applies only to integer satoshi counts, not to XID amounts. Parse
  amounts as decimals instead (Python: `json.loads(body, parse_float=Decimal)`, as
  `wallet/wallet_cli.py` does). Single amounts that large are rare, but totals are not:
  under the final shape the mined supply (`gettxoutsetinfo` `total_amount`) passes <!-- [EMISSION-SHAPE] -->
  2^26 XID around block 10,621,510 (~2128).
- The explorer in this tree now parses node JSON with `Decimal` and formats every amount
  through integer satoshis; its JSON API still returns plain numbers.

IPC (multiprocess) interface
----------------------------

- `src/ipc/capnp/mining.capnp`: the `maxMoney` constant is now 10,000,000,000,000,000
  (was 2,100,000,000,000,000), and `BlockWaitOptions.feeThreshold` defaults to it. Cap'n
  Proto stores a field as its value XOR its default, so between a client built against
  the old schema and this node an explicitly set `feeThreshold` is decoded as a different
  number (an unset one reads as each side's own default). Rebuild any IPC client against
  this schema. No such client is in this tree, and the default build has
  `ENABLE_IPC=OFF`.
