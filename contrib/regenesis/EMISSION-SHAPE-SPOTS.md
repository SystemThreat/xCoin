# Where the emission shape is stated

The cap (100,000,000 XID, 8 decimals) and the emission SHAPE under it are decided (owner
decision 2026-09-25): the Annual Tenth, charter section 4. It replaced the provisional
"50 XID per block from block 1, halving every 1,000,000 blocks, to zero". This file lists
every place in this tree that states the shape, so that any later statement of it (and
any new chain built from this tree) misses nothing. The generated table in the canonical
row format is `contrib/regenesis/emission-rows.txt` (SHA-256
`356de0dce26aa5e5b9481c3936ecdefb1f81d14dd5e2ca2a43cc7b2775d0a230`, the digest section 4
states); ctest `emission_policy_check_params` requires the policy to generate it byte for byte.

Every such line or block carries the grep tag `[EMISSION-SHAPE]` (in Markdown, inside an
HTML comment, so it does not render). Some of these lines do not contain the word
"provisional", so a search for that word is not enough. Find them with:

```sh
git grep -nF '[EMISSION-SHAPE]'
```

`python3 contrib/regenesis/emission.py --check-spots` (ctest `emission_shape_spots`)
fails when the tagged lines in a file no longer match the count in the table below: a
new statement of the shape was added without the tag or without listing it here, or a
tagged one was removed. When you add or remove a spot, update the table in the same
change.

## Installing the final shape (done 2026-09-25 for the Annual Tenth; testnet A re-mine outstanding)

1. Replace `contrib/regenesis/emission-policy.json` with the chosen policy and set its
   `"status"` to start with `FINAL` (for example `"FINAL (owner decision <date>)"`).
2. `python3 contrib/regenesis/emission.py --write-params`. This rewrites the generated
   block in `src/consensus/params.h`, including `EMISSION_SHAPE_IS_FINAL = true`.
3. Rewrite charter section 4 for the final shape and delete its `<!-- PROVISIONAL … -->`
   comment, in `contrib/regenesis/CHARTER.md` and in the root `CHARTER.md` (identical
   copies). Re-pin `CHARTER_HASH` (`src/consensus/params.h`) and `CHARTER_HASH_HEX`
   (`src/test/regenesis_tests.cpp`), and the charter hash wherever TESTNET-A.md and
   README.md quote it (`git grep -n fd9b475a`; before 2026-09-25 it was `095b503d`).
4. Rewrite every tagged spot in the table below for the final shape. Keep the tag on each
   one: after the change it marks where the final shape is stated.
5. Re-mine testnet A against the final charter (TESTNET-A.md section 1).
6. Green: `emission.py --check-params`, `emission.py --check-spots` (both in ctest) and
   `test_bitcoin` (`regenesis_tests` includes `emission_shape_finality_matches_charter`,
   which requires the charter's PROVISIONAL comment to be gone exactly when
   `EMISSION_SHAPE_IS_FINAL` is true).

Until step 2 and step 3 are both done, the mainnet genesis cannot be made by accident:
`xcoin-genesis -chain=main` refuses while the charter says PROVISIONAL or
`EMISSION_SHAPE_IS_FINAL` is false (`-allowprovisional` overrides it for the local dress
rehearsal only), and `GENESIS_IS_FINAL = true` does not compile outside a local
`-DXCOIN_REHEARSAL_BUILD=ON` build.

## Tagged spots

| File | Tagged lines | What states the shape | How to update |
|---|---|---|---|
| `src/consensus/params.h` | 4 | The monetary-policy comment above the table; the generated block (one tag for the whole block, written by `emission.py`); the `CHARTER_HASH` comment (section 4's content); the `MIN_OUTPUT_VALUE_SAT` comment (the first era whose subsidy is under the 10,000-sat floor) | Regenerate the block (step 2); rewrite the three comments by hand |
| `src/consensus/tx_check.cpp` | 1 | The coinbase floor-exemption comment (the final table has no row under the floor) | Name the first row under the floor, or say none is |
| `src/kernel/chainparams.cpp` | 2 | The mainnet and testnet A emission-table comments | Restate in one line, or drop the numbers |
| `src/validation.cpp` | 1 | The `GetBlockSubsidy` comment | Restate in one line, or drop the numbers |
| `src/test/regenesis_tests.cpp` | 3 | The file header; the whole `annual_tenth_emission_shape` case (it re-derives the table from charter section 4's rules, checks the rows digest, and pins the owner's test vectors); the floor-exemption test comment | Rewrite `annual_tenth_emission_shape` for any other table; fix the two comments |
| `contrib/regenesis/emission.py` | 1 | The module docstring | One sentence |
| `contrib/regenesis/REGENESIS.md` | 6 | Section 0 table rows "Emission" and "Emission after the first eras"; the 300 s interval paragraph; the shape sentence and the year reference in section 2; the output-floor paragraph | Rewrite each for the final shape |
| `contrib/regenesis/REHEARSAL-2.md` | 3 | Block 1's subsidy in the introduction, in section 3 and in the daily check | The first row's reward (6.25 XID) |
| `contrib/regenesis/TESTNET-A.md` | 4 | The "Block 1" identity row; the rules-identical-to-mainnet paragraph; the day 1 and day 2 checks | The first row's reward (6.25 XID) and the shape |
| `README.md` | 2 | The "Block reward" and "Reduction" rows of the consensus table | Rewrite both rows |
| `doc/monetary-policy.md` | 1 | The note at the top (shape and end year) | Rewrite the sentence |
| `doc/release-notes-xid-100m.md` | 2 | The release notes' emission paragraph; the year the mined supply passes 2^26 XID | Rewrite both |
| `explorer/xcoin-explorer.py` | 1 | `EMISSION_NOTE`, the one line the explorer renders about the schedule (the block reward itself is read from the chain) | Rewrite the constant |
| `explorer/README.md` | 2 | The network panel description; the render test description | Rewrite both |
| `explorer/tests/test_render.py` | 5 | The stub chain's era-0 reward: the docstring, `SUBSIDY`, `SPEND_OUT_*`, and the two assertions of "50" | Only for realism: the stub chain may keep paying 50. If `SUBSIDY` changes, change the spend amounts and asserted strings with it |

## Spots without the tag

| Place | Why no tag | What checks it |
|---|---|---|
| `contrib/regenesis/emission-policy.json` | JSON has no comments. It is the shape's source: replaced whole in step 1 | `emission.py --check-params` |
| `contrib/regenesis/emission-rows.txt` | The canonical rows file (data, hashed by the charter) | `emission.py --check-params --rows` (ctest) and `annual_tenth_emission_shape` |
| `contrib/regenesis/CHARTER.md` and `CHARTER.md`, section 4 | The charter is hashed into the genesis: a tag would change `CHARTER_HASH`. Its `<!-- PROVISIONAL … -->` comment is the marker | `emission.py --check-params`, `regenesis_tests`, and `xcoin-genesis -chain=main` |
| `CHARTER_HASH`, `CHARTER_HASH_HEX`, the charter hash in TESTNET-A.md and README.md | They are digests of the charter, not statements of the shape; they change in step 3 | `regenesis_charter_tests` (recomputes the digest from the embedded charter) |
| Testnet A genesis (`TESTNET_GENESIS_*` in `src/kernel/chainparams.cpp`, the pins in `regenesis_tests.cpp`, TESTNET-A.md, README.md, `vps/bootstrap.sh`, `miner/MetalDAGEngine.swift`) | Re-mined in step 5; the genesis commits to the charter | `regenesis_testnet_a_tests`; the testnet A startup refusal |

## Not the mainnet shape

The regtest emission table (`REGTEST_EMISSION_TABLE` in `src/kernel/chainparams.cpp`:
50 XID for 150 blocks, then halvings) is a test fixture with its own shape, and so are the
amounts the test suites derive from it (`test/functional/test_framework/blocktools.py`,
`src/test/util/setup_common.cpp`, `src/test/xcoin_levy_tests.cpp`,
`src/wallet/test/spend_tests.cpp`, `src/test/xcoin_consensus_rule_tests.cpp`). They do not
change with the mainnet shape and carry no tag. The pool's `STUB_COINBASE_VALUE`
(`xcoin-pool/test_coinbase.py`) is a stub template value, not any chain's subsidy.

## Outside this tree

The site drafts (`launch/nov1-drafts`) state the shape through `{{EMISSION_*}}`
placeholders filled from `emission/placeholders.json`. The XIPs, the forum, MMM, the
wallet app and the AYEDEX bridge keep their own copies; the owners of those repos update
them when the final shape is announced.
