# xCoin re-genesis specification (v2 chain)

Status: DRAFT for implementation on branch `regenesis`. Written 2026-09-05 from the One Money Architecture report.
Everything here is a consensus change. The rules below are meant to be frozen at genesis and then only
extended by soft fork. Read it as a contract for the code, the charter and the cutover.

## 0. Decisions and defaults

| Decision | Default (used unless the founder changes it) | Why |
|---|---|---|
| Supply cap | 21,000,000 XCF, unchanged | Inscribed in the v1 genesis; part of the currency's identity |
| Base unit | 1 XCF = 10^8 base units, unchanged; ledgers use a 1/1000 sub-unit off chain | Same reason; sub-unit is an L2 convention |
| Block interval | 300 s, unchanged | ASERT (2 h half-life) and MetalDAG epochs are tuned and tested for it |
| Block weight | 64,000,000 WU | Anchor and exit capacity: ~11,300 PQ spends or ~20,000 anchors per block. Set high AT GENESIS because raising a block limit is a HARD fork and lowering one is a soft fork: the ceiling must be generous enough that growth never needs a hard fork, and is tightened later by soft fork or by miner policy (`-blockmaxweight`) if it proves too generous |
| Derived from the block weight | `MAX_BLOCK_SIGOPS_COST` 1,280,000; `MAX_BLOCK_SERIALIZED_SIZE` 64,000,000 bytes; `MAX_PROTOCOL_MESSAGE_LENGTH` 64,000,000 bytes (`consensus/consensus.h`, `net.h`). The transports carry less (v1 32 MiB, BIP324 v2 16,777,215 bytes), so `-blockmaxweight` is capped at `MAX_RELAYABLE_BLOCK_WEIGHT` = 16,000,000 WU (`policy.h`, audit finding 8); `XCOIN_V3_VALIDATION_WEIGHT_MLDSA` 200 and `XCOIN_V3_VALIDATION_WEIGHT_SLH` 1080 (`script/xcoin_v3.h`) | Bitcoin's 80,000 / 4 MB / 4 MB scaled by the same 16x so a full block still fits one P2P message and the sigop budget keeps its ratio to the weight. The two validation weights are scaled 4x with the weight so the CPU bound does NOT move: 64,000,000 / 200 is the same 320,000 ML-DSA checks that 16,000,000 / 50 bought |
| Emission | 14 XCF per block, halved every 750,000 blocks (seven years and 49 days) in whole satoshis until it reaches zero: 31 eras, the final subsidy block also minting the 0.09 XCF remainder; 14 × 750,000 × 2 = 21,000,000 exactly. Seven cycles of seven carry the chain into its 49th year; the subsidy then fades and never stops at once | FINAL founder decision 2026-09-14 (charter section 4) |
| Emission after 2077 | Under 0.11 XCF/block and halving on; fees carry security from there — market fees under relay policy; the settlement-levy machinery ships dormant at zero and can be switched on by soft fork (section 6) | Report deliverable 1 |
| Coinbase maturity | 1,000 blocks (~3.5 days at 300 s) on every chain, regtest included; the test harnesses pass `-coinbasematurity=100` for the inherited fixtures | founder decision 2026-09-14 |
| Carry-over | Every v1 UTXO is re-created 1:1 in the v2 block 1 | Nobody who mined v1 loses anything |
| Ownership commitment | Witness v3: Merkle root of algorithm-tagged spend conditions (BIP-360 shape) | Crypto-agility; script |
| Everyday algorithm | ML-DSA-65 (FIPS 204), unchanged | Device support (Apple, Android 17, TPM 2.0 v1.85, Infineon SLC27) |
| Fallback algorithm | SLH-DSA-SHA2-128s (FIPS 205), hash-based, stateless | Standard; shares no structure with lattices; emergency use only (7.9 KB sig) |
| Legacy v2 outputs | None exist on mainnet or testnet A, and none can be created there (`bad-txout-not-pq`); regtest still permits them for the inherited fixtures | One output type on the public chains |
| OP_RETURN | 80 bytes standard; consensus cap of 8,000 data-carrier bytes per block (100 anchors of 80) | Liability and spam; no height is exempt — nothing is inscribed |
| Finality | Work, plus release checkpoints (section 6): block hashes compiled into each release, no key. Signed k-of-N checkpoints were REMOVED 2026-09-14 — charter section 8 forbids an administrative key, and that is what they were. The settlement levy (5 bp minimum fee, section 6) ships at genesis | 51 percent costs nothing today; the answer is hashrate, not a key |
| Founder allocation | NONE. No premine. The founder mines like everyone else | FINAL founder decision 2026-09-05; removes the Howey/maturity/legitimacy exposure the report flagged |
| Charter | Text file, hash committed in the genesis coinbase; currency id = SHA-256(genesis header || charter text) | Report deliverable 11 |
| PoW | MetalDAG, unchanged | Distribution engine and, with release checkpoints, the only finality; later merged mining or a gadget |

**CONFIRMED 2026-09-07 (founder): block weight 64,000,000 WU; block interval 300 s.**

*Interval — 300 s, unchanged.* The emission table is DEFINED against it (era = 750,000 blocks IS seven years and 49 days at 300 s), ASERT's 2 h half-life is tuned to it (24 blocks), and the rehearsal chain ran under it. 120 s would rewrite every era length and the per-block subsidy, re-tune ASERT, and raise the orphan rate on a chain running at ~2 MH/s, while buying only cosmetic latency: confirmation security is accumulated work, so 120 s blocks need 2.5x the confirmations for the same security. (One reason previously given for 300 s does not hold and should not be repeated: MetalDAG is NOT tuned to the block interval. Its epoch is time-based — `metaldagEpochSeconds`, ~14 d, `src/metaldag/metaldag.cpp` — so it is interval-independent.)

*Weight — 64,000,000 WU. This SUPERSEDES the 2026-09-06 entry, which froze 16M on the belief that 32M was reachable later by soft fork.* That belief was wrong and it was the only thing holding the number down. **Raising a block limit is a HARD fork** — blocks that were invalid become valid and old nodes reject them — while **lowering one is a soft fork**. The ceiling therefore has to be set generously at genesis and tightened afterwards, never the other way round.

Why 64M and not more: every doubling past it is paid for by the people running nodes, and *that population cannot be recovered by a later parameter change even though the parameter itself is reversible*. Centralization by parameter is a one-way door in a way the parameter is not. At 64M the worst case is 6.7 TB/year of chain growth, ~5.1 s to move one block on a 100 Mbps link (~1.7% of the interval, so orphan rate stays small) and ~8 GB of peer-buffer exposure at 125 peers. At 128M those become 13.5 TB/year and 3.4%; past 256M the network is datacenter-only under attack. The consensus limit costs nothing in normal operation — miners cap themselves with `-blockmaxweight` — so the only thing it governs is the adversarial worst case, and it should be set where that worst case is survivable by the operators the chain wants to keep.

The CPU bound did not move. `XCOIN_V3_VALIDATION_WEIGHT_MLDSA` goes 50 -> 200 and `XCOIN_V3_VALIDATION_WEIGHT_SLH` 270 -> 1080, both scaled 4x with the weight, so 64,000,000 / 200 is the same 320,000 ML-DSA checks that 16,000,000 / 50 bought and the worst case stays **25.3 s** single-threaded (section 4). Capacity quadrupled; the ceiling is unchanged. Ordinary spends are unaffected because the budget grows with the witness and PQ signatures are large (ML-DSA leaf: ~5,300 witness bytes of budget, spends 200; SLH leaf: ~7,900, spends 1,080).

*How NOT to describe this number.* "16x Bitcoin" is wrong in three ways and should never be used: it files the chain under the block-size wars; it overstates capacity roughly tenfold, because a Bitcoin 1-in-2-out P2WPKH spend is ~560 WU against ~5,650 WU here, so 16x the weight buys about **1.6x** the transactions; and it points at the wrong variable entirely, since the per-transaction storage cost is ~10x Bitcoin's and is FIXED by signature size no matter what the block limit is. At the previous 16M this chain carried *fewer* transactions per block than Bitcoin (2,832 against ~7,140). The honest framing is per transaction: ~11,300 PQ settlements per block, roughly 1.6x Bitcoin's transaction count, for signatures ten times larger. Expect to be asked about worst-case yearly growth (6.7 TB against Bitcoin's ~210 GB, ~32x, from 16x the weight and 2x the block rate); have the per-transaction breakdown ready before publishing, not after.

Still open before the cutover: the founder lock schedule. (The checkpoint signer set is no longer a question — signed checkpoints were removed 2026-09-14.)


## 1. Charter and currency id

`contrib/regenesis/CHARTER.md` is the charter: name, unit names (XCF; base unit "sat"; ledger sub-unit "msat"), the cap, the emission table, the genesis hash of v1 (lineage), the four invariants (identity, supply, ownership-commitment form, history continuity), the predicate sunset rule (an algorithm may be retired only by hard fork with a minimum 4-year migration window), the upgrade process (additions by soft fork with miner signalling; removals by hard fork with node-operator supermajority; the supply rule carries a veto and is never changed), and the reserved witness versions.

- `CHARTER_HASH = SHA-256(charter text, UTF-8, LF line endings, no trailing whitespace)`.
- The v2 genesis coinbase scriptSig carries `"Hic experimentum prosperat - <date> - 2,100,000,000,000,000 sats, 21M XCF"` (`charter::GenesisMessage`): no numeral — this is the genesis, not a second one — and no charter hex in the text, because the whole 32-byte digest is committed in the output below and a coinbase scriptSig is capped at 100 bytes by the unchanged `bad-cb-length` rule, which `CheckBlock` applies to the genesis too. The genesis coinbase mints nothing; that output is its only output. (An earlier draft of this section described a "II … charter <hex>" message; rehearsal 2 caught the drift — the helper in consensus/charter.cpp is the single source of truth.)
- The genesis coinbase also has one OP_RETURN output with `"XCOIN/charter/1" || CHARTER_HASH || SHA-256(v1 genesis header)` (`Consensus::CHARTER_COMMITMENT_TAG`; 15 + 32 + 32 = 79 bytes of payload, an 82-byte script). The tag names the project, never the ticker (the naming rule of section 4); the testnet A genesis carries this tag (TESTNET-A.md).
- `CURRENCY_ID = SHA-256(v2 genesis header (80 bytes) || charter text)` and is printed by `nex-cli getcharter`.
- After genesis, the founder timestamps `CURRENCY_ID` and `CHARTER_HASH` in Bitcoin with OpenTimestamps and publishes the proofs; the terminal and the explorer label the genesis "attested" only against those proofs.

## 2. Emission

`GetBlockSubsidy(h)`: block 0 mints nothing; from block 1 the era subsidy: 14 XCF per block for 750,000 blocks, then halved every 750,000 blocks in whole satoshis until the shift reaches zero (31 eras); the final subsidy block (23,250,000) also mints the 0.09 XCF remainder, so that sum(era subsidies) + remainder == 21,000,000 XCF exactly. There is no carry and no distribution.

    sum(subsidies) + dust == 21,000,000 * 10^8 exactly.

There is no premine and nothing is carried in. The table is generated by `contrib/regenesis/emission.py` and pasted into `consensus/params.h` as `EMISSION_TABLE`.

Reference: era 0 mints 10,500,000 (exactly half the cap, ends ~2033.9), era 1 5,250,000 (~2041.0), era 2 2,625,000 (~2048.2); seven eras reach 99.2 % (~2076.7, the 49th year); the remaining 0.8 % fades over eras 8–31 to ~2248.

Security after emission ends comes from market fees paid to miners under relay policy, with the settlement-levy machinery (section 6) shipped dormant at zero so that a value-proportional minimum can be switched on by soft fork if fee income ever proves insufficient, and from merged mining or a finality gadget; the latter must be live well before the subsidy is small.

Consensus checks: `bad-cb-amount` uses the table; `EMISSION_END_HEIGHT` is the last block of era 3; `MAX_SUPPLY_SAT` stays 2.1e15 and a unit test proves the table sums to it.

## 3. Block 1

Block 1 is an ordinary block: it pays the era-0 subsidy to whoever mines it, and nothing else. Nothing is carried in from any earlier chain, there is no premine and no founder allocation (charter sections 3 and 4; founder decisions 2026-09-05 and 2026-09-09), and nothing is inscribed. The block-1 distribution mechanism once built for a carry-over (`-genesisdistribution`, a compiled-in block-1 commitment, `consensus/genesis_distribution.*`, the, `block1.py` and `carry.py`) was removed on 2026-09-14; no chain has a block-1 rule of its own, and `GetBlockSubsidy` is the only mint rule at every height.

### Output rule after genesis

On mainnet and on the rehearsal chain (`Consensus::Params::permitV2Outputs = false`), a transaction in any block after the genesis block may create only `WITNESS_V3_PQ` and `OP_RETURN` outputs; creating a witness v2 output is `bad-txout-not-pq` (`consensus/tx_check.cpp`), block 1 included, which is consistent because block 1 pays v3. The genesis coinbase is exempt on every chain: mainnet's zero-value witness v2 marker output is part of that chain's permanent identity. Regtest keeps v2 outputs valid so the ~70 shared fixtures still mine and relay. The v2 SPEND path in the interpreter is untouched everywhere: if a v2 output ever existed, it stays spendable forever. `-permitv2outputs` is therefore a REGTEST-ONLY relay knob and is refused on any other chain.

Output-value floor: on mainnet and the rehearsal chain every output that is not `OP_RETURN` carries at least `Consensus::MIN_OUTPUT_VALUE_SAT` = 10,000 sat (`bad-txout-below-min`, `consensus/tx_check.cpp`; regtest sets `minOutputValueSat` to 0 so the inherited fixtures still build sub-floor outputs). A PQ output costs ~5.4 kB of witness to spend, so anything smaller can never be spent for less than it is worth and exists only to bloat the UTXO set. The genesis coinbase is exempt (its marker output is zero-value). Coinbase exemption (founder decision 2026-09-15): a coinbase whose non-`OP_RETURN` outputs number exactly one may pay that output any value from 1 sat, because from era 18 (height 13,500,001) the subsidy, 5,340 sat, is under the floor and an otherwise empty block could not have claimed it; every era's subsidy, down to era 30's single satoshi plus the closing remainder, is mintable with zero fees. A coinbase with two or more spendable outputs is held to the floor on every one of them, so the reward cannot be sprayed into the UTXO set as sub-floor outputs. The block assembler and the pool (`build_coinbase`) both build one spendable output plus the witness-commitment `OP_RETURN`, so the exemption applies to what they mine.

The rule reaches one place that is not a transaction anybody sends: the block assembler's DEFAULT coinbase placeholder (`node::BlockCreateOptions::coinbase_output_script`, `src/node/types.h`). `getblocktemplate` builds its template with it — pool software builds its own coinbase from `coinbasevalue`, so the RPC passes no script — and then runs `TestBlockValidity` over that template, which applies this rule. The placeholder was still `OP_2 <32 zero bytes>` after stage B5, so **every `getblocktemplate` call on mainnet and the rehearsal chain failed with `bad-txout-not-pq`** at every height whose coinbase is not the block-1 distribution: the pool could not have mined a single block. Stage T2 made it `OP_3 <32 zero bytes>` — the same 34-byte size and sigop cost, valid on every chain, and unspendable for the same reason as before (no leaf hashes to zero). Unit test: `regenesis_tests/block_assembler_default_coinbase_is_v3`.

## 4. Witness v3 (P2MR-style, post-quantum)

Implemented in stage B1 (`src/script/xcoin_v3.h`, `src/script/interpreter.cpp`, tests in `src/test/xcoin_v3_tests.cpp`) and stage B2 (the SLH-DSA leaf: `src/slhkey.{h,cpp}`, `src/pqcrypto/slh-dsa-sha2-128s/`, test helpers in `src/test/util/slh.{h,cpp}`, vectors in `src/test/slhkey_tests.cpp`). Every consensus tag, constant, identifier, RPC name and P2P message is scoped to the PROJECT name (`xcoin` / `XCoin` / `XCOIN`), never to the ticker: the ticker is a presentation detail that may be renamed, a consensus tag may not. Prose calls the unit XCF.

Program: 32-byte Merkle root over leaves (`WITNESS_V3_SIZE = 32`); bech32m, HRP `xpa`, witness version 3, so mainnet addresses read `xpa1r…` and the rehearsal chain's read `txa1r…` (`WitnessV3PQ` destination, `TxoutType::WITNESS_V3_PQ` = `witness_v3_pq`, `CScript::IsPayToXcoinV3`). This is the ONLY spendable output type on those two chains: block 1 carries every first-chain balance into a single-leaf v3 output (section 3), so there is no witness v2 output to spend anywhere. No key path: the internal-key slot of the Taproot-shaped control block holds the fixed 32-byte marker `XCOIN_V3_NOKEY = SHA-256("xcoin/v3/nokey")` (plain SHA-256, hex `54b62806c9e55d19448216fc3426a3a04466fbc59c18238795cbbc9003330a65`); any other value invalidates the control block. A one-item witness (the Taproot key-path shape) is invalid (`WITNESS_PROGRAM_MISMATCH`).

Witness stack: `[stack items…] [leaf script] [control block] [annex]?`. Control block = `leaf_version (1) || XCOIN_V3_NOKEY (32) || path (32 × m)`, `m ≤ 128`; the parity bit (bit 0 of byte 0) has no meaning without a key and must be 0. Annex as in BIP-341 (tag byte 0x50; committed by the sighash; non-standard). Validation is gated by `SCRIPT_VERIFY_XCOIN_V3`, which is on for consensus on every chain (`GetBlockScriptFlags`) and is in both the MANDATORY and STANDARD policy flag sets; without it a v3 spend is an unknown witness program (soft-fork shape).

Hashing (BIP-340 tagged hashes, `tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`):

- leaf: `ComputeXcoinLeafHash = tagged_hash("XCoinLeaf", leaf_version || compact_size(script) || script)`
- branch: `ComputeXcoinBranchHash = tagged_hash("XCoinBranch", sorted(a, b))`
- root: walk the path from the leaf with the branch tag (`ComputeXcoinV3MerkleRoot`); a single-leaf tree's root is the leaf hash; the computed root must equal the program.

The tags differ from Bitcoin's `TapLeaf`/`TapBranch`, so an xCoin commitment can never be confused with a Taproot one; Bitcoin's functions are untouched. Pinned vectors (also checked against an independent Python implementation in the unit test): leaf 0xc0 over `20 0102…20 ac` = `50371c29…8902d6`; leaf 0xc0 over the empty script = `e3bb8e80…b1c2f9`; leaf 0xc2 over `51` = `cb25e1b1…922adf`; branch of the first two = `2339dd5a…f76845`.

Leaf versions (`leaf_version = control[0] & 0xfe`):

| Version | Name | Script semantics |
|---|---|---|
| 0xc0 | `XCOIN_LEAF_PQ` — ML-DSA-65 tapscript | Bitcoin tapscript rules (BIP-342: minimal IF, no `OP_CHECKMULTISIG`, `OP_CHECKSIGADD`, OP_SUCCESSx, validation-weight budget) under `SigVersion::XCOIN_PQ_TAPSCRIPT`. `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` take `(pubkey sig pubkeyhash -- bool)` and `OP_CHECKSIGADD` takes `(pubkey sig num pubkeyhash -- num)`: the script pushes the 32-byte SHA-256 of the ML-DSA public key and the witness stack supplies the 1,952-byte key immediately below the signature; the check is `SHA-256(pubkey) == pubkeyhash` and ML-DSA-65 verify. An empty signature yields false without failing (k-of-n slots), and then the key slot must be empty too; a non-empty signature with a wrong key size, a hash mismatch or a bad signature fails the script. Key-hash pushes of any other size are an upgradable key type (success unchanged; discouraged). `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`, hash locks and `OP_CHECKSIGADD` k-of-n as in tapscript; `OP_CHECKTEMPLATEVERIFY` (BIP-119 semantics) on `OP_NOP4` |
| 0xc2 | `XCOIN_LEAF_SLH` — SLH-DSA-SHA2-128s tapscript (the fallback; stage B2) | The same tapscript rules under `SigVersion::XCOIN_SLH_TAPSCRIPT` (CTV included) with BIP-342's stack shapes: `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` take `(sig pubkey -- bool)` and `OP_CHECKSIGADD` takes `(sig num pubkey -- num)`, where the 32-byte SLH-DSA public key is pushed by the leaf script itself (no hash, no key on the witness). An empty signature yields false without failing (k-of-n slots); a non-empty one must be a valid SLH-DSA-SHA2-128s signature (`BaseSignatureChecker::CheckSLHSigV3`) or the script fails. Key pushes of any other size are an upgradable key type (success unchanged; discouraged). `key_version 0x03`; validation weight 1080 per check (stage B6; measured, see below) |
| 0xc4 | `XCOIN_LEAF_RESERVED_PROOF` — proof predicate (v4 in the charter) | unknown → success unless `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` (`DISCOURAGE_UPGRADABLE_XCOIN_LEAF_VERSION`) |
| 0xc6 | `XCOIN_LEAF_RESERVED_LEDGER` — ledger commitment / Merkle exit | unknown → success unless discouraged |
| others | unknown leaf version | success unless discouraged (soft-fork room) |

Note on OP_SUCCESSx: the BIP-342 set is unchanged inside a v3 leaf, so the bytes 0xbb/0xbc that are `OP_CHECKSIG_PQ`/`OP_CHECKSIGVERIFY_PQ` in legacy contexts are `OP_SUCCESS187`/`188` in a v3 leaf (anyone-can-spend, discouraged by policy). Never put them in a leaf; `OP_CHECKSIG` is the PQ check there. `OP_CHECKSIG_PQ` keeps working unchanged everywhere else.

Sighash (`SignatureHashXcoinV3`): the BIP-341 message (`SignatureHashSchnorr` construction with `ext_flag = 1`, `key_version = 0x02` for ML-DSA and `0x03` for SLH-DSA, the xCoin leaf hash, the annex and the codeseparator position; `XcoinV3SighashMessage`) is then hashed with the tag `"XCoinSighash/v3"` (`XcoinV3TagSighash`). Under the PQ leaf that 32-byte digest is the message given to ML-DSA-65 (signed and verified as-is, never pre-hashed again). Under the SLH leaf it is signed with SLH-DSA-SHA2-128s in FIPS 205 pure mode with an empty context, i.e. the bytes actually fed to `slh_sign_internal` / `slh_verify_internal` are `0x00 || 0x00 || digest` (`CSLHPubKey::Verify`); that is what any FIPS 205 implementation produces for a raw 32-byte message with no context (`openssl pkeyutl -sign -rawin` on OpenSSL ≥ 3.5), so an emergency signer needs no xCoin-specific code. A signature over the untagged BIP-341 digest, over the other leaf's key_version, or in internal mode does not verify. Signature encoding is strict: exactly 3,309 bytes (`PQ_SIGNATURE_SIZE`) for ML-DSA or exactly 7,856 bytes (`SLH_SIGNATURE_SIZE`) for SLH-DSA, optionally followed by ONE hash-type byte; a missing byte means `SIGHASH_DEFAULT` (= ALL) and an explicit 0x00 byte is invalid, as in BIP-341. Allowed types: 0x00–0x03 and 0x81–0x83. The key must be exactly 1,952 bytes (ML-DSA, on the witness) or 32 bytes (SLH-DSA, in the script). The checker entry points are `BaseSignatureChecker::CheckPQSigV3` and `CheckSLHSigV3`.

SLH-DSA implementation note: `src/slhkey.{h,cpp}` wraps PQClean's `sphincs-sha2-128s-simple` (clean), vendored at commit `0586a824` into `src/pqcrypto/slh-dsa-sha2-128s/` with documented inline modifications (record in that directory's `PQCLEAN` file; there is no patch file), the consensus-relevant one being the FORS bit order: PQClean still implements SPHINCS+ v3.1 (PQClean issue #562), which differs from FIPS 205 only in the FORS `base_2^b` index bit order for this parameter set; key generation is identical. The patched code cross-verifies with OpenSSL 3.6.1 in both directions and agrees with all 28 NIST ACVP `SLH-DSA-SHA2-128s` sigVer cases (pure and internal); `src/test/data/slh_dsa_sha2_128s_vectors.json` pins the PQClean key-generation KAT, OpenSSL vectors and four ACVP cases. Key generation and signing are `CSLHKey` in `src/slhkey.h` (stage B3; the test helper `CSLHTestKey` is an alias).

`OP_CHECKTEMPLATEVERIFY` (`OP_NOP4`, BIP-119) inside the executed v3 leaves (PQ and SLH, which share one rule set): the 32-byte template hash on top of the stack must equal `GetDefaultCheckTemplateVerifyHash` = `SHA256(version || locktime || [SHA256(scriptSigs), only if any scriptSig is non-empty] || input count || SHA256(sequences) || output count || SHA256(outputs) || input index)`; the hash stays on the stack; a mismatch fails (`TEMPLATE_MISMATCH`); a non-32-byte argument is a NOP (discouraged). Everywhere else `OP_NOP4` stays a NOP. The template hashes are precomputed once per transaction (`PrecomputedTransactionData::m_ctv_ready`).

Sizes and weight: initial witness stack elements under v3 may be up to `MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE = 8,192` bytes (fits an SLH-DSA-128s signature plus its hash-type byte, 7,857); elements pushed during execution stay at 520. Validation weight budget as BIP-342 (`witness size + 50` per input, charged per non-empty signature check), with `XCOIN_V3_VALIDATION_WEIGHT_MLDSA = 50` and `XCOIN_V3_VALIDATION_WEIGHT_SLH = 270`. Because an element can be 16x larger than anywhere else, the executed v3 leaves (PQ and SLH, never BIP-342 tapscript) carry three limits beyond BIP 342 (founder decision "cpu", fee study D8; the derivation is the comment on `MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE` in `script/xcoin_v3.h`): the leaf script is limited to `MAX_SCRIPT_SIZE` (10,000 bytes, `SCRIPT_SIZE`) and `MAX_OPS_PER_SCRIPT` (201 non-push opcodes, `OP_COUNT`) exactly as a BASE or WITNESS_V0 script is; every hash opcode (`OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`, `OP_HASH160`, `OP_HASH256`) charges one unit of the same validation-weight budget per byte hashed (`XCOIN_V3_VALIDATION_WEIGHT_PER_HASHED_BYTE = 1`; `OP_HASH160`/`OP_HASH256` charge `size + 32` for their second pass) and fails with `XCOIN_V3_HASH_WEIGHT` when the budget goes negative; the stack-copying opcodes are not charged, because the opcode limit already bounds them at 201 x 3 x 8,192 bytes of memcpy per input. Before these limits a 3-byte leaf, `OP_DUP OP_SHA256 OP_DROP`, could hash about 10.9 GB per 4M WU block and 175 GB per 64M WU block; now a block hashes at most its weight plus 50 per v3 input, about 5.0 MB per 4M and 80 MB per 64M block, and the 25.3 s signature bound below stays the worst case. A v3 input is charged `PQ_SIGOPS_COST` (2) sigops like a v2 input. Script errors: `XCOIN_V3_CONTROL`, `XCOIN_V3_SIG_SIZE`, `XCOIN_V3_SIG_HASHTYPE`, `XCOIN_V3_SIG`, `XCOIN_V3_PUBKEY`, `XCOIN_V3_HASH_WEIGHT`, `DISCOURAGE_UPGRADABLE_XCOIN_LEAF_VERSION`, `TEMPLATE_MISMATCH`.

**The two weights and the block's worst case (stage B6; the number the founder freezes).** A witness byte costs one unit of block weight, so a 64,000,000 WU block can buy a budget of about 64,000,000 and therefore about `64,000,000 / weight` signature checks of one kind, whatever the scripts look like. The two constants must stand in the ratio of the two verification COSTS or the cheaper one makes its leaf the block's worst case. Measured on the founder's M3 Pro in a release build against this tree's own PQClean code, with the benchmark this stage adds (`src/bench/xcoin_pq.cpp`; run it with `build/bin/bench_bitcoin -filter='XcoinVerify.*'`, 6 runs): **ML-DSA-65 verify 79.1 us median (76.8-81.1), SLH-DSA-SHA2-128s verify 418.9 us median (383.9-432.3), ratio 5.30** at the medians and 5.63 at the worst pairing. A separate tight-loop harness over the same code agreed (79.9 us and 408.8 us, ratio 5.12), and an independent reviewer measured 79.6 us and 433.1 us, ratio 5.44. `1080 / 200 = 5.4` sits in the middle of that spread (the pair was 270 / 50 while the block was 16M WU; both were scaled 4x with the block weight on 2026-09-07, which is what keeps the bound below unchanged).

| Leaf | Weight | Checks a 64M WU block can afford | Single-threaded verification |
|---|---|---|---|
| ML-DSA-65 (0xc0) | 200 | 320,000 | **25.3 s** |
| SLH-DSA-SHA2-128s (0xc2) at the chosen 1080 | 1080 | 59,259 | 24.8 s |
| SLH-DSA-SHA2-128s at the old 200 | 200 | 80,000 | 33.5 s (this was the worst case; that is the bug B6 fixes) |

So the bound frozen at genesis is **25.3 seconds of single-threaded signature verification for the worst possible 64,000,000 WU block**, set by the ML-DSA leaf, with the SLH leaf now safely under it. Two things make the real number smaller: script verification runs on `-par` threads (about 3.2 s on eight cores) and the signature cache means a block whose transactions were already in the mempool re-verifies almost nothing. An ordinary block of single-leaf ML-DSA spends costs about 11,300 checks, 0.89 s; the 25.3 s ceiling is only reachable by a leaf script that runs one witness signature through OP_CHECKSIG thousands of times, which is exactly what the budget exists to bound. Raising `XCOIN_V3_VALIDATION_WEIGHT_MLDSA` is the lever if a tighter ceiling is wanted, and it must be pulled BEFORE genesis: both constants are consensus.

Descriptors and the wallet (stage B3; `src/script/descriptor.cpp`, `src/script/sign.cpp`, `src/script/signingprovider.cpp`, `src/wallet/`, unit tests `src/test/xcoin_descriptor_tests.cpp` and `src/wallet/test/xcoin_wallet_tests.cpp`, functional test `test/functional/xcoin_v3_wallet.py`):

- `pqtr(TREE)` (top level only) is the witness v3 output `OP_3 <root>`; `TREE` uses the `tr()` brace syntax (`{A,B}` nesting, at most 128 levels), has no internal key and at least one leaf. Leaves: `pq(KEY)` (ML-DSA-65 leaf 0xc0: `<SHA256(pubkey)> OP_CHECKSIG`), `slh(KEY)` (SLH-DSA leaf 0xc2: `<pubkey32> OP_CHECKSIG`), and the time-locked forms `and_v(v:pq(KEY),after(N))`, `and_v(v:pq(KEY),older(N))` and the same two with `slh` (`<key> OP_CHECKSIGVERIFY <N> OP_CHECKLOCKTIMEVERIFY|OP_CHECKSEQUENCEVERIFY`, `1 <= N <= 2^31-1`). `pq(KEY)` at the top level is the legacy witness v2 output `OP_2 <SHA256(pubkey)>` (`OutputType xcoin-v2`); `pqtr` is `xcoin-v3`.
- `KEY` inside `pq()`: a 1,952-byte ML-DSA-65 public key (hex), a 32-byte seed (hex, private; FIPS 204 KeyGen seed) or a 4,032-byte expanded secret key (hex, private), or a BIP32 expression `[origin]xpub.../path/*` / `xprv.../path/*`. Inside `slh()`: a 32-byte public key, a 48-byte seed or a 64-byte secret key (hex), or a BIP32 expression. Private strings print the seed. Multipath `<0;1>` works as in BIP 389.
- BIP32-derived post-quantum keys (`src/pqhd.h`): the ROOT extended private key and the full path to each position seed the key pair, never a child key: `material = root_privkey32 || root_chaincode32 || u32le(path...)`, `mldsa_seed(32) = SHAKE-256(material || "xcoin/hd/ml-dsa-65/seed/v2")`, `slh_seed(48) = SHAKE-256(material || "xcoin/hd/slh-dsa-sha2-128s/seed/v2")`. An exported account xpub therefore leads to no post-quantum key even for an adversary who can solve discrete logarithms (audit finding 5, 2026-09-14). There is no public derivation: expanding needs the private key; the wallet caches every derived public key (`walletdescriptorxcoincache` records), so a locked wallet still solves and displays its addresses but cannot look ahead. This is a wallet convention, frozen so a seed backup restores every address.
- Default wallet: purpose `3h` (= witness version) and coin type as in BIP 44: `pqtr({pq(xpub/3h/COINh/0h/CHAIN/*),slh(xpub/3h/COINh/0h/CHAIN/*)})`, both keys from the same BIP32 position with distinct domains; the legacy type is `pq(xpub/2h/COINh/0h/CHAIN/*)`. `-addresstype` defaults to `xcoin-v3`; change always goes to a v3 address. `xcoin-v2` is still a type the wallet can derive (`getnewaddress "" xcoin-v2`), but on mainnet and the rehearsal chain nothing can pay it (a v2 output is invalid there and the address string is refused on the paying side), so it is only useful on a chain that still has witness v2 outputs; a carried holder's own v1 key is reachable through, not through a new v2 address. The automatic v3 keypool look-ahead is 20 (each address costs an SLH-DSA key generation; `keypoolrefill N` fills any size).
- Signing (`ProduceSignature`): v2 inputs get `[sig||hashtype, pubkey]` (BIP143-style sighash, `SIGHASH_DEFAULT` signed as `ALL`); v3 inputs get `[leaf items..., leaf script, control block]` for the cheapest leaf the signer can satisfy — the ML-DSA leaf `[pubkey, sig]` whenever the ML-DSA key is known, the SLH leaf `[sig]` otherwise; time-locked leaves only when the transaction already meets the lock; `SIGHASH_DEFAULT` omits the hash-type byte, other types append it. Fee estimation budgets the ML-DSA leaf (the fallback leaf is only used by explicit descriptor signing, e.g. `descriptorprocesspsbt` with `pqtr({pq(<pubkey>),slh(<seed>)})`). PSBTs default to `SIGHASH_DEFAULT` for v3 inputs like Taproot.
- RPC: `getnewaddress`/`getrawchangeaddress` accept `xcoin-v3` and `xcoin-v2`; `getaddressinfo` shows `desc` (`pqtr(...)`/`pq(...)`), `xcoin_v3_leaves` (leaf version, algorithm, script, key, time lock) or `pubkey`/`pubkey_algorithm`; `validateaddress`/`decodescript`/`deriveaddresses`/`getdescriptorinfo`/`importdescriptors`/`scantxoutset` understand the descriptors and addresses. `decodescript` returns `xcoin_v3_leaf_warnings` and each `getaddressinfo` leaf a `warnings` array, present only when that script would be ANYONE-CAN-SPEND as a v3 leaf: it carries an OP_SUCCESSx byte (the `OP_CHECKSIG_PQ` trap of the note above) or its key push is not 32 bytes (an upgradable key type, which passes the check without verifying anything). Neither is invalid, both are the soft-fork room, and both are a mistake in a leaf someone means to pay (`XcoinV3LeafWarnings`, `src/script/sign.cpp`; stage B6). On mainnet and the rehearsal chain every one of them refuses an `xpa1z…`/`txa1z…` string and names the `xpa1r…`/`txa1r…` of the SAME key instead (one choke point: `DecodeDestination`), `validateaddress` returning `isvalid: false` with that message, and, a raw `5220…` script or a bare 32-byte key hash. The legacy sweep tooling (`sweepv2`, `getwalletinfo`'s `v3_sweep_recommended`) is gone (founder decision 5, 2026-09-15): no chain carries coins any more, and `sendtoaddress`/`send`/`sendall` spend v2 and v3 inputs alike. A witness v2 address is handed out (`getnewaddress`/`getrawchangeaddress address_type=xcoin-v2`, `-changetype=xcoin-v2`) and paid (`sendtoaddress`/`send`/`sendall`/`walletcreatefundedpsbt`) only where the node relays and mines new v2 outputs: regtest started with `-permitv2outputs=1` (`interfaces::Chain::permitV2Outputs`, `CWallet::PermitsV2Outputs`); anywhere else the wallet refuses up front and names the flag, instead of committing a transaction the node's own mempool would refuse (audit finding T9). Existing v2 coins stay recognised and spendable regardless.
- Address-reuse refusal: `getnewaddress` never hands out the same v3 address twice — the descriptor index only moves forward, a returned reservation is burned, and an address already in the address book or already spent from (a rescanned look-ahead address) is skipped.

Policy: v3 outputs standard (PQ- and SLH-leaf stack items are capped at `MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE = 8,192`; annexes non-standard); v2 outputs non-standard to create (`IsStandardTx` reason `legacy-v2-output`, default off, reported by `getmempoolinfo`) but spendable forever. `-permitv2outputs=1` overrides that policy and is a REGTEST-ONLY option: on any other chain the node refuses to start with it, because on mainnet and the rehearsal chain a new v2 output is consensus-invalid (section 3). Consensus (`bad-txout-not-pq`) admits v3 and OP_RETURN everywhere, plus v2 where `Consensus::Params::permitV2Outputs` is set (regtest) and in the genesis block of every chain; v0/v1 are never creatable.

## 5. Data carrier

- Policy: `-datacarriersize` default 80 bytes; `MAX_OP_RETURN_RELAY = 80`.
- Consensus: sum of bytes in all `OP_RETURN` outputs of a block ≤ `MAX_BLOCK_DATACARRIER_BYTES = 100,000`, except block 1. Enforced in `ContextualCheckBlock`; error `bad-blk-datacarrier`.

## 6. Settlement levy and release checkpoints

The levy shipped in stage B4 (`src/consensus/levy.h`; unit tests `src/test/xcoin_levy_tests.cpp`). Release checkpoints are `Consensus::Params::release_checkpoints` (`bad-checkpoint-release` in `ContextualCheckBlockHeader`).

### Settlement levy

**The chain ships without a levy (founder decision 2026-09-14, DECISIONS.md).** The machinery stays in consensus, dormant, with a genesis schedule row of zero rate and zero cap, so no transaction owes anything and fees are set by relay policy (`-minrelaytxfee`, default 1 sat/vB at Bitcoin parity, founder decision 2026-09-15: 1,480 sat, 0.0000148 XCF, for a typical 1-in-2-out ML-DSA payment of 1,480 vB; `DEFAULT_MIN_RELAY_TX_FEE` in `policy/policy.h`, a policy default a release can move as the price moves; the wallet's `-fallbackfee` defaults to the same rate) and the fee market alone, as on Bitcoin.

- Consensus (the machinery): every non-coinbase transaction must pay a fee of at least `SettlementLevy(sum of its output values, rule) = min(ceil(sum × rule.bp / 10,000), rule.capSat)`, integer arithmetic, rounded up, under `rule = Consensus::Params::SettlementLevyAt(height)`: a schedule keyed by height, `settlementLevySchedule`. Every chain ships one row, `SETTLEMENT_LEVY_GENESIS_RULE = {0, 0 bp, 0 sat}`. Regtest only: `-levybp=<1..10000>` enables the levy for a test at that rate under the reference cap `SETTLEMENT_LEVY_CAP_SAT = 10,000 sat`; the levy tests pass `-levybp=5`, the reference rate `SETTLEMENT_LEVY_BP`. Rejection is `bad-txns-levy`, applied per transaction in `ConnectBlock` (after `CheckTxInputs` computes the fee), in mempool acceptance (`Consensus::CheckSettlementLevy`, `tx_verify.h`) and by the block assembler before a transaction enters a template. Coinbases are exempt in any case.
- Why zero, and why the machinery stays: a minimum fee fixed in satoshi cannot know what a satoshi is worth and there is no oracle; the reference cap made the levy a flat 10,000 sat above 0.2 XCF; every pre-signed transaction (vault refund, swap timeout, covenant rung) would have had to carry a levy it could not know in advance; and the fork asymmetry decides the rest. Switching a levy ON is a soft fork — a later schedule row that raises the rate or the cap, plus a deployment — and `SettlementLevyScheduleIsSoftForkOnly` accepts it. Switching one OFF, or lowering it, is a hard fork and is refused. A zero genesis row is therefore the one starting point from which every later choice is reversible in the cheap direction, and the code, schedule, wallet path and tests remain in the tree so that an activation is a table row and nothing else.
- Wallet: when the rule in force has a non-zero rate, coin selection adds the levy on the recipients to the target and floors the final fee at the levy the finished outputs owe (`SettlementLevyFromInputs` = the smallest `f` with `f ≥ levy(in − f)`, for change, `sendall` and subtract-fee-from-amount). Under the genesis rule the path is inert and the fee is the byte-rate fee alone.
- Unit tests (`src/test/xcoin_levy_tests.cpp`): the genesis rule on every chain and on regtest without `-levybp` (`xcoin_no_levy_chain_tests`: a fee one satoshi above the relay floor is accepted and mined, a fee one satoshi below it, or of 200 sat, or of zero is stopped by relay policy, never by `bad-txns-levy`); and, under `-levybp=5`, the exact boundary, rounding up, multi-output sums, mempool rejection, block rejection via `TestBlockValidity` and `ProcessNewBlock`, the assembler skipping a levy-short entry, and the fee landing in the coinbase.

### Checkpoints

**Signed checkpoints were removed on 2026-09-14.** The mechanism shipped in stage B4 — k-of-N ML-DSA-65 signer keys in
`Consensus::Params`, the `xcoinckpt` P2P message, `getcheckpoint` / `submitcheckpoint`, `EnforceCheckpoint` (which could
invalidate a block on the active chain and lift `BLOCK_FAILED_VALID` from the block the signers named), the hashrate
sunset rule and the `xcoin-signcheckpoint` binary — was an administrative key over which chain the network follows.
Charter section 8 says there is none, and the section is unamendable. The signer slots were all-zero placeholders, so
nothing ever ran; the code is gone so nothing ever can.

What remains is the keyless kind: **release checkpoints**, `{height, hash}` pairs compiled into a build
(`consensus.release_checkpoints` in `kernel/chainparams.cpp`). A release states which block it saw at a height and a
node running that release refuses a header that disagrees. Nothing is signed, nothing is transmitted, and it binds
only people who choose to run that build — the same thing Bitcoin did from 2010, and the only protection a node
syncing from scratch has. Add the newest entry at every release once the chain has depth (cutover checklist step 6).

Finality at launch is therefore work and nothing else. That is the honest position; the scaffolding it replaces
would have been a founder-held override dressed as finality.

## 7. Reserved for soft forks after genesis (not in this cutover)

Settlement levy activation (the machinery ships dormant at zero, section 6; switching it on is a schedule row plus a deployment) and its 100-block smoothing; per-epoch UTXO-set accumulator commitment in the coinbase; ledger-commitment output and Merkle-exit leaf (0xc6); proof predicate (0xc4); OP_VAULT/CCV; merged mining or a finality gadget replacing checkpoints. Each is additive under the unknown-leaf-version rule or a coinbase-commitment rule and is a soft fork.

**Multi-algorithm proof of work (merged mining), reserved at genesis, activated later by fork.** Founder decision 2026-09-05: keep it as an option after re-genesis. Reserved in stage B4 so the later activation is a parameter change: (a) block header `nVersion` bits 28..29 are the PoW-algorithm id (`Consensus::POW_ALGO_ID_MASK` = `0x30000000`, `GetPowAlgoId`; 0 = MetalDAG; 1 = AuxPoW/SHA-256d merged with Bitcoin; 2..3 reserved) and `ContextualCheckBlockHeader` rejects a non-zero id with `bad-pow-algo` until `multi_algo_activation_height`. To make room the BIP9 top bits of this chain are `01` in bits 31..30 (`VERSIONBITS_TOP_BITS` = `0x40000000`, `VERSIONBITS_TOP_MASK` = `0xC0000000`, 28 deployment bits 0..27, `DEPLOYMENT_TESTDUMMY` on bit 27) instead of Bitcoin's `001` in bits 31..29: a Bitcoin-style `0x20000000` version carries algorithm id 2 and is invalid here, and a pool's version-rolling mask must exclude bits 28..29 (`xcoin-pool` uses `0x0fffe000`, bits 13..27). (b) `Consensus::Params` gained `pow_algos` (per-algorithm `powLimit`, ASERT half-life and target spacing so each algorithm keeps its own difficulty; today one entry, MetalDAG with the chain's own values), `pow_share` (target share of blocks per algorithm in basis points, sums to 10,000; today `{10000}`; the split is a parameter, not decided), `max_consecutive_same_algo` (cap on a run of blocks from one algorithm; 0 = none) and `multi_algo_activation_height` (0 = inactive on every chain). No AuxPoW validation exists yet. Still reserved for the activating fork: (c) chainwork defined as the sum of per-algorithm work normalized by each algorithm's share so a reorg must outweigh the combined chain; (d) an AuxPoW block carrying the Bitcoin coinbase, its Merkle branch and the parent header as in Namecoin. Bitcoin anchoring (periodic OP_RETURN of the xCoin tip into Bitcoin, verified by nodes with Bitcoin headers, reorgs below an anchored tip refused) is the lighter finality gadget and needs no PoW change; it is planned first. Neither replaces the fee side: merged miners are paid by the same subsidy and levy.

## 8. Cutover checklist

1. Announce the cutover height H on the v1 chain and the genesis time T (≥ 24 h after H).
2. At H: stop the earlier chain's infrastructure. Nothing from it is carried into this chain.
3. Build the genesis: `xcoin-genesis -time=<T>` (src/xcoin-genesis.cpp, built with the tests) builds the charter genesis, mines its header with the node's own MetalDAG path at `metaldagBaseTime = T` and `powLimit` (0x1e0fffff, ~2^20 hashes), and prints `FINAL_GENESIS_*`, `CURRENCY_ID` and the hash rate; paste into `kernel/chainparams.cpp`, set `GENESIS_IS_FINAL = true`; rebuild; `test_bitcoin` and the functional suite green; `nex-cli getcharter` reports `genesis_is_final: true`. The v2 mainnet has its own network identity, so a regenesis node can never peer with the v1 chain (the identity row, in the style of TESTNET-A.md section 1; unit test `regenesis_tests/mainnet_v2_identity_and_startup_gate`):

   | | mainnet v2 (this tree) | v1 (retired at H, for comparison) |
   |---|---|---|
   | Select | default | default on the v1 tree |
   | Magic | `'X','P','A',0x03` | `'X','P','A',0x02` — nobody's on this tree (`GetNetworkForMagic` rejects it) |
   | P2P port | 9333 (unchanged) | 9333 |
   | RPC port | 8332 | 8332 |
   | bech32 HRP | `xpa` (unchanged), but witness v3 only: `xpa1r…`. An `xpa1z…` string is refused | `xpa` (`xpa1z…`) |
   | Genesis | `FINAL_GENESIS_*` from `xcoin-genesis`, `GENESIS_IS_FINAL = true` | `0000012c4eed…a3bc` |
   | Startup gate | while `GENESIS_IS_FINAL` is false (the v1 genesis stands in) `nexd` refuses to start on mainnet unless `-allowunfinalgenesis=1` is given (cutover dry run only, never for a node that peers) | — |

   Two pinned test values follow this identity and were re-derived in stage B4, not relaxed: the `bip324_tests` packet vectors (the network magic is mixed into the BIP324 HKDF salt, so every `mid_`/`out_` field moves with it; re-pinning the magic to `0x02` reproduces the previous values byte for byte, which is how the magic was confirmed to be the only cause) and the regtest assumeutxo entry's `.blockhash` in `kernel/chainparams.cpp` with its copy in `validation_tests/test_assumeutxo` (the BIP9 top-bit move of section 7 changed every header's `nVersion`, and with it every block hash on the deterministic test chain; the UTXO set is untouched, so `hash_serialized` is unchanged).
4. Start node 1 (Mac) and node 2 (VPS); mine block 1 (an ordinary block); verify both nodes agree on it. `getblocktemplate` on mainnet is gated as upstream (a peer required, not in initial block download; test chains exempt): if block 1 is to be mined before node 2 is peered, or more than 24 h after T, start node 1 with `-allowsolomining=1` (startup warning; remove it once the node has a peer). Functional test `mining_template_gate.py`.
5. Publish: charter, genesis hash, `CURRENCY_ID`, OpenTimestamps proofs; update explorer, pool, NerdMiner, browser miner (`metaldagBaseTime = T`), xPay, wallet CLI (v3 addresses), the four sites and the whitepaper; the terminal re-pins genesis.
6. Once the chain has depth, add the first release checkpoint (`consensus.release_checkpoints` in `kernel/chainparams.cpp`) and ship a release. There is nothing to arm and no signer set.
7. Keep a v1 archive node read-only for one year for anyone verifying the carry-over.

## 9. Test plan

Unit: emission sums to the cap; subsidy at every era boundary; block-1 distribution accept/reject; the v2-to-v3 carry conversion agreeing between C++ and `block1.py` on a shared vector (the founder's key included) and with NerdMiner's own pin; block 1 with converted outputs accepted on regtest and on the rehearsal chain, block 1 paying a v2 output rejected (`bad-genesis-distribution` on regtest, `bad-txout-not-pq` where v2 is invalid); a v2 output in a later block rejected on the rehearsal chain and on mainnet but accepted on regtest, with the genesis coinbase exempt; the wallet and the RPCs refusing an `xpa1z` and returning its `xpa1r`; v3 leaf hashing vectors; ML-DSA and SLH-DSA leaf spends (valid, wrong key, wrong sighash, reused key across leaves, oversize element, CLTV early/late, k-of-n with CHECKSIGADD, CTV valid/invalid template); v2 legacy spend still valid; v0/v1 invalid; data-carrier cap accept/reject; settlement levy boundary/rounding/multi-output, mempool and block rejection, fee paid to the miner; checkpoint accept/reject (bad signature, below threshold, unknown/duplicate signer, stale epoch, replay), header rejection and reorg refusal below a checkpoint, sunset by height and by hashrate (mocked estimator), the sunset estimate refusing a window of forged minimal timestamps while an honest window at the bar passes and a single outlier moving nothing (section 6); the v3 sighash committing to the OP_CODESEPARATOR position; the anyone-can-spend leaf warnings; SLH-DSA random key generation; multi-algorithm header bits rejected while inactive; mainnet identity and startup gate; the block assembler's default coinbase placeholder being a witness v3 output that the PQ-only rule takes on a chain where a v2 output is refused (section 3; without it `getblocktemplate` fails at every height there).

Functional: fresh regtest chain with the v2 rules; carry-over from a synthetic v1 UTXO set; wallet creates `xpa1r` addresses, receives, spends via ML-DSA leaf, spends a v2 output (where one exists) into a fresh two-leaf v3 address, hands out and pays a v2 address only on a node started with `-permitv2outputs=1`, spends the SLH-DSA leaf; mempool rejects 81-byte OP_RETURN; miner rejects a block over the data cap; checkpoint refuses a reorg; sunset disables it.

### The functional test framework and the base suite (stage B6b)

Until stage B6b only `xcoin_v3_wallet.py` could run, and the rest of the base suite had been dark
since the fork. Two framework files carried Bitcoin's values: `test/functional/test_framework/messages.py`
still had Bitcoin's `MAGIC_BYTES`, so every p2p test failed to connect, and the framework's mining
helper paid a Bitcoin-style output, which the PQ-only output rule refuses (`bad-txout-not-pq`), so
even `create_cache.py` could not build the shared chain. The repair, and the baseline the cutover
checklist gates on, are below.

**What changed in `test/functional/test_framework/`.**

- `xcoin.py` (new): witness v3 in Python: the `XCoinLeaf` / `XCoinBranch` tagged hashes, the Merkle
  root that IS the program, and the Taproot-shaped control block with the fixed `XCOIN_V3_NOKEY`
  marker. It is the counterpart of `src/test/util/pq.{h,cpp}`, and its unit test (registered in
  `feature_framework_unit_tests.py`) recomputes the four vectors section 4 pins, so the Python and
  the consensus implementation cannot drift apart silently. The everyday object it provides is the
  ANYONE-CAN-SPEND witness v3 output: one 0xc0 leaf whose script is `OP_TRUE`, spent with the
  witness `[leaf script, control block]` and no signature. That is this chain's only anyone-can-spend
  output, and it is the exact size of Bitcoin's p2tr-OP_TRUE one (34-byte scriptPubKey, 1-byte leaf,
  33-byte control block), so every inherited fee and vsize constant that depended on it still holds
  (a MiniWallet self-transfer is still 104 vbytes).
- `messages.py`: `MAGIC_BYTES` carries this chain's per-network magic: mainnet `X P A 0x03`, the
  rehearsal chain `X T A 0x02`, regtest `NEX 0x03`. The chain types are those three: the inherited
  testnet4 and signet were removed (founder decision, batch "chains"), because their Bitcoin genesis
  blocks fail the post-quantum output rule and both nodes crashed at startup (audit finding C6).
  The BIP324 salt in `v2_p2p.py` follows the magic, as it does in `src/bip324.cpp`.
- `blocktools.py`: `create_coinbase` pays the anyone-can-spend v3 output instead of a bare
  `OP_TRUE`; its subsidy follows this chain's regtest emission (era k runs from `1 + 150k`, because
  block 0 mints nothing). `create_tx_with_script` defaults to the same v3 output.
- `wallet.py`: `MiniWalletMode.ADDRESS_OP_TRUE` is that v3 address, and its spend vsize is measured
  rather than pinned, because a tagged wallet's leaf script is longer than the untagged one. The two
  RAW modes are kept but cannot be mined or relayed here (a bare `OP_TRUE` and a P2PK output are
  both `bad-txout-not-pq`); the tests that need a modifiable scriptSig are skipped, listed below.
- `test_node.py` and `test_framework.py`: the per-node deterministic coinbase key. Upstream mines to
  `TestNode.PRIV_KEYS[i]` and imports that P2PKH privkey into node i's wallet, so `self.generate()`
  funds the wallet; a P2PKH output cannot be mined here at all. The replacement is
  `deterministic_coinbase_descriptor(i)` = `pqtr(pq(<tprv>/0/0))` over a BIP32 key that depends only
  on the node index. `TestNode.generate` mines to it with `generatetodescriptor`, `init_wallet`
  imports it, and the shared chain cache mines its 199 blocks to nodes 0-2's descriptors plus
  MiniWallet's script, exactly as upstream splits them. **It has to be the BIP32 form, not a literal
  ML-DSA seed**: see the open item below.
- `test_framework.py`: a clean chain starts at height 0 and block 1 is an ordinary block, exactly as on
  mainnet; nothing is mined before a test starts.
- `util.py`: no levy setting is needed; the chain ships without one (section 6). `-levybp` is the
  regtest knob that enables the dormant levy for a test, and the machinery is covered by
  `xcoin_levy_tests` and by `xcoin_v3_wallet.py`,
  which passes `-levybp=5` back.
- `address.py`: `ADDRESS_UNSPENDABLE` (witness v3, all-zero program: no leaf hashes to zero, so
  nothing can spend it) and `ADDRESS_ANYONECANSPEND` replace the two `ADDRESS_BCRT1_*` constants,
  and `address_to_scriptpubkey` understands `nxrt1`/`xpa1`/`txa1` addresses.
- `feature_loadblock.py` wrote Bitcoin's regtest magic into `linearize.cfg`, so `linearize-data.py`
  scanned the block files forever without ever matching. It takes the magic from `MAGIC_BYTES` now.

Four defects in the tree itself came out of the run and are fixed here, not worked around:

1. `importdescriptors` asked only `keys.keys` (secp256k1) when deciding whether an import carries
   private keys, so it refused every post-quantum descriptor that HAD its key and would have let one
   into a private-keys-disabled wallet. Both checks now look at the ML-DSA and SLH-DSA maps too.
2. `help` with no argument aborted with an internal-bug error: three fork-added RPCs
   (`getmetaldagpowhash`; the two seed-taking RPCs were removed 2026-09-14) began their description with a
   newline, which `RPCHelpMan::ToString` rejects.
3. `sweepv2`'s numeric and object arguments were missing from `src/rpc/client.cpp`, so
   `nex-cli -named sweepv2 conf_target=6` sent strings (`rpc_help.py` catches this).
   (The RPC itself was removed on 2026-09-15, founder decision 5.)
4. Twelve of the 177 benchmarks aborted under `bench_bitcoin -sanity-check`, all on Bitcoin output
   types or a Bitcoin address: `AssembleBlock`, `BlockAssemblerAddPackageTxns`, `BlockFilterIndexSync`,
   `DuplicateInputs` and the four `WalletBalance*` now use the anyone-can-spend witness v3 script
   (`XcoinV3OpTrueScript()` in `src/test/util/script.h`) and an unspendable v3 address.

**Baseline** (founder's Mac, `build/test/functional/test_runner.py --jobs=8`, no filter). BASE_SCRIPTS
is 284 entries; `tool_bench_sanity_check.py` expands to one run per benchmark, so the runner executes
460 scripts:

| | count |
|---|---|
| passed | 280 |
| skipped: not applicable to this chain (each with a one-line reason in the test) | 55 |
| skipped: environment (previous releases, USDT, IPC, zmq, ports) | 20 |
| red (enumerated in `contrib/regenesis/functional-baseline.txt`) | 105 |

The 55 marked not applicable are tests whose premise this chain does not have, and they are skipped
with `self.skip_on_xcoin("<reason>")`, never deleted: Taproot and Schnorr (`feature_taproot`,
`wallet_taproot`), segwit v0 and P2SH (`feature_segwit`, `p2p_segwit`, `feature_bip68_sequence`,
`mempool_accept_wtxid`, `mempool_sigoplimit`), ECDSA script rules (`feature_dersig`, `feature_cltv`,
`feature_csv_activation`, `feature_nulldummy`, `feature_block`, `rpc_createmultisig`,
`rpc_signrawtransactionwithkey`), Bitcoin address and descriptor forms (`rpc_deriveaddresses`,
`rpc_decodescript`, `rpc_invalid_address_message`, `rpc_rawtransaction`, `rpc_getdescriptoractivity`,
`wallet_address_types`, `wallet_avoid_mixing_output_types`, `wallet_balance`, `wallet_descriptor`,
`wallet_hd`, `wallet_keypool`, `wallet_labels`, `wallet_listdescriptors`, `wallet_listsinceblock`,
`wallet_rescan_unconfirmed`, `wallet_signrawtransactionwithwallet`, `wallet_send`,
`wallet_createwallet`, `wallet_createwalletdescriptor`, `wallet_gethdkeys`, `wallet_signer`,
`wallet_miniscript`, `wallet_miniscript_decaying_multisig_descriptor_psbt`,
`wallet_multisig_descriptor_psbt`, `wallet_musig`), MiniWallet's raw modes (`p2p_orphan_handling`,
`p2p_opportunistic_1p1c`, `p2p_1p1c_network`), mainnet, which refuses to start while `GENESIS_IS_FINAL` is false
(`mining_mainnet`, `rpc_validateaddress`), and five benchmarks (the three `ConnectBlock*` ECDSA and
Schnorr ones, and `DeserializeAndCheckBlockTest` / `ReadBlockBench`, whose fixture is a real Bitcoin
mainnet block this chain cannot accept).

The 104 still red group as follows, and each group is work, not a chain difference:

- **16 count absolute block heights or pin a chain hash**, and everything moved by one when the
  framework began mining block 1 (`mining_basic`, `rpc_blockchain` on both transports,
  `rpc_dumptxoutset`, `wallet_create_tx`, `feature_reindex`, `rpc_invalidateblock`,
  `wallet_importprunedfunds`, `interface_bitcoin_cli`, `p2p_mutated_blocks`, `wallet_backup`,
  `feature_coinstatsindex`, `feature_utxo_set_hash`, `rpc_getblockstats`, `rpc_getblockfrompeer`,
  `feature_remove_pruned_files_on_startup`, `feature_loadblock`). Each needs its expected height or
  hash re-derived.
- **4 pad a transaction to a target vsize with an OP_RETURN output** larger than the 80-byte
  `-datacarriersize` of section 5 (`feature_blocksxor`, `feature_rbf`, `mempool_cluster`,
  `mempool_package_limits`). `MiniWallet._bulk_tx` needs a padding form this chain relays.
- **About 30 pin a txid, a size, a fee rate or a mempool shape** that moved because a witness v3
  spend is a different transaction from a p2tr one once a real ML-DSA-65 signature is in it
  (`mempool_packages`, `mempool_reorg`, `mempool_resurrect`, `mempool_ephemeral_dust`,
  `mempool_updatefromblock`, `mempool_truc`, `mempool_accept`, `mempool_dust`, `mempool_limit`,
  `mempool_package_rbf`, `mining_prioritisetransaction`, `p2p_tx_download`, `rpc_packages`,
  `rpc_psbt`, `wallet_*` fee and coin-selection tests).
- **14 still build a Bitcoin-type output somewhere** and hit `bad-txout-not-pq`
  (`feature_assumeutxo`, `feature_fastprune`, `feature_reindex_readonly`, `interface_rest`,
  `p2p_filter`, `p2p_outbound_eviction`, `rpc_generate`, `rpc_scanblocks`, `rpc_scantxoutset`,
  `rpc_txoutproof`, `tool_utxo_to_sqlite`, `wallet_fast_rescan`, `wallet_importdescriptors`,
  `feature_notifications`).
- The rest are p2p and tooling tests whose expectations have not been re-derived for this chain
  (`p2p_*`, `tool_bitcoin`, `tool_wallet`, `tool_utils`, `feature_settings`, `feature_config_args`,
  `interface_rpc`, `rpc_users`, `rpc_whitelist`, `example_test`).

**Open item, found by this stage and not fixed here.** `DescriptorScriptPubKeyMan` persists only
secp256k1 private keys (`m_map_keys` / `m_map_crypted_keys`), and `HavePrivateKeys()` is what gates
`ExpandPrivate` at signing time. A descriptor whose only private material is a LITERAL ML-DSA-65 or
SLH-DSA key (`pqtr(pq(<32-byte seed>))`, `slh(<48-byte seed>)`) therefore imports, reports `ismine`
and `solvable`, and then cannot sign: the coins are unspendable. `importdescriptors` now refuses such
a descriptor out loud instead, and points at the BIP32 form, which works because the post-quantum
keys are derived from the child secp256k1 key. Storing a raw post-quantum key in a wallet is a
wallet feature that has to be built (new database records, encryption) before an emergency SLH-DSA
signer can be imported; it is not a consensus matter and does not gate genesis.

**Cutover gate (checklist step 3).** `test_bitcoin` green AND `test_runner.py` reporting no script
failing that is not named in `contrib/regenesis/functional-baseline.txt`. The gate is that FILE, not a
count: a count cannot tell you whether one script was fixed while another broke, and an independent
re-run of the B6b baseline differed from it by exactly one script for that reason. Regenerate the file
with the command in its header and commit the diff whenever a script is fixed, so the list only ever
shrinks. No test may move from red to skipped without a stated reason written in the test itself.

The file as recorded on 2026-09-06 at `bdd7c28` holds 105 scripts, against 280 passed and 75 skipped
(55 not applicable to this chain, 20 environment).

Re-recorded on 2026-09-14 at `a36b3c3` (audit finding T1: the gate had gone red without the file
saying so). 87 scripts, each with its reason on the same line, tagged INHERITED (an unchanged upstream
test whose Bitcoin-shaped premise this chain does not satisfy) or XCOIN (a failure this tree's own
changes caused: a stale assertion or constant, an unrescaled node constant, the cost of post-quantum
key generation, the reach of the MetalDAG proof-of-work oracle); the XCOIN entries are the ones to fix
first. 21 entries of the 2026-09-06 list pass now; three scripts had gone red since it was recorded
(`feature_framework_testshell`, `wallet_signmessagewithaddress`, `wallet_transactiontime_rescan`) and
are in the file with their causes; `wallet_encryption.py`, which had gone red with `de4c68c`, is green
again with its probe rewritten around a `pqtr` spend, so encrypt / lock / unlock / passphrase change of
a post-quantum wallet is covered by the suite. `bench_bitcoin` is not built in that configuration, so
`tool_bench_sanity_check` expands to nothing and 285 scripts run: 127 passed, 71 skipped, 87 red.

Dress rehearsal (private; not a public testnet, never called one): the full v2 rules on a separate chain for at least 3 days with both nodes, the pool and NerdMiner before mainnet genesis. The relaunched chain IS mainnet; if it fails, that is documented afterwards as a test. Genesis is gated on the go/no-go checklist in section 8, not on a date. The runbook for those three days — the exact commands for both nodes, the pool, the miner and the daily checks, and the record of what stage T2 proved — is `contrib/regenesis/TESTNET-A.md`.
