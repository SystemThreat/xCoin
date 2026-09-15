// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_XCOIN_V3_H
#define BITCOIN_SCRIPT_XCOIN_V3_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

/**
 * Witness v3 (contrib/regenesis/REGENESIS.md section 4): the post-quantum
 * script-tree output. A 32-byte program commits to a Merkle root of
 * algorithm-tagged leaves; there is no key path.
 *
 * Every tag, constant and identifier here is scoped to the PROJECT name
 * (xcoin / XCoin), never to the ticker: the ticker is a presentation detail
 * that may change, consensus tags may not.
 */

/** Size of a witness v3 program (the Merkle root). */
static constexpr size_t WITNESS_V3_SIZE = 32;

/** Tag strings. Tagged hashing is BIP-340 style: SHA256(SHA256(tag) || SHA256(tag) || msg). */
static constexpr std::string_view XCOIN_V3_LEAF_TAG{"XCoinLeaf"};
static constexpr std::string_view XCOIN_V3_BRANCH_TAG{"XCoinBranch"};
static constexpr std::string_view XCOIN_V3_SIGHASH_TAG{"XCoinSighash/v3"};
/** The "no key" marker is a PLAIN SHA-256 of this string (not a tagged hash). */
static constexpr std::string_view XCOIN_V3_NOKEY_TAG{"xcoin/v3/nokey"};

/** The 32 bytes that occupy the internal-key slot of every v3 control block:
 *  SHA-256("xcoin/v3/nokey"). Any other value makes the control block invalid. */
extern const uint256 XCOIN_V3_NOKEY;

/** Leaf versions (control block byte 0; bit 0 is the Taproot parity bit and must be 0). */
static constexpr uint8_t XCOIN_LEAF_PQ = 0xc0;              //!< ML-DSA-65 tapscript (everyday; key hash in the script, key on the witness)
static constexpr uint8_t XCOIN_LEAF_SLH = 0xc2;             //!< SLH-DSA-SHA2-128s tapscript (fallback; 32-byte key in the script)
static constexpr uint8_t XCOIN_LEAF_RESERVED_PROOF = 0xc4;  //!< reserved: proof predicate
static constexpr uint8_t XCOIN_LEAF_RESERVED_LEDGER = 0xc6; //!< reserved: ledger commitment / Merkle exit

/** key_version bytes committed in the v3 sighash (BIP-341 message, tapscript extension). */
static constexpr uint8_t XCOIN_V3_KEY_VERSION_MLDSA = 0x02;
static constexpr uint8_t XCOIN_V3_KEY_VERSION_SLH = 0x03;

/** Control block: leaf version (1) || XCOIN_V3_NOKEY (32) || path (32 * m), same shape as Taproot. */
static constexpr size_t XCOIN_V3_CONTROL_BASE_SIZE = 33;
static constexpr size_t XCOIN_V3_CONTROL_NODE_SIZE = 32;
static constexpr size_t XCOIN_V3_CONTROL_MAX_NODE_COUNT = 128;
static constexpr size_t XCOIN_V3_CONTROL_MAX_SIZE = XCOIN_V3_CONTROL_BASE_SIZE + XCOIN_V3_CONTROL_NODE_SIZE * XCOIN_V3_CONTROL_MAX_NODE_COUNT;

/** Initial witness stack elements under v3 may be this large (an SLH-DSA-128s
 *  signature plus its hash-type byte is 7,857 bytes). Elements pushed DURING
 *  execution keep MAX_SCRIPT_ELEMENT_SIZE (520).
 *
 *  Because an element can be 16x larger than in any other script context, a v3
 *  leaf carries three limits that BIP 342 tapscript does not (fee study D8,
 *  founder decision "cpu"; all enforced in EvalScript for SigVersion::
 *  XCOIN_PQ_TAPSCRIPT and XCOIN_SLH_TAPSCRIPT only, never for TAPSCRIPT):
 *
 *   1. MAX_SCRIPT_SIZE (10,000 bytes, SCRIPT_ERR_SCRIPT_SIZE) and
 *      MAX_OPS_PER_SCRIPT (201 non-push opcodes, SCRIPT_ERR_OP_COUNT) apply to
 *      the leaf script exactly as they do to BASE / WITNESS_V0 scripts. Pushes
 *      (up to OP_16) do not count; OP_SUCCESSx is still scanned for first.
 *   2. Every hash opcode (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160,
 *      OP_HASH256) charges XCOIN_V3_VALIDATION_WEIGHT_PER_HASHED_BYTE per byte
 *      hashed against the same validation-weight budget as the signature checks
 *      (OP_HASH160 / OP_HASH256 hash their input and then the 32-byte digest, so
 *      they charge size + 32), and the script fails with
 *      SCRIPT_ERR_XCOIN_V3_HASH_WEIGHT when the budget goes negative. The charge
 *      is made before the hash is computed.
 *   3. The stack-copying opcodes (OP_DUP, OP_2DUP, OP_3DUP, OP_OVER, OP_2OVER,
 *      OP_IFDUP, OP_TUCK, OP_PICK) and the moving ones (OP_ROLL, OP_2ROT,
 *      OP_TOALTSTACK, OP_FROMALTSTACK) charge nothing; limit 1 bounds them, see
 *      below.
 *
 *  Why. Before these limits a 3-byte leaf, OP_DUP OP_SHA256 OP_DROP, hashed an
 *  8,192-byte witness element over and over: 2,731 bytes of SHA-256 per script
 *  byte, and every script byte is one weight unit, so about 10.9 GB of hashing
 *  per 4,000,000 WU block and 175 GB per 64,000,000 WU block, against 25.3 s of
 *  signature verification that the two weights below are tuned to bound.
 *
 *  Worst case now. Bytes hashed by an input can never exceed its budget, the
 *  serialized witness stack plus VALIDATION_WEIGHT_OFFSET (50), and every
 *  witness byte is one weight unit, so a block hashes at most
 *  block weight + 50 x (number of v3 inputs). The smallest v3 input is 41 base
 *  bytes (164 WU) plus a 37-byte witness ([OP_1 leaf, 33-byte control block]),
 *  201 WU, so a 4,000,000 WU block holds at most 19,900 v3 inputs and a
 *  64,000,000 WU block at most 318,407:
 *    4M block:  4,000,000 + 50 x 19,900  =  4,995,000 bytes, about 5.0 MB;
 *    64M block: 64,000,000 + 50 x 318,407 = 79,920,350 bytes, about 80 MB
 *  of hashing (a few hundred milliseconds single-threaded at SHA-256 speed),
 *  down from 10.9 GB and 175 GB. The budget is shared with the signature
 *  checks, so a block that hashes 80 MB verifies no signatures and vice versa;
 *  the 25.3 s signature bound of section 4 stays the block's worst case.
 *
 *  Why copies are not charged (limit 3). With limit 1 a leaf runs at most 201
 *  non-push opcodes and the widest of them, OP_3DUP, copies three elements, so
 *  an input copies at most 201 x 3 x 8,192 = 4,939,776 bytes, about 4.9 MB, and
 *  holds at most MAX_STACK_SIZE x 8,192 = 8.2 MB of stack. An input that
 *  carries an 8,192-byte element and a 201-opcode leaf weighs at least 8,596
 *  WU (164 base, 8,432 witness), so at most 465 of them fit a 4M block and
 *  7,445 a 64M block: under 2.3 GB and 36.8 GB of memcpy per block (the bound
 *  is loose: three 8,192-byte elements for OP_3DUP to copy make the input three
 *  times heavier), one to two seconds single-threaded
 *  at the speed of a cache-resident 8 KB copy, under 8% of the signature
 *  bound. A charge on the copying opcodes alone would not tighten that, because
 *  the moving opcodes (OP_ROLL, OP_2ROT, OP_TOALTSTACK, OP_FROMALTSTACK) copy
 *  the same bytes inside the interpreter without creating a new element, and a
 *  charge on those would refuse a witness that merely reorders a 7,857-byte
 *  SLH-DSA signature. Hashing had to be charged because SHA-256 costs 20-50x
 *  more per byte than a copy and, before limit 1, was bounded only by the block
 *  size. */
static constexpr size_t MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE = 8192;

/** Validation weight charged per byte hashed by a hash opcode inside a v3 leaf
 *  (limit 2 above). One unit per byte: a 32-byte hash-lock preimage costs 32 of
 *  the ~5,300 units an ML-DSA leaf spend carries, or ~7,900 for an SLH one. */
static constexpr int64_t XCOIN_V3_VALIDATION_WEIGHT_PER_HASHED_BYTE = 1;

/** Validation weight (BIP-342 budget) charged per non-empty signature check.
 *
 *  The budget for an input is its serialized witness stack plus
 *  VALIDATION_WEIGHT_OFFSET (50), and a witness byte costs one unit of block
 *  weight, so a full 64,000,000 WU block can afford about
 *  64,000,000 / weight checks of a given kind. The two constants must
 *  therefore stand in the ratio of the two verification COSTS, or the cheaper
 *  constant makes its leaf the block's worst case.
 *
 *  Measured on the founder's M3 Pro, release build, this tree's own PQClean
 *  code (bench_bitcoin -filter='XcoinVerify.*', src/bench/xcoin_pq.cpp, 6 runs):
 *  ML-DSA-65 verify 79.1 us median (76.8-81.1), SLH-DSA-SHA2-128s verify
 *  418.9 us median (383.9-432.3), a ratio of 5.30 at the medians and 5.63 at
 *  the worst pairing; an independent reviewer measured 79.6 us and 433.1 us,
 *  a ratio of 5.44. 1080 / 200 = 5.4 sits in the middle of that spread.
 *
 *  Both constants were scaled 4x with MAX_BLOCK_WEIGHT when it went from 16M
 *  to 64M WU (founder decision 2026-09-07), which is what keeps the CPU bound
 *  where it was: 64,000,000 / 200 is the same 320,000 ML-DSA checks that
 *  16,000,000 / 50 bought, so the bound these two constants freeze is still
 *  25.3 s of single-threaded verification for the worst possible block, set by
 *  the ML-DSA leaf, with the SLH leaf at 64,000,000 / 1080 = 59,259 checks and
 *  24.8 s just under it. Capacity doubled twice; the worst case did not move.
 *
 *  Raising the weights does not constrain ordinary spends, because the budget
 *  grows with the witness and post-quantum signatures are large: an ML-DSA leaf
 *  spend carries ~5,300 witness bytes of budget and spends 200 of it (26x
 *  headroom), an SLH leaf ~7,900 and spends 1,080 (7.4x). Multi-signature
 *  scales too, since each further signature brings its own witness bytes. The
 *  budget only binds a script that runs many checks against FEW signature
 *  bytes, which is exactly the case it exists to bound.
 *
 *  See REGENESIS.md section 4 for the table. */
static constexpr int64_t XCOIN_V3_VALIDATION_WEIGHT_MLDSA = 200;
static constexpr int64_t XCOIN_V3_VALIDATION_WEIGHT_SLH = 1080;

/** Compute the v3 leaf hash: tagged_hash("XCoinLeaf", leaf_version || compact_size(script) || script). */
uint256 ComputeXcoinLeafHash(uint8_t leaf_version, std::span<const unsigned char> script);
/** Compute the v3 branch hash: tagged_hash("XCoinBranch", sorted(a, b)). Spans must be 32 bytes each. */
uint256 ComputeXcoinBranchHash(std::span<const unsigned char> a, std::span<const unsigned char> b);
/** Walk the control block's Merkle path from a leaf hash to the root with the xCoin branch tag.
 *  Requires control block to have valid length (33 + k*32, with k in {0,1,..,128}). */
uint256 ComputeXcoinV3MerkleRoot(std::span<const unsigned char> control, const uint256& leaf_hash);
/** The 32-byte message an ML-DSA leaf signature is over, and the digest an SLH-DSA leaf
 *  signature covers in FIPS 205 pure mode with an empty context:
 *  tagged_hash("XCoinSighash/v3", bip341_message). */
uint256 XcoinV3TagSighash(const uint256& bip341_message);

#endif // BITCOIN_SCRIPT_XCOIN_V3_H
