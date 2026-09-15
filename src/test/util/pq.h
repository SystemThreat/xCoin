// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_PQ_H
#define BITCOIN_TEST_UTIL_PQ_H

#include <consensus/params.h>
#include <pqkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/xcoin_v3.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

struct CMutableTransaction;
class CTxOut;

/** Deterministic ML-DSA-65 key for test fixtures. The NEX PQ-only output rule
 *  (bad-txout-not-pq) means every spendable output a test mines or relays must
 *  be WITNESS_V2_PQ, and spending one always requires a real ML-DSA-65
 *  signature — there is no anyone-can-spend script type on NEX. */
const CPQKey& GetTestPQKey();
const CPQPubKey& GetTestPQPubKey();

/** scriptPubKey paying to GetTestPQKey(): OP_2 <SHA256(pubkey)>. */
const CScript& GetTestPQScript();

/** Whether spk is the WITNESS_V2_PQ output locked to GetTestPQKey(). */
bool IsTestPQScript(const CScript& spk);

/** Fill tx.vin[nIn].scriptWitness with a valid ML-DSA-65 witness spending a
 *  WITNESS_V2_PQ prevout locked to GetTestPQKey(). */
void SignTestPQInput(CMutableTransaction& tx, unsigned int nIn, const CTxOut& spent_output, int nHashType = 1 /* SIGHASH_ALL */);

// ── Witness v3 (REGENESIS.md section 4) ─────────────────────────────────────

/** One leaf of an xCoin witness v3 script tree. */
struct XcoinV3Leaf {
    uint8_t version{XCOIN_LEAF_PQ};
    CScript script;
};

/** `<SHA256(pubkey)> OP_CHECKSIG`: the everyday ML-DSA-65 leaf. */
CScript XcoinV3PQLeafScript(const CPQPubKey& pubkey);
/** tagged_hash("XCoinLeaf", version || compact_size(script) || script). */
uint256 XcoinV3LeafHash(const XcoinV3Leaf& leaf);
/** Merkle root of a 1- or 2-leaf tree (a single leaf's root is its leaf hash). */
uint256 XcoinV3Root(const std::vector<XcoinV3Leaf>& leaves);
/** scriptPubKey OP_3 <root>. */
CScript XcoinV3ScriptPubKey(const std::vector<XcoinV3Leaf>& leaves);
/** Control block `[version || XCOIN_V3_NOKEY || path]` proving leaves[index] (1- or 2-leaf tree). */
std::vector<unsigned char> XcoinV3ControlBlock(const std::vector<XcoinV3Leaf>& leaves, size_t index);

/** Everything besides the transaction that the v3 sighash commits to. `sigversion` selects the
 *  leaf algorithm and therefore the key_version byte: XCOIN_PQ_TAPSCRIPT (0x02, ML-DSA) or
 *  XCOIN_SLH_TAPSCRIPT (0x03, SLH-DSA). */
struct XcoinV3SignContext {
    uint256 leaf_hash;
    uint32_t codeseparator_pos{0xFFFFFFFF};
    std::optional<std::vector<unsigned char>> annex;
    SigVersion sigversion{SigVersion::XCOIN_PQ_TAPSCRIPT};
};
/** The BIP-341 message (key_version per ctx.sigversion) BEFORE the "XCoinSighash/v3" tag. */
uint256 XcoinV3SighashMessageForTest(const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type = 0 /* SIGHASH_DEFAULT */);
/** The final tagged digest that ML-DSA signs (or SLH-DSA, in FIPS 205 pure mode with an empty context). */
uint256 XcoinV3SighashForTest(const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type = 0 /* SIGHASH_DEFAULT */);
/** ML-DSA-65 signature over the final digest; the hash-type byte is appended unless SIGHASH_DEFAULT. */
std::vector<unsigned char> XcoinV3Sign(const CPQKey& key, const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type = 0 /* SIGHASH_DEFAULT */);

/** scriptPubKey OP_3 <root of the single PQ leaf for GetTestPQKey()>. */
const CScript& GetTestXcoinV3Script();
/** Fill tx.vin[nIn].scriptWitness with `[pubkey, sig, leaf script, control]` spending a
 *  GetTestXcoinV3Script() prevout. spent_outputs must list the prevout of EVERY input. */
void SignTestXcoinV3Input(CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, int hash_type = 0 /* SIGHASH_DEFAULT */);

#endif // BITCOIN_TEST_UTIL_PQ_H
