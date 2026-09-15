// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SLH_H
#define BITCOIN_TEST_UTIL_SLH_H

#include <script/script.h>
#include <slhkey.h>
#include <test/util/pq.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

struct CMutableTransaction;
class CTxOut;

/** The SLH-DSA-SHA2-128s secret key with key generation and signing now lives in
 *  src/slhkey.h (CSLHKey, stage B3); the old test name is kept as an alias. */
using CSLHTestKey = CSLHKey;

/** Deterministic SLH-DSA key for test fixtures. */
const CSLHTestKey& GetTestSLHKey();
const CSLHPubKey& GetTestSLHPubKey();

/** `<pubkey32> OP_CHECKSIG`: the SLH-DSA fallback leaf (the key itself is in the script). */
CScript XcoinV3SLHLeafScript(const CSLHPubKey& pubkey);

/** SLH-DSA signature over the v3 digest of an SLH leaf (key_version 0x03); the hash-type
 *  byte is appended unless SIGHASH_DEFAULT. ctx.sigversion must be XCOIN_SLH_TAPSCRIPT. */
std::vector<unsigned char> XcoinV3SignSLH(const CSLHTestKey& key, const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type = 0 /* SIGHASH_DEFAULT */);

/** The two-leaf tree {pq(GetTestPQPubKey()), slh(GetTestSLHPubKey())} — leaf 0 is the
 *  ML-DSA leaf, leaf 1 the SLH-DSA leaf — and its scriptPubKey OP_3 <root>. */
const std::vector<XcoinV3Leaf>& GetTestXcoinV3PQSLHLeaves();
const CScript& GetTestXcoinV3PQSLHScript();

/** Fill tx.vin[nIn].scriptWitness with `[sig, leaf script, control]` spending a
 *  GetTestXcoinV3PQSLHScript() prevout through the SLH-DSA leaf. spent_outputs must list
 *  the prevout of EVERY input. */
void SignTestXcoinV3SLHInput(CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, int hash_type = 0 /* SIGHASH_DEFAULT */);

#endif // BITCOIN_TEST_UTIL_SLH_H
