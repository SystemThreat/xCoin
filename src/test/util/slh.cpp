// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/slh.h>

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/util/pq.h>
#include <uint256.h>

#include <cassert>
#include <string_view>

namespace {
struct TestSLHKeyData {
    CSLHTestKey key;
    CSLHPubKey pubkey;
    std::vector<XcoinV3Leaf> leaves;
    CScript script;

    TestSLHKeyData()
    {
        // Fixed 48-byte seed so every test process derives the same key pair.
        static constexpr std::string_view seed{"xcoin-test-slh-dsa-sha2-128s-fallback-seed-00001"};
        static_assert(seed.size() == SLH_SEED_SIZE);
        pubkey = key.MakeKeyFromSeed(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});
        assert(pubkey.IsValid());
        leaves = {XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(GetTestPQPubKey())},
                  XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3SLHLeafScript(pubkey)}};
        script = XcoinV3ScriptPubKey(leaves);
    }
};

const TestSLHKeyData& GetTestSLHKeyData()
{
    static const TestSLHKeyData data;
    return data;
}
} // namespace

const CSLHTestKey& GetTestSLHKey() { return GetTestSLHKeyData().key; }
const CSLHPubKey& GetTestSLHPubKey() { return GetTestSLHKeyData().pubkey; }
const std::vector<XcoinV3Leaf>& GetTestXcoinV3PQSLHLeaves() { return GetTestSLHKeyData().leaves; }
const CScript& GetTestXcoinV3PQSLHScript() { return GetTestSLHKeyData().script; }

CScript XcoinV3SLHLeafScript(const CSLHPubKey& pubkey)
{
    assert(pubkey.IsValid());
    return CScript() << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIG;
}

std::vector<unsigned char> XcoinV3SignSLH(const CSLHTestKey& key, const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type)
{
    assert(ctx.sigversion == SigVersion::XCOIN_SLH_TAPSCRIPT);
    const uint256 digest{XcoinV3SighashForTest(tx, nIn, spent_outputs, ctx, hash_type)};
    std::vector<unsigned char> sig;
    const bool ok{key.Sign(digest, sig)};
    assert(ok);
    assert(sig.size() == SLH_SIGNATURE_SIZE);
    if (hash_type != 0 /* SIGHASH_DEFAULT */) sig.push_back(static_cast<unsigned char>(hash_type));
    return sig;
}

void SignTestXcoinV3SLHInput(CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, int hash_type)
{
    const std::vector<XcoinV3Leaf>& leaves{GetTestXcoinV3PQSLHLeaves()};
    const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[1]), .sigversion = SigVersion::XCOIN_SLH_TAPSCRIPT};
    std::vector<unsigned char> sig{XcoinV3SignSLH(GetTestSLHKey(), tx, nIn, spent_outputs, ctx, hash_type)};
    tx.vin[nIn].scriptWitness.stack = {std::move(sig), ToByteVector(leaves[1].script), XcoinV3ControlBlock(leaves, 1)};
}
