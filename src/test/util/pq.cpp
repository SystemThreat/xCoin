// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/pq.h>

#include <addresstype.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>

namespace {
struct TestPQKeyData {
    CPQKey key;
    CPQPubKey pubkey;
    CScript script;
    CScript v3_script;

    TestPQKeyData()
    {
        // Fixed 32-byte seed so every test process derives the same keypair
        // and TestChain100Setup stays deterministic.
        static constexpr unsigned char seed[32] = {'n', 'e', 'x', '-', 't', 'e', 's', 't', '-', 'p', 'q', '-', 'c', 'o', 'i', 'n',
                                                   'b', 'a', 's', 'e', '-', 'k', 'e', 'y', '-', 's', 'e', 'e', 'd', '-', '0', '1'};
        pubkey = key.MakeKeyFromSeed(seed);
        assert(pubkey.IsValid());
        script = CScript() << OP_2 << ToByteVector(pubkey.GetID());
        v3_script = XcoinV3ScriptPubKey({XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(pubkey)}});
    }
};

const TestPQKeyData& GetTestPQKeyData()
{
    static const TestPQKeyData data;
    return data;
}

void FillExecData(ScriptExecutionData& execdata, const XcoinV3SignContext& ctx)
{
    execdata.m_tapleaf_hash = ctx.leaf_hash;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = ctx.codeseparator_pos;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_annex_present = ctx.annex.has_value();
    if (ctx.annex) execdata.m_annex_hash = (HashWriter{} << *ctx.annex).GetSHA256();
    execdata.m_annex_init = true;
}
} // namespace

const CPQKey& GetTestPQKey() { return GetTestPQKeyData().key; }
const CPQPubKey& GetTestPQPubKey() { return GetTestPQKeyData().pubkey; }
const CScript& GetTestPQScript() { return GetTestPQKeyData().script; }
const CScript& GetTestXcoinV3Script() { return GetTestPQKeyData().v3_script; }

bool IsTestPQScript(const CScript& spk)
{
    return spk == GetTestPQScript();
}

void SignTestPQInput(CMutableTransaction& tx, unsigned int nIn, const CTxOut& spent_output, int nHashType)
{
    // The witness v2 sighash scriptCode is OP_2 <program>, which is exactly the
    // scriptPubKey being spent (see VerifyWitnessProgram in interpreter.cpp).
    const uint256 sighash{SignatureHash(spent_output.scriptPubKey, tx, nIn, nHashType,
                                        spent_output.nValue, SigVersion::WITNESS_V0)};
    std::vector<unsigned char> sig;
    const bool ok{GetTestPQKey().Sign(sighash, sig)};
    assert(ok);
    sig.push_back(static_cast<unsigned char>(nHashType));
    tx.vin[nIn].scriptWitness.stack = {std::move(sig), ToByteVector(GetTestPQPubKey())};
}

// ── Witness v3 ───────────────────────────────────────────────────────────────

CScript XcoinV3PQLeafScript(const CPQPubKey& pubkey)
{
    return CScript() << ToByteVector(pubkey.GetID()) << OP_CHECKSIG;
}

uint256 XcoinV3LeafHash(const XcoinV3Leaf& leaf)
{
    return ComputeXcoinLeafHash(leaf.version, std::span<const unsigned char>{leaf.script.data(), leaf.script.size()});
}

uint256 XcoinV3Root(const std::vector<XcoinV3Leaf>& leaves)
{
    assert(leaves.size() == 1 || leaves.size() == 2);
    if (leaves.size() == 1) return XcoinV3LeafHash(leaves[0]);
    const uint256 a{XcoinV3LeafHash(leaves[0])};
    const uint256 b{XcoinV3LeafHash(leaves[1])};
    return ComputeXcoinBranchHash(a, b);
}

CScript XcoinV3ScriptPubKey(const std::vector<XcoinV3Leaf>& leaves)
{
    return GetScriptForDestination(WitnessV3PQ{XcoinV3Root(leaves)});
}

std::vector<unsigned char> XcoinV3ControlBlock(const std::vector<XcoinV3Leaf>& leaves, size_t index)
{
    assert(index < leaves.size());
    assert(leaves.size() == 1 || leaves.size() == 2);
    std::vector<unsigned char> control;
    control.push_back(leaves[index].version);
    control.insert(control.end(), XCOIN_V3_NOKEY.begin(), XCOIN_V3_NOKEY.end());
    if (leaves.size() == 2) {
        const uint256 sibling{XcoinV3LeafHash(leaves[1 - index])};
        control.insert(control.end(), sibling.begin(), sibling.end());
    }
    return control;
}

uint256 XcoinV3SighashMessageForTest(const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
    ScriptExecutionData execdata;
    FillExecData(execdata, ctx);
    uint256 out;
    const bool ok{XcoinV3SighashMessage(out, execdata, tx, nIn, static_cast<uint8_t>(hash_type), ctx.sigversion, txdata, MissingDataBehavior::FAIL)};
    assert(ok);
    return out;
}

uint256 XcoinV3SighashForTest(const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
    ScriptExecutionData execdata;
    FillExecData(execdata, ctx);
    uint256 out;
    const bool ok{SignatureHashXcoinV3(out, execdata, tx, nIn, static_cast<uint8_t>(hash_type), ctx.sigversion, txdata, MissingDataBehavior::FAIL)};
    assert(ok);
    return out;
}

std::vector<unsigned char> XcoinV3Sign(const CPQKey& key, const CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, const XcoinV3SignContext& ctx, int hash_type)
{
    assert(ctx.sigversion == SigVersion::XCOIN_PQ_TAPSCRIPT);
    const uint256 digest{XcoinV3SighashForTest(tx, nIn, spent_outputs, ctx, hash_type)};
    std::vector<unsigned char> sig;
    const bool ok{key.SignMessage(std::span<const unsigned char>{digest.begin(), digest.size()}, sig)};
    assert(ok);
    assert(sig.size() == PQ_SIGNATURE_SIZE);
    if (hash_type != 0 /* SIGHASH_DEFAULT */) sig.push_back(static_cast<unsigned char>(hash_type));
    return sig;
}

void SignTestXcoinV3Input(CMutableTransaction& tx, unsigned int nIn, const std::vector<CTxOut>& spent_outputs, int hash_type)
{
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(GetTestPQPubKey())}};
    const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0])};
    std::vector<unsigned char> sig{XcoinV3Sign(GetTestPQKey(), tx, nIn, spent_outputs, ctx, hash_type)};
    tx.vin[nIn].scriptWitness.stack = {ToByteVector(GetTestPQPubKey()), std::move(sig), ToByteVector(leaves[0].script), XcoinV3ControlBlock(leaves, 0)};
}
