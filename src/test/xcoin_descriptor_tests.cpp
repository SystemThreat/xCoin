// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stage B3 (contrib/regenesis/REGENESIS.md section 4): the post-quantum
// descriptors pq(KEY) (legacy witness v2), slh(KEY) and pqtr(TREE) (witness v3),
// their time-locked leaf forms, BIP32-derived keys, the descriptor cache, and
// signing through ProduceSignature (ML-DSA leaf, SLH-DSA leaf, witness v2).

#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pqhd.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <script/xcoin_v3.h>
#include <slhkey.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>
#include <test/util/slh.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using valtype = std::vector<unsigned char>;

namespace {

/** The seeds of the shared test keys (src/test/util/pq.cpp, slh.cpp), as descriptor private keys. */
std::string TestPQSeedHex()
{
    static constexpr std::string_view seed{"nex-test-pq-coinbase-key-seed-01"};
    return HexStr(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});
}
std::string TestSLHSeedHex()
{
    static constexpr std::string_view seed{"xcoin-test-slh-dsa-sha2-128s-fallback-seed-00001"};
    return HexStr(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});
}
std::string TestPQPubHex() { return HexStr(GetTestPQPubKey()); }
std::string TestSLHPubHex() { return HexStr(GetTestSLHPubKey()); }

std::unique_ptr<Descriptor> ParseOne(const std::string& str, FlatSigningProvider& keys)
{
    std::string error;
    auto descs = Parse(str, keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, str + ": " + error);
    return std::move(descs.at(0));
}

std::string ParseError(const std::string& str)
{
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(str, keys, error, /*require_checksum=*/false);
    BOOST_CHECK_MESSAGE(descs.empty(), str + " unexpectedly parsed");
    return error;
}

/** Strip a trailing #checksum. */
std::string NoChecksum(std::string s)
{
    if (s.size() > 9 && s[s.size() - 9] == '#') s.resize(s.size() - 9);
    return s;
}

CScript ExpandOne(const Descriptor& desc, int pos, const SigningProvider& keys, FlatSigningProvider& out, DescriptorCache* cache = nullptr)
{
    std::vector<CScript> scripts;
    BOOST_REQUIRE(desc.Expand(pos, keys, scripts, out, cache));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    return scripts[0];
}

/** A one-input transaction spending `spk`; signs with ProduceSignature and verifies with the
 *  real checker under the standard flags (the same path the wallet and PSBT signers use). */
struct Spend {
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    static constexpr CAmount VALUE{100 * COIN};

    explicit Spend(const CScript& spk, uint32_t sequence = CTxIn::SEQUENCE_FINAL - 1, uint32_t locktime = 0)
    {
        spent.emplace_back(VALUE, spk);
        tx.version = 2;
        tx.nLockTime = locktime;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, sequence);
        tx.vout.emplace_back(VALUE - 10000, GetTestXcoinV3Script());
    }

    bool Sign(const SigningProvider& provider, int hash_type = SIGHASH_DEFAULT)
    {
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
        MutableTransactionSignatureCreator creator{tx, 0, spent[0].nValue, &txdata, hash_type};
        SignatureData sigdata;
        const bool ok = ProduceSignature(provider, creator, spent[0].scriptPubKey, sigdata);
        if (ok) UpdateInput(tx.vin[0], sigdata);
        return ok;
    }

    bool Verify(ScriptError* err = nullptr) const
    {
        const CTransaction ctx{tx};
        PrecomputedTransactionData txdata;
        txdata.Init(ctx, std::vector<CTxOut>{spent});
        const TransactionSignatureChecker checker(&ctx, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);
        return VerifyScript(ctx.vin[0].scriptSig, spent[0].scriptPubKey, &ctx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, err);
    }

    std::vector<size_t> WitnessSizes() const
    {
        std::vector<size_t> sizes;
        for (const auto& item : tx.vin[0].scriptWitness.stack) sizes.push_back(item.size());
        return sizes;
    }
};

const std::vector<size_t> MLDSA_LEAF_WITNESS{PQ_PUBKEY_SIZE, PQ_SIGNATURE_SIZE, 34, 65};
const std::vector<size_t> SLH_LEAF_WITNESS{SLH_SIGNATURE_SIZE, 34, 65};

} // namespace

BOOST_FIXTURE_TEST_SUITE(xcoin_descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_witness_v2_descriptor)
{
    const std::string prv = "pq(" + TestPQSeedHex() + ")";
    const std::string pub = "pq(" + TestPQPubHex() + ")";

    FlatSigningProvider keys_prv, keys_pub;
    auto desc_prv = ParseOne(prv, keys_prv);
    auto desc_pub = ParseOne(pub, keys_pub);
    BOOST_CHECK_EQUAL(keys_prv.pq_keys.size(), 1U);
    BOOST_CHECK(keys_pub.pq_keys.empty());

    // Strings: the public form is the 1,952-byte key, the private form the 32-byte seed.
    BOOST_CHECK_EQUAL(NoChecksum(desc_prv->ToString()), pub);
    BOOST_CHECK_EQUAL(NoChecksum(desc_pub->ToString()), pub);
    std::string prv_out;
    BOOST_CHECK(desc_prv->ToPrivateString(keys_prv, prv_out));
    BOOST_CHECK_EQUAL(NoChecksum(prv_out), prv);
    BOOST_CHECK(!desc_pub->ToPrivateString(keys_pub, prv_out));
    BOOST_CHECK(desc_prv->HavePrivateKeys(keys_prv));
    BOOST_CHECK(!desc_pub->HavePrivateKeys(keys_pub));
    BOOST_CHECK(!desc_prv->IsRange());
    BOOST_CHECK(desc_prv->IsSolvable());
    BOOST_CHECK(desc_prv->IsSingleType());
    BOOST_CHECK(desc_prv->GetOutputType() == OutputType::XCOIN_V2);
    BOOST_CHECK_EQUAL(desc_prv->GetKeyCount(), 1U);
    BOOST_CHECK_EQUAL(desc_prv->GetMaxKeyExpr(), 0U);
    BOOST_CHECK_EQUAL(*desc_prv->ScriptSize(), 34);
    BOOST_CHECK_EQUAL(*desc_prv->MaxSatisfactionWeight(true), 3 + 1952 + 3 + 3310);
    BOOST_CHECK_EQUAL(*desc_prv->MaxSatisfactionElems(), 2);

    // Expansion: OP_2 <SHA256(pubkey)>, i.e. the shared test v2 script.
    FlatSigningProvider out_prv, out_pub;
    const CScript spk = ExpandOne(*desc_prv, 0, keys_prv, out_prv);
    BOOST_CHECK(spk == GetTestPQScript());
    BOOST_CHECK(ExpandOne(*desc_pub, 0, keys_pub, out_pub) == spk);
    BOOST_CHECK_EQUAL(out_pub.pq_pubkeys.size(), 1U);
    BOOST_CHECK(out_pub.pq_pubkeys.begin()->second == GetTestPQPubKey());
    FlatSigningProvider signing;
    desc_prv->ExpandPrivate(0, keys_prv, signing);
    BOOST_CHECK_EQUAL(signing.pq_keys.size(), 1U);

    // Signing: [sig || hashtype, pubkey]; the public provider alone cannot sign.
    {
        Spend s{spk};
        BOOST_CHECK(!s.Sign(out_pub));
        FlatSigningProvider all{out_pub};
        all.Merge(FlatSigningProvider{signing});
        BOOST_REQUIRE(s.Sign(all));
        BOOST_CHECK(s.WitnessSizes() == std::vector<size_t>({PQ_SIGNATURE_SIZE + 1, PQ_PUBKEY_SIZE}));
        BOOST_CHECK_EQUAL(s.tx.vin[0].scriptWitness.stack[0].back(), SIGHASH_ALL); // SIGHASH_DEFAULT is signed as ALL on v2
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(s.Verify(&err), ScriptErrorString(err));
    }

    // Inference: pq(<pubkey>) when the key is known, addr() otherwise.
    BOOST_CHECK_EQUAL(NoChecksum(InferDescriptor(spk, out_pub)->ToString()), pub);
    BOOST_CHECK(InferDescriptor(spk, out_pub)->IsSolvable());
    const FlatSigningProvider empty;
    BOOST_CHECK(InferDescriptor(spk, empty)->ToString().rfind("addr(", 0) == 0);
    BOOST_CHECK(!InferDescriptor(spk, empty)->IsSolvable());

    // A 4,032-byte expanded secret key is accepted as a private form too and prints as the seed-less key.
    const CPQKey& key = GetTestPQKey();
    FlatSigningProvider keys_sk;
    auto desc_sk = ParseOne("pq(" + HexStr(std::span<const unsigned char>{key.data(), key.size()}) + ")", keys_sk);
    BOOST_CHECK_EQUAL(NoChecksum(desc_sk->ToString()), pub);
    BOOST_CHECK(desc_sk->ToPrivateString(keys_sk, prv_out));
    BOOST_CHECK_EQUAL(prv_out.size(), std::string("pq()").size() + PQ_SECRETKEY_SIZE * 2 + 9);
}

BOOST_AUTO_TEST_CASE(pqtr_two_leaf_tree)
{
    const std::string prv = "pqtr({pq(" + TestPQSeedHex() + "),slh(" + TestSLHSeedHex() + ")})";
    const std::string pub = "pqtr({pq(" + TestPQPubHex() + "),slh(" + TestSLHPubHex() + ")})";
    FlatSigningProvider keys_prv, keys_pub;
    auto desc_prv = ParseOne(prv, keys_prv);
    auto desc_pub = ParseOne(pub, keys_pub);
    BOOST_CHECK_EQUAL(keys_prv.pq_keys.size(), 1U);
    BOOST_CHECK_EQUAL(keys_prv.slh_keys.size(), 1U);
    BOOST_CHECK_EQUAL(NoChecksum(desc_prv->ToString()), pub);
    std::string prv_out;
    BOOST_CHECK(desc_prv->ToPrivateString(keys_prv, prv_out));
    BOOST_CHECK_EQUAL(NoChecksum(prv_out), prv);
    BOOST_CHECK(desc_prv->GetOutputType() == OutputType::XCOIN_V3);
    BOOST_CHECK_EQUAL(desc_prv->GetKeyCount(), 2U);
    BOOST_CHECK_EQUAL(desc_prv->GetMaxKeyExpr(), 1U);
    BOOST_CHECK_EQUAL(*desc_prv->ScriptSize(), 34);
    // Fee budget: the ML-DSA leaf, which carries no timelock, so the signer can always take it
    // and every ordinary spend does (audit finding W7 is the time-locked case, tested below):
    // pubkey item + signature item + script + control block.
    BOOST_CHECK_EQUAL(*desc_prv->MaxSatisfactionWeight(true), (3 + 1952) + (3 + 3309) + (1 + 34) + (1 + 65));
    BOOST_CHECK_EQUAL(*desc_prv->MaxSatisfactionElems(), 4);
    BOOST_CHECK_EQUAL(*desc_prv->MaxSatisfactionWeight(true), *desc_pub->MaxSatisfactionWeight(true));

    // The tree is exactly the {pq, slh} tree of the B2 test helpers: same root, same control blocks.
    FlatSigningProvider out;
    const CScript spk = ExpandOne(*desc_prv, 0, keys_prv, out);
    BOOST_CHECK(spk == GetTestXcoinV3PQSLHScript());
    BOOST_CHECK(ExpandOne(*desc_pub, 0, keys_pub, out) == spk);
    const uint256 root{std::vector<unsigned char>(spk.begin() + 2, spk.end())};
    XcoinV3SpendData spenddata;
    BOOST_REQUIRE(out.GetXcoinV3SpendData(root, spenddata));
    BOOST_CHECK(spenddata.merkle_root == root);
    BOOST_REQUIRE_EQUAL(spenddata.scripts.size(), 2U);
    const auto& leaves = GetTestXcoinV3PQSLHLeaves();
    for (size_t i = 0; i < 2; ++i) {
        const auto it = spenddata.scripts.find({ToByteVector(leaves[i].script), leaves[i].version});
        BOOST_REQUIRE(it != spenddata.scripts.end());
        BOOST_REQUIRE_EQUAL(it->second.size(), 1U);
        BOOST_CHECK(*it->second.begin() == XcoinV3ControlBlock(leaves, i));
    }
    // InferXcoinV3Tree reconstructs the tree with siblings in leaf-hash order (a control block
    // cannot tell left from right); the inferred descriptor is one of the two equivalent strings.
    const auto tree = InferXcoinV3Tree(spenddata, root);
    BOOST_REQUIRE(tree);
    BOOST_REQUIRE_EQUAL(tree->size(), 2U);
    BOOST_CHECK_EQUAL(std::get<0>((*tree)[0]), 1);
    BOOST_CHECK_EQUAL(std::get<0>((*tree)[1]), 1);
    const bool pq_first = XcoinV3LeafHash(leaves[0]) < XcoinV3LeafHash(leaves[1]);
    BOOST_CHECK_EQUAL(std::get<2>((*tree)[0]), pq_first ? XCOIN_LEAF_PQ : XCOIN_LEAF_SLH);
    BOOST_CHECK_EQUAL(std::get<2>((*tree)[1]), pq_first ? XCOIN_LEAF_SLH : XCOIN_LEAF_PQ);
    const std::string pub_swapped = "pqtr({slh(" + TestSLHPubHex() + "),pq(" + TestPQPubHex() + ")})";
    BOOST_CHECK_EQUAL(NoChecksum(InferDescriptor(spk, out)->ToString()), pq_first ? pub : pub_swapped);
    BOOST_CHECK_EQUAL(NoChecksum(InferDescriptor(spk, out)->ToString()), NoChecksum(InferDescriptor(spk, out)->ToString())); // stable

    FlatSigningProvider signing;
    desc_prv->ExpandPrivate(0, keys_prv, signing);
    BOOST_CHECK_EQUAL(signing.pq_keys.size(), 1U);
    BOOST_CHECK_EQUAL(signing.slh_keys.size(), 1U);

    // Both keys: the (smaller) ML-DSA leaf is chosen; [pubkey, sig, script, control].
    {
        Spend s{spk};
        FlatSigningProvider all{out};
        all.Merge(FlatSigningProvider{signing});
        BOOST_REQUIRE(s.Sign(all));
        BOOST_CHECK(s.WitnessSizes() == MLDSA_LEAF_WITNESS);
        BOOST_CHECK(s.tx.vin[0].scriptWitness.stack[2] == ToByteVector(leaves[0].script));
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(s.Verify(&err), ScriptErrorString(err));
        // Explicit hash types get the trailing byte.
        Spend s1{spk};
        BOOST_REQUIRE(s1.Sign(all, SIGHASH_ALL));
        BOOST_CHECK_EQUAL(s1.tx.vin[0].scriptWitness.stack[1].size(), PQ_SIGNATURE_SIZE + 1);
        BOOST_CHECK(s1.Verify());
        Spend s2{spk};
        BOOST_REQUIRE(s2.Sign(all, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY));
        BOOST_CHECK(s2.Verify());
    }
    // Only the SLH-DSA key (the fallback, e.g. descriptorprocesspsbt with pqtr({pq(<pub>),slh(<seed>)})):
    // [sig, script, control], key_version 0x03.
    {
        const std::string slh_only = "pqtr({pq(" + TestPQPubHex() + "),slh(" + TestSLHSeedHex() + ")})";
        FlatSigningProvider keys_slh, out_slh;
        auto desc_slh = ParseOne(slh_only, keys_slh);
        BOOST_CHECK(!desc_slh->HavePrivateKeys(keys_slh)); // not ALL keys
        BOOST_CHECK(ExpandOne(*desc_slh, 0, keys_slh, out_slh) == spk);
        FlatSigningProvider signing_slh;
        desc_slh->ExpandPrivate(0, keys_slh, signing_slh);
        BOOST_CHECK(signing_slh.pq_keys.empty());
        BOOST_CHECK_EQUAL(signing_slh.slh_keys.size(), 1U);
        Spend s{spk};
        FlatSigningProvider all{out_slh};
        all.Merge(FlatSigningProvider{signing_slh});
        BOOST_REQUIRE(s.Sign(all));
        BOOST_CHECK(s.WitnessSizes() == SLH_LEAF_WITNESS);
        BOOST_CHECK(s.tx.vin[0].scriptWitness.stack[1] == ToByteVector(leaves[1].script));
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(s.Verify(&err), ScriptErrorString(err));
    }
    // No private keys: unsignable, but the dummy signer (fee estimation) produces the right shape.
    {
        Spend s{spk};
        BOOST_CHECK(!s.Sign(out));
        SignatureData sigdata;
        BOOST_CHECK(ProduceSignature(out, DUMMY_SIGNATURE_CREATOR, spk, sigdata));
        BOOST_CHECK(sigdata.complete);
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack.size(), 4U);
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[1].size(), PQ_SIGNATURE_SIZE);
    }
    // Ordering inside {} matters for the DFS/leaf order but not for the root (branch hashes sort).
    FlatSigningProvider keys_swapped, out_swapped;
    auto desc_swapped = ParseOne("pqtr({slh(" + TestSLHPubHex() + "),pq(" + TestPQPubHex() + ")})", keys_swapped);
    BOOST_CHECK(ExpandOne(*desc_swapped, 0, keys_swapped, out_swapped) == spk);
    // A single-leaf tree: root == leaf hash.
    FlatSigningProvider keys_single, out_single;
    auto desc_single = ParseOne("pqtr(pq(" + TestPQPubHex() + "))", keys_single);
    BOOST_CHECK(ExpandOne(*desc_single, 0, keys_single, out_single) == GetTestXcoinV3Script());
    BOOST_CHECK_EQUAL(*desc_single->MaxSatisfactionWeight(true), (3 + 1952) + (3 + 3309) + (1 + 34) + (1 + 33));
}

BOOST_AUTO_TEST_CASE(pqtr_timelocked_leaves)
{
    // Leaf 0: an ML-DSA key (seed "11"*32); leaf 1: the shared test key behind after(500).
    const std::string seed_a(64, '1');
    CPQKey key_a;
    const CPQPubKey pub_a = key_a.MakeKeyFromSeed(ParseHex(seed_a));
    const std::string prv = "pqtr({pq(" + seed_a + "),and_v(v:pq(" + TestPQSeedHex() + "),after(500))})";
    const std::string pub = "pqtr({pq(" + HexStr(pub_a) + "),and_v(v:pq(" + TestPQPubHex() + "),after(500))})";
    FlatSigningProvider keys, out;
    auto desc = ParseOne(prv, keys);
    BOOST_CHECK_EQUAL(NoChecksum(desc->ToString()), pub);
    std::string prv_out;
    BOOST_CHECK(desc->ToPrivateString(keys, prv_out));
    BOOST_CHECK_EQUAL(NoChecksum(prv_out), prv);
    // Fee budget: leaf 0, the ML-DSA leaf without a timelock (34-byte script), not the time-locked
    // leaf 1 (<hash> OP_CHECKSIGVERIFY <500> OP_CLTV, 38 bytes): the signer can always take leaf 0.
    BOOST_CHECK_EQUAL(*desc->MaxSatisfactionWeight(true), (3 + 1952) + (3 + 3309) + (1 + 34) + (1 + 65));
    BOOST_CHECK_EQUAL(*desc->MaxSatisfactionElems(), 4);
    // Audit finding W7: when every ML-DSA leaf is time-locked the spend may have to go through the
    // SLH-DSA leaf before the lock matures, so the budget is the largest leaf, the SLH-DSA one.
    {
        FlatSigningProvider keys_locked;
        auto locked = ParseOne("pqtr({and_v(v:pq(" + TestPQPubHex() + "),after(500)),slh(" + TestSLHPubHex() + ")})", keys_locked);
        BOOST_REQUIRE(locked);
        BOOST_CHECK_EQUAL(*locked->MaxSatisfactionWeight(true), (3 + 7856) + (1 + 34) + (1 + 65));
    }
    const CScript spk = ExpandOne(*desc, 0, keys, out);
    {
        // Inferred in leaf-hash order: one of the two equivalent strings, and it round-trips.
        const std::string inferred = NoChecksum(InferDescriptor(spk, out)->ToString());
        const std::string pub_swapped = "pqtr({and_v(v:pq(" + TestPQPubHex() + "),after(500)),pq(" + HexStr(pub_a) + ")})";
        BOOST_CHECK_MESSAGE(inferred == pub || inferred == pub_swapped, inferred);
        FlatSigningProvider k2, o2;
        BOOST_CHECK(ExpandOne(*ParseOne(inferred, k2), 0, k2, o2) == spk);
    }
    // The time-locked leaf script: <hash> OP_CHECKSIGVERIFY <500> OP_CHECKLOCKTIMEVERIFY
    const CScript expected_leaf = CScript() << ToByteVector(GetTestPQPubKey().GetID()) << OP_CHECKSIGVERIFY << int64_t{500} << OP_CHECKLOCKTIMEVERIFY;
    XcoinV3SpendData spenddata;
    BOOST_REQUIRE(out.GetXcoinV3SpendData(uint256{std::vector<unsigned char>(spk.begin() + 2, spk.end())}, spenddata));
    BOOST_CHECK(spenddata.scripts.contains({ToByteVector(expected_leaf), XCOIN_LEAF_PQ}));
    const auto tmpl = ParseXcoinV3LeafTemplate(XCOIN_LEAF_PQ, expected_leaf);
    BOOST_REQUIRE(tmpl);
    BOOST_CHECK(tmpl->timelock == XcoinV3LeafTemplate::Timelock::AFTER);
    BOOST_CHECK_EQUAL(tmpl->timelock_value, 500U);

    FlatSigningProvider signing_all;
    desc->ExpandPrivate(0, keys, signing_all);
    BOOST_CHECK_EQUAL(signing_all.pq_keys.size(), 2U);
    // Only the time-locked key: fails before the lock, signs at/after it (non-final sequence).
    FlatSigningProvider only_locked{out};
    only_locked.pq_keys.emplace(GetTestPQPubKey().GetID(), GetTestPQKey());
    {
        Spend early{spk, CTxIn::SEQUENCE_FINAL - 1, 499};
        BOOST_CHECK(!early.Sign(only_locked));
        Spend late{spk, CTxIn::SEQUENCE_FINAL - 1, 500};
        BOOST_REQUIRE(late.Sign(only_locked));
        BOOST_CHECK_EQUAL(late.tx.vin[0].scriptWitness.stack.size(), 4U);
        BOOST_CHECK(late.tx.vin[0].scriptWitness.stack[2] == ToByteVector(expected_leaf));
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(late.Verify(&err), ScriptErrorString(err));
        // A final sequence disables nLockTime, so the leaf is not satisfiable.
        Spend final_seq{spk, CTxIn::SEQUENCE_FINAL, 500};
        BOOST_CHECK(!final_seq.Sign(only_locked));
    }
    // Both keys: leaf 0 (no lock) wins even before the lock.
    {
        FlatSigningProvider all{out};
        all.Merge(FlatSigningProvider{signing_all});
        Spend s{spk, CTxIn::SEQUENCE_FINAL - 1, 0};
        BOOST_REQUIRE(s.Sign(all));
        BOOST_CHECK(s.tx.vin[0].scriptWitness.stack[2] != ToByteVector(expected_leaf));
        BOOST_CHECK(s.Verify());
    }
    // older(N) on an SLH leaf: needs nSequence >= N (relative lock, version 2).
    {
        const std::string prv2 = "pqtr({pq(" + TestPQPubHex() + "),and_v(v:slh(" + TestSLHSeedHex() + "),older(10))})";
        FlatSigningProvider keys2, out2;
        auto desc2 = ParseOne(prv2, keys2);
        BOOST_CHECK_EQUAL(NoChecksum(desc2->ToString()), "pqtr({pq(" + TestPQPubHex() + "),and_v(v:slh(" + TestSLHPubHex() + "),older(10))})");
        const CScript spk2 = ExpandOne(*desc2, 0, keys2, out2);
        FlatSigningProvider signing2{out2};
        desc2->ExpandPrivate(0, keys2, signing2);
        Spend young{spk2, 9};
        BOOST_CHECK(!young.Sign(signing2));
        Spend old{spk2, 10};
        BOOST_REQUIRE(old.Sign(signing2));
        BOOST_CHECK_EQUAL(old.tx.vin[0].scriptWitness.stack.size(), 3U);
        BOOST_CHECK_EQUAL(old.tx.vin[0].scriptWitness.stack[0].size(), SLH_SIGNATURE_SIZE);
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(old.Verify(&err), ScriptErrorString(err));
        // A large CLTV value is a minimal CScriptNum push, still recognized.
        const CScript big = CScript() << ToByteVector(GetTestPQPubKey().GetID()) << OP_CHECKSIGVERIFY << int64_t{1700000000} << OP_CHECKLOCKTIMEVERIFY;
        const auto big_tmpl = ParseXcoinV3LeafTemplate(XCOIN_LEAF_PQ, big);
        BOOST_REQUIRE(big_tmpl);
        BOOST_CHECK_EQUAL(big_tmpl->timelock_value, 1700000000U);
        // Not a template: a non-minimal number, a foreign opcode, a 20-byte key.
        BOOST_CHECK(!ParseXcoinV3LeafTemplate(XCOIN_LEAF_PQ, CScript() << ToByteVector(GetTestPQPubKey().GetID()) << OP_CHECKSIGVERIFY << std::vector<unsigned char>{0x0a, 0x00} << OP_CHECKLOCKTIMEVERIFY));
        BOOST_CHECK(!ParseXcoinV3LeafTemplate(XCOIN_LEAF_PQ, CScript() << ToByteVector(GetTestPQPubKey().GetID()) << OP_CHECKSIGADD));
        BOOST_CHECK(!ParseXcoinV3LeafTemplate(XCOIN_LEAF_PQ, CScript() << std::vector<unsigned char>(20, 1) << OP_CHECKSIG));
        BOOST_CHECK(!ParseXcoinV3LeafTemplate(XCOIN_LEAF_RESERVED_PROOF, CScript() << ToByteVector(GetTestPQPubKey().GetID()) << OP_CHECKSIG));
    }
}

// XcoinV3LeafWarnings: the two shapes that make a leaf anyone-can-spend, which
// decodescript and getaddressinfo report so a wallet can warn (stage B6).
BOOST_AUTO_TEST_CASE(xcoin_v3_leaf_warnings)
{
    const std::vector<unsigned char> key32{ToByteVector(GetTestPQPubKey().GetID())};
    // Clean leaves say nothing.
    BOOST_CHECK(XcoinV3LeafWarnings(CScript() << key32 << OP_CHECKSIG).empty());
    BOOST_CHECK(XcoinV3LeafWarnings(CScript() << key32 << OP_CHECKSIGVERIFY << 500 << OP_CHECKLOCKTIMEVERIFY).empty());
    BOOST_CHECK(XcoinV3LeafWarnings(CScript() << key32 << OP_CHECKSIG << key32 << OP_CHECKSIGADD).empty());
    BOOST_CHECK(XcoinV3LeafWarnings(CScript{}).empty());
    // Not a key slot at all: no push before the signature opcode.
    BOOST_CHECK(XcoinV3LeafWarnings(CScript() << OP_CHECKSIGADD).empty());
    // A script that does not parse is a BAD_OPCODE failure, not a giveaway.
    const std::vector<unsigned char> truncated{0x6a, 0x02, 0xee};
    BOOST_CHECK(XcoinV3LeafWarnings(CScript{truncated.begin(), truncated.end()}).empty());

    // 1. An OP_SUCCESSx byte anywhere: the leaf succeeds before it runs. The
    //    trap this is really for is OP_CHECKSIG_PQ (0xbb), which is the legacy
    //    PQ checksig everywhere else on this chain and OP_SUCCESS187 in a leaf.
    const auto legacy_pq{XcoinV3LeafWarnings(CScript() << key32 << OP_CHECKSIG_PQ)};
    BOOST_REQUIRE_EQUAL(legacy_pq.size(), 1U);
    BOOST_CHECK(legacy_pq[0].find("ANYONE-CAN-SPEND") != std::string::npos);
    BOOST_CHECK(legacy_pq[0].find("OP_SUCCESS187") != std::string::npos);
    BOOST_CHECK_EQUAL(XcoinV3LeafWarnings(CScript() << OP_RESERVED).size(), 1U); // 0x50 = OP_SUCCESS80

    // 2. A key push that is not 32 bytes: an upgradable key type, which the
    //    interpreter passes without verifying anything.
    for (const size_t size : {size_t{20}, size_t{31}, size_t{33}, size_t{64}}) {
        const auto w{XcoinV3LeafWarnings(CScript() << std::vector<unsigned char>(size, 0x01) << OP_CHECKSIG)};
        BOOST_REQUIRE_EQUAL(w.size(), 1U);
        BOOST_CHECK(w[0].find("not 32") != std::string::npos);
        BOOST_CHECK(w[0].find("OP_CHECKSIG") != std::string::npos);
    }
    BOOST_CHECK_EQUAL(XcoinV3LeafWarnings(CScript() << std::vector<unsigned char>(33, 0x01) << OP_CHECKSIGADD).size(), 1U);
    BOOST_CHECK_EQUAL(XcoinV3LeafWarnings(CScript() << std::vector<unsigned char>(33, 0x01) << OP_CHECKSIGVERIFY << 5 << OP_CHECKSEQUENCEVERIFY).size(), 1U);
}

BOOST_AUTO_TEST_CASE(pqtr_bip32_derivation_and_cache)
{
    // A fixed master key; the wallet's default tree shape (pqhd.h derivation).
    CExtKey master;
    const std::string seed_str{"xcoin-b3-descriptor-test-master-seed"};
    master.SetSeed(std::as_bytes(std::span{seed_str}));
    const std::string xprv = EncodeExtKey(master);
    const std::string xpub = EncodeExtPubKey(master.Neuter());
    const std::string prv = "pqtr({pq(" + xprv + "/3h/1h/0h/0/*),slh(" + xprv + "/3h/1h/0h/0/*)})";
    const std::string pub = "pqtr({pq(" + xpub + "/3h/1h/0h/0/*),slh(" + xpub + "/3h/1h/0h/0/*)})";

    FlatSigningProvider keys_prv, keys_pub;
    auto desc_prv = ParseOne(prv, keys_prv);
    auto desc_pub = ParseOne(pub, keys_pub);
    BOOST_CHECK(desc_prv->IsRange());
    BOOST_CHECK(desc_prv->IsSolvable());
    BOOST_CHECK_EQUAL(desc_prv->GetKeyCount(), 2U);
    BOOST_CHECK_EQUAL(keys_prv.keys.size(), 1U); // the master private key, keyed by the master pubkey
    BOOST_CHECK_EQUAL(NoChecksum(desc_prv->ToString()), pub);
    std::string prv_out;
    BOOST_CHECK(desc_prv->ToPrivateString(keys_prv, prv_out));
    BOOST_CHECK_EQUAL(NoChecksum(prv_out), prv);
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> xpubs;
    desc_prv->GetPubKeys(pubkeys, xpubs);
    BOOST_CHECK_EQUAL(xpubs.size(), 1U);

    // Without the private key nothing expands (there is no public derivation) ...
    FlatSigningProvider out_pub;
    std::vector<CScript> scripts;
    BOOST_CHECK(!desc_pub->Expand(0, keys_pub, scripts, out_pub));
    // ... with it, positions differ and the cache reproduces them for the public descriptor.
    DescriptorCache cache;
    FlatSigningProvider out0, out1;
    const CScript spk0 = ExpandOne(*desc_prv, 0, keys_prv, out0, &cache);
    const CScript spk1 = ExpandOne(*desc_prv, 1, keys_prv, out1, &cache);
    BOOST_CHECK(spk0 != spk1);
    BOOST_CHECK(spk0.IsPayToXcoinV3() && spk1.IsPayToXcoinV3());
    BOOST_CHECK_EQUAL(cache.GetCachedXcoinPubKeys().size(), 2U); // one entry per key expression
    BOOST_CHECK_EQUAL(cache.GetCachedXcoinPubKeys().at(0).size(), 2U);
    BOOST_CHECK_EQUAL(cache.GetCachedXcoinPubKeys().at(0).at(0).size(), PQ_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(cache.GetCachedXcoinPubKeys().at(1).at(1).size(), SLH_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(cache.GetCachedLastHardenedExtPubKeys().size(), 2U); // inner BIP32 caches are kept too
    for (int pos = 0; pos < 2; ++pos) {
        FlatSigningProvider cached;
        std::vector<CScript> cached_scripts;
        BOOST_REQUIRE(desc_pub->ExpandFromCache(pos, cache, cached_scripts, cached));
        BOOST_CHECK(cached_scripts[0] == (pos == 0 ? spk0 : spk1));
        BOOST_CHECK_EQUAL(cached.pq_pubkeys.size(), 1U);
        BOOST_CHECK_EQUAL(cached.xcoin_v3_trees.size(), 1U);
        BOOST_CHECK(cached.xcoin_v3_trees == (pos == 0 ? out0 : out1).xcoin_v3_trees);
    }
    std::vector<CScript> missing;
    FlatSigningProvider missing_out;
    BOOST_CHECK(!desc_pub->ExpandFromCache(2, cache, missing, missing_out));
    BOOST_CHECK(!desc_prv->RangeSize());

    // Export for a wallet without private keys (audit finding W3): the cached public keys are
    // written out as explicit key lists, one key per position, and the result expands to the
    // same scripts without any private key, at exactly those positions.
    {
        std::string exported;
        BOOST_REQUIRE(desc_prv->ToExportString(keys_prv, exported, &cache));
        BOOST_CHECK_MESSAGE(exported.rfind("pqtr({pq(keys(" + HexStr(out0.pq_pubkeys.begin()->second) + ",", 0) == 0, exported.substr(0, 40));
        BOOST_CHECK(exported.find("xpub") == std::string::npos);
        BOOST_CHECK(exported.find('*') == std::string::npos);
        std::string exported_pub;
        BOOST_REQUIRE(desc_pub->ToExportString(keys_pub, exported_pub, &cache)); // the public descriptor exports the same
        BOOST_CHECK_EQUAL(exported_pub, exported);
        FlatSigningProvider keys_exp;
        auto desc_exp = ParseOne(exported, keys_exp);
        BOOST_CHECK(keys_exp.keys.empty() && keys_exp.pq_keys.empty() && keys_exp.slh_keys.empty());
        BOOST_CHECK(desc_exp->IsRange());
        BOOST_CHECK(desc_exp->IsSolvable());
        BOOST_CHECK(desc_exp->IsSingleType());
        BOOST_CHECK(desc_exp->GetOutputType() == OutputType::XCOIN_V3);
        BOOST_CHECK_EQUAL(*desc_exp->RangeSize(), 2);
        BOOST_CHECK(!desc_exp->HavePrivateKeys(keys_exp));
        BOOST_CHECK_EQUAL(desc_exp->ToString(), exported); // round-trips, checksum included
        FlatSigningProvider exp0, exp1;
        BOOST_CHECK(ExpandOne(*desc_exp, 0, keys_exp, exp0) == spk0);
        BOOST_CHECK(ExpandOne(*desc_exp, 1, keys_exp, exp1) == spk1);
        BOOST_CHECK(exp0.xcoin_v3_trees == out0.xcoin_v3_trees);
        BOOST_CHECK_EQUAL(exp0.pq_pubkeys.size(), 1U);
        std::vector<CScript> beyond;
        FlatSigningProvider beyond_out;
        BOOST_CHECK(!desc_exp->Expand(2, keys_exp, beyond, beyond_out));
        BOOST_CHECK(!desc_exp->Expand(-1, keys_exp, beyond, beyond_out));
        // The exported form expands from an empty cache too (a fresh wallet), and its normalized
        // and export strings are itself.
        DescriptorCache empty_cache;
        std::vector<CScript> from_empty;
        FlatSigningProvider from_empty_out;
        BOOST_REQUIRE(desc_exp->ExpandFromCache(1, empty_cache, from_empty, from_empty_out));
        BOOST_CHECK(from_empty[0] == spk1);
        std::string again;
        BOOST_CHECK(desc_exp->ToNormalizedString(keys_exp, again, nullptr));
        BOOST_CHECK_EQUAL(again, exported);
        BOOST_CHECK(desc_exp->ToExportString(keys_exp, again, &empty_cache));
        BOOST_CHECK_EQUAL(again, exported);
        BOOST_CHECK(!desc_exp->ToPrivateString(keys_exp, again));
        BOOST_CHECK_EQUAL(again, exported);
        // The ranged private form is unchanged, and without a cache the export is the normalized form.
        BOOST_CHECK(desc_prv->ToPrivateString(keys_prv, prv_out));
        BOOST_CHECK_EQUAL(NoChecksum(prv_out), prv);
        std::string no_cache, normalized;
        BOOST_REQUIRE(desc_prv->ToExportString(keys_prv, no_cache, nullptr));
        BOOST_REQUIRE(desc_prv->ToNormalizedString(keys_prv, normalized, nullptr));
        BOOST_CHECK_EQUAL(no_cache, normalized);
        // keys() carries public keys only, and every entry must be one; a comma outside keys() is no key.
        const std::string P = TestPQPubHex();
        BOOST_CHECK_EQUAL(ParseError("pqtr(pq(keys(" + P + "," + TestPQSeedHex() + ")))"), "pq(): key 1 of keys() is 32 bytes, not a 1952-byte public key (keys() carries public keys only)");
        BOOST_CHECK_EQUAL(ParseError("pqtr(slh(keys(" + TestSLHPubHex() + "," + TestSLHSeedHex() + ")))"), "slh(): key 1 of keys() is 48 bytes, not a 32-byte public key (keys() carries public keys only)");
        BOOST_CHECK_EQUAL(ParseError("pqtr(pq(keys(" + P + ",)))"), "pq(): keys() holds hex public keys separated by ','");
        BOOST_CHECK_EQUAL(ParseError("pq(keys(" + P + ",zz))"), "pq(): keys() holds hex public keys separated by ','");
        BOOST_CHECK_EQUAL(ParseError("pq(keys())"), "pq(): keys() holds hex public keys separated by ','");
        BOOST_CHECK(ParseError("pq(" + P + "," + P + ")").rfind("pq(): ", 0) == 0);
        // A single key is a list too (ranged, one position), unlike the constant form.
        FlatSigningProvider keys_one;
        auto desc_one = ParseOne("pqtr(pq(keys(" + P + ")))", keys_one);
        BOOST_CHECK(desc_one->IsRange());
        BOOST_CHECK_EQUAL(*desc_one->RangeSize(), 1);
        FlatSigningProvider out_one;
        BOOST_CHECK(ExpandOne(*desc_one, 0, keys_one, out_one) == GetTestXcoinV3Script());
        BOOST_CHECK(!desc_one->Expand(1, keys_one, beyond, beyond_out));
        BOOST_CHECK(!ParseOne("pqtr(pq(" + P + "))", keys_one)->IsRange());
        // The legacy v2 form lists keys the same way.
        FlatSigningProvider keys_v2l;
        auto desc_v2l = ParseOne("pq(keys(" + P + "," + P + "))", keys_v2l);
        BOOST_CHECK(desc_v2l->IsRange());
        BOOST_CHECK_EQUAL(*desc_v2l->RangeSize(), 2);
        BOOST_CHECK(desc_v2l->GetOutputType() == OutputType::XCOIN_V2);
        FlatSigningProvider out_v2l;
        BOOST_CHECK(ExpandOne(*desc_v2l, 1, keys_v2l, out_v2l) == GetTestPQScript());
    }
    // MergeAndDiff carries the post-quantum entries.
    DescriptorCache merged;
    const DescriptorCache diff = merged.MergeAndDiff(cache);
    BOOST_CHECK_EQUAL(diff.GetCachedXcoinPubKeys().size(), 2U);
    BOOST_CHECK_EQUAL(merged.MergeAndDiff(cache).GetCachedXcoinPubKeys().size(), 0U);

    // Normalized form: origin + the last hardened xpub, unhardened tail.
    std::string norm;
    BOOST_REQUIRE(desc_prv->ToNormalizedString(keys_prv, norm, &cache));
    const std::string fp = HexStr(std::span<const unsigned char>{master.key.GetPubKey().GetID().begin(), 4});
    BOOST_CHECK(norm.rfind("pqtr({pq([" + fp + "/3h/1h/0h]", 0) == 0);
    BOOST_CHECK(norm.find("/0/*),slh([" + fp + "/3h/1h/0h]") != std::string::npos);

    // Determinism of the derivation itself (pqhd.h): the ROOT key and the full path
    // m/3h/1h/0h/0/0 seed both algorithms with their own domains, and that is what the
    // leaves commit to. No child key is involved (audit finding 5).
    const std::vector<uint32_t> path{0x80000003U, 0x80000001U, 0x80000000U, 0U, 0U};
    const std::span<const unsigned char> root_bytes{reinterpret_cast<const unsigned char*>(master.key.data()), master.key.size()};
    const std::span<const unsigned char> chaincode{master.chaincode.begin(), master.chaincode.size()};
    std::array<unsigned char, 32> mldsa_seed;
    DeriveXcoinMLDSASeed(root_bytes, chaincode, path, mldsa_seed);
    CPQKey mldsa_key;
    const CPQPubKey mldsa_pub = mldsa_key.MakeKeyFromSeed(mldsa_seed);
    std::array<unsigned char, 48> slh_seed;
    DeriveXcoinSLHSeed(root_bytes, chaincode, path, slh_seed);
    CSLHKey slh_key;
    const CSLHPubKey slh_pub = slh_key.MakeKeyFromSeed(slh_seed);
    BOOST_CHECK(out0.pq_pubkeys.begin()->second == mldsa_pub);
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(mldsa_pub)}, XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3SLHLeafScript(slh_pub)}};
    BOOST_CHECK(spk0 == XcoinV3ScriptPubKey(leaves));
    BOOST_CHECK(std::memcmp(mldsa_seed.data(), slh_seed.data(), 32) != 0); // distinct domains
    // The account-level key (m/3h/1h/0h, the one whose xpub the wallet exports) with the
    // unhardened tail does NOT reproduce the seed: only the root key and the full path do.
    CExtKey account = master;
    for (uint32_t step : {0x80000003U, 0x80000001U, 0x80000000U}) BOOST_REQUIRE(account.Derive(account, step));
    const std::vector<uint32_t> tail{0U, 0U};
    std::array<unsigned char, 32> from_account;
    DeriveXcoinMLDSASeed(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(account.key.data()), account.key.size()},
                         std::span<const unsigned char>{account.chaincode.begin(), account.chaincode.size()}, tail, from_account);
    BOOST_CHECK(from_account != mldsa_seed);

    // The derived private keys sign; the SLH one alone signs through the fallback leaf.
    FlatSigningProvider signing{out0};
    desc_prv->ExpandPrivate(0, keys_prv, signing);
    BOOST_CHECK_EQUAL(signing.pq_keys.size(), 1U);
    BOOST_CHECK_EQUAL(signing.slh_keys.size(), 1U);
    BOOST_CHECK(signing.slh_keys.begin()->second == slh_key);
    {
        Spend s{spk0};
        BOOST_REQUIRE(s.Sign(signing));
        BOOST_CHECK(s.WitnessSizes() == MLDSA_LEAF_WITNESS);
        BOOST_CHECK(s.Verify());
        FlatSigningProvider slh_only{out0};
        slh_only.slh_keys = signing.slh_keys;
        Spend f{spk0};
        BOOST_REQUIRE(f.Sign(slh_only));
        BOOST_CHECK(f.WitnessSizes() == SLH_LEAF_WITNESS);
        BOOST_CHECK(f.Verify());
    }
    // The private key at position 1 does not sign position 0.
    {
        FlatSigningProvider wrong{out0};
        desc_prv->ExpandPrivate(1, keys_prv, wrong);
        Spend s{spk0};
        BOOST_CHECK(!s.Sign(wrong));
    }

    // Multipath: <0;1> yields the receive and change descriptors.
    FlatSigningProvider keys_mp;
    std::string error;
    auto descs = Parse("pqtr({pq(" + xprv + "/3h/1h/0h/<0;1>/*),slh(" + xprv + "/3h/1h/0h/<0;1>/*)})", keys_mp, error);
    BOOST_REQUIRE_MESSAGE(descs.size() == 2, error);
    FlatSigningProvider out_mp;
    BOOST_CHECK(ExpandOne(*descs[0], 0, keys_mp, out_mp) == spk0);
    BOOST_CHECK(ExpandOne(*descs[1], 0, keys_mp, out_mp) != spk0);

    // The legacy v2 descriptor derives the same way: pq(xprv/2h/1h/0h/0/*).
    FlatSigningProvider keys_v2, out_v2;
    auto desc_v2 = ParseOne("pq(" + xprv + "/2h/1h/0h/0/*)", keys_v2);
    BOOST_CHECK(desc_v2->GetOutputType() == OutputType::XCOIN_V2);
    const CScript spk_v2 = ExpandOne(*desc_v2, 0, keys_v2, out_v2);
    BOOST_CHECK_EQUAL(spk_v2.size(), 34U);
    BOOST_CHECK_EQUAL(spk_v2[0], OP_2);
    FlatSigningProvider signing_v2{out_v2};
    desc_v2->ExpandPrivate(0, keys_v2, signing_v2);
    Spend s2{spk_v2};
    BOOST_REQUIRE(s2.Sign(signing_v2));
    BOOST_CHECK(s2.Verify());
}

BOOST_AUTO_TEST_CASE(descriptor_parse_errors_and_checksums)
{
    const std::string P = TestPQPubHex();
    const std::string S = TestSLHPubHex();
    BOOST_CHECK_EQUAL(ParseError("slh(" + S + ")"), "Can only have slh() inside pqtr()");
    BOOST_CHECK_EQUAL(ParseError("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pq(" + P + "))"), "Can only have pq() at top level (witness v2) or inside pqtr()");
    BOOST_CHECK_EQUAL(ParseError("wsh(pqtr(pq(" + P + ")))"), "Can only have pqtr at top level");
    BOOST_CHECK_EQUAL(ParseError("pqtr(pk(" + P + "))"), "pqtr(): a leaf must be pq(KEY), slh(KEY), and_v(v:pq(KEY),after(N)), and_v(v:pq(KEY),older(N)) or the slh() forms of those");
    BOOST_CHECK_EQUAL(ParseError("pqtr({pq(" + P + ")})"), "pqtr(): expected ',' after script expression");
    BOOST_CHECK_EQUAL(ParseError("pqtr(pq(" + P + "),slh(" + S + "))"), "pqtr(): expected ')' after script expression");
    BOOST_CHECK_EQUAL(ParseError("pq(0011)"), "pq(): a 2-byte hex key is neither a 1952-byte ML-DSA-65 public key, a 32-byte seed nor a 4032-byte secret key");
    // Whitespace around a key is refused without echoing the key (a seed is a secret; audit finding W1).
    BOOST_CHECK_EQUAL(ParseError("pq(" + TestPQSeedHex() + " )"), "pq(): key contains leading or trailing whitespace");
    BOOST_CHECK_EQUAL(ParseError("pqtr(slh( " + TestSLHSeedHex() + "))"), "slh(): key contains leading or trailing whitespace");
    BOOST_CHECK(ParseError("pq(" + TestPQSeedHex() + " )").find(TestPQSeedHex()) == std::string::npos);
    BOOST_CHECK_EQUAL(ParseError("pqtr(slh(" + P + "))"), "slh(): a 1952-byte hex key is neither a 32-byte SLH-DSA-SHA2-128s public key, a 48-byte seed nor a 64-byte secret key");
    BOOST_CHECK_EQUAL(ParseError("pqtr(and_v(v:pq(" + P + "),after(0)))"), "after(): value must be between 1 and 2147483647");
    BOOST_CHECK_EQUAL(ParseError("pqtr(and_v(v:pq(" + P + "),older(2147483648)))"), "older(): value must be between 1 and 2147483647");
    BOOST_CHECK_EQUAL(ParseError("pqtr(and_v(pq(" + P + "),after(1)))"), "pqtr(): and_v() takes v:pq(KEY) or v:slh(KEY) as its first argument");
    BOOST_CHECK_EQUAL(ParseError("pqtr(and_v(v:pq(" + P + "),sha256(" + S + ")))"), "pqtr(): and_v() takes after(N) or older(N) as its second argument");
    BOOST_CHECK_EQUAL(ParseError("pq(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"), "pq(): a 33-byte hex key is neither a 1952-byte ML-DSA-65 public key, a 32-byte seed nor a 4032-byte secret key");
    BOOST_CHECK(ParseError("pq(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)").rfind("pq(): ", 0) == 0); // a WIF is not a BIP32 expression
    BOOST_CHECK_EQUAL(ParseError("pqtr()"), "pqtr(): a leaf must be pq(KEY), slh(KEY), and_v(v:pq(KEY),after(N)), and_v(v:pq(KEY),older(N)) or the slh() forms of those");

    // Checksums are stable and enforced.
    const std::string desc = "pqtr({pq(" + P + "),slh(" + S + ")})";
    const std::string checksum = GetDescriptorChecksum(desc);
    BOOST_CHECK_EQUAL(checksum.size(), 8U);
    FlatSigningProvider keys;
    std::string error;
    BOOST_CHECK_EQUAL(Parse(desc + "#" + checksum, keys, error, /*require_checksum=*/true).size(), 1U);
    BOOST_CHECK(Parse(desc, keys, error, /*require_checksum=*/true).empty());
    BOOST_CHECK(Parse(desc + "#aaaaaaaa", keys, error, /*require_checksum=*/false).empty());
    BOOST_CHECK_EQUAL(ParseOne(desc, keys)->ToString(), desc + "#" + checksum);
    // The compat string (DescriptorID) is the public form as well.
    BOOST_CHECK_EQUAL(ParseOne(desc, keys)->ToString(/*compat_format=*/true), desc + "#" + checksum);
}

BOOST_AUTO_TEST_SUITE_END()
