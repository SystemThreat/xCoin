// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Re-genesis stages B1 and B2 (contrib/regenesis/REGENESIS.md section 4):
// witness v3, the post-quantum script tree. Leaf/branch hash vectors, the
// ML-DSA-65 PQ leaf, the SLH-DSA-SHA2-128s fallback leaf, control-block rules,
// timelocks, k-of-n with OP_CHECKSIGADD, OP_CHECKTEMPLATEVERIFY, the annex,
// standardness, addresses, and an end-to-end mempool + block round trip.
// Legacy witness v2 spends stay valid.

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <chainparams.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <slhkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/solver.h>
#include <script/xcoin_v3.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>
#include <test/util/slh.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

using valtype = std::vector<unsigned char>;

namespace {

constexpr CAmount SPEND_VALUE{100 * COIN};
constexpr script_verify_flags STD{STANDARD_SCRIPT_VERIFY_FLAGS};
constexpr script_verify_flags MAND{MANDATORY_SCRIPT_VERIFY_FLAGS};

CPQKey KeyFromSeedByte(unsigned char b)
{
    std::array<unsigned char, 32> seed{};
    seed.fill(b);
    CPQKey key;
    const CPQPubKey pub{key.MakeKeyFromSeed(seed)};
    assert(pub.IsValid());
    return key;
}

/** A one-input transaction spending `spk`, with everything needed to verify input 0. */
struct Spend {
    CMutableTransaction tx;
    std::vector<CTxOut> spent;

    explicit Spend(const CScript& spk, CAmount value = SPEND_VALUE, uint32_t sequence = CTxIn::SEQUENCE_FINAL - 1)
    {
        spent.emplace_back(value, spk);
        tx.version = 2;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, sequence);
        tx.vout.emplace_back(value - 10000, GetTestXcoinV3Script());
    }

    std::vector<valtype>& Witness() { return tx.vin[0].scriptWitness.stack; }

    bool Verify(script_verify_flags flags, ScriptError* err) const
    {
        const CTransaction ctx{tx};
        PrecomputedTransactionData txdata;
        txdata.Init(ctx, std::vector<CTxOut>{spent});
        const TransactionSignatureChecker checker(&ctx, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);
        return VerifyScript(ctx.vin[0].scriptSig, spent[0].scriptPubKey, &ctx.vin[0].scriptWitness, flags, checker, err);
    }

    void ExpectOk(script_verify_flags flags, const std::string& what) const
    {
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(Verify(flags, &err), what + ": " + ScriptErrorString(err));
    }

    void ExpectErr(script_verify_flags flags, ScriptError expected, const std::string& what) const
    {
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK_MESSAGE(!Verify(flags, &err), what + ": unexpectedly valid");
        BOOST_CHECK_MESSAGE(err == expected, what + ": got " + ScriptErrorString(err) + ", expected " + ScriptErrorString(expected));
    }
};

/** Witness for a PQ leaf spend: [pubkey, sig, leaf script, control]. */
std::vector<valtype> PQLeafWitness(const CPQKey& key, const std::vector<XcoinV3Leaf>& leaves, size_t index, const Spend& s, int hash_type = SIGHASH_DEFAULT, const std::optional<valtype>& annex = std::nullopt)
{
    const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[index]), .annex = annex};
    std::vector<valtype> w{ToByteVector(key.GetPubKey()), XcoinV3Sign(key, s.tx, 0, s.spent, ctx, hash_type), ToByteVector(leaves[index].script), XcoinV3ControlBlock(leaves, index)};
    if (annex) w.push_back(*annex);
    return w;
}

uint256 Sha256(std::string_view s)
{
    uint256 h;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(h.begin());
    return h;
}

/** interpreter.cpp's CastToBool: non-zero, and not a negative zero. */
bool Truthy(const valtype& v)
{
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] != 0) return !(i == v.size() - 1 && v[i] == 0x80);
    }
    return false;
}

/** The validation-weight budget VerifyWitnessProgram gives input 0 of `s`: serialized witness
 *  stack plus VALIDATION_WEIGHT_OFFSET. */
int64_t Budget(const Spend& s)
{
    return static_cast<int64_t>(::GetSerializeSize(s.tx.vin[0].scriptWitness.stack)) + VALIDATION_WEIGHT_OFFSET;
}

/** Run input 0 of `s` through EvalScript the way VerifyWitnessProgram does for a v3 leaf (the
 *  witness is [initial elements..., leaf script, control block], no annex) and return the
 *  validation weight left afterwards, so a test can show the budget arithmetic. Also checks
 *  that VerifyScript agrees on the outcome. */
int64_t RunLeafForBudget(const Spend& s, const XcoinV3Leaf& leaf, script_verify_flags flags, bool expect_ok, ScriptError expected_err, const std::string& what)
{
    const CTransaction ctx{s.tx};
    PrecomputedTransactionData txdata;
    txdata.Init(ctx, std::vector<CTxOut>{s.spent});
    const TransactionSignatureChecker checker(&ctx, 0, s.spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);
    const auto& witness{ctx.vin[0].scriptWitness.stack};
    BOOST_REQUIRE(witness.size() >= 2);
    ScriptExecutionData execdata;
    execdata.m_tapleaf_hash = XcoinV3LeafHash(leaf);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_validation_weight_left = Budget(s);
    execdata.m_validation_weight_left_init = true;
    std::vector<valtype> stack(witness.begin(), witness.end() - 2);
    const SigVersion sigversion{leaf.version == XCOIN_LEAF_PQ ? SigVersion::XCOIN_PQ_TAPSCRIPT : SigVersion::XCOIN_SLH_TAPSCRIPT};
    ScriptError err{SCRIPT_ERR_OK};
    const bool ok{EvalScript(stack, leaf.script, flags, checker, sigversion, execdata, &err) && stack.size() == 1 && Truthy(stack.back())};
    BOOST_CHECK_MESSAGE(ok == expect_ok, what + ": EvalScript " + (ok ? "succeeded" : "failed: " + ScriptErrorString(err)));
    if (expect_ok) {
        s.ExpectOk(flags, what);
    } else {
        BOOST_CHECK_MESSAGE(err == expected_err, what + ": got " + ScriptErrorString(err) + ", expected " + ScriptErrorString(expected_err));
        s.ExpectErr(flags, expected_err, what);
    }
    return execdata.m_validation_weight_left;
}

} // namespace

BOOST_AUTO_TEST_SUITE(xcoin_v3_tests)

// Pinned against an independent Python (hashlib) implementation of
// tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m).
BOOST_FIXTURE_TEST_CASE(xcoin_v3_constants_and_hash_vectors, BasicTestingSetup)
{
    BOOST_CHECK_EQUAL(WITNESS_V3_SIZE, 32U);
    BOOST_CHECK_EQUAL(XCOIN_LEAF_PQ, 0xc0);
    BOOST_CHECK_EQUAL(XCOIN_LEAF_SLH, 0xc2);
    BOOST_CHECK_EQUAL(XCOIN_LEAF_RESERVED_PROOF, 0xc4);
    BOOST_CHECK_EQUAL(XCOIN_LEAF_RESERVED_LEDGER, 0xc6);
    BOOST_CHECK_EQUAL(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE, 8192U);
    BOOST_CHECK_EQUAL(XCOIN_V3_VALIDATION_WEIGHT_MLDSA, 200);
    BOOST_CHECK_EQUAL(XCOIN_V3_VALIDATION_WEIGHT_SLH, 1080);
    // Both were scaled 4x with MAX_BLOCK_WEIGHT (16M -> 64M WU, 2026-09-07) so the
    // worst-case block still affords the same 320,000 ML-DSA checks and the 25.3 s
    // single-threaded bound of REGENESIS.md section 4 did not move.
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT / XCOIN_V3_VALIDATION_WEIGHT_MLDSA, 320000);
    // The two weights must stand in the ratio of the two verification costs, or
    // the cheaper constant makes its leaf the block's worst case (stage B6;
    // measured with bench_bitcoin -filter='XcoinVerify.*': 79.1 us and 418.9 us
    // medians, ratio 5.30; an independent reviewer measured 5.44). A block can
    // afford about MAX_BLOCK_WEIGHT / weight checks of one kind, so the SLH
    // leaf's worst-case block must not cost more wall clock than the ML-DSA
    // leaf's: (MAX_BLOCK_WEIGHT / W_SLH) * 418.9us <= (MAX_BLOCK_WEIGHT / W_MLDSA) * 79.1us,
    // i.e. W_SLH / W_MLDSA >= 5.30. Kept as integers: 1080 * 791 >= 200 * 4189.
    BOOST_CHECK_GE(XCOIN_V3_VALIDATION_WEIGHT_SLH * 791, XCOIN_V3_VALIDATION_WEIGHT_MLDSA * 4189);
    BOOST_CHECK_EQUAL(XCOIN_V3_CONTROL_BASE_SIZE, 33U);

    // The no-key marker is a plain SHA-256 of "xcoin/v3/nokey".
    BOOST_CHECK_EQUAL(HexStr(XCOIN_V3_NOKEY), "54b62806c9e55d19448216fc3426a3a04466fbc59c18238795cbbc9003330a65");
    BOOST_CHECK(XCOIN_V3_NOKEY == Sha256(XCOIN_V3_NOKEY_TAG));

    // Vector 1: leaf 0xc0, script = PUSH32(01..20) OP_CHECKSIG
    valtype s1{0x20};
    for (unsigned char i = 1; i <= 32; ++i) s1.push_back(i);
    s1.push_back(OP_CHECKSIG);
    BOOST_CHECK_EQUAL(HexStr(s1), "200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20ac");
    const uint256 l1{ComputeXcoinLeafHash(0xc0, s1)};
    BOOST_CHECK_EQUAL(HexStr(l1), "50371c2936f8bfda05c69228affb83119c687ad8a477b1a18bd01c0a468902d6");
    // Vector 2: leaf 0xc0, empty script
    const uint256 l2{ComputeXcoinLeafHash(0xc0, valtype{})};
    BOOST_CHECK_EQUAL(HexStr(l2), "e3bb8e8060cd8ae48c5e91228aa5c257cd5bb80ae1cf853f4dec66a042b1c2f9");
    // Vector 3: leaf 0xc2 (SLH), script = OP_1
    const uint256 l3{ComputeXcoinLeafHash(0xc2, valtype{0x51})};
    BOOST_CHECK_EQUAL(HexStr(l3), "cb25e1b1ec8b174d327f1e6466c018383dd0e23860f6805cab1738dd65922adf");
    // Branch of 1 and 2 (sorted pair: same result either way), then with 3.
    const uint256 b12{ComputeXcoinBranchHash(l1, l2)};
    BOOST_CHECK_EQUAL(HexStr(b12), "2339dd5ab68ae3ec676b327297e620ce7f2f7e7eb594be396a12ce600df76845");
    BOOST_CHECK(ComputeXcoinBranchHash(l2, l1) == b12);
    BOOST_CHECK_EQUAL(HexStr(ComputeXcoinBranchHash(b12, l3)), "44546098ecf80a10fbf7441c650152021a8f099a8eb816d80a04e0f01df60687");
    // The xCoin tags differ from Bitcoin's TapLeaf: a Taproot commitment can never be confused with a v3 one.
    BOOST_CHECK_EQUAL(HexStr(ComputeTapleafHash(0xc0, s1)), "e52b79f83ba9c697d8bd985e635c92b48e1beec6ac061c8f5350156642cb6c84");
    BOOST_CHECK(ComputeTapleafHash(0xc0, s1) != l1);
    // Sighash tag.
    BOOST_CHECK_EQUAL(HexStr(XcoinV3TagSighash(uint256::ZERO)), "ca2115605609aa667201bcb32f4fb217d4a673fa026e8ba76adbf01dc4ed37cd");

    // Merkle path walk: a single-leaf control block yields the leaf hash; one node yields the branch.
    valtype control{0xc0};
    control.insert(control.end(), XCOIN_V3_NOKEY.begin(), XCOIN_V3_NOKEY.end());
    BOOST_CHECK(ComputeXcoinV3MerkleRoot(control, l1) == l1);
    control.insert(control.end(), l2.begin(), l2.end());
    BOOST_CHECK(ComputeXcoinV3MerkleRoot(control, l1) == b12);

    // The test helpers agree with the consensus functions.
    const XcoinV3Leaf leaf1{0xc0, CScript(s1.begin(), s1.end())};
    const XcoinV3Leaf leaf2{0xc0, CScript{}};
    BOOST_CHECK(XcoinV3LeafHash(leaf1) == l1);
    BOOST_CHECK(XcoinV3Root({leaf1}) == l1);
    BOOST_CHECK(XcoinV3Root({leaf1, leaf2}) == b12);
    BOOST_CHECK(XcoinV3ControlBlock({leaf1, leaf2}, 0) == control);

    // Flags: v3 is mandatory on every chain and part of the standard set; it has a name.
    BOOST_CHECK((MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_XCOIN_V3) != 0);
    BOOST_CHECK((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_XCOIN_V3) != 0);
    BOOST_CHECK((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) != 0);
    const auto names{GetScriptFlagNames(SCRIPT_VERIFY_XCOIN_V3)};
    BOOST_REQUIRE_EQUAL(names.size(), 1U);
    BOOST_CHECK_EQUAL(names[0], "XCOIN_V3");
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_single_leaf_spend, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const CPQKey b{KeyFromSeedByte(0xb0)};
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(a.GetPubKey())}};
    const CScript spk{XcoinV3ScriptPubKey(leaves)};
    BOOST_CHECK(spk == GetTestXcoinV3Script());
    BOOST_CHECK(spk.IsPayToXcoinV3());

    for (const int hash_type : std::vector<int>{SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY}) {
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s, hash_type);
        BOOST_CHECK_EQUAL(s.Witness()[1].size(), PQ_SIGNATURE_SIZE + (hash_type == SIGHASH_DEFAULT ? 0 : 1));
        s.ExpectOk(STD, "valid spend, hash type " + std::to_string(hash_type));
        // The precomputation recognises a v3 spend (BIP-341 data and the CTV data are ready).
        PrecomputedTransactionData txdata;
        txdata.Init(s.tx, std::vector<CTxOut>{s.spent});
        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK(txdata.m_ctv_ready);
    }

    {
        // The helper's signature is the same as a SignTestXcoinV3Input one.
        Spend s{spk};
        SignTestXcoinV3Input(s.tx, 0, s.spent);
        s.ExpectOk(STD, "SignTestXcoinV3Input");
    }
    {
        // Explicit 0x00 hash-type byte is not allowed (one encoding per sighash type, as BIP 341).
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[1].push_back(0x00);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_HASHTYPE, "explicit SIGHASH_DEFAULT byte");
    }
    {
        // Non-canonical signature sizes are rejected before any verification.
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[1].pop_back();
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "3308-byte signature");
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[1].push_back(0x01);
        s.Witness()[1].push_back(0x01);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "3311-byte signature");
    }
    {
        // Wrong key: b signs, the witness carries a's key (hash matches, signature does not).
        Spend s{spk};
        s.Witness() = PQLeafWitness(b, leaves, 0, s);
        s.Witness()[0] = ToByteVector(a.GetPubKey());
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "wrong key");
    }
    {
        // Key hash mismatch: b's key and b's valid signature under a leaf that commits to a's key hash.
        Spend s{spk};
        s.Witness() = PQLeafWitness(b, leaves, 0, s);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "key hash mismatch");
    }
    {
        // Wrong key size (a truncated key never reaches ML-DSA).
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[0].pop_back();
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "1951-byte key");
    }
    {
        // Wrong sighash digest: a valid ML-DSA signature over some other 32 bytes.
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        valtype sig;
        BOOST_REQUIRE(a.SignMessage(std::span<const unsigned char>{uint256::ONE.begin(), 32}, sig));
        s.Witness()[1] = sig;
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "wrong digest");
    }
    {
        // Signature over the UNTAGGED BIP-341 message (the digest before "XCoinSighash/v3") must fail.
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0])};
        const uint256 untagged{XcoinV3SighashMessageForTest(s.tx, 0, s.spent, ctx)};
        const uint256 tagged{XcoinV3SighashForTest(s.tx, 0, s.spent, ctx)};
        BOOST_CHECK(XcoinV3TagSighash(untagged) == tagged);
        BOOST_CHECK(untagged != tagged);
        valtype sig;
        BOOST_REQUIRE(a.SignMessage(std::span<const unsigned char>{untagged.begin(), 32}, sig));
        s.Witness()[1] = sig;
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "untagged digest");
    }
    {
        // Empty signature: false without aborting (so the lone CHECKSIG leaves false), key slot must be empty.
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[0].clear();
        s.Witness()[1].clear();
        s.ExpectErr(STD, SCRIPT_ERR_EVAL_FALSE, "empty signature");
        s.Witness()[0] = ToByteVector(a.GetPubKey());
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "empty signature with a key");
    }
    {
        // Without the v3 flag the program is an unknown witness version (soft-fork shape).
        Spend s{spk};
        s.Witness() = {valtype{0x01}};
        s.ExpectOk(MAND & ~SCRIPT_VERIFY_XCOIN_V3, "no XCOIN_V3 flag");
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_stack_and_control_rules, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const valtype hash_a{ToByteVector(a.GetPubKey().GetID())};
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(a.GetPubKey())}};
    const CScript spk{XcoinV3ScriptPubKey(leaves)};

    {
        // No key path: a one-item stack (Taproot key path shape) and an empty witness both fail.
        Spend s{spk};
        s.Witness() = {valtype(PQ_SIGNATURE_SIZE, 0x01)};
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "key-path attempt");
        s.Witness().clear();
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "empty witness");
    }
    {
        // Control block rules: parity bit, no-key slot, size, path.
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3][0] = 0xc1;
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_CONTROL, "parity bit set");
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3][1] ^= 0x01;
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_CONTROL, "wrong no-key slot");
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3].push_back(0x00);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_CONTROL, "34-byte control block");
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3].resize(33 + 32, 0x00);
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "bogus path node on a single-leaf tree");
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[2].push_back(OP_NOP);
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "script not in the tree");
    }
    {
        // Initial witness elements may be up to 8,192 bytes; 8,193 fails.
        const std::vector<XcoinV3Leaf> drop_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_DROP << hash_a << OP_CHECKSIG}};
        Spend s{XcoinV3ScriptPubKey(drop_leaves)};
        s.Witness() = PQLeafWitness(a, drop_leaves, 0, s);
        s.Witness().insert(s.Witness().begin() + 2, valtype(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE, 0x5a));
        s.ExpectOk(STD, "8192-byte initial element");
        s.Witness()[2].push_back(0x5a);
        s.ExpectErr(STD, SCRIPT_ERR_PUSH_SIZE, "8193-byte initial element");
    }
    {
        // Elements pushed DURING execution keep the 520-byte limit.
        const std::vector<XcoinV3Leaf> ok_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x01) << OP_DROP << hash_a << OP_CHECKSIG}};
        Spend ok{XcoinV3ScriptPubKey(ok_leaves)};
        ok.Witness() = PQLeafWitness(a, ok_leaves, 0, ok);
        ok.ExpectOk(STD, "520-byte push during execution");
        const std::vector<XcoinV3Leaf> big_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << valtype(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x01) << OP_DROP << hash_a << OP_CHECKSIG}};
        Spend big{XcoinV3ScriptPubKey(big_leaves)};
        big.Witness() = PQLeafWitness(a, big_leaves, 0, big);
        big.ExpectErr(STD, SCRIPT_ERR_PUSH_SIZE, "521-byte push during execution");
    }
    {
        // Unknown leaf versions (0xc4 and 0xc6 reserved, 0xd0 unassigned): valid by consensus,
        // discouraged by policy. Parity bit on an unknown version is still a control error.
        for (const uint8_t version : {XCOIN_LEAF_RESERVED_PROOF, XCOIN_LEAF_RESERVED_LEDGER, uint8_t{0xd0}}) {
            const std::vector<XcoinV3Leaf> unk{XcoinV3Leaf{version, CScript() << OP_RETURN}};
            Spend s{XcoinV3ScriptPubKey(unk)};
            s.Witness() = {ToByteVector(unk[0].script), XcoinV3ControlBlock(unk, 0)};
            s.ExpectOk(MAND, "unknown leaf version accepted by consensus");
            s.ExpectErr(STD, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_XCOIN_LEAF_VERSION, "unknown leaf version discouraged");
            s.Witness()[1][0] = version | 1;
            s.ExpectErr(MAND, SCRIPT_ERR_XCOIN_V3_CONTROL, "parity bit on unknown leaf version");
        }
    }
    {
        // Tapscript rules inside the PQ leaf: minimal IF, no CHECKMULTISIG, OP_SUCCESSx.
        const std::vector<XcoinV3Leaf> if_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_IF << OP_1 << OP_ENDIF}};
        Spend s{XcoinV3ScriptPubKey(if_leaves)};
        s.Witness() = {valtype{0x01}, ToByteVector(if_leaves[0].script), XcoinV3ControlBlock(if_leaves, 0)};
        s.ExpectOk(STD, "minimal IF argument");
        s.Witness()[0] = valtype{0x02};
        s.ExpectErr(STD, SCRIPT_ERR_TAPSCRIPT_MINIMALIF, "non-minimal IF argument");

        const std::vector<XcoinV3Leaf> ms_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_1 << hash_a << OP_1 << OP_CHECKMULTISIG}};
        Spend ms{XcoinV3ScriptPubKey(ms_leaves)};
        ms.Witness() = {valtype{}, valtype{}, ToByteVector(ms_leaves[0].script), XcoinV3ControlBlock(ms_leaves, 0)};
        ms.ExpectErr(STD, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG, "CHECKMULTISIG in a PQ leaf");

        // OP_CHECKSIG_PQ (0xbb) is OP_SUCCESS187 inside a v3 leaf: anyone-can-spend by consensus, discouraged.
        const std::vector<XcoinV3Leaf> succ_leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_CHECKSIG_PQ}};
        Spend succ{XcoinV3ScriptPubKey(succ_leaves)};
        succ.Witness() = {ToByteVector(succ_leaves[0].script), XcoinV3ControlBlock(succ_leaves, 0)};
        succ.ExpectOk(MAND, "OP_SUCCESSx by consensus");
        succ.ExpectErr(STD, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS, "OP_SUCCESSx discouraged");
    }
    {
        // Validation weight budget: each passing check costs XCOIN_V3_VALIDATION_WEIGHT_MLDSA
        // of the budget (witness size + VALIDATION_WEIGHT_OFFSET), charged before the key rule.
        // Use the upgradable key-hash path (2-byte hash, nothing verified) so the only thing
        // under test is the budget. The filler is derived from the constant rather than pinned,
        // so this boundary follows XCOIN_V3_VALIDATION_WEIGHT_MLDSA if it is ever rescaled with
        // MAX_BLOCK_WEIGHT again (it went 50 -> 200 on 2026-09-07): sized to afford exactly one
        // check and never three.
        const size_t mldsa_filler{static_cast<size_t>(2 * XCOIN_V3_VALIDATION_WEIGHT_MLDSA)};
        auto make = [&](int n) {
            CScript leaf;
            leaf << OP_DROP; // eats the budget filler, which is the top witness element
            for (int i = 0; i < n; ++i) leaf << valtype{0x01, 0x02} << OP_CHECKSIG << OP_DROP;
            leaf << OP_1;
            return std::vector<XcoinV3Leaf>{XcoinV3Leaf{XCOIN_LEAF_PQ, leaf}};
        };
        for (const int n : {1, 3}) {
            const auto wl{make(n)};
            Spend s{XcoinV3ScriptPubKey(wl)};
            for (int i = 0; i < n; ++i) {
                s.Witness().push_back(valtype{});     // key slot
                s.Witness().push_back(valtype{0x78}); // non-empty "signature"
            }
            s.Witness().push_back(valtype(mldsa_filler, 0x00)); // budget filler (unused by the script)
            s.Witness().push_back(ToByteVector(wl[0].script));
            s.Witness().push_back(XcoinV3ControlBlock(wl, 0));
            if (n == 1) {
                s.ExpectOk(MAND, "one upgradable check within budget");
            } else {
                s.ExpectErr(MAND, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, "three upgradable checks exceed the budget");
            }
            s.ExpectErr(STD, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, "upgradable key hash size discouraged");
        }
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_two_leaf_tree, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const CPQKey b{KeyFromSeedByte(0xb1)};
    const std::vector<XcoinV3Leaf> leaves{
        XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(a.GetPubKey())},
        XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(b.GetPubKey())},
    };
    const CScript spk{XcoinV3ScriptPubKey(leaves)};
    BOOST_CHECK(XcoinV3Root(leaves) == ComputeXcoinBranchHash(XcoinV3LeafHash(leaves[0]), XcoinV3LeafHash(leaves[1])));

    {
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        BOOST_CHECK_EQUAL(s.Witness()[3].size(), 33U + 32U);
        s.ExpectOk(STD, "spend via leaf 0");
    }
    {
        Spend s{spk};
        s.Witness() = PQLeafWitness(b, leaves, 1, s);
        s.ExpectOk(STD, "spend via leaf 1");
    }
    {
        Spend s{spk};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3][40] ^= 0x01;
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "wrong path");
        // Leaf 0's script with leaf 1's control block: the path leads elsewhere.
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness()[3] = XcoinV3ControlBlock(leaves, 1);
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "control block of the other leaf");
        // Leaf 1's script with a signature by a (the leaf commits to b's hash).
        s.Witness() = PQLeafWitness(a, leaves, 1, s);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "key hash of the other leaf");
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_timelocks, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const valtype hash_a{ToByteVector(a.GetPubKey().GetID())};

    // OP_CHECKLOCKTIMEVERIFY leaf: spendable once nLockTime >= 500.
    const std::vector<XcoinV3Leaf> cltv{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << 500 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << hash_a << OP_CHECKSIG}};
    for (const uint32_t locktime : {499U, 500U, 501U}) {
        Spend s{XcoinV3ScriptPubKey(cltv)};
        s.tx.nLockTime = locktime;
        s.Witness() = PQLeafWitness(a, cltv, 0, s);
        if (locktime < 500) {
            s.ExpectErr(STD, SCRIPT_ERR_UNSATISFIED_LOCKTIME, "CLTV early");
        } else {
            s.ExpectOk(STD, "CLTV late");
        }
    }
    // OP_CHECKSEQUENCEVERIFY leaf: spendable once the input's relative lock >= 5 blocks.
    const std::vector<XcoinV3Leaf> csv{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << 5 << OP_CHECKSEQUENCEVERIFY << OP_DROP << hash_a << OP_CHECKSIG}};
    for (const uint32_t sequence : {4U, 5U, 6U}) {
        Spend s{XcoinV3ScriptPubKey(csv), SPEND_VALUE, sequence};
        s.Witness() = PQLeafWitness(a, csv, 0, s);
        if (sequence < 5) {
            s.ExpectErr(STD, SCRIPT_ERR_UNSATISFIED_LOCKTIME, "CSV early");
        } else {
            s.ExpectOk(STD, "CSV late");
        }
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_checksigadd_2_of_3, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const CPQKey b{KeyFromSeedByte(0xb2)};
    const CPQKey c{KeyFromSeedByte(0xb3)};
    // <hA> CHECKSIG <hB> CHECKSIGADD <hC> CHECKSIGADD 2 NUMEQUAL
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ,
        CScript() << ToByteVector(a.GetPubKey().GetID()) << OP_CHECKSIG
                  << ToByteVector(b.GetPubKey().GetID()) << OP_CHECKSIGADD
                  << ToByteVector(c.GetPubKey().GetID()) << OP_CHECKSIGADD
                  << OP_2 << OP_NUMEQUAL}};
    const CScript spk{XcoinV3ScriptPubKey(leaves)};
    const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0])};

    // Witness (bottom to top): [keyC, sigC, keyB, sigB, keyA, sigA, script, control];
    // a non-signer's slot is [empty, empty].
    auto witness = [&](const Spend& s, bool sa, bool sb, bool sc) {
        std::vector<valtype> w;
        auto slot = [&](const CPQKey& k, bool sign) {
            if (sign) {
                w.push_back(ToByteVector(k.GetPubKey()));
                w.push_back(XcoinV3Sign(k, s.tx, 0, s.spent, ctx));
            } else {
                w.push_back(valtype{});
                w.push_back(valtype{});
            }
        };
        slot(c, sc);
        slot(b, sb);
        slot(a, sa);
        w.push_back(ToByteVector(leaves[0].script));
        w.push_back(XcoinV3ControlBlock(leaves, 0));
        return w;
    };

    Spend s{spk};
    s.Witness() = witness(s, true, false, true);
    s.ExpectOk(STD, "A+C");
    s.Witness() = witness(s, true, true, false);
    s.ExpectOk(STD, "A+B");
    s.Witness() = witness(s, false, true, true);
    s.ExpectOk(STD, "B+C");
    s.Witness() = witness(s, true, false, false);
    s.ExpectErr(STD, SCRIPT_ERR_EVAL_FALSE, "A only");
    s.Witness() = witness(s, true, true, true);
    s.ExpectErr(STD, SCRIPT_ERR_EVAL_FALSE, "A+B+C is 3, not 2");
    s.Witness() = witness(s, true, false, true);
    s.Witness()[2] = ToByteVector(b.GetPubKey()); // key without a signature in B's slot
    s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "key next to an empty signature");
    s.Witness() = witness(s, true, false, true);
    s.Witness().erase(s.Witness().begin()); // drop keyC: CHECKSIGADD needs 4 items
    s.ExpectErr(STD, SCRIPT_ERR_INVALID_STACK_OPERATION, "missing key slot");
    s.Witness() = witness(s, true, false, true);
    s.Witness()[1] = XcoinV3Sign(b, s.tx, 0, s.spent, ctx); // C's slot carries C's key but B's signature
    s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signature by the wrong key in a slot");
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_checktemplateverify, BasicTestingSetup)
{
    // The template commits to everything but the prevouts, so build the spend first, derive the
    // template hash, and only then lock the prevout to `<hash> OP_CHECKTEMPLATEVERIFY`.
    Spend s{CScript() << OP_3 << valtype(32, 0x00)};
    s.tx.vout.emplace_back(COIN, GetTestPQScript());
    PrecomputedTransactionData txdata;
    txdata.Init(s.tx, {}, /*force=*/true);
    BOOST_REQUIRE(txdata.m_ctv_ready);
    BOOST_CHECK(!txdata.m_ctv_has_scriptsigs);
    const uint256 tmpl{GetDefaultCheckTemplateVerifyHash(s.tx, txdata, 0)};

    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << ToByteVector(tmpl) << OP_CHECKTEMPLATEVERIFY}};
    s.spent[0].scriptPubKey = XcoinV3ScriptPubKey(leaves);
    s.Witness() = {ToByteVector(leaves[0].script), XcoinV3ControlBlock(leaves, 0)};
    s.ExpectOk(STD, "template matches");
    // The same template leaf under the SLH leaf version: CTV is part of the shared v3 leaf rules.
    {
        const std::vector<XcoinV3Leaf> slh_leaves{XcoinV3Leaf{XCOIN_LEAF_SLH, leaves[0].script}};
        Spend t{XcoinV3ScriptPubKey(slh_leaves)};
        t.tx = s.tx;
        t.Witness() = {ToByteVector(slh_leaves[0].script), XcoinV3ControlBlock(slh_leaves, 0)};
        t.ExpectOk(STD, "template matches under the SLH leaf");
        t.tx.nLockTime = 1;
        t.ExpectErr(STD, SCRIPT_ERR_TEMPLATE_MISMATCH, "locktime changed under the SLH leaf");
    }

    // The template hash changes with outputs, locktime and sequences, and a mismatch fails.
    {
        Spend bad{s.spent[0].scriptPubKey};
        bad.tx = s.tx;
        bad.tx.vout[0].nValue -= 1;
        bad.ExpectErr(STD, SCRIPT_ERR_TEMPLATE_MISMATCH, "output changed");
        bad.tx = s.tx;
        bad.tx.nLockTime = 1;
        bad.ExpectErr(STD, SCRIPT_ERR_TEMPLATE_MISMATCH, "locktime changed");
        bad.tx = s.tx;
        bad.tx.vin[0].nSequence = 7;
        bad.ExpectErr(STD, SCRIPT_ERR_TEMPLATE_MISMATCH, "sequence changed");
        bad.tx = s.tx;
        bad.tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
        bad.spent.emplace_back(COIN, s.spent[0].scriptPubKey);
        bad.ExpectErr(STD, SCRIPT_ERR_TEMPLATE_MISMATCH, "input count changed");
    }
    // A non-empty scriptSig anywhere is committed too (BIP-119 "scriptSigs hash if any").
    {
        CMutableTransaction with_sig{s.tx};
        with_sig.vin[0].scriptSig = CScript() << OP_1;
        PrecomputedTransactionData d2;
        d2.Init(with_sig, {}, /*force=*/true);
        BOOST_CHECK(d2.m_ctv_has_scriptsigs);
        BOOST_CHECK(GetDefaultCheckTemplateVerifyHash(with_sig, d2, 0) != tmpl);
    }
    // A non-32-byte argument is a NOP by consensus and discouraged by policy.
    {
        const std::vector<XcoinV3Leaf> nop{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << valtype(31, 0x01) << OP_CHECKTEMPLATEVERIFY}};
        Spend n{XcoinV3ScriptPubKey(nop)};
        n.Witness() = {ToByteVector(nop[0].script), XcoinV3ControlBlock(nop, 0)};
        n.ExpectOk(MAND, "31-byte CTV argument is a NOP");
        n.ExpectErr(STD, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "31-byte CTV argument discouraged");
        const std::vector<XcoinV3Leaf> empty{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_CHECKTEMPLATEVERIFY}};
        Spend e{XcoinV3ScriptPubKey(empty)};
        e.Witness() = {ToByteVector(empty[0].script), XcoinV3ControlBlock(empty, 0)};
        e.ExpectErr(MAND, SCRIPT_ERR_INVALID_STACK_OPERATION, "CTV on an empty stack");
    }
    // Outside a v3 leaf OP_NOP4 keeps NOP semantics: a garbage 32-byte argument passes.
    for (const SigVersion sv : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        std::vector<valtype> stack{valtype(32, 0xee)};
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK(EvalScript(stack, CScript() << OP_NOP4, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, sv, &err));
        BOOST_CHECK_EQUAL(stack.size(), 1U);
    }
    BOOST_CHECK_EQUAL(static_cast<int>(OP_CHECKTEMPLATEVERIFY), static_cast<int>(OP_NOP4));
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_annex, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(a.GetPubKey())}};
    const CScript spk{XcoinV3ScriptPubKey(leaves)};
    const valtype annex{ANNEX_TAG, 0x01, 0x02, 0x03};

    Spend s{spk};
    s.Witness() = PQLeafWitness(a, leaves, 0, s, SIGHASH_DEFAULT, annex);
    BOOST_CHECK_EQUAL(s.Witness().size(), 5U);
    s.ExpectOk(MAND, "annex committed by the signature");
    s.ExpectOk(STD, "annex is consensus-valid under standard flags too");

    // The annex is committed: a signature made without it does not verify with it present.
    s.Witness() = PQLeafWitness(a, leaves, 0, s);
    s.Witness().push_back(annex);
    s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "annex not committed");

    // Policy: annexes are non-standard; a plain spend is standard.
    CCoinsView base;
    CCoinsViewCache view{&base};
    view.AddCoin(s.tx.vin[0].prevout, Coin{s.spent[0], 1, false}, false);
    BOOST_CHECK(!IsWitnessStandard(CTransaction{s.tx}, view));
    s.Witness() = PQLeafWitness(a, leaves, 0, s);
    BOOST_CHECK(IsWitnessStandard(CTransaction{s.tx}, view));
    // Policy also caps PQ-leaf stack items at MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE.
    s.Witness().insert(s.Witness().begin(), valtype(MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE + 1, 0x00));
    BOOST_CHECK(!IsWitnessStandard(CTransaction{s.tx}, view));
    BOOST_CHECK_EQUAL(MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE, MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE);
}

// OP_CODESEPARATOR inside a v3 leaf: the sighash commits to the position of
// the last EXECUTED codeseparator (BIP-341 ext_flag = 1, codesep_pos), so a
// signature is bound to the point in the leaf script it was made at and cannot
// be replayed at another one. Both leaves here have the same script bytes as
// far as the key is concerned; only the committed position differs.
BOOST_FIXTURE_TEST_CASE(xcoin_v3_codeseparator, BasicTestingSetup)
{
    const CPQKey& a{GetTestPQKey()};
    const valtype key_hash{ToByteVector(a.GetPubKey().GetID())};
    // OP_CODESEPARATOR is opcode 0 of this leaf, so an executed one leaves
    // m_codeseparator_pos == 0; without it the position stays 0xFFFFFFFF.
    const std::vector<XcoinV3Leaf> sep{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_CODESEPARATOR << key_hash << OP_CHECKSIG}};
    const std::vector<XcoinV3Leaf> plain{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << key_hash << OP_CHECKSIG}};
    constexpr uint32_t NO_CODESEP{0xFFFFFFFF};

    // Valid: the leaf executes a codeseparator at position 0 and the signature
    // commits to position 0.
    {
        Spend s{XcoinV3ScriptPubKey(sep)};
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(sep[0]), .codeseparator_pos = 0};
        s.Witness() = {ToByteVector(a.GetPubKey()), XcoinV3Sign(a, s.tx, 0, s.spent, ctx),
                       ToByteVector(sep[0].script), XcoinV3ControlBlock(sep, 0)};
        s.ExpectOk(STD, "codeseparator at position 0, signature committed to 0");
    }
    // Mutated: the same leaf and the same witness shape, but the signature was
    // made as if no codeseparator had run. The sighash differs, so it fails.
    {
        Spend s{XcoinV3ScriptPubKey(sep)};
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(sep[0]), .codeseparator_pos = NO_CODESEP};
        s.Witness() = {ToByteVector(a.GetPubKey()), XcoinV3Sign(a, s.tx, 0, s.spent, ctx),
                       ToByteVector(sep[0].script), XcoinV3ControlBlock(sep, 0)};
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "codeseparator position not committed");
    }
    // The mirror, so the commitment is shown to bind in both directions: a leaf
    // with no codeseparator rejects a signature that claims position 0.
    {
        Spend ok{XcoinV3ScriptPubKey(plain)};
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(plain[0]), .codeseparator_pos = NO_CODESEP};
        ok.Witness() = {ToByteVector(a.GetPubKey()), XcoinV3Sign(a, ok.tx, 0, ok.spent, ctx),
                        ToByteVector(plain[0].script), XcoinV3ControlBlock(plain, 0)};
        ok.ExpectOk(STD, "no codeseparator, signature committed to 0xFFFFFFFF");

        Spend bad{XcoinV3ScriptPubKey(plain)};
        const XcoinV3SignContext wrong{.leaf_hash = XcoinV3LeafHash(plain[0]), .codeseparator_pos = 0};
        bad.Witness() = {ToByteVector(a.GetPubKey()), XcoinV3Sign(a, bad.tx, 0, bad.spent, wrong),
                         ToByteVector(plain[0].script), XcoinV3ControlBlock(plain, 0)};
        bad.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signature claims a codeseparator the leaf never ran");
    }
    // The two messages really are different (and the leaf hashes differ too,
    // which is why the scripts cannot simply be swapped).
    const XcoinV3SignContext at0{.leaf_hash = XcoinV3LeafHash(sep[0]), .codeseparator_pos = 0};
    const XcoinV3SignContext none{.leaf_hash = XcoinV3LeafHash(sep[0]), .codeseparator_pos = NO_CODESEP};
    Spend probe{XcoinV3ScriptPubKey(sep)};
    BOOST_CHECK(XcoinV3SighashForTest(probe.tx, 0, probe.spent, at0) != XcoinV3SighashForTest(probe.tx, 0, probe.spent, none));
    BOOST_CHECK(XcoinV3LeafHash(sep[0]) != XcoinV3LeafHash(plain[0]));
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_legacy_v2_and_consensus_output_rule, BasicTestingSetup)
{
    // A legacy witness v2 spend is unchanged and still valid.
    {
        Spend s{GetTestPQScript()};
        SignTestPQInput(s.tx, 0, s.spent[0]);
        s.ExpectOk(STD, "legacy v2 spend");
        s.Witness()[0][10] ^= 0x01;
        s.ExpectErr(STD, SCRIPT_ERR_CHECKSIGVERIFY, "legacy v2 spend with a bad signature");
    }
    // The PQ-only output rule admits v2 and v3 programs and OP_RETURN; v0 and v1 stay invalid to create.
    auto check = [](const CScript& spk, bool expect_ok) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(COIN, spk);
        TxValidationState state;
        const bool ok{CheckTransaction(CTransaction{tx}, state, /*permit_v2_outputs=*/true)};
        BOOST_CHECK_EQUAL(ok, expect_ok);
        if (!expect_ok) BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txout-not-pq");
    };
    check(GetTestPQScript(), true);
    check(GetTestXcoinV3Script(), true);
    check(CScript() << OP_RETURN << valtype{0x01}, true);
    check(CScript() << OP_0 << valtype(20, 0x01), false);
    check(CScript() << OP_0 << valtype(32, 0x01), false);
    check(CScript() << OP_1 << valtype(32, 0x01), false);
    check(CScript() << OP_3 << valtype(31, 0x01), false);
    check(CScript() << OP_DUP << OP_HASH160 << valtype(20, 0x01) << OP_EQUALVERIFY << OP_CHECKSIG, false);
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_standardness_and_addresses, BasicTestingSetup)
{
    const CScript v3{GetTestXcoinV3Script()};
    const CScript v2{GetTestPQScript()};

    TxoutType type;
    BOOST_CHECK(IsStandard(v3, type));
    BOOST_CHECK(type == TxoutType::WITNESS_V3_PQ);
    BOOST_CHECK_EQUAL(GetTxnOutputType(type), "witness_v3_pq");
    BOOST_CHECK(IsStandard(v2, type));
    BOOST_CHECK(type == TxoutType::WITNESS_V2_PQ);

    // v3 outputs are standard to create; v2 outputs are not unless the node permits them.
    auto tx_paying = [](const CScript& spk) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(COIN, spk);
        return CTransaction{tx};
    };
    std::string reason;
    BOOST_CHECK(IsStandardTx(tx_paying(v3), MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, /*permit_v2_outputs=*/false, CFeeRate{DUST_RELAY_TX_FEE}, reason));
    BOOST_CHECK(!IsStandardTx(tx_paying(v2), MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, /*permit_v2_outputs=*/false, CFeeRate{DUST_RELAY_TX_FEE}, reason));
    BOOST_CHECK_EQUAL(reason, "legacy-v2-output");
    BOOST_CHECK(IsStandardTx(tx_paying(v2), MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, /*permit_v2_outputs=*/true, CFeeRate{DUST_RELAY_TX_FEE}, reason));
    BOOST_CHECK(!DEFAULT_PERMIT_V2_OUTPUTS);

    // Sigops: a v3 input is charged like a v2 input.
    CScriptWitness wit;
    wit.stack = {valtype{}, valtype{}};
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript{}, v3, wit, STD), static_cast<size_t>(PQ_SIGOPS_COST));
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript{}, v2, wit, STD), static_cast<size_t>(PQ_SIGOPS_COST));

    // Destination and address plumbing: bech32m witness version 3 reads <hrp>1r...
    CTxDestination dest;
    BOOST_REQUIRE(ExtractDestination(v3, dest));
    BOOST_REQUIRE(std::holds_alternative<WitnessV3PQ>(dest));
    BOOST_CHECK(IsValidDestination(dest));
    BOOST_CHECK(GetScriptForDestination(dest) == v3);
    const std::string addr{EncodeDestination(dest)};
    const std::string hrp{Params().Bech32HRP()};
    BOOST_CHECK_EQUAL(addr.substr(0, hrp.size() + 2), hrp + "1r");
    std::string error;
    const CTxDestination decoded{DecodeDestination(addr, error, nullptr)};
    BOOST_CHECK_MESSAGE(error.empty(), error);
    BOOST_REQUIRE(std::holds_alternative<WitnessV3PQ>(decoded));
    BOOST_CHECK(std::get<WitnessV3PQ>(decoded) == std::get<WitnessV3PQ>(dest));
    BOOST_CHECK(GetScriptForDestination(decoded) == v3);
    // Mainnet HRP is "xpa", so mainnet v3 addresses read xpa1r...
    BOOST_CHECK_EQUAL(CreateChainParams(*m_node.args, ChainType::MAIN)->Bech32HRP(), "xpa");
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_mempool_and_block, TestChain100Setup)
{
    const CTransactionRef coinbase{m_coinbase_txns[0]};
    BOOST_REQUIRE(IsTestPQScript(coinbase->vout[0].scriptPubKey));
    const int start_height{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};

    // tx1: legacy v2 coinbase -> v3 output (a "sweep into v3").
    CMutableTransaction tx1;
    tx1.version = 2;
    tx1.vin.emplace_back(COutPoint{coinbase->GetHash(), 0}, CScript{}, CTxIn::SEQUENCE_FINAL - 1);
    tx1.vout.emplace_back(coinbase->vout[0].nValue - COIN / 100, GetTestXcoinV3Script());
    SignTestPQInput(tx1, 0, coinbase->vout[0]);

    // tx2: v3 -> {pq, slh} (the everyday leaf next to the fallback), signed through the ML-DSA leaf.
    CMutableTransaction tx2;
    tx2.version = 2;
    tx2.vin.emplace_back(COutPoint{CTransaction{tx1}.GetHash(), 0}, CScript{}, CTxIn::SEQUENCE_FINAL - 1);
    tx2.vout.emplace_back(tx1.vout[0].nValue - COIN / 100, GetTestXcoinV3PQSLHScript());
    SignTestXcoinV3Input(tx2, 0, {tx1.vout[0]});

    // tx3: {pq, slh} -> v3, signed through the SLH-DSA fallback leaf (a 7,856-byte witness item).
    CMutableTransaction tx3;
    tx3.version = 2;
    tx3.vin.emplace_back(COutPoint{CTransaction{tx2}.GetHash(), 0}, CScript{}, CTxIn::SEQUENCE_FINAL - 1);
    tx3.vout.emplace_back(tx2.vout[0].nValue - COIN / 100, GetTestXcoinV3Script());
    SignTestXcoinV3SLHInput(tx3, 0, {tx2.vout[0]});
    BOOST_CHECK_EQUAL(tx3.vin[0].scriptWitness.stack.size(), 3U);
    BOOST_CHECK_EQUAL(tx3.vin[0].scriptWitness.stack[0].size(), SLH_SIGNATURE_SIZE);

    // Policy path: tx1 and tx2 enter the mempool, tx3 is accepted against them (test-accept keeps
    // it out so the block below is built from the explicit list). Tampered ML-DSA and SLH-DSA
    // signatures are rejected by the mempool.
    {
        LOCK(cs_main);
        const auto r1{m_node.chainman->ProcessTransaction(MakeTransactionRef(tx1))};
        BOOST_REQUIRE_MESSAGE(r1.m_result_type == MempoolAcceptResult::ResultType::VALID, r1.m_state.ToString());
        CMutableTransaction bad2{tx2};
        bad2.vin[0].scriptWitness.stack[1][100] ^= 0x01;
        const auto r2bad{m_node.chainman->ProcessTransaction(MakeTransactionRef(bad2), /*test_accept=*/true)};
        BOOST_CHECK(r2bad.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        const auto r2{m_node.chainman->ProcessTransaction(MakeTransactionRef(tx2))};
        BOOST_REQUIRE_MESSAGE(r2.m_result_type == MempoolAcceptResult::ResultType::VALID, r2.m_state.ToString());
        CMutableTransaction bad3{tx3};
        bad3.vin[0].scriptWitness.stack[0][4000] ^= 0x01;
        const auto r3bad{m_node.chainman->ProcessTransaction(MakeTransactionRef(bad3), /*test_accept=*/true)};
        BOOST_CHECK(r3bad.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        const auto r3{m_node.chainman->ProcessTransaction(MakeTransactionRef(tx3), /*test_accept=*/true)};
        BOOST_REQUIRE_MESSAGE(r3.m_result_type == MempoolAcceptResult::ResultType::VALID, r3.m_state.ToString());
    }

    // Consensus path: a block with a tampered SLH-DSA spend is rejected, the honest one connects.
    {
        CMutableTransaction bad3{tx3};
        bad3.vin[0].scriptWitness.stack[0][4000] ^= 0x01;
        CreateAndProcessBlock({tx1, tx2, bad3}, GetTestPQScript());
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), start_height);
    }
    const CBlock block{CreateAndProcessBlock({tx1, tx2, tx3}, GetTestPQScript())};
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(m_node.chainman->ActiveChain().Height(), start_height + 1);
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    // tx2's {pq, slh} output is spent; tx3's v3 output is now in the UTXO set.
    BOOST_CHECK(!m_node.chainman->ActiveChainstate().CoinsTip().GetCoin(COutPoint{CTransaction{tx2}.GetHash(), 0}).has_value());
    const auto coin{m_node.chainman->ActiveChainstate().CoinsTip().GetCoin(COutPoint{CTransaction{tx3}.GetHash(), 0})};
    BOOST_REQUIRE(coin.has_value());
    BOOST_CHECK(coin->out.scriptPubKey == GetTestXcoinV3Script());
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_slh_leaf, BasicTestingSetup)
{
    const CSLHTestKey& skey{GetTestSLHKey()};
    const CSLHPubKey& spub{GetTestSLHPubKey()};
    const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3SLHLeafScript(spub)}};
    const CScript spk{XcoinV3ScriptPubKey(leaves)};
    const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0]), .sigversion = SigVersion::XCOIN_SLH_TAPSCRIPT};
    // The leaf script is <32-byte key> OP_CHECKSIG: the key itself, no hash; the witness carries
    // nothing but the signature.
    BOOST_CHECK(leaves[0].script == (CScript() << valtype(spub.begin(), spub.end()) << OP_CHECKSIG));
    BOOST_CHECK_EQUAL(leaves[0].script.size(), 34U);
    auto witness = [&](const valtype& sig) { return std::vector<valtype>{sig, ToByteVector(leaves[0].script), XcoinV3ControlBlock(leaves, 0)}; };

    // Valid spends: SIGHASH_DEFAULT (a 7,856-byte element) and explicit hash types (7,857 bytes).
    for (const int hash_type : {int{SIGHASH_DEFAULT}, int{SIGHASH_ALL}, int{SIGHASH_SINGLE | SIGHASH_ANYONECANPAY}}) {
        Spend s{spk};
        const valtype sig{XcoinV3SignSLH(skey, s.tx, 0, s.spent, ctx, hash_type)};
        BOOST_CHECK_EQUAL(sig.size(), SLH_SIGNATURE_SIZE + (hash_type == SIGHASH_DEFAULT ? 0U : 1U));
        s.Witness() = witness(sig);
        s.ExpectOk(STD, "SLH leaf spend, hash type " + std::to_string(hash_type));
    }
    {
        Spend s{spk};
        const valtype good{XcoinV3SignSLH(skey, s.tx, 0, s.spent, ctx)};
        // key_version 0x03: neither the ML-DSA digest (0x02) nor the untagged BIP-341 message
        // verifies; nor does an internal-mode (no FIPS 205 prefix) signature over the right digest.
        const uint256 slh_digest{XcoinV3SighashForTest(s.tx, 0, s.spent, ctx)};
        const uint256 pq_digest{XcoinV3SighashForTest(s.tx, 0, s.spent, XcoinV3SignContext{.leaf_hash = ctx.leaf_hash})};
        BOOST_CHECK(slh_digest != pq_digest);
        valtype sig;
        BOOST_REQUIRE(skey.Sign(pq_digest, sig));
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signature over the ML-DSA key_version digest");
        BOOST_REQUIRE(skey.Sign(XcoinV3SighashMessageForTest(s.tx, 0, s.spent, ctx), sig));
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signature over the untagged message");
        BOOST_REQUIRE(skey.SignInternal(slh_digest, sig));
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "internal-mode signature without the FIPS 205 prefix");
        // Tampered signature.
        sig = good;
        sig[1234] ^= 0x01;
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "tampered signature");
        // Wrong key: the leaf commits to another key.
        CSLHTestKey other;
        std::array<unsigned char, SLH_SEED_SIZE> seed{};
        seed.fill(0xb5);
        const CSLHPubKey other_pub{other.MakeKeyFromSeed(seed)};
        const std::vector<XcoinV3Leaf> other_leaves{XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3SLHLeafScript(other_pub)}};
        Spend o{XcoinV3ScriptPubKey(other_leaves)};
        const XcoinV3SignContext octx{.leaf_hash = XcoinV3LeafHash(other_leaves[0]), .sigversion = SigVersion::XCOIN_SLH_TAPSCRIPT};
        o.Witness() = {XcoinV3SignSLH(skey, o.tx, 0, o.spent, octx), ToByteVector(other_leaves[0].script), XcoinV3ControlBlock(other_leaves, 0)};
        o.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signed by a key other than the leaf's");
        o.Witness()[0] = XcoinV3SignSLH(other, o.tx, 0, o.spent, octx);
        o.ExpectOk(STD, "signed by the leaf's key");
        // Sizes: exactly 7,856 or 7,857 bytes; an explicit 0x00 hash type is invalid; unknown hash
        // types fail; 8,192 bytes is within the element limit but not a signature; 8,193 is over it.
        sig = good;
        sig.push_back(SIGHASH_DEFAULT);
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_HASHTYPE, "explicit 0x00 hash type");
        sig = good;
        sig.push_back(0x04);
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_HASHTYPE, "unknown hash type");
        sig = good;
        sig.push_back(SIGHASH_ALL);
        sig.push_back(SIGHASH_ALL);
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "7,858 bytes");
        sig = good;
        sig.pop_back();
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "7,855 bytes");
        sig = good;
        sig.resize(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE, 0x00);
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "8,192 bytes");
        sig.push_back(0x00);
        s.Witness() = witness(sig);
        s.ExpectErr(STD, SCRIPT_ERR_PUSH_SIZE, "8,193 bytes");
        // An empty signature is false without failing (k-of-n slots); here it is the only check.
        s.Witness() = witness(valtype{});
        s.ExpectErr(STD, SCRIPT_ERR_EVAL_FALSE, "empty signature");
        // The algorithms are not interchangeable. An ML-DSA signature under the SLH leaf has the
        // wrong size; so does an SLH leaf built over an ML-DSA key hash with the ML-DSA witness
        // (the SLH rule reads (sig pubkey): the 1,952-byte key sits where the signature belongs).
        const CPQKey& a{GetTestPQKey()};
        s.Witness() = witness(XcoinV3Sign(a, s.tx, 0, s.spent, XcoinV3SignContext{.leaf_hash = ctx.leaf_hash}));
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "ML-DSA signature under the SLH leaf");
        const std::vector<XcoinV3Leaf> hash_leaves{XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3PQLeafScript(a.GetPubKey())}};
        Spend h{XcoinV3ScriptPubKey(hash_leaves)};
        const XcoinV3SignContext hctx{.leaf_hash = XcoinV3LeafHash(hash_leaves[0])};
        h.Witness() = {ToByteVector(a.GetPubKey()), XcoinV3Sign(a, h.tx, 0, h.spent, hctx), ToByteVector(hash_leaves[0].script), XcoinV3ControlBlock(hash_leaves, 0)};
        h.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG_SIZE, "ML-DSA witness under an SLH-version leaf");
        // ...and an SLH witness under the PQ leaf version is refused as a bad key (the PQ rule
        // wants a 1,952-byte ML-DSA key below the signature).
        const std::vector<XcoinV3Leaf> pq_version{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3SLHLeafScript(spub)}};
        Spend p{XcoinV3ScriptPubKey(pq_version)};
        const XcoinV3SignContext pctx{.leaf_hash = XcoinV3LeafHash(pq_version[0])};
        valtype psig;
        BOOST_REQUIRE(skey.Sign(XcoinV3SighashForTest(p.tx, 0, p.spent, pctx), psig));
        p.Witness() = {valtype(spub.begin(), spub.end()), psig, ToByteVector(pq_version[0].script), XcoinV3ControlBlock(pq_version, 0)};
        p.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_PUBKEY, "SLH witness under the PQ leaf version");
    }
    // Upgradable key types inside the SLH leaf: a key push of another size is not checked
    // (success unchanged) and discouraged by policy, the same soft-fork room as BIP 342; an
    // empty key fails.
    {
        // (OP_DROP eats a filler that keeps the validation-weight budget above the
        // XCOIN_V3_VALIDATION_WEIGHT_SLH the non-empty signature is charged before the key rule.
        // Derived from the constant, not pinned: it was 250 while the weight was 270 and the
        // block 16M WU, and follows the weight now that both are 4x.)
        const std::vector<XcoinV3Leaf> up{XcoinV3Leaf{XCOIN_LEAF_SLH, CScript() << OP_DROP << valtype(33, 0x02) << OP_CHECKSIG}};
        Spend s{XcoinV3ScriptPubKey(up)};
        s.Witness() = {valtype{0x01}, valtype(static_cast<size_t>(XCOIN_V3_VALIDATION_WEIGHT_SLH), 0x00), ToByteVector(up[0].script), XcoinV3ControlBlock(up, 0)};
        s.ExpectOk(MAND, "33-byte key: upgradable by consensus");
        s.ExpectErr(STD, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, "33-byte key discouraged");
        const std::vector<XcoinV3Leaf> empty_key{XcoinV3Leaf{XCOIN_LEAF_SLH, CScript() << OP_0 << OP_CHECKSIG}};
        Spend e{XcoinV3ScriptPubKey(empty_key)};
        e.Witness() = {valtype{}, ToByteVector(empty_key[0].script), XcoinV3ControlBlock(empty_key, 0)};
        e.ExpectErr(MAND, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY, "empty key");
    }
    // Validation weight: a non-empty signature costs XCOIN_V3_VALIDATION_WEIGHT_SLH of the
    // budget witness size + 50, charged before the key rule. Leaf OP_DROP <33-byte key> OP_CHECKSIG
    // with witness [1-byte sig, filler]: the filler sets the budget (budget = filler + 125), and
    // the pass/fail boundary sits exactly at XCOIN_V3_VALIDATION_WEIGHT_SLH. The sweep is centred
    // on the constant rather than pinned to a literal, so it still straddles the boundary if the
    // weight is rescaled with MAX_BLOCK_WEIGHT (270 -> 1080 on 2026-09-07).
    {
        const std::vector<XcoinV3Leaf> wl{XcoinV3Leaf{XCOIN_LEAF_SLH, CScript() << OP_DROP << valtype(33, 0x02) << OP_CHECKSIG}};
        const CScript wspk{XcoinV3ScriptPubKey(wl)};
        bool saw_ok{false}, saw_fail{false};
        const size_t slh_centre{static_cast<size_t>(XCOIN_V3_VALIDATION_WEIGHT_SLH) - 125};
        for (size_t filler = slh_centre - 5; filler <= slh_centre + 5; ++filler) {
            Spend s{wspk};
            s.Witness() = {valtype{0x01}, valtype(filler, 0x00), ToByteVector(wl[0].script), XcoinV3ControlBlock(wl, 0)};
            const int64_t budget{static_cast<int64_t>(::GetSerializeSize(s.tx.vin[0].scriptWitness.stack)) + VALIDATION_WEIGHT_OFFSET};
            if (budget >= XCOIN_V3_VALIDATION_WEIGHT_SLH) {
                s.ExpectOk(MAND, "budget " + std::to_string(budget));
                saw_ok = true;
            } else {
                s.ExpectErr(MAND, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, "budget " + std::to_string(budget));
                saw_fail = true;
            }
        }
        BOOST_CHECK(saw_ok && saw_fail);
    }
    // 1-of-2 with OP_CHECKSIGADD in the BIP 342 shape (sig num pubkey -- num): the witness is
    // [sig for key 2, sig for key 1] bottom to top, an empty signature for the non-signer.
    {
        CSLHTestKey other;
        std::array<unsigned char, SLH_SEED_SIZE> seed{};
        seed.fill(0xb6);
        const CSLHPubKey other_pub{other.MakeKeyFromSeed(seed)};
        const std::vector<XcoinV3Leaf> kn{XcoinV3Leaf{XCOIN_LEAF_SLH,
            CScript() << valtype(spub.begin(), spub.end()) << OP_CHECKSIG
                      << valtype(other_pub.begin(), other_pub.end()) << OP_CHECKSIGADD
                      << OP_1 << OP_NUMEQUAL}};
        Spend s{XcoinV3ScriptPubKey(kn)};
        const XcoinV3SignContext kctx{.leaf_hash = XcoinV3LeafHash(kn[0]), .sigversion = SigVersion::XCOIN_SLH_TAPSCRIPT};
        const valtype sig_test{XcoinV3SignSLH(skey, s.tx, 0, s.spent, kctx)};
        const valtype sig_other{XcoinV3SignSLH(other, s.tx, 0, s.spent, kctx)};
        const valtype script{ToByteVector(kn[0].script)};
        const valtype control{XcoinV3ControlBlock(kn, 0)};
        s.Witness() = {valtype{}, sig_test, script, control};
        s.ExpectOk(STD, "1-of-2 by the first key");
        s.Witness() = {sig_other, valtype{}, script, control};
        s.ExpectOk(STD, "1-of-2 by the second key");
        s.Witness() = {sig_other, sig_test, script, control};
        s.ExpectErr(STD, SCRIPT_ERR_EVAL_FALSE, "both signed: 2, not 1");
        s.Witness() = {sig_test, valtype{}, script, control};
        s.ExpectErr(STD, SCRIPT_ERR_XCOIN_V3_SIG, "signature in the wrong slot");
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_pq_slh_tree, BasicTestingSetup)
{
    // {pq(A), slh(S)}: the everyday ML-DSA leaf next to the hash-based fallback leaf.
    const std::vector<XcoinV3Leaf>& leaves{GetTestXcoinV3PQSLHLeaves()};
    const CScript spk{GetTestXcoinV3PQSLHScript()};
    BOOST_REQUIRE_EQUAL(leaves.size(), 2U);
    BOOST_CHECK_EQUAL(static_cast<int>(leaves[0].version), static_cast<int>(XCOIN_LEAF_PQ));
    BOOST_CHECK_EQUAL(static_cast<int>(leaves[1].version), static_cast<int>(XCOIN_LEAF_SLH));
    BOOST_CHECK(XcoinV3Root(leaves) == ComputeXcoinBranchHash(XcoinV3LeafHash(leaves[0]), XcoinV3LeafHash(leaves[1])));
    // The leaf version is committed: the same script hashes differently under 0xc0 and 0xc2.
    BOOST_CHECK(ComputeXcoinLeafHash(XCOIN_LEAF_SLH, leaves[1].script) != ComputeXcoinLeafHash(XCOIN_LEAF_PQ, leaves[1].script));

    // Spend through the SLH leaf (the helper the round-trip test uses).
    {
        Spend s{spk};
        SignTestXcoinV3SLHInput(s.tx, 0, s.spent);
        BOOST_CHECK_EQUAL(s.Witness().size(), 3U);
        BOOST_CHECK_EQUAL(s.Witness()[0].size(), SLH_SIGNATURE_SIZE);
        BOOST_CHECK_EQUAL(s.Witness()[2].size(), XCOIN_V3_CONTROL_BASE_SIZE + XCOIN_V3_CONTROL_NODE_SIZE);
        BOOST_CHECK_EQUAL(static_cast<int>(s.Witness()[2][0]), static_cast<int>(XCOIN_LEAF_SLH));
        s.ExpectOk(STD, "spend via the SLH leaf");
        // Policy: a 7,856-byte item is standard under the SLH leaf; an 8,193-byte item is not.
        CCoinsView base;
        CCoinsViewCache view{&base};
        view.AddCoin(s.tx.vin[0].prevout, Coin{s.spent[0], 1, false}, false);
        BOOST_CHECK(IsWitnessStandard(CTransaction{s.tx}, view));
        s.Witness().insert(s.Witness().begin(), valtype(MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE + 1, 0x00));
        BOOST_CHECK(!IsWitnessStandard(CTransaction{s.tx}, view));
        // Cross-leaf confusion: the SLH script with the PQ leaf's control block, or claimed as
        // version 0xc0 on the right path, no longer hashes to the committed root.
        SignTestXcoinV3SLHInput(s.tx, 0, s.spent);
        s.Witness()[2] = XcoinV3ControlBlock(leaves, 0);
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "SLH script with the PQ leaf's control block");
        SignTestXcoinV3SLHInput(s.tx, 0, s.spent);
        s.Witness()[2][0] = XCOIN_LEAF_PQ;
        s.ExpectErr(STD, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "SLH leaf claimed as version 0xc0");
    }
    // Spend through the PQ leaf.
    {
        Spend s{spk};
        s.Witness() = PQLeafWitness(GetTestPQKey(), leaves, 0, s);
        s.ExpectOk(STD, "spend via the PQ leaf");
    }
}

// Founder decision "cpu" (fee study D8): the v3 leaves charge every byte hashed against the
// validation-weight budget, and carry MAX_SCRIPT_SIZE and MAX_OPS_PER_SCRIPT like BASE and
// WITNESS_V0. See the comment on MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE in script/xcoin_v3.h for the
// worst-case derivation (about 5.0 MB hashed per 4M WU block, 80 MB per 64M WU block, down
// from 10.9 GB and 175 GB).
BOOST_FIXTURE_TEST_CASE(xcoin_v3_hash_budget, BasicTestingSetup)
{
    BOOST_CHECK_EQUAL(XCOIN_V3_VALIDATION_WEIGHT_PER_HASHED_BYTE, 1);
    // The hole itself: a leaf that hashes an 8,192-byte witness element twice asks for 16,384
    // bytes of hashing from a budget of 1 + (3 + 8,192) + (1 + 8) + (1 + 33) + 50 = 8,289 units;
    // hashing it once (8,192, budget 8,286 with the 5-byte leaf) fits. Both leaf versions, all
    // five hash opcodes.
    for (const uint8_t version : {XCOIN_LEAF_PQ, XCOIN_LEAF_SLH}) {
        for (const opcodetype hash_op : {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256}) {
            // OP_HASH160 / OP_HASH256 hash the input and then the 32-byte digest.
            const int64_t per_hash_extra{(hash_op == OP_HASH160 || hash_op == OP_HASH256) ? int64_t{32} : int64_t{0}};
            for (const int hashes : {1, 2}) {
                CScript script;
                for (int i = 0; i < hashes; ++i) script << OP_DUP << hash_op << OP_DROP;
                script << OP_DROP << OP_1;
                const XcoinV3Leaf leaf{version, script};
                Spend s{XcoinV3ScriptPubKey({leaf})};
                s.Witness() = {valtype(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE, 0x5a), ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
                const int64_t budget{Budget(s)};
                const int64_t hashed{hashes * (static_cast<int64_t>(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE) + per_hash_extra)};
                const std::string what{"leaf 0x" + HexStr(std::vector<uint8_t>{version}) + " " + GetOpName(hash_op) + " x" + std::to_string(hashes) + ", budget " + std::to_string(budget) + ", hashed " + std::to_string(hashed)};
                if (hashes == 1) {
                    BOOST_CHECK(hashed <= budget);
                    const int64_t left{RunLeafForBudget(s, leaf, MAND, true, SCRIPT_ERR_OK, what)};
                    BOOST_CHECK_EQUAL(left, budget - hashed);
                } else {
                    BOOST_CHECK(hashed > budget);
                    const int64_t left{RunLeafForBudget(s, leaf, MAND, false, SCRIPT_ERR_XCOIN_V3_HASH_WEIGHT, what)};
                    BOOST_CHECK(left < 0); // charged before the hash was computed, then failed
                }
            }
        }
    }
    // The exact boundary. `OP_DUP <op> OP_DROP OP_DUP <op> OP_DROP OP_DROP OP_1` (8 bytes) over
    // one n-byte element: budget = 1 + (1 + n) + (1 + 8) + (1 + 33) + 50 = n + 95 for n < 253;
    // hashed = 2 x (n + extra). OP_SHA256 fails first at n = 96 (192 > 191); OP_HASH256, with
    // its extra 32 bytes per hash, at n = 32 (128 > 127).
    for (const opcodetype hash_op : {OP_SHA256, OP_HASH256}) {
        const int64_t extra{hash_op == OP_HASH256 ? int64_t{32} : int64_t{0}};
        const XcoinV3Leaf leaf{XCOIN_LEAF_PQ, CScript() << OP_DUP << hash_op << OP_DROP << OP_DUP << hash_op << OP_DROP << OP_DROP << OP_1};
        const CScript spk{XcoinV3ScriptPubKey({leaf})};
        const size_t first_fail{hash_op == OP_HASH256 ? 32U : 96U};
        for (size_t n = first_fail - 3; n <= first_fail + 2; ++n) {
            Spend s{spk};
            s.Witness() = {valtype(n, 0x00), ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
            const int64_t budget{Budget(s)};
            BOOST_CHECK_EQUAL(budget, static_cast<int64_t>(n) + 95);
            const int64_t hashed{2 * (static_cast<int64_t>(n) + extra)};
            const std::string what{std::string{GetOpName(hash_op)} + " twice over " + std::to_string(n) + " bytes"};
            if (n < first_fail) {
                BOOST_CHECK(hashed <= budget);
                BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaf, MAND, true, SCRIPT_ERR_OK, what), budget - hashed);
            } else {
                BOOST_CHECK(hashed > budget);
                RunLeafForBudget(s, leaf, MAND, false, SCRIPT_ERR_XCOIN_V3_HASH_WEIGHT, what);
            }
        }
    }
    // One budget for hashing and signature checks together: a hash that fits, followed by a
    // signature check that no longer does, fails with the signature-check error. The upgradable
    // key-hash path (2-byte hash, nothing verified, but a non-empty signature charges 200) keeps
    // the ML-DSA machinery out of the arithmetic. Witness: [key slot (empty), "sig", preimage,
    // filler]; the script hashes the preimage, drops filler, hash and result.
    {
        const XcoinV3Leaf leaf{XCOIN_LEAF_PQ, CScript() << OP_DROP << OP_SHA256 << OP_DROP << valtype{0x01, 0x02} << OP_CHECKSIG};
        const CScript spk{XcoinV3ScriptPubKey({leaf})};
        const size_t preimage{MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE};
        bool saw_ok{false}, saw_fail{false};
        for (size_t filler = 90; filler <= 110; ++filler) {
            Spend s{spk};
            s.Witness() = {valtype{}, valtype{0x78}, valtype(preimage, 0x00), valtype(filler, 0x00), ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
            const int64_t budget{Budget(s)};
            const int64_t charged{static_cast<int64_t>(preimage) + XCOIN_V3_VALIDATION_WEIGHT_MLDSA};
            const std::string what{"hash 8,192 then a 200-unit check, budget " + std::to_string(budget)};
            BOOST_CHECK(static_cast<int64_t>(preimage) <= budget); // the hash alone always fits
            if (charged <= budget) {
                BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaf, MAND, true, SCRIPT_ERR_OK, what), budget - charged);
                saw_ok = true;
            } else {
                RunLeafForBudget(s, leaf, MAND, false, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, what);
                saw_fail = true;
            }
        }
        BOOST_CHECK(saw_ok && saw_fail);
    }
    // Hash opcodes in an unexecuted branch charge nothing.
    {
        const XcoinV3Leaf leaf{XCOIN_LEAF_SLH, CScript() << OP_0 << OP_IF << OP_DUP << OP_SHA256 << OP_DROP << OP_DUP << OP_SHA256 << OP_DROP << OP_ENDIF << OP_DROP << OP_1};
        Spend s{XcoinV3ScriptPubKey({leaf})};
        s.Witness() = {valtype(MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE, 0x5a), ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
        BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaf, MAND, true, SCRIPT_ERR_OK, "unexecuted hashes"), Budget(s));
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_script_size_and_op_count, BasicTestingSetup)
{
    // MAX_SCRIPT_SIZE: a 10,000-byte leaf passes, a 10,001-byte one fails with SCRIPT_SIZE. The
    // bulk is 520-byte pushes inside an unexecuted OP_IF so that neither the stack limit nor the
    // opcode limit (pushes do not count) is what is under test. Both leaf versions.
    auto sized_leaf = [](uint8_t version, size_t target) {
        CScript script;
        script << OP_0 << OP_IF;
        const size_t tail{2}; // OP_ENDIF OP_1
        while (script.size() + tail < target) {
            const size_t room{target - tail - script.size()};
            // The largest data push whose encoding (1, 2 or 3 opcode bytes plus the data) fits.
            size_t data{0};
            if (room >= 3 + MAX_SCRIPT_ELEMENT_SIZE) {
                data = MAX_SCRIPT_ELEMENT_SIZE;
            } else if (room >= 259) {
                data = room - 3;
            } else if (room >= 78) {
                data = std::min<size_t>(room - 2, 255);
            } else if (room >= 2) {
                data = std::min<size_t>(room - 1, 75);
            }
            if (data > 0) {
                script << valtype(data, 0x00);
            } else {
                script << OP_NOP;
            }
        }
        script << OP_ENDIF << OP_1;
        BOOST_REQUIRE_EQUAL(script.size(), target);
        return XcoinV3Leaf{version, script};
    };
    for (const uint8_t version : {XCOIN_LEAF_PQ, XCOIN_LEAF_SLH}) {
        for (const size_t size : {size_t{MAX_SCRIPT_SIZE}, size_t{MAX_SCRIPT_SIZE} + 1}) {
            const XcoinV3Leaf leaf{sized_leaf(version, size)};
            Spend s{XcoinV3ScriptPubKey({leaf})};
            s.Witness() = {ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
            const std::string what{std::to_string(size) + "-byte leaf, version 0x" + HexStr(std::vector<uint8_t>{version})};
            if (size <= static_cast<size_t>(MAX_SCRIPT_SIZE)) {
                s.ExpectOk(STD, what);
            } else {
                s.ExpectErr(MAND, SCRIPT_ERR_SCRIPT_SIZE, what);
            }
        }
    }
    // MAX_OPS_PER_SCRIPT: 201 non-push opcodes pass, 202 fail with OP_COUNT. Pushes (OP_0 to
    // OP_16 and the data pushes) do not count, and unexecuted opcodes do.
    for (const uint8_t version : {XCOIN_LEAF_PQ, XCOIN_LEAF_SLH}) {
        for (const int ops : {MAX_OPS_PER_SCRIPT, MAX_OPS_PER_SCRIPT + 1}) {
            CScript script;
            for (int i = 0; i < ops; ++i) script << OP_NOP;
            script << OP_1;
            const XcoinV3Leaf leaf{version, script};
            Spend s{XcoinV3ScriptPubKey({leaf})};
            s.Witness() = {ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
            const std::string what{std::to_string(ops) + " NOPs, version 0x" + HexStr(std::vector<uint8_t>{version})};
            if (ops <= MAX_OPS_PER_SCRIPT) {
                s.ExpectOk(STD, what);
            } else {
                s.ExpectErr(MAND, SCRIPT_ERR_OP_COUNT, what);
            }
        }
    }
    {
        // Pushes are free and unexecuted opcodes are not: OP_0 OP_IF <1,000 pushes> OP_ENDIF then
        // n NOPs and OP_1 runs 2 + n non-push opcodes. n = 199 passes (201), n = 200 fails (202).
        for (const int nops : {MAX_OPS_PER_SCRIPT - 2, MAX_OPS_PER_SCRIPT - 1}) {
            CScript script;
            script << OP_0 << OP_IF;
            for (int i = 0; i < 1000; ++i) script << OP_1;
            script << OP_ENDIF;
            for (int i = 0; i < nops; ++i) script << OP_NOP;
            script << OP_1;
            const XcoinV3Leaf leaf{XCOIN_LEAF_PQ, script};
            Spend s{XcoinV3ScriptPubKey({leaf})};
            s.Witness() = {ToByteVector(leaf.script), XcoinV3ControlBlock({leaf}, 0)};
            if (2 + nops <= MAX_OPS_PER_SCRIPT) {
                s.ExpectOk(STD, "1,000 free pushes and 201 opcodes");
            } else {
                s.ExpectErr(MAND, SCRIPT_ERR_OP_COUNT, "1,000 free pushes and 202 opcodes");
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(xcoin_v3_reference_leaves_within_budget, BasicTestingSetup)
{
    // The everyday spends validate exactly as before; the arithmetic is shown against
    // EvalScript's remaining budget. No reference leaf hashes anything but a hash-lock
    // preimage, so the hash charge never touches them.
    const CPQKey& a{GetTestPQKey()};
    const valtype hash_a{ToByteVector(a.GetPubKey().GetID())};
    {
        // Ordinary ML-DSA spend: witness [key 1,952, sig 3,309, script 34, control 33] serializes
        // to 1 + 1,955 + 3,312 + 35 + 34 = 5,337 bytes, budget 5,387; one check spends 200.
        const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, XcoinV3PQLeafScript(a.GetPubKey())}};
        Spend s{XcoinV3ScriptPubKey(leaves)};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        const int64_t budget{Budget(s)};
        BOOST_CHECK_EQUAL(budget, 1 + (3 + PQ_PUBKEY_SIZE) + (3 + PQ_SIGNATURE_SIZE) + (1 + 34) + (1 + 33) + VALIDATION_WEIGHT_OFFSET);
        BOOST_CHECK_EQUAL(budget, 5387);
        BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, true, SCRIPT_ERR_OK, "ML-DSA spend"), budget - XCOIN_V3_VALIDATION_WEIGHT_MLDSA);
    }
    {
        // Ordinary SLH spend: witness [sig 7,856, script 34, control 33] serializes to
        // 1 + 7,859 + 35 + 34 = 7,929 bytes, budget 7,979; one check spends 1,080.
        const CSLHTestKey& skey{GetTestSLHKey()};
        const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_SLH, XcoinV3SLHLeafScript(GetTestSLHPubKey())}};
        Spend s{XcoinV3ScriptPubKey(leaves)};
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0]), .sigversion = SigVersion::XCOIN_SLH_TAPSCRIPT};
        s.Witness() = {XcoinV3SignSLH(skey, s.tx, 0, s.spent, ctx), ToByteVector(leaves[0].script), XcoinV3ControlBlock(leaves, 0)};
        const int64_t budget{Budget(s)};
        BOOST_CHECK_EQUAL(budget, 1 + (3 + SLH_SIGNATURE_SIZE) + (1 + 34) + (1 + 33) + VALIDATION_WEIGHT_OFFSET);
        BOOST_CHECK_EQUAL(budget, 7979);
        BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, true, SCRIPT_ERR_OK, "SLH spend"), budget - XCOIN_V3_VALIDATION_WEIGHT_SLH);
    }
    {
        // 2-of-3 CHECKSIGADD leaf signed by A and C: two keys and two signatures, two empty
        // slots; two non-empty checks spend 400. Script: 3 x 33 + 3 + 2 = 104 bytes. Budget
        // 1 + 2 x (1,955 + 3,312) + 2 x 1 + 105 + 34 + 50 = 10,726.
        const CPQKey b{KeyFromSeedByte(0xb2)};
        const CPQKey c{KeyFromSeedByte(0xb3)};
        const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ,
            CScript() << hash_a << OP_CHECKSIG
                      << ToByteVector(b.GetPubKey().GetID()) << OP_CHECKSIGADD
                      << ToByteVector(c.GetPubKey().GetID()) << OP_CHECKSIGADD
                      << OP_2 << OP_NUMEQUAL}};
        Spend s{XcoinV3ScriptPubKey(leaves)};
        const XcoinV3SignContext ctx{.leaf_hash = XcoinV3LeafHash(leaves[0])};
        s.Witness() = {ToByteVector(c.GetPubKey()), XcoinV3Sign(c, s.tx, 0, s.spent, ctx), valtype{}, valtype{},
                       ToByteVector(a.GetPubKey()), XcoinV3Sign(a, s.tx, 0, s.spent, ctx),
                       ToByteVector(leaves[0].script), XcoinV3ControlBlock(leaves, 0)};
        const int64_t budget{Budget(s)};
        BOOST_CHECK_EQUAL(budget, 1 + 2 * ((3 + PQ_PUBKEY_SIZE) + (3 + PQ_SIGNATURE_SIZE)) + 2 * 1 + (1 + 104) + (1 + 33) + VALIDATION_WEIGHT_OFFSET);
        BOOST_CHECK_EQUAL(budget, 10726);
        BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, true, SCRIPT_ERR_OK, "2-of-3 CHECKSIGADD"), budget - 2 * XCOIN_V3_VALIDATION_WEIGHT_MLDSA);
    }
    {
        // Hash-lock leaf: `OP_SHA256 <h> OP_EQUALVERIFY <hash_a> OP_CHECKSIG` (69 bytes) over a
        // 32-byte preimage. Witness [key, sig, preimage 32, script 69, control 33]: budget
        // 1 + 1,955 + 3,312 + 33 + 70 + 34 + 50 = 5,455; the hash charges 32, the check 200.
        const valtype preimage(32, 0x42);
        valtype h(32);
        CSHA256().Write(preimage.data(), preimage.size()).Finalize(h.data());
        const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << OP_SHA256 << h << OP_EQUALVERIFY << hash_a << OP_CHECKSIG}};
        BOOST_CHECK_EQUAL(leaves[0].script.size(), 69U);
        Spend s{XcoinV3ScriptPubKey(leaves)};
        s.Witness() = PQLeafWitness(a, leaves, 0, s);
        s.Witness().insert(s.Witness().begin() + 2, preimage);
        const int64_t budget{Budget(s)};
        BOOST_CHECK_EQUAL(budget, 5455);
        BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, true, SCRIPT_ERR_OK, "hash-lock"), budget - 32 - XCOIN_V3_VALIDATION_WEIGHT_MLDSA);
        // Wrong preimage still fails on the hash, not on the budget.
        s.Witness()[2][0] ^= 0x01;
        s.ExpectErr(STD, SCRIPT_ERR_EQUALVERIFY, "wrong preimage");
    }
    {
        // CLTV leaf `<500> OP_CHECKLOCKTIMEVERIFY OP_DROP <hash_a> OP_CHECKSIG` (39 bytes):
        // budget 1 + 1,955 + 3,312 + 40 + 34 + 50 = 5,392; nothing but the check is charged.
        const std::vector<XcoinV3Leaf> leaves{XcoinV3Leaf{XCOIN_LEAF_PQ, CScript() << 500 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << hash_a << OP_CHECKSIG}};
        BOOST_CHECK_EQUAL(leaves[0].script.size(), 39U);
        for (const uint32_t locktime : {499U, 500U}) {
            Spend s{XcoinV3ScriptPubKey(leaves)};
            s.tx.nLockTime = locktime;
            s.Witness() = PQLeafWitness(a, leaves, 0, s);
            const int64_t budget{Budget(s)};
            BOOST_CHECK_EQUAL(budget, 5392);
            if (locktime < 500) {
                BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, false, SCRIPT_ERR_UNSATISFIED_LOCKTIME, "CLTV early"), budget);
            } else {
                BOOST_CHECK_EQUAL(RunLeafForBudget(s, leaves[0], STD, true, SCRIPT_ERR_OK, "CLTV late"), budget - XCOIN_V3_VALIDATION_WEIGHT_MLDSA);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
