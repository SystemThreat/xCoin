// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Re-genesis stage B2: SLH-DSA-SHA2-128s (FIPS 205), the hash-based fallback
// algorithm of witness v3. Known-answer vectors from PQClean (key generation),
// OpenSSL 3.6.1 and the NIST ACVP FIPS 205 sigVer set, plus API strictness.

#include <slhkey.h>
#include <test/data/slh_dsa_sha2_128s_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <test/util/slh.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <vector>

namespace {
std::string Hex(const CSLHPubKey& pub)
{
    return HexStr(std::span<const unsigned char>{pub.begin(), pub.end()});
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(slhkey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(slh_constants)
{
    BOOST_CHECK_EQUAL(SLH_PUBKEY_SIZE, 32U);
    BOOST_CHECK_EQUAL(SLH_SECRETKEY_SIZE, 64U);
    BOOST_CHECK_EQUAL(SLH_SIGNATURE_SIZE, 7856U);
    BOOST_CHECK_EQUAL(SLH_SEED_SIZE, 48U);
    BOOST_CHECK_EQUAL(SLH_MAX_CONTEXT_SIZE, 255U);
    BOOST_CHECK_EQUAL(CSLHPubKey::SIZE, SLH_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(CSLHPubKey::SIGNATURE_SIZE, SLH_SIGNATURE_SIZE);

    // The pure-mode prefix: 0x00 || len(context) || context || msg.
    std::vector<unsigned char> mprime;
    const std::vector<unsigned char> msg{0xaa, 0xbb};
    BOOST_REQUIRE(SLHPureMessage(mprime, msg, {}));
    BOOST_CHECK(mprime == (std::vector<unsigned char>{0x00, 0x00, 0xaa, 0xbb}));
    const std::vector<unsigned char> ctx{0x01, 0x02, 0x03};
    BOOST_REQUIRE(SLHPureMessage(mprime, msg, ctx));
    BOOST_CHECK(mprime == (std::vector<unsigned char>{0x00, 0x03, 0x01, 0x02, 0x03, 0xaa, 0xbb}));
    BOOST_REQUIRE(SLHPureMessage(mprime, msg, std::vector<unsigned char>(255, 0x7f)));
    BOOST_CHECK_EQUAL(mprime.size(), 2U + 255U + 2U);
    BOOST_CHECK_EQUAL(mprime[1], 0xff);
    BOOST_CHECK(!SLHPureMessage(mprime, msg, std::vector<unsigned char>(256, 0x7f)));
    BOOST_CHECK(mprime.empty());
}

// Pinned vectors (src/test/data/slh_dsa_sha2_128s_vectors.json):
//  - PQClean NIST KAT count 0: key generation from the 48-byte seed (identical between
//    SPHINCS+ v3.1 and FIPS 205) and its SPHINCS+ v3.1 signature, which must NOT verify under
//    FIPS 205 rules (FORS base_2^b bit order; see src/pqcrypto/slh-dsa-sha2-128s/PQCLEAN);
//  - OpenSSL 3.6.1 (independent FIPS 205 implementation): key pair, a pure-mode signature with
//    an empty context over a 32-byte message (the consensus mode) and an internal-mode one;
//  - NIST ACVP FIPS 205 SLH-DSA sigVer: two valid and two invalid SLH-DSA-SHA2-128s cases.
BOOST_AUTO_TEST_CASE(slh_known_answer_vectors)
{
    const UniValue vectors{read_json(json_tests::slh_dsa_sha2_128s_vectors)};
    BOOST_REQUIRE(vectors.isArray());
    int keygen{0}, pure_valid{0}, pure_invalid{0}, internal_valid{0}, internal_invalid{0};
    for (const UniValue& v : vectors.getValues()) {
        const std::string name{v["name"].get_str()};
        const std::string kind{v["kind"].get_str()};
        const std::string pk_hex{v["pk"].get_str()};
        BOOST_REQUIRE_EQUAL(pk_hex.size(), 2 * SLH_PUBKEY_SIZE);
        if (kind == "keygen") {
            const std::vector<unsigned char> seed{ParseHex(v["seed"].get_str())};
            BOOST_REQUIRE_EQUAL(seed.size(), SLH_SEED_SIZE);
            CSLHTestKey key;
            const CSLHPubKey pub{key.MakeKeyFromSeed(seed)};
            BOOST_CHECK_MESSAGE(key.IsValid() && pub.IsValid(), name);
            BOOST_CHECK_MESSAGE(Hex(pub) == pk_hex, name + ": pk " + Hex(pub));
            BOOST_CHECK_MESSAGE(HexStr(key.data()) == v["sk"].get_str(), name + ": sk");
            BOOST_CHECK(key.GetPubKey() == pub);
            ++keygen;
            continue;
        }
        const CSLHPubKey pub{ParseHex(pk_hex)};
        BOOST_REQUIRE(pub.IsValid());
        const std::vector<unsigned char> msg{ParseHex(v["msg"].get_str())};
        const std::vector<unsigned char> sig{ParseHex(v["sig"].get_str())};
        const bool valid{v["valid"].get_bool()};
        BOOST_REQUIRE_EQUAL(sig.size(), SLH_SIGNATURE_SIZE);
        if (kind == "pure") {
            const std::vector<unsigned char> ctx{ParseHex(v["ctx"].get_str())};
            BOOST_CHECK_MESSAGE(pub.VerifyMessage(msg, sig, ctx) == valid, name);
            if (ctx.empty() && msg.size() == 32) {
                // The consensus entry point is the same check.
                BOOST_CHECK_MESSAGE(pub.Verify(uint256{msg}, sig) == valid, name + " (Verify)");
            }
            (valid ? pure_valid : pure_invalid)++;
        } else {
            BOOST_REQUIRE_EQUAL(kind, "internal");
            BOOST_CHECK_MESSAGE(pub.VerifyInternal(msg, sig) == valid, name);
            (valid ? internal_valid : internal_invalid)++;
        }
    }
    BOOST_CHECK_EQUAL(keygen, 2);
    BOOST_CHECK_EQUAL(pure_valid, 2);
    BOOST_CHECK_EQUAL(pure_invalid, 2);
    BOOST_CHECK_EQUAL(internal_valid, 2);
    BOOST_CHECK_EQUAL(internal_invalid, 3);
}

BOOST_AUTO_TEST_CASE(slh_sign_verify_and_strictness)
{
    std::array<unsigned char, SLH_SEED_SIZE> seed{};
    seed.fill(0x5a);
    CSLHTestKey key;
    const CSLHPubKey pub{key.MakeKeyFromSeed(seed)};
    BOOST_REQUIRE(key.IsValid() && pub.IsValid());
    BOOST_CHECK(key.GetPubKey() == pub);
    // Deterministic key generation; a different seed gives a different key; a bad seed size fails.
    CSLHTestKey again;
    BOOST_CHECK(again.MakeKeyFromSeed(seed) == pub);
    seed[0] ^= 0xff;
    CSLHTestKey other;
    const CSLHPubKey other_pub{other.MakeKeyFromSeed(seed)};
    BOOST_CHECK(other_pub.IsValid() && other_pub != pub);
    CSLHTestKey bad_seed;
    BOOST_CHECK(!bad_seed.MakeKeyFromSeed(std::span<const unsigned char>{seed.data(), 47}).IsValid());
    BOOST_CHECK(!bad_seed.IsValid());

    // Sign and verify the consensus way: a 32-byte digest, pure mode, empty context.
    const uint256 digest{uint256::ONE};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(digest, sig));
    BOOST_CHECK_EQUAL(sig.size(), SLH_SIGNATURE_SIZE);
    BOOST_CHECK(pub.Verify(digest, sig));
    BOOST_CHECK(pub.VerifyMessage(digest, sig, {}));
    // The same bytes are an internal-mode signature over 0x00 || 0x00 || digest, and nothing else.
    std::vector<unsigned char> mprime;
    BOOST_REQUIRE(SLHPureMessage(mprime, digest, {}));
    BOOST_CHECK_EQUAL(mprime.size(), 34U);
    BOOST_CHECK(pub.VerifyInternal(mprime, sig));
    BOOST_CHECK(!pub.VerifyInternal(digest, sig));
    // Wrong digest, wrong key, tampered signature (first and last byte).
    BOOST_CHECK(!pub.Verify(uint256::ZERO, sig));
    BOOST_CHECK(!other_pub.Verify(digest, sig));
    sig[0] ^= 0x01;
    BOOST_CHECK(!pub.Verify(digest, sig));
    sig[0] ^= 0x01;
    sig[SLH_SIGNATURE_SIZE - 1] ^= 0x01;
    BOOST_CHECK(!pub.Verify(digest, sig));
    sig[SLH_SIGNATURE_SIZE - 1] ^= 0x01;
    BOOST_CHECK(pub.Verify(digest, sig));
    // Strict sizes: 7,855 and 7,857 bytes are not signatures here (the interpreter strips the
    // hash-type byte before calling Verify).
    sig.push_back(0x01);
    BOOST_CHECK(!pub.Verify(digest, sig));
    sig.pop_back();
    sig.pop_back();
    BOOST_CHECK(!pub.Verify(digest, sig));
    BOOST_CHECK(!pub.Verify(digest, std::vector<unsigned char>{}));
    // An invalid key verifies nothing.
    const CSLHPubKey invalid{std::vector<unsigned char>(31, 0x01)};
    BOOST_CHECK(!invalid.IsValid());
    BOOST_CHECK_EQUAL(invalid.size(), 0U);
    BOOST_REQUIRE(key.Sign(digest, sig));
    BOOST_CHECK(!invalid.Verify(digest, sig));

    // Hedged signing: two signatures over the same digest differ (random opt_rand) and both verify.
    std::vector<unsigned char> sig2;
    BOOST_REQUIRE(key.Sign(digest, sig2));
    BOOST_CHECK(sig2 != sig);
    BOOST_CHECK(pub.Verify(digest, sig2));

    // Contexts: bound to the signature, at most 255 bytes, in both directions.
    const std::vector<unsigned char> msg{'x', 'c', 'o', 'i', 'n'};
    const std::vector<unsigned char> ctx(255, 0x11);
    std::vector<unsigned char> csig;
    BOOST_REQUIRE(key.SignMessage(msg, csig, ctx));
    BOOST_CHECK(pub.VerifyMessage(msg, csig, ctx));
    BOOST_CHECK(!pub.VerifyMessage(msg, csig, {}));
    BOOST_CHECK(!pub.VerifyMessage(msg, csig, std::vector<unsigned char>(254, 0x11)));
    const std::vector<unsigned char> too_long(256, 0x11);
    BOOST_CHECK(!key.SignMessage(msg, csig, too_long));
    BOOST_CHECK(csig.empty());
    BOOST_REQUIRE(key.SignMessage(msg, csig, {}));
    BOOST_CHECK(!pub.VerifyMessage(msg, csig, too_long));
    BOOST_CHECK(pub.VerifyMessage(msg, csig, {}));
    // An invalid key signs nothing.
    BOOST_CHECK(!bad_seed.Sign(digest, csig));
    BOOST_CHECK(csig.empty());
}

// Random key generation: the 48-byte seed is drawn in two calls because
// GetStrongRandBytes asserts num <= 32, so asking for all 48 at once aborted
// the process (stage B6 fix). Two keys in a row must differ and both must
// sign and verify; the key must round-trip through its own 48-byte seed.
BOOST_AUTO_TEST_CASE(slh_make_new_key)
{
    CSLHTestKey key;
    const CSLHPubKey pub{key.MakeNewKey()};
    BOOST_REQUIRE(key.IsValid());
    BOOST_REQUIRE(pub.IsValid());
    BOOST_CHECK(key.GetPubKey() == pub);
    BOOST_CHECK_EQUAL(key.seed().size(), SLH_SEED_SIZE);
    BOOST_CHECK_EQUAL(key.data().size(), SLH_SECRETKEY_SIZE);

    // Two fresh keys differ (all 48 seed bytes are random, not just the first 32).
    CSLHTestKey key2;
    const CSLHPubKey pub2{key2.MakeNewKey()};
    BOOST_REQUIRE(pub2.IsValid());
    BOOST_CHECK(pub2 != pub);
    BOOST_CHECK(!std::equal(key.seed().begin(), key.seed().end(), key2.seed().begin()));
    BOOST_CHECK(!std::equal(key.seed().begin() + 32, key.seed().end(), key2.seed().begin() + 32));

    // The generated key round-trips through its seed and signs.
    const std::vector<unsigned char> seed{key.seed().begin(), key.seed().end()};
    CSLHTestKey restored;
    BOOST_CHECK(restored.MakeKeyFromSeed(seed) == pub);
    const uint256 digest{uint256::ONE};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(digest, sig));
    BOOST_CHECK(pub.Verify(digest, sig));
    BOOST_CHECK(!pub2.Verify(digest, sig));
}

BOOST_AUTO_TEST_SUITE_END()
