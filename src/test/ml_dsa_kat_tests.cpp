// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>
#include <test/data/ml_dsa_65_fips204.json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <vector>

// PQClean's C API, as pqkey.cpp includes it.
extern "C" {
#include <pqcrypto/ml-dsa-65/api.h>
}

// ML-DSA-65 against NIST's FIPS 204 ACVP vectors (usnistgov/ACVP-Server,
// gen-val/json-files/ML-DSA-{keyGen,sigVer}-FIPS204, revision FIPS204; the
// subset kept is described in src/test/data/ml_dsa_65_fips204.json). Every
// coin on this chain is locked with this algorithm, so: key generation must
// reproduce NIST's public and secret keys byte for byte from the 32-byte seed
// xi, and verification must accept and reject exactly what NIST says, tampered
// signatures, messages and keys included. Signing is hedged (randomized) in
// this implementation, so NIST's deterministic sigGen vectors cannot be
// reproduced here; the accepted sigVer vectors plus a sign-then-verify round
// trip under a NIST key cover the signing side.
BOOST_FIXTURE_TEST_SUITE(ml_dsa_kat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ml_dsa_65_fips204_keygen)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::ml_dsa_65_fips204)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    const UniValue& keygen{vectors["keyGen"]};
    BOOST_REQUIRE(keygen.isArray());
    BOOST_REQUIRE_GE(keygen.size(), 10U);
    for (size_t i = 0; i < keygen.size(); ++i) {
        const UniValue& t{keygen[i]};
        const std::vector<unsigned char> seed{ParseHex(t["seed"].get_str())};
        const std::vector<unsigned char> pk_expected{ParseHex(t["pk"].get_str())};
        const std::vector<unsigned char> sk_expected{ParseHex(t["sk"].get_str())};
        BOOST_REQUIRE_EQUAL(seed.size(), 32U);
        BOOST_REQUIRE_EQUAL(pk_expected.size(), static_cast<size_t>(PQ_PUBKEY_SIZE));
        BOOST_REQUIRE_EQUAL(sk_expected.size(), static_cast<size_t>(PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES));

        std::vector<unsigned char> pk(PQ_PUBKEY_SIZE), sk(PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
        BOOST_REQUIRE_EQUAL(PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(pk.data(), sk.data(), seed.data()), 0);
        BOOST_CHECK_MESSAGE(pk == pk_expected, "tcId " << t["tcId"].getInt<int>() << ": public key differs from FIPS 204");
        BOOST_CHECK_MESSAGE(sk == sk_expected, "tcId " << t["tcId"].getInt<int>() << ": secret key differs from FIPS 204");

        // The node's own wrapper takes the same path, and recomputes the public
        // key from the secret key the way the wallet does.
        CPQKey key;
        const CPQPubKey pub{key.MakeKeyFromSeed(seed)};
        BOOST_REQUIRE(pub.IsValid());
        BOOST_CHECK(std::vector<unsigned char>(pub.begin(), pub.end()) == pk_expected);
        const CPQPubKey recomputed{key.GetPubKey()};
        BOOST_CHECK(std::vector<unsigned char>(recomputed.begin(), recomputed.end()) == pk_expected);
    }
}

BOOST_AUTO_TEST_CASE(ml_dsa_65_fips204_sigver)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::ml_dsa_65_fips204)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    const UniValue& sigver{vectors["sigVer"]};
    BOOST_REQUIRE(sigver.isArray());
    BOOST_REQUIRE_GE(sigver.size(), 10U);
    int accepted{0}, rejected{0};
    for (size_t i = 0; i < sigver.size(); ++i) {
        const UniValue& t{sigver[i]};
        const std::vector<unsigned char> pk{ParseHex(t["pk"].get_str())};
        const std::vector<unsigned char> msg{ParseHex(t["message"].get_str())};
        const std::vector<unsigned char> ctx{ParseHex(t["context"].get_str())};
        const std::vector<unsigned char> sig{ParseHex(t["signature"].get_str())};
        const bool expected{t["testPassed"].get_bool()};
        BOOST_REQUIRE_EQUAL(pk.size(), static_cast<size_t>(PQ_PUBKEY_SIZE));

        const bool ok{PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(sig.data(), sig.size(), msg.data(), msg.size(), ctx.data(), ctx.size(), pk.data()) == 0};
        BOOST_CHECK_MESSAGE(ok == expected, "tcId " << t["tcId"].getInt<int>() << " (" << t["reason"].get_str() << "): verify returned " << ok << ", FIPS 204 says " << expected);
        (expected ? accepted : rejected)++;

        if (ctx.empty()) {
            // An empty context is what the chain signs under: the wrapper must agree.
            const CPQPubKey pub{pk};
            BOOST_REQUIRE(pub.IsValid());
            BOOST_CHECK_EQUAL(pub.VerifyMessage(msg, sig), expected);
        }
    }
    BOOST_CHECK_GT(accepted, 0);
    BOOST_CHECK_GT(rejected, 0);
}

BOOST_AUTO_TEST_CASE(ml_dsa_65_openssl_verify32)
{
    // The consensus entry point is CPQPubKey::Verify(uint256, sig): a 32-byte
    // digest as the message, an empty context. None of NIST's sigVer vectors
    // above has an empty context, so this is the positive external known-answer
    // vector for that path: an OpenSSL 3.6.4 signature (deterministic variant,
    // pure mode, no context) under the NIST keyGen tcId 26 key, over a 32-byte
    // message. Anything that changes what this tree accepts as a valid
    // ML-DSA-65 signature over a sighash digest fails here.
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::ml_dsa_65_fips204)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    const UniValue& verify32{vectors["verify32"]};
    BOOST_REQUIRE(verify32.isArray());
    BOOST_REQUIRE_GE(verify32.size(), 1U);
    for (size_t i = 0; i < verify32.size(); ++i) {
        const UniValue& t{verify32[i]};
        const std::vector<unsigned char> seed{ParseHex(t["seed"].get_str())};
        const std::vector<unsigned char> msg{ParseHex(t["message"].get_str())};
        const std::vector<unsigned char> sig{ParseHex(t["signature"].get_str())};
        BOOST_REQUIRE(t["context"].get_str().empty());
        BOOST_REQUIRE_EQUAL(msg.size(), 32U);
        BOOST_REQUIRE_EQUAL(sig.size(), static_cast<size_t>(PQ_SIGNATURE_SIZE));

        // The key is the NIST one: same seed, same public key as the keyGen vector.
        const UniValue& kg{vectors["keyGen"][0]};
        BOOST_REQUIRE_EQUAL(kg["tcId"].getInt<int>(), t["keyGenTcId"].getInt<int>());
        BOOST_REQUIRE_EQUAL(kg["seed"].get_str(), t["seed"].get_str());
        CPQKey key;
        const CPQPubKey pub{key.MakeKeyFromSeed(seed)};
        BOOST_REQUIRE(pub.IsValid());
        BOOST_CHECK(std::vector<unsigned char>(pub.begin(), pub.end()) == ParseHex(kg["pk"].get_str()));

        const uint256 digest{std::span<const unsigned char>{msg}};
        BOOST_CHECK(pub.Verify(digest, sig));
        BOOST_CHECK(pub.VerifyMessage(msg, sig));
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(sig.data(), sig.size(), msg.data(), msg.size(), nullptr, 0, pub.data()), 0);

        // The same signature is not valid for any other message, key, or with
        // a context, or after a bit flip anywhere in it.
        uint256 other{digest};
        other.data()[0] ^= 0x01;
        BOOST_CHECK(!pub.Verify(other, sig));
        CPQKey other_key;
        const CPQPubKey other_pub{other_key.MakeKeyFromSeed(ParseHex(vectors["keyGen"][1]["seed"].get_str()))};
        BOOST_CHECK(!other_pub.Verify(digest, sig));
        static constexpr unsigned char ctx1[]{0x00};
        BOOST_CHECK_NE(PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(sig.data(), sig.size(), msg.data(), msg.size(), ctx1, 1, pub.data()), 0);
        for (const size_t pos : {size_t{0}, size_t{47}, size_t{1000}, sig.size() - 1}) {
            std::vector<unsigned char> bad{sig};
            bad[pos] ^= 0x80;
            BOOST_CHECK(!pub.Verify(digest, bad));
        }
        std::vector<unsigned char> truncated{sig};
        truncated.pop_back();
        BOOST_CHECK(!pub.Verify(digest, truncated));

        // And a signature this tree makes over the same digest verifies too (the
        // hedged signer's output differs from OpenSSL's deterministic bytes, but
        // both are valid FIPS 204 signatures under the same key).
        std::vector<unsigned char> ours;
        BOOST_REQUIRE(key.Sign(digest, ours));
        BOOST_CHECK(pub.Verify(digest, ours));
    }
}

BOOST_AUTO_TEST_CASE(ml_dsa_65_fips204_sign_round_trip)
{
    // Under a NIST key: our (hedged) signature verifies, and one flipped bit does not.
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::ml_dsa_65_fips204)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    CPQKey key;
    const CPQPubKey pub{key.MakeKeyFromSeed(ParseHex(vectors["keyGen"][0]["seed"].get_str()))};
    BOOST_REQUIRE(pub.IsValid());
    const std::vector<unsigned char> msg{ParseHex(vectors["sigVer"][0]["message"].get_str())};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.SignMessage(msg, sig));
    BOOST_CHECK_EQUAL(sig.size(), static_cast<size_t>(PQ_SIGNATURE_SIZE));
    BOOST_CHECK(pub.VerifyMessage(msg, sig));
    sig[100] ^= 0x01;
    BOOST_CHECK(!pub.VerifyMessage(msg, sig));
}

BOOST_AUTO_TEST_SUITE_END()
