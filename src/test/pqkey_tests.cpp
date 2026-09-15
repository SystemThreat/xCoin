// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>
#include <pqhd.h>

#include <addresstype.h>
#include <hash.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(pqkey_tests, BasicTestingSetup)

// Deterministic keygen: the same 32-byte seed must always produce the same
// ML-DSA-65 keypair, and the recovered pubkey must verify signatures. This is
// what makes seed-phrase backup of post-quantum keys actually recoverable.
BOOST_AUTO_TEST_CASE(pqkey_deterministic_from_seed)
{
    std::array<unsigned char, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i + 1);

    CPQKey k1, k2;
    CPQPubKey p1 = k1.MakeKeyFromSeed(seed);
    CPQPubKey p2 = k2.MakeKeyFromSeed(seed);

    BOOST_CHECK(k1.IsValid() && p1.IsValid());
    BOOST_CHECK(k2.IsValid() && p2.IsValid());
    // Same seed → identical secret key AND identical public key.
    BOOST_CHECK(k1 == k2);
    BOOST_CHECK_EQUAL(HexStr(p1), HexStr(p2));

    // A different seed → a different key.
    std::array<unsigned char, 32> seed2 = seed; seed2[0] ^= 0xFF;
    CPQKey k3; CPQPubKey p3 = k3.MakeKeyFromSeed(seed2);
    BOOST_CHECK(!(HexStr(p1) == HexStr(p3)));

    // The deterministically-derived key signs and its recovered pubkey verifies.
    uint256 h = uint256::ONE;
    std::vector<unsigned char> sig;
    BOOST_CHECK(k1.Sign(h, sig));
    BOOST_CHECK(p1.Verify(h, sig));

    // GetPubKey() must reconstruct the same pubkey from the secret key alone.
    CPQPubKey prec = k1.GetPubKey();
    BOOST_CHECK(prec.IsValid());
    BOOST_CHECK_EQUAL(HexStr(prec), HexStr(p1));
}

// HD derivation must be deterministic end-to-end: same master seed + index
// yields the same child key across independent calls.
BOOST_AUTO_TEST_CASE(pqhd_deterministic_derivation)
{
    std::vector<unsigned char> masterSeed(64);
    for (size_t i = 0; i < masterSeed.size(); ++i) masterSeed[i] = static_cast<unsigned char>(0xA0 + i);

    CPQKey a_key, b_key;
    CPQPubKey a_pub, b_pub;
    BOOST_CHECK(DerivePQKeyFromSeed(masterSeed, 0, a_key, a_pub));
    BOOST_CHECK(DerivePQKeyFromSeed(masterSeed, 0, b_key, b_pub));
    BOOST_CHECK(a_key.IsValid() && a_pub.IsValid());
    BOOST_CHECK(a_key == b_key);
    BOOST_CHECK_EQUAL(HexStr(a_pub), HexStr(b_pub));

    // Different index → different key.
    CPQKey c_key; CPQPubKey c_pub;
    BOOST_CHECK(DerivePQKeyFromSeed(masterSeed, 1, c_key, c_pub));
    BOOST_CHECK(!(HexStr(a_pub) == HexStr(c_pub)));
}

BOOST_AUTO_TEST_CASE(pqkey_generate)
{
    // Generate a fresh ML-DSA-65 keypair
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();

    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), PQ_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(key.size(), PQ_SECRETKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pqkey_sign_verify)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(pubkey.IsValid());

    // Create a test hash
    uint256 hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>("test"), 4).Finalize(hash.data());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK(!sig.empty());
    BOOST_CHECK(sig.size() <= PQ_SIGNATURE_SIZE);

    // Verify the signature
    BOOST_CHECK(pubkey.Verify(hash, sig));

    // Verification with wrong hash must fail
    uint256 wrong_hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>("wrong"), 5).Finalize(wrong_hash.data());
    BOOST_CHECK(!pubkey.Verify(wrong_hash, sig));

    // Verification with truncated sig must fail
    std::vector<unsigned char> bad_sig(sig.begin(), sig.begin() + sig.size() / 2);
    BOOST_CHECK(!pubkey.Verify(hash, bad_sig));

    // Verification with empty sig must fail
    std::vector<unsigned char> empty_sig;
    BOOST_CHECK(!pubkey.Verify(hash, empty_sig));
}

BOOST_AUTO_TEST_CASE(pqkey_sign_message)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();

    // Sign a variable-length message
    std::string msg_str = "NEX post-quantum test message for ML-DSA-65";
    std::vector<unsigned char> msg(msg_str.begin(), msg_str.end());
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.SignMessage(msg, sig));

    // Verify
    BOOST_CHECK(pubkey.VerifyMessage(msg, sig));

    // Tampered message must fail
    msg.push_back(0x00);
    BOOST_CHECK(!pubkey.VerifyMessage(msg, sig));
}

BOOST_AUTO_TEST_CASE(pqkey_verify_pubkey)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();

    // Key should verify against its own pubkey
    BOOST_CHECK(key.VerifyPubKey(pubkey));

    // Should NOT verify against a different pubkey
    CPQKey key2;
    CPQPubKey pubkey2 = key2.MakeNewKey();
    BOOST_CHECK(!key.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey));
}

BOOST_AUTO_TEST_CASE(pqkey_deterministic_pubkey_hash)
{
    // Two keypairs must produce different IDs
    CPQKey key1, key2;
    CPQPubKey pub1 = key1.MakeNewKey();
    CPQPubKey pub2 = key2.MakeNewKey();

    CPQKeyID id1 = pub1.GetID();
    CPQKeyID id2 = pub2.GetID();

    BOOST_CHECK(id1 != id2);

    // Same pubkey must produce same ID
    CPQKeyID id1_again = pub1.GetID();
    BOOST_CHECK(id1 == id1_again);
}

BOOST_AUTO_TEST_CASE(pqkey_invalid_default)
{
    // Default-constructed keys are invalid
    CPQKey key;
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), 0u);

    CPQPubKey pubkey;
    BOOST_CHECK(!pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), 0u);

    // Signing with invalid key must fail
    uint256 hash;
    std::vector<unsigned char> sig;
    BOOST_CHECK(!key.Sign(hash, sig));
    BOOST_CHECK(sig.empty());

    // Verifying with invalid pubkey must fail
    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(pqkey_pubkey_serialization)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();

    // Construct a new pubkey from the raw bytes
    CPQPubKey pubkey2(pubkey.begin(), pubkey.end());
    BOOST_CHECK(pubkey2.IsValid());
    BOOST_CHECK(pubkey == pubkey2);
    BOOST_CHECK(pubkey.GetID() == pubkey2.GetID());

    // Wrong-sized bytes must produce invalid pubkey
    std::vector<unsigned char> bad(100, 0x42);
    CPQPubKey pubkey3(bad.data(), bad.data() + bad.size());
    BOOST_CHECK(!pubkey3.IsValid());

    // Stream round trip: a valid key comes back equal; an invalid one
    // serializes as an empty payload and comes back invalid.
    {
        DataStream ds;
        ds << pubkey;
        BOOST_CHECK_EQUAL(ds.size(), GetSizeOfCompactSize(PQ_PUBKEY_SIZE) + PQ_PUBKEY_SIZE);
        CPQPubKey back;
        ds >> back;
        BOOST_CHECK(back == pubkey);
        BOOST_CHECK(ds.empty());

        DataStream ds_invalid;
        ds_invalid << CPQPubKey{};
        BOOST_CHECK_EQUAL(ds_invalid.size(), 1U);
        CPQPubKey back_invalid{pubkey};
        ds_invalid >> back_invalid;
        BOOST_CHECK(!back_invalid.IsValid());
    }

    // Unserialize with a length field other than PQ_PUBKEY_SIZE: the payload is
    // skipped (nothing is allocated for it), the key is invalid and the stream
    // is left positioned after the payload; a length field longer than the
    // data available fails instead of reading past the end.
    {
        DataStream ds;
        WriteCompactSize(ds, 100);
        ds << std::span{bad};
        ds << uint8_t{0x77};
        CPQPubKey back{pubkey};
        ds >> back;
        BOOST_CHECK(!back.IsValid());
        uint8_t trailer{0};
        ds >> trailer;
        BOOST_CHECK_EQUAL(trailer, 0x77);
        BOOST_CHECK(ds.empty());

        DataStream ds_short;
        WriteCompactSize(ds_short, MAX_SIZE); // the largest length ReadCompactSize accepts
        ds_short << uint8_t{0x00};
        CPQPubKey back_short{pubkey};
        BOOST_CHECK_THROW(ds_short >> back_short, std::ios_base::failure);
        BOOST_CHECK(!back_short.IsValid());
    }
}

BOOST_AUTO_TEST_CASE(pqkey_copy_move)
{
    CPQKey key1;
    CPQPubKey pub1 = key1.MakeNewKey();

    // Copy
    CPQKey key2 = key1;
    BOOST_CHECK(key2.IsValid());
    BOOST_CHECK(key1 == key2);

    // Move
    CPQKey key3 = std::move(key2);
    BOOST_CHECK(key3.IsValid());
    BOOST_CHECK(key1 == key3);
}

BOOST_AUTO_TEST_CASE(pqkey_multiple_signatures)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();

    uint256 hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>("multi"), 5).Finalize(hash.data());

    std::vector<unsigned char> sig1, sig2;
    BOOST_CHECK(key.Sign(hash, sig1));
    BOOST_CHECK(key.Sign(hash, sig2));

    // Both must verify
    BOOST_CHECK(pubkey.Verify(hash, sig1));
    BOOST_CHECK(pubkey.Verify(hash, sig2));
}

BOOST_AUTO_TEST_CASE(pq_address_witness_v2)
{
    CPQKey key;
    CPQPubKey pubkey = key.MakeNewKey();
    CPQKeyID id = pubkey.GetID();

    // Create a WitnessV2PQ destination
    WitnessV2PQ dest(pubkey);

    // Generate scriptPubKey: OP_2 <32-byte-hash>
    CTxDestination txdest{dest};
    CScript script = GetScriptForDestination(txdest);
    BOOST_CHECK_EQUAL(script.size(), 34u); // OP_2 (1) + push32 (1) + hash (32)
    BOOST_CHECK_EQUAL(script[0], 0x52); // OP_2
    BOOST_CHECK_EQUAL(script[1], 0x20); // push 32 bytes

    // Verify destination is valid
    BOOST_CHECK(IsValidDestination(txdest));
}

BOOST_AUTO_TEST_CASE(pq_cross_key_verification_fails)
{
    CPQKey keyA, keyB;
    CPQPubKey pubA = keyA.MakeNewKey();
    CPQPubKey pubB = keyB.MakeNewKey();

    uint256 hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>("cross"), 5).Finalize(hash.data());

    std::vector<unsigned char> sigA;
    BOOST_CHECK(keyA.Sign(hash, sigA));

    BOOST_CHECK(pubA.Verify(hash, sigA));
    BOOST_CHECK(!pubB.Verify(hash, sigA));
}

BOOST_AUTO_TEST_SUITE_END()
