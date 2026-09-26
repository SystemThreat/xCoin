// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <crypto/sha3.h>
#include <span.h>
#include <support/lockedpool.h>
#include <test/data/ml_kem_768_fips203.json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include <crypto/mlkem-native/xcoin_hooks.h>
#include <pqcrypto/common/fips202.h>
}

using namespace mlkem768;

// ML-KEM-768 (FIPS 203) as crypto/mlkem768.h exposes the vendored
// mlkem-native, against the vectors XIP-4 requires before HX1 may use it
// ("Test vectors and tests", "ML-KEM-768 primitive"). The pinned data and
// their sources are described in src/test/data/ml_kem_768_fips203.json and
// contrib/testgen/gen_mlkem768_vectors.py. SHAKE128/256 for the accumulated
// test and for J(z || c) come from PQClean's fips202 (src/pqcrypto/common),
// not from the library under test.
namespace {
UniValue Vectors()
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::ml_kem_768_fips203)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    return vectors;
}

template <size_t N>
std::array<std::byte, N> FromHex(std::string_view hex)
{
    const std::vector<std::byte> bytes{ParseHex<std::byte>(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), N);
    std::array<std::byte, N> out;
    std::ranges::copy(bytes, out.begin());
    return out;
}

template <size_t N>
std::array<std::byte, N> FromHex(const UniValue& hex)
{
    return FromHex<N>(std::string_view{hex.get_str()});
}

std::string Hex(const UniValue& hex) { return ToLower(hex.get_str()); }

std::string Sha256Hex(std::span<const std::byte> data)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> out;
    CSHA256().Write(UCharCast(data.data()), data.size()).Finalize(out.data());
    return HexStr(out);
}

std::string Sha3_256Hex(std::span<const std::byte> data)
{
    std::array<unsigned char, SHA3_256::OUTPUT_SIZE> out;
    SHA3_256().Write(MakeUCharSpan(data)).Finalize(out);
    return HexStr(out);
}

//! J(z || ct) = SHAKE256(z || ct, 256 bits), with z the last 32 bytes of dk (FIPS 203 Algorithm 18, line 7).
std::string ImplicitRejectionHex(std::span<const std::byte, DECAPS_KEY_SIZE> dk, std::span<const std::byte, CIPHERTEXT_SIZE> ct)
{
    std::vector<unsigned char> input(SEED_SIZE + ct.size());
    std::ranges::copy(MakeUCharSpan(dk.last<SEED_SIZE>()), input.begin());
    std::ranges::copy(MakeUCharSpan(ct), input.begin() + SEED_SIZE);
    std::array<unsigned char, SHARED_SECRET_SIZE> out;
    shake256(out.data(), out.size(), input.data(), input.size());
    return HexStr(out);
}

//! ek with its 12-bit coefficient number index (0 <= index < 768) set to value (0 <= value < 4096).
EncapsKey SetCoefficient(EncapsKey ek, size_t index, unsigned value)
{
    const size_t pos{384 * (index / 256) + 3 * ((index % 256) / 2)};
    auto b0{std::to_integer<unsigned>(ek[pos])}, b1{std::to_integer<unsigned>(ek[pos + 1])}, b2{std::to_integer<unsigned>(ek[pos + 2])};
    if (index % 2 == 0) {
        b0 = value & 0xff;
        b1 = (b1 & 0xf0) | (value >> 8);
    } else {
        b1 = (b1 & 0x0f) | ((value & 0x0f) << 4);
        b2 = value >> 4;
    }
    ek[pos] = std::byte(b0);
    ek[pos + 1] = std::byte(b1);
    ek[pos + 2] = std::byte(b2);
    return ek;
}

mlkem768::KeyPair RequireKeyGen(std::span<const std::byte, SEED_SIZE> d, std::span<const std::byte, SEED_SIZE> z)
{
    auto key_pair{KeyGen(d, z)};
    BOOST_REQUIRE(key_pair.has_value());
    return std::move(*key_pair);
}

Encapsulation RequireEncaps(std::span<const std::byte, ENCAPS_KEY_SIZE> ek, std::span<const std::byte, SEED_SIZE> m)
{
    auto enc{Encaps(ek, m)};
    BOOST_REQUIRE(enc.has_value());
    return std::move(*enc);
}

SharedSecret RequireDecaps(std::span<const std::byte, DECAPS_KEY_SIZE> dk, std::span<const std::byte, CIPHERTEXT_SIZE> ct)
{
    auto shared_secret{Decaps(dk, ct)};
    BOOST_REQUIRE(shared_secret.has_value());
    return std::move(*shared_secret);
}

//! Go crypto/mlkem TestAccumulated for ML-KEM-768 (XIP-4).
std::string GoAccumulated(int iterations)
{
    shake128incctx rng, acc;
    shake128_inc_init(&rng);
    shake128_inc_finalize(&rng); // SHAKE128 of the empty string
    shake128_inc_init(&acc);
    for (int i{0}; i < iterations; ++i) {
        std::array<std::byte, SEED_SIZE> d, z, m;
        Ciphertext random_ct;
        shake128_inc_squeeze(UCharCast(d.data()), d.size(), &rng);
        shake128_inc_squeeze(UCharCast(z.data()), z.size(), &rng);
        shake128_inc_squeeze(UCharCast(m.data()), m.size(), &rng);
        shake128_inc_squeeze(UCharCast(random_ct.data()), random_ct.size(), &rng);
        const mlkem768::KeyPair key_pair{RequireKeyGen(d, z)};
        const Encapsulation enc{RequireEncaps(key_pair.ek, m)};
        BOOST_REQUIRE(*RequireDecaps(*key_pair.dk, enc.ct) == *enc.shared_secret);
        const SharedSecret rejected{RequireDecaps(*key_pair.dk, random_ct)};
        shake128_inc_absorb(&acc, UCharCast(key_pair.ek.data()), key_pair.ek.size());
        shake128_inc_absorb(&acc, UCharCast(enc.ct.data()), enc.ct.size());
        shake128_inc_absorb(&acc, UCharCast(enc.shared_secret->data()), enc.shared_secret->size());
        shake128_inc_absorb(&acc, UCharCast(rejected->data()), rejected->size());
    }
    shake128_inc_finalize(&acc);
    std::array<unsigned char, 32> out;
    shake128_inc_squeeze(out.data(), out.size(), &acc);
    shake128_inc_ctx_release(&acc);
    shake128_inc_ctx_release(&rng);
    return HexStr(out);
}

// XIP-4 "Inputs" d, z, m and the "ML-KEM-768 known answers for the seeds above".
constexpr std::string_view XIP4_D{"944becfa471193433f423fb1e6459505957eace2a3a2343ae25f84c5d602cb46"};
constexpr std::string_view XIP4_Z{"101ca7e793947879e8c8a02911faea5f4f5b021b1f0a0c91911028159051dfcb"};
constexpr std::string_view XIP4_M{"b21100cd8bfa86e05d3416452f314a1f99e61303273c8e9afc78f77cf5e2b066"};
} // namespace

BOOST_FIXTURE_TEST_SUITE(mlkem768_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(acvp_keygen)
{
    const UniValue vectors{Vectors()};
    const UniValue& tests{vectors["keyGen"]};
    BOOST_REQUIRE_EQUAL(tests.size(), 25U);
    for (const UniValue& t : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << t["tcId"].getInt<int>())
        {
            const mlkem768::KeyPair key_pair{RequireKeyGen(FromHex<SEED_SIZE>(t["d"]), FromHex<SEED_SIZE>(t["z"]))};
            BOOST_CHECK_EQUAL(HexStr(key_pair.ek), Hex(t["ek"]));
            BOOST_CHECK_EQUAL(HexStr(*key_pair.dk), Hex(t["dk"]));
        }
    }
}

BOOST_AUTO_TEST_CASE(acvp_encapsulation)
{
    const UniValue vectors{Vectors()};
    const UniValue& tests{vectors["encapsulation"]};
    BOOST_REQUIRE_EQUAL(tests.size(), 25U);
    for (const UniValue& t : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << t["tcId"].getInt<int>())
        {
            const Encapsulation enc{RequireEncaps(FromHex<ENCAPS_KEY_SIZE>(t["ek"]), FromHex<SEED_SIZE>(t["m"]))};
            BOOST_CHECK_EQUAL(HexStr(enc.ct), Hex(t["c"]));
            BOOST_CHECK_EQUAL(HexStr(*enc.shared_secret), Hex(t["k"]));
        }
    }
}

BOOST_AUTO_TEST_CASE(acvp_decapsulation)
{
    const UniValue vectors{Vectors()};
    const UniValue& tests{vectors["decapsulation"]};
    BOOST_REQUIRE_EQUAL(tests.size(), 10U);
    int modified{0};
    for (const UniValue& t : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << t["tcId"].getInt<int>() << ", " << t["reason"].get_str())
        {
            const auto dk{FromHex<DECAPS_KEY_SIZE>(t["dk"])};
            const auto ct{FromHex<CIPHERTEXT_SIZE>(t["c"])};
            BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(dk, ct)), Hex(t["k"]));
            // A modified ciphertext is rejected implicitly: no error, and K = J(z || c).
            if (t["reason"].get_str() == "modified ciphertext") {
                ++modified;
                BOOST_CHECK_EQUAL(Hex(t["k"]), ImplicitRejectionHex(dk, ct));
            }
        }
    }
    BOOST_CHECK_EQUAL(modified, 5);
}

BOOST_AUTO_TEST_CASE(acvp_key_checks)
{
    const UniValue vectors{Vectors()};
    int invalid{0};
    for (const UniValue& t : vectors["encapsulationKeyCheck"].getValues()) {
        BOOST_TEST_CONTEXT("tcId " << t["tcId"].getInt<int>() << ", " << t["reason"].get_str())
        {
            const auto ek{FromHex<ENCAPS_KEY_SIZE>(t["ek"])};
            const bool valid{t["testPassed"].get_bool()};
            BOOST_CHECK_EQUAL(CheckEncapsKey(ek), valid);
            const auto enc{Encaps(ek, std::array<std::byte, SEED_SIZE>{})};
            BOOST_CHECK_EQUAL(enc.has_value(), valid);
            if (!valid) {
                ++invalid;
                BOOST_CHECK(enc.error() == Error::INVALID_ENCAPS_KEY);
            }
        }
    }
    for (const UniValue& t : vectors["decapsulationKeyCheck"].getValues()) {
        BOOST_TEST_CONTEXT("tcId " << t["tcId"].getInt<int>() << ", " << t["reason"].get_str())
        {
            const auto dk{FromHex<DECAPS_KEY_SIZE>(t["dk"])};
            const bool valid{t["testPassed"].get_bool()};
            BOOST_CHECK_EQUAL(CheckDecapsKey(dk), valid);
            const auto shared_secret{Decaps(dk, Ciphertext{})};
            BOOST_CHECK_EQUAL(shared_secret.has_value(), valid);
            if (!valid) {
                ++invalid;
                BOOST_CHECK(shared_secret.error() == Error::INVALID_DECAPS_KEY);
            }
        }
    }
    BOOST_CHECK_EQUAL(invalid, 10);
}

BOOST_AUTO_TEST_CASE(go_accumulated_100)
{
    const UniValue vectors{Vectors()};
    BOOST_CHECK_EQUAL(GoAccumulated(100), vectors["go_accumulated"]["iterations_100"].get_str());
}

BOOST_AUTO_TEST_CASE(go_accumulated_10000)
{
    const UniValue vectors{Vectors()};
    BOOST_CHECK_EQUAL(GoAccumulated(10'000), vectors["go_accumulated"]["iterations_10000"].get_str());
}

BOOST_AUTO_TEST_CASE(cctv_modulus)
{
    // Every value from 3329 to 4095 in some position, and every position with
    // some such value, one key each (C2SP CCTV ML-KEM modulus/).
    const UniValue vectors{Vectors()};
    const UniValue& modulus{vectors["cctv_modulus"]};
    const auto valid_ek{FromHex<ENCAPS_KEY_SIZE>(modulus["ek"])};
    BOOST_REQUIRE(CheckEncapsKey(valid_ek));
    BOOST_REQUIRE(Encaps(valid_ek, std::array<std::byte, SEED_SIZE>{}).has_value());
    const UniValue& changes{modulus["changes"]};
    BOOST_REQUIRE_EQUAL(changes.size(), 780U);
    for (const UniValue& change : changes.getValues()) {
        const auto index{change[0].getInt<size_t>()};
        const auto value{change[1].getInt<unsigned>()};
        BOOST_TEST_CONTEXT("coefficient " << index << " = " << value)
        {
            BOOST_REQUIRE(index < 768 && value >= 3329 && value < 4096);
            const EncapsKey bad_ek{SetCoefficient(valid_ek, index, value)};
            BOOST_CHECK(!CheckEncapsKey(bad_ek));
            const auto enc{Encaps(bad_ek, std::array<std::byte, SEED_SIZE>{})};
            BOOST_CHECK(!enc.has_value() && enc.error() == Error::INVALID_ENCAPS_KEY);
        }
    }
}

BOOST_AUTO_TEST_CASE(cctv_unluckysample)
{
    // SampleNTT needs more than 575 SHAKE128 bytes for this ek's matrix, which
    // Encaps samples and Decaps samples again to re-encrypt.
    const UniValue vectors{Vectors()};
    const UniValue& t{vectors["cctv_unluckysample"]};
    const auto ek{FromHex<ENCAPS_KEY_SIZE>(t["ek"])};
    const auto dk{FromHex<DECAPS_KEY_SIZE>(t["dk"])};
    BOOST_CHECK(CheckEncapsKey(ek));
    BOOST_CHECK(CheckDecapsKey(dk));
    const Encapsulation enc{RequireEncaps(ek, FromHex<SEED_SIZE>(t["m"]))};
    BOOST_CHECK_EQUAL(HexStr(enc.ct), Hex(t["c"]));
    BOOST_CHECK_EQUAL(HexStr(*enc.shared_secret), Hex(t["k"]));
    BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(dk, enc.ct)), Hex(t["k"]));
}

BOOST_AUTO_TEST_CASE(cctv_strcmp)
{
    // The re-encryption matches c up to a zero byte: a strcmp()-style
    // comparison would accept c instead of rejecting it.
    const UniValue vectors{Vectors()};
    const UniValue& t{vectors["cctv_strcmp"]};
    const auto dk{FromHex<DECAPS_KEY_SIZE>(t["dk"])};
    const auto ct{FromHex<CIPHERTEXT_SIZE>(t["c"])};
    BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(dk, ct)), Hex(t["k"]));
    BOOST_CHECK_EQUAL(Hex(t["k"]), ImplicitRejectionHex(dk, ct));
}

BOOST_AUTO_TEST_CASE(openssl_crosscheck)
{
    // OpenSSL 3.6.4: genpkey hexseed:d||z, pkeyutl -encap hexikme:m, and
    // -decap of c with bit 0 of byte 0 flipped (test_framework/crypto/mlkem.py).
    const UniValue vectors{Vectors()};
    const UniValue& tests{vectors["openssl"]};
    BOOST_REQUIRE_EQUAL(tests.size(), 4U);
    for (const UniValue& t : tests.getValues()) {
        const mlkem768::KeyPair key_pair{RequireKeyGen(FromHex<SEED_SIZE>(t["d"]), FromHex<SEED_SIZE>(t["z"]))};
        BOOST_CHECK_EQUAL(Sha3_256Hex(key_pair.ek), t["ek_sha3_256"].get_str());
        BOOST_CHECK_EQUAL(Sha3_256Hex(*key_pair.dk), t["dk_sha3_256"].get_str());
        const Encapsulation enc{RequireEncaps(key_pair.ek, FromHex<SEED_SIZE>(t["m"]))};
        BOOST_CHECK_EQUAL(Sha3_256Hex(enc.ct), t["c_sha3_256"].get_str());
        BOOST_CHECK_EQUAL(HexStr(*enc.shared_secret), t["k"].get_str());
        BOOST_CHECK(*RequireDecaps(*key_pair.dk, enc.ct) == *enc.shared_secret);
        Ciphertext flipped{enc.ct};
        flipped[0] ^= std::byte{1};
        BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(*key_pair.dk, flipped)), t["k_flipped"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(framework_crosscheck)
{
    // The test framework's pure-Python ML-KEM (test_framework/crypto/mlkem.py),
    // which the HX1 handshake vectors are built on, agrees on 50 fixed seeds.
    const UniValue vectors{Vectors()};
    const UniValue& tests{vectors["framework"]};
    BOOST_REQUIRE_EQUAL(tests.size(), 50U);
    for (size_t i{0}; i < tests.size(); ++i) {
        const UniValue& t{tests[i]};
        BOOST_TEST_CONTEXT("case " << i)
        {
            const auto d{FromHex<SEED_SIZE>(t["d"])};
            const auto z{FromHex<SEED_SIZE>(t["z"])};
            const mlkem768::KeyPair key_pair{RequireKeyGen(d, z)};
            BOOST_CHECK_EQUAL(Sha256Hex(key_pair.ek), t["ek_sha256"].get_str());
            BOOST_CHECK_EQUAL(Sha256Hex(*key_pair.dk), t["dk_sha256"].get_str());
            const Encapsulation enc{RequireEncaps(key_pair.ek, FromHex<SEED_SIZE>(t["m"]))};
            BOOST_CHECK_EQUAL(Sha256Hex(enc.ct), t["c_sha256"].get_str());
            BOOST_CHECK_EQUAL(HexStr(*enc.shared_secret), t["k"].get_str());
            BOOST_CHECK(*RequireDecaps(*key_pair.dk, enc.ct) == *enc.shared_secret);
            Ciphertext tampered{enc.ct};
            tampered.at(t["tampered_byte"].getInt<size_t>()) ^= std::byte(1 << t["tampered_bit"].getInt<int>());
            BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(*key_pair.dk, tampered)), t["k_tampered"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(xip4_known_answers)
{
    const mlkem768::KeyPair key_pair{RequireKeyGen(FromHex<SEED_SIZE>(XIP4_D), FromHex<SEED_SIZE>(XIP4_Z))};
    BOOST_CHECK_EQUAL(Sha256Hex(key_pair.ek), "ae3a136caa7c43a7fc2b05daf6afff9f95976dce1d7d02f61c605a330c7be520");
    BOOST_CHECK_EQUAL(HexStr(std::span{key_pair.ek}.first(16)), "9f29b0242341d214812a75276aeb89b7");
    BOOST_CHECK_EQUAL(Sha256Hex(*key_pair.dk), "7921456ea03b771e033ca449884f5e7be5b9c09ed5f151daa9671c21dc67d8f1");
    const Encapsulation enc{RequireEncaps(key_pair.ek, FromHex<SEED_SIZE>(XIP4_M))};
    BOOST_CHECK_EQUAL(Sha256Hex(enc.ct), "09c5ef9842d4eb16f9d4a25ec61d32765407015bba41ac1ed52ee817bf190ad3");
    BOOST_CHECK_EQUAL(HexStr(std::span{enc.ct}.first(16)), "076ad99627b20ac3218569dbd310c755");
    BOOST_CHECK_EQUAL(HexStr(*enc.shared_secret), "ec378be1bd4d2cc452b73ae26af3c066c3941ddf715d2bf2b09e1d5b3a7737dd");
    BOOST_CHECK(*RequireDecaps(*key_pair.dk, enc.ct) == *enc.shared_secret);
    Ciphertext flipped{enc.ct};
    flipped[0] ^= std::byte{1};
    BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(*key_pair.dk, flipped)), "f25fddfbf8e6bab2f844876899e4d111abd96e248e00f21b2709bcfe810aa454");

    // V6: V1's ek with one coefficient out of range.
    const EncapsKey bad1{SetCoefficient(key_pair.ek, 0, 3329)};
    BOOST_CHECK_EQUAL(HexStr(std::span{bad1}.first(2)), "012d");
    BOOST_CHECK_EQUAL(Sha256Hex(bad1), "f7b117ca93a1a7ecdd7ac4c8633c16dc4e5cdd669d1f0570b252826b26896c4f");
    const EncapsKey bad2{SetCoefficient(key_pair.ek, 767, 4095)};
    BOOST_CHECK_EQUAL(HexStr(std::span{bad2}.subspan(1150, 2)), "fbff");
    BOOST_CHECK_EQUAL(Sha256Hex(bad2), "6c98f6febda74c7f19030c2f8c07e5c7415459d00d698610c042e49ee4b20402");
    for (const EncapsKey& bad : {bad1, bad2}) {
        BOOST_CHECK_EQUAL(HexStr(std::span{bad}.last(32)), "ecd19b0450bec54abd525d9c467b2865af1dcd1eaf866fda668ed1cbc6d38daa");
        BOOST_CHECK(!CheckEncapsKey(bad));
        const auto bad_enc{Encaps(bad, FromHex<SEED_SIZE>(XIP4_M))};
        BOOST_CHECK(!bad_enc.has_value() && bad_enc.error() == Error::INVALID_ENCAPS_KEY);
    }
}

BOOST_AUTO_TEST_CASE(invalid_encaps_key)
{
    // FIPS 203 section 7.2: ByteEncode12(ByteDecode12(ek[0:1152])) == ek[0:1152],
    // at the first and last coefficient of each of the three polynomials.
    const mlkem768::KeyPair key_pair{RequireKeyGen(FromHex<SEED_SIZE>(XIP4_D), FromHex<SEED_SIZE>(XIP4_Z))};
    for (const size_t index : {0, 1, 255, 256, 511, 512, 766, 767}) {
        for (const unsigned value : {0U, 1U, 3328U, 3329U, 3330U, 4095U}) {
            const bool valid{value < 3329};
            const EncapsKey ek{SetCoefficient(key_pair.ek, index, value)};
            BOOST_CHECK_EQUAL(CheckEncapsKey(ek), valid);
            const auto enc{Encaps(ek, FromHex<SEED_SIZE>(XIP4_M))};
            BOOST_CHECK_EQUAL(enc.has_value(), valid);
            if (!valid) BOOST_CHECK(enc.error() == Error::INVALID_ENCAPS_KEY);
            const auto random_enc{Encapsulate(ek)};
            BOOST_CHECK_EQUAL(random_enc.has_value(), valid);
            if (!valid) BOOST_CHECK(random_enc.error() == Error::INVALID_ENCAPS_KEY);
        }
    }
    // The seed rho (the last 32 bytes) is not range checked.
    EncapsKey any_rho{key_pair.ek};
    std::fill(any_rho.end() - 32, any_rho.end(), std::byte{0xff});
    BOOST_CHECK(CheckEncapsKey(any_rho));
    // All-ones coefficients (4095) everywhere.
    EncapsKey all_ones{};
    std::fill(all_ones.begin(), all_ones.end() - 32, std::byte{0xff});
    BOOST_CHECK(!CheckEncapsKey(all_ones));
    BOOST_CHECK(!Encapsulate(all_ones).has_value());
    // An all-zero key is well formed (every coefficient 0).
    BOOST_CHECK(CheckEncapsKey(EncapsKey{}));
}

BOOST_AUTO_TEST_CASE(implicit_rejection)
{
    // A tampered ciphertext is not an error: Decaps returns J(z || c'), a value
    // unrelated to K, the same way it returns K.
    const mlkem768::KeyPair key_pair{RequireKeyGen(FromHex<SEED_SIZE>(XIP4_D), FromHex<SEED_SIZE>(XIP4_Z))};
    const Encapsulation enc{RequireEncaps(key_pair.ek, FromHex<SEED_SIZE>(XIP4_M))};
    for (const size_t position : {size_t{0}, size_t{1}, size_t{959}, size_t{960}, CIPHERTEXT_SIZE - 1}) {
        for (const int bit : {0, 7}) {
            Ciphertext tampered{enc.ct};
            tampered[position] ^= std::byte(1 << bit);
            const SharedSecret rejected{RequireDecaps(*key_pair.dk, tampered)};
            BOOST_CHECK(*rejected != *enc.shared_secret);
            BOOST_CHECK_EQUAL(HexStr(*rejected), ImplicitRejectionHex(*key_pair.dk, tampered));
        }
    }
    for (const Ciphertext& junk : {Ciphertext{}, [] { Ciphertext c; c.fill(std::byte{0xff}); return c; }()}) {
        BOOST_CHECK_EQUAL(HexStr(*RequireDecaps(*key_pair.dk, junk)), ImplicitRejectionHex(*key_pair.dk, junk));
    }
    // A different z changes only the rejection value.
    std::array<std::byte, DECAPS_KEY_SIZE> other_z{*key_pair.dk};
    std::fill(other_z.end() - 32, other_z.end(), std::byte{0});
    BOOST_CHECK(CheckDecapsKey(other_z));
    BOOST_CHECK(*RequireDecaps(other_z, enc.ct) == *enc.shared_secret);
    Ciphertext flipped{enc.ct};
    flipped[0] ^= std::byte{1};
    BOOST_CHECK(*RequireDecaps(other_z, flipped) != *RequireDecaps(*key_pair.dk, flipped));
    // Section 7.3: a dk whose stored H(ek) or ek is corrupted is refused.
    for (const size_t position : {size_t{1152}, size_t{2335}, size_t{2336}, size_t{2367}}) {
        std::array<std::byte, DECAPS_KEY_SIZE> corrupt{*key_pair.dk};
        corrupt[position] ^= std::byte{0x80};
        BOOST_CHECK(!CheckDecapsKey(corrupt));
        const auto shared_secret{Decaps(corrupt, enc.ct)};
        BOOST_CHECK(!shared_secret.has_value() && shared_secret.error() == Error::INVALID_DECAPS_KEY);
    }
}

BOOST_AUTO_TEST_CASE(random_path)
{
    // The node's RNG serves at most 32 bytes per GetStrongRandBytes call and
    // aborts on more (random.cpp ProcRand), so these requests only complete
    // because the hook splits them.
    for (const size_t size : {0, 1, 31, 32, 33, 64, 100, 1088}) {
        std::vector<uint8_t> out(size);
        BOOST_CHECK_EQUAL(xcoin_mlkem_randombytes(out.data(), out.size()), 0);
        if (size >= 32) BOOST_CHECK(std::ranges::any_of(out, [](uint8_t b) { return b != 0; }));
    }

    // GenerateKeyPair takes d || z from the hook in one 64-byte request,
    // Encapsulate m in one 32-byte request.
    auto first{GenerateKeyPair()};
    auto second{GenerateKeyPair()};
    BOOST_REQUIRE(first.has_value() && second.has_value());
    BOOST_CHECK(first->ek != second->ek);
    BOOST_CHECK(*first->dk != *second->dk);
    BOOST_CHECK(CheckEncapsKey(first->ek));
    BOOST_CHECK(CheckDecapsKey(*first->dk));
    auto enc1{Encapsulate(first->ek)};
    auto enc2{Encapsulate(first->ek)};
    BOOST_REQUIRE(enc1.has_value() && enc2.has_value());
    BOOST_CHECK(enc1->ct != enc2->ct);
    BOOST_CHECK(*enc1->shared_secret != *enc2->shared_secret);
    BOOST_CHECK(*RequireDecaps(*first->dk, enc1->ct) == *enc1->shared_secret);
    BOOST_CHECK(*RequireDecaps(*first->dk, enc2->ct) == *enc2->shared_secret);
    // The key from the other pair gives an unrelated secret.
    BOOST_CHECK(*RequireDecaps(*second->dk, enc1->ct) != *enc1->shared_secret);
}

BOOST_AUTO_TEST_CASE(secrets_in_locked_memory)
{
    // dk and K live in the secure allocator's locked pool, which wipes them
    // when they are freed, on success and error paths alike.
    const auto used{[] { return LockedPoolManager::Instance().stats().used; }};
    const size_t before{used()};
    {
        auto key_pair{GenerateKeyPair()};
        BOOST_REQUIRE(key_pair.has_value());
        BOOST_CHECK_GE(used(), before + DECAPS_KEY_SIZE);
        auto enc{Encapsulate(key_pair->ek)};
        BOOST_REQUIRE(enc.has_value());
        auto shared_secret{Decaps(*key_pair->dk, enc->ct)};
        BOOST_REQUIRE(shared_secret.has_value());
        BOOST_CHECK_GE(used(), before + DECAPS_KEY_SIZE + 2 * SHARED_SECRET_SIZE);
        // A failed call leaves nothing allocated behind.
        const size_t during{used()};
        BOOST_CHECK(!Encapsulate(EncapsKey{std::byte{0xff}, std::byte{0xff}}).has_value());
        BOOST_CHECK_EQUAL(used(), during);
    }
    BOOST_CHECK_EQUAL(used(), before);
}

BOOST_AUTO_TEST_SUITE_END()
