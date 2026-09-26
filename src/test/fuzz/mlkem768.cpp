// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The ML-KEM-768 wrapper (XIP-4, HX1) on arbitrary inputs. The input checks of FIPS 203 sections 7.2 and 7.3 are
// written out here from the standard, so that the library's own checks are tested against them.

#include <crypto/mlkem768.h>
#include <crypto/sha3.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

using namespace mlkem768;

namespace {

/** The next N input bytes, zero-padded once the input runs out. */
template <size_t N>
std::array<std::byte, N> ConsumeArray(FuzzedDataProvider& provider)
{
    std::array<std::byte, N> ret{};
    std::ranges::copy(provider.ConsumeBytes<std::byte>(N), ret.begin());
    return ret;
}

//! ek = ByteEncode12 of k = 3 polynomials (384 bytes each) || rho (32 bytes).
constexpr size_t POLYVEC_BYTES{3 * 384};
//! dk = dk_PKE (1152 bytes) || ek || H(ek) (32 bytes) || z (32 bytes).
constexpr size_t DK_EK_OFFSET{POLYVEC_BYTES};
constexpr size_t DK_HASH_OFFSET{DK_EK_OFFSET + ENCAPS_KEY_SIZE};
constexpr size_t DK_Z_OFFSET{DK_HASH_OFFSET + 32};

/** The modulus check of FIPS 203 section 7.2 (equation 7.1): every 12-bit coefficient of the encoded polynomials is
 *  below q = 3329, so that ByteDecode12 followed by ByteEncode12 gives the bytes back. */
bool ModulusCheck(std::span<const std::byte, ENCAPS_KEY_SIZE> ek)
{
    for (size_t pos{0}; pos < POLYVEC_BYTES; pos += 3) {
        const unsigned b0{std::to_integer<unsigned>(ek[pos])};
        const unsigned b1{std::to_integer<unsigned>(ek[pos + 1])};
        const unsigned b2{std::to_integer<unsigned>(ek[pos + 2])};
        if ((b0 | ((b1 & 0x0f) << 8)) >= 3329 || ((b1 >> 4) | (b2 << 4)) >= 3329) return false;
    }
    return true;
}

/** The hash check of FIPS 203 section 7.3 (equation 7.2): the H(ek) stored in dk is SHA3-256 of the ek stored in dk. */
bool HashCheck(std::span<const std::byte, DECAPS_KEY_SIZE> dk)
{
    std::array<unsigned char, SHA3_256::OUTPUT_SIZE> hash;
    SHA3_256().Write(MakeUCharSpan(dk.subspan(DK_EK_OFFSET, ENCAPS_KEY_SIZE))).Finalize(hash);
    return std::ranges::equal(MakeByteSpan(hash), dk.subspan(DK_HASH_OFFSET, 32));
}

} // namespace

FUZZ_TARGET(mlkem768_encaps)
{
    // Encapsulation to an arbitrary key never crashes, is refused exactly when the section 7.2 check fails, and is
    // otherwise a function of (ek, m).
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto ek{ConsumeArray<ENCAPS_KEY_SIZE>(provider)};
    const auto m{ConsumeArray<SEED_SIZE>(provider)};

    const bool valid{CheckEncapsKey(ek)};
    assert(valid == ModulusCheck(ek));
    const auto enc{Encaps(ek, m)};
    assert(enc.has_value() == valid);
    if (!valid) {
        assert(enc.error() == Error::INVALID_ENCAPS_KEY);
        return;
    }
    const auto again{Encaps(ek, m)};
    assert(again && again->ct == enc->ct && *again->shared_secret == *enc->shared_secret);
    auto other_m{m};
    other_m[0] ^= std::byte{1};
    const auto other{Encaps(ek, other_m)};
    assert(other && other->ct != enc->ct && *other->shared_secret != *enc->shared_secret);
}

FUZZ_TARGET(mlkem768_decaps)
{
    // Decapsulation of an arbitrary ciphertext never crashes or fails: a ciphertext that was not made for dk gives
    // the implicit-rejection value, deterministically and without a distinguishable error. dk is arbitrary too, and
    // then refused exactly when the section 7.3 check fails; deriving it from seeds instead reaches the
    // decapsulation itself.
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint8_t flags{provider.ConsumeIntegral<uint8_t>()};
    std::optional<KeyPair> key_pair;
    std::array<std::byte, DECAPS_KEY_SIZE> dk;
    if (flags & 1) {
        const auto d{ConsumeArray<SEED_SIZE>(provider)};
        const auto z{ConsumeArray<SEED_SIZE>(provider)};
        auto generated{KeyGen(d, z)};
        assert(generated);
        dk = *generated->dk;
        key_pair.emplace(std::move(*generated));
    } else {
        dk = ConsumeArray<DECAPS_KEY_SIZE>(provider);
    }
    const bool valid{CheckDecapsKey(dk)};
    assert(valid == HashCheck(dk));

    Ciphertext ct;
    std::optional<std::array<std::byte, SHARED_SECRET_SIZE>> shared_secret; //!< what the untouched ct decapsulates to
    bool tampered{false};
    if (key_pair && (flags & 2)) {
        const auto m{ConsumeArray<SEED_SIZE>(provider)};
        const auto enc{Encaps(key_pair->ek, m)};
        assert(enc);
        ct = enc->ct;
        shared_secret = *enc->shared_secret;
        const auto flips{provider.ConsumeIntegralInRange<unsigned>(0, 8)};
        for (unsigned i{0}; i < flips; ++i) {
            const auto bit{provider.ConsumeIntegralInRange<size_t>(0, CIPHERTEXT_SIZE * 8 - 1)};
            ct[bit / 8] ^= std::byte{static_cast<uint8_t>(1U << (bit % 8))};
        }
        tampered = ct != enc->ct;
    } else {
        ct = ConsumeArray<CIPHERTEXT_SIZE>(provider);
    }

    const auto dec{Decaps(dk, ct)};
    assert(dec.has_value() == valid);
    if (!valid) {
        assert(dec.error() == Error::INVALID_DECAPS_KEY);
        return;
    }
    const auto again{Decaps(dk, ct)};
    assert(again && **again == **dec);
    if (shared_secret) assert((**dec == *shared_secret) == !tampered);
}

FUZZ_TARGET(mlkem768_keygen)
{
    // Key generation from arbitrary seeds always succeeds and gives a key pair in the FIPS 203 layout that passes
    // both checks, round-trips through encapsulation and decapsulation, and is a function of the seeds.
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto d{ConsumeArray<SEED_SIZE>(provider)};
    const auto z{ConsumeArray<SEED_SIZE>(provider)};
    const auto m{ConsumeArray<SEED_SIZE>(provider)};

    const auto key_pair{KeyGen(d, z)};
    assert(key_pair);
    const std::span<const std::byte, DECAPS_KEY_SIZE> dk{*key_pair->dk};
    assert(CheckEncapsKey(key_pair->ek) && ModulusCheck(key_pair->ek));
    assert(CheckDecapsKey(dk) && HashCheck(dk));
    assert(std::ranges::equal(dk.subspan(DK_EK_OFFSET, ENCAPS_KEY_SIZE), key_pair->ek));
    assert(std::ranges::equal(dk.subspan(DK_Z_OFFSET, SEED_SIZE), z));

    const auto again{KeyGen(d, z)};
    assert(again && again->ek == key_pair->ek && *again->dk == *key_pair->dk);
    // z only enters dk.
    auto other_z{z};
    other_z[0] ^= std::byte{1};
    const auto other{KeyGen(d, other_z)};
    assert(other && other->ek == key_pair->ek && *other->dk != *key_pair->dk);

    const auto enc{Encaps(key_pair->ek, m)};
    assert(enc);
    const auto dec{Decaps(dk, enc->ct)};
    assert(dec && **dec == *enc->shared_secret);
}
