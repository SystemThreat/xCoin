// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mlkem768.h>

#include <span.h>

#include <algorithm>

// The same configuration crypto/mlkem-native/mlkem768.c builds the library with.
#define MLK_CONFIG_FILE "crypto/mlkem-native/xcoin_config.h"
#include <crypto/mlkem-native/mlkem/mlkem_native.h>

static_assert(MLK_CONFIG_PARAMETER_SET == 768);
static_assert(MLKEM768_PUBLICKEYBYTES == mlkem768::ENCAPS_KEY_SIZE);
static_assert(MLKEM768_SECRETKEYBYTES == mlkem768::DECAPS_KEY_SIZE);
static_assert(MLKEM768_CIPHERTEXTBYTES == mlkem768::CIPHERTEXT_SIZE);
static_assert(MLKEM768_BYTES == mlkem768::SHARED_SECRET_SIZE);
static_assert(MLKEM768_SYMBYTES == mlkem768::SEED_SIZE);

namespace mlkem768 {
namespace {
Error ToError(int ret)
{
    switch (ret) {
    case MLK_ERR_INVALID_PK:
        return Error::INVALID_ENCAPS_KEY;
    case MLK_ERR_INVALID_SK:
        return Error::INVALID_DECAPS_KEY;
    case MLK_ERR_RNG_FAIL:
        return Error::RNG_FAILURE;
    default:
        return Error::LIBRARY_FAILURE;
    }
}

KeyPair NewKeyPair()
{
    return {.ek = {}, .dk = make_secure_unique<std::array<std::byte, DECAPS_KEY_SIZE>>()};
}

Encapsulation NewEncapsulation()
{
    return {.ct = {}, .shared_secret = make_secure_unique<std::array<std::byte, SHARED_SECRET_SIZE>>()};
}
} // namespace

util::Expected<KeyPair, Error> KeyGen(std::span<const std::byte, SEED_SIZE> d, std::span<const std::byte, SEED_SIZE> z)
{
    // mlkem-native takes d || z as one array.
    const auto coins{make_secure_unique<std::array<std::byte, 2 * SEED_SIZE>>()};
    std::ranges::copy(d, coins->begin());
    std::ranges::copy(z, coins->begin() + SEED_SIZE);
    KeyPair key_pair{NewKeyPair()};
    const int ret{xcoin_mlkem768_keypair_derand(UCharCast(key_pair.ek.data()), UCharCast(key_pair.dk->data()), UCharCast(coins->data()))};
    if (ret != 0) return util::Unexpected{ToError(ret)};
    return key_pair;
}

util::Expected<Encapsulation, Error> Encaps(std::span<const std::byte, ENCAPS_KEY_SIZE> ek, std::span<const std::byte, SEED_SIZE> m)
{
    Encapsulation enc{NewEncapsulation()};
    const int ret{xcoin_mlkem768_enc_derand(UCharCast(enc.ct.data()), UCharCast(enc.shared_secret->data()), UCharCast(ek.data()), UCharCast(m.data()))};
    if (ret != 0) return util::Unexpected{ToError(ret)};
    return enc;
}

util::Expected<SharedSecret, Error> Decaps(std::span<const std::byte, DECAPS_KEY_SIZE> dk, std::span<const std::byte, CIPHERTEXT_SIZE> ct)
{
    SharedSecret shared_secret{make_secure_unique<std::array<std::byte, SHARED_SECRET_SIZE>>()};
    const int ret{xcoin_mlkem768_dec(UCharCast(shared_secret->data()), UCharCast(ct.data()), UCharCast(dk.data()))};
    if (ret != 0) return util::Unexpected{ToError(ret)};
    return shared_secret;
}

bool CheckEncapsKey(std::span<const std::byte, ENCAPS_KEY_SIZE> ek)
{
    return xcoin_mlkem768_check_pk(UCharCast(ek.data())) == 0;
}

bool CheckDecapsKey(std::span<const std::byte, DECAPS_KEY_SIZE> dk)
{
    return xcoin_mlkem768_check_sk(UCharCast(dk.data())) == 0;
}

util::Expected<KeyPair, Error> GenerateKeyPair()
{
    KeyPair key_pair{NewKeyPair()};
    const int ret{xcoin_mlkem768_keypair(UCharCast(key_pair.ek.data()), UCharCast(key_pair.dk->data()))};
    if (ret != 0) return util::Unexpected{ToError(ret)};
    return key_pair;
}

util::Expected<Encapsulation, Error> Encapsulate(std::span<const std::byte, ENCAPS_KEY_SIZE> ek)
{
    Encapsulation enc{NewEncapsulation()};
    const int ret{xcoin_mlkem768_enc(UCharCast(enc.ct.data()), UCharCast(enc.shared_secret->data()), UCharCast(ek.data()))};
    if (ret != 0) return util::Unexpected{ToError(ret)};
    return enc;
}

} // namespace mlkem768
