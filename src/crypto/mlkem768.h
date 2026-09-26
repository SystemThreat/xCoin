// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLKEM768_H
#define BITCOIN_CRYPTO_MLKEM768_H

#include <support/allocators/secure.h>
#include <util/expected.h>

#include <array>
#include <cstddef>
#include <span>

/** ML-KEM-768 (FIPS 203) for the hybrid v2 transport (XIP-4, HX1).
 *
 * The implementation is the vendored mlkem-native, portable C
 * (crypto/mlkem-native/PINNED). Secret outputs are returned in locked memory
 * that is wiped when freed; the library wipes its own intermediates.
 */
namespace mlkem768 {

//! FIPS 203 section 8, Table 3.
inline constexpr size_t ENCAPS_KEY_SIZE{1184};
inline constexpr size_t DECAPS_KEY_SIZE{2400};
inline constexpr size_t CIPHERTEXT_SIZE{1088};
inline constexpr size_t SHARED_SECRET_SIZE{32};
//! Each of the seeds d and z (key generation) and m (encapsulation).
inline constexpr size_t SEED_SIZE{32};

using EncapsKey = std::array<std::byte, ENCAPS_KEY_SIZE>;
using Ciphertext = std::array<std::byte, CIPHERTEXT_SIZE>;
using DecapsKey = secure_unique_ptr<std::array<std::byte, DECAPS_KEY_SIZE>>;
using SharedSecret = secure_unique_ptr<std::array<std::byte, SHARED_SECRET_SIZE>>;

enum class Error {
    //! ek failed the FIPS 203 section 7.2 modulus check: some 12-bit coefficient is 3329 or more.
    INVALID_ENCAPS_KEY,
    //! dk failed the FIPS 203 section 7.3 hash check: the H(ek) stored in it does not match its ek.
    INVALID_DECAPS_KEY,
    //! The random-bytes source reported a failure.
    RNG_FAILURE,
    //! Any other error mlkem-native returned.
    LIBRARY_FAILURE,
};

struct KeyPair {
    EncapsKey ek;
    DecapsKey dk; //!< the 2400-byte expanded form: dk_PKE || ek || H(ek) || z
};

struct Encapsulation {
    Ciphertext ct;
    SharedSecret shared_secret;
};

/** ML-KEM.KeyGen_internal(d, z), FIPS 203 Algorithm 16. */
[[nodiscard]] util::Expected<KeyPair, Error> KeyGen(std::span<const std::byte, SEED_SIZE> d, std::span<const std::byte, SEED_SIZE> z);

/** ML-KEM.Encaps_internal(ek, m), FIPS 203 Algorithm 17, run only if ek passes
 *  the section 7.2 check (the span type is its length check). */
[[nodiscard]] util::Expected<Encapsulation, Error> Encaps(std::span<const std::byte, ENCAPS_KEY_SIZE> ek, std::span<const std::byte, SEED_SIZE> m);

/** ML-KEM.Decaps_internal(dk, ct), FIPS 203 Algorithm 18, run only if dk
 *  passes the section 7.3 hash check.
 *
 *  A ciphertext that was not made for dk is not an error: the result is then
 *  the implicit-rejection value J(z || ct), computed in constant time like a
 *  real shared secret, so no caller can branch on it. */
[[nodiscard]] util::Expected<SharedSecret, Error> Decaps(std::span<const std::byte, DECAPS_KEY_SIZE> dk, std::span<const std::byte, CIPHERTEXT_SIZE> ct);

/** The FIPS 203 section 7.2 modulus check on its own. */
[[nodiscard]] bool CheckEncapsKey(std::span<const std::byte, ENCAPS_KEY_SIZE> ek);

/** The FIPS 203 section 7.3 hash check on its own. */
[[nodiscard]] bool CheckDecapsKey(std::span<const std::byte, DECAPS_KEY_SIZE> dk);

/** ML-KEM.KeyGen, FIPS 203 Algorithm 19: KeyGen with d and z drawn from
 *  GetStrongRandBytes, one 32-byte call each. */
[[nodiscard]] util::Expected<KeyPair, Error> GenerateKeyPair();

/** ML-KEM.Encaps, FIPS 203 Algorithm 20: Encaps with m drawn from
 *  GetStrongRandBytes. */
[[nodiscard]] util::Expected<Encapsulation, Error> Encapsulate(std::span<const std::byte, ENCAPS_KEY_SIZE> ek);

} // namespace mlkem768

#endif // BITCOIN_CRYPTO_MLKEM768_H
