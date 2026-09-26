/*
 * Copyright (c) 2026 The xCoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_HOOKS_H
#define BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_HOOKS_H

/* xCoin addition (not in mlkem-native): the two platform functions that
 * xcoin_config.h hands to the vendored library. Both are defined in
 * src/pqrandom.cpp (bitcoin_util). */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fills out[0..outlen) from the node's GetStrongRandBytes, at most 32 bytes
 * per call, and returns 0. */
int xcoin_mlkem_randombytes(uint8_t *out, size_t outlen);

/* memory_cleanse(ptr, len). */
void xcoin_mlkem_zeroize(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_HOOKS_H */
