/*
 * Copyright (c) 2026 The xCoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_CONFIG_H
#define BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_CONFIG_H

/* xCoin addition (not in mlkem-native): the build configuration of the
 * vendored library, used in place of upstream's mlkem/mlkem_native_config.h
 * (not vendored, see PINNED). mlkem768.c and crypto/mlkem768.cpp both select
 * it through MLK_CONFIG_FILE, so the library and its one caller agree on the
 * parameter set and the symbol names. Every option not set here keeps
 * upstream's default. */

#define MLK_CONFIG_PARAMETER_SET 768

/* The public functions are xcoin_mlkem768_keypair_derand and so on. */
#define MLK_CONFIG_NAMESPACE_PREFIX xcoin_mlkem768

#if defined(MLK_BUILD_INTERNAL)
/* mlkem768.c is the only compilation unit, so everything below the public
 * API can be static. */
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static

/* MLK_CONFIG_USE_NATIVE_BACKEND_ARITH and MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
 * stay unset: portable C only, no assembly or intrinsics backends. The empty
 * asm statement upstream uses as a constant-time value barrier (verify.h)
 * stays; it emits no instructions. */

#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#define MLK_CONFIG_CUSTOM_ZEROIZE
#if !defined(__ASSEMBLER__)
#include "mlkem/src/sys.h"
#include "xcoin_hooks.h"

/* The key generation seed d || z arrives as one 64-byte request; the hook
 * splits it (XIP-4, "Secrets"). */
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_randombytes(uint8_t *ptr, size_t len)
{
  return xcoin_mlkem_randombytes(ptr, len);
}

static MLK_INLINE void mlk_zeroize(void *ptr, size_t len)
{
  xcoin_mlkem_zeroize(ptr, len);
}
#endif /* !__ASSEMBLER__ */
#endif /* MLK_BUILD_INTERNAL */

#endif /* BITCOIN_CRYPTO_MLKEM_NATIVE_XCOIN_CONFIG_H */
