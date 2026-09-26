// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" {
#include <crypto/mlkem-native/xcoin_hooks.h>
#include <pqcrypto/common/randombytes.h>
}

namespace {
// GetStrongRandBytes serves at most 32 bytes per call (one CSHA512 output
// block, random.cpp ProcRand, which asserts on more), so longer requests are
// served in 32-byte chunks.
void StrongRandBytesChunked(std::span<unsigned char> out)
{
    while (!out.empty()) {
        const size_t chunk{std::min<size_t>(out.size(), 32)};
        GetStrongRandBytes(out.first(chunk));
        out = out.subspan(chunk);
    }
}
} // namespace

// The vendored PQClean code (src/pqcrypto) draws the randomness for ML-DSA-65
// key generation and hedged signing, and for SLH-DSA-SHA2-128s key generation
// and opt_rand, through PQCLEAN_randombytes. PQClean's own randombytes.c (a
// direct OS RNG call) is not built; this shim routes every request through the
// node's GetStrongRandBytes instead, so PQ keys and signatures use the same
// RNG as everything else in the node: hardware and OS entropy, the
// strengthened persisted state and the per-process key (src/random.h).
//
// GetStrongRandBytes never fails (it aborts the process if the OS RNG is
// unusable, as the rest of the node does), so the PQClean-style return code is
// always 0; callers still check it, so a future failing RNG fails closed.
extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n)
{
    StrongRandBytesChunked({output, n});
    return 0;
}

// The same for the vendored mlkem-native (src/crypto/mlkem-native), whose
// randomized key generation asks for d || z in one 64-byte request: XIP-4
// requires d and z to be separate 32-byte draws. mlkem-native checks the
// return code and fails with MLK_ERR_RNG_FAIL on non-zero.
extern "C" int xcoin_mlkem_randombytes(uint8_t* out, size_t outlen)
{
    StrongRandBytesChunked({out, outlen});
    return 0;
}

// mlkem-native wipes its stack buffers and, on failure, its outputs with this.
extern "C" void xcoin_mlkem_zeroize(void* ptr, size_t len)
{
    memory_cleanse(ptr, len);
}
