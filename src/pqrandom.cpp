// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" {
#include <pqcrypto/common/randombytes.h>
}

// The vendored PQClean code (src/pqcrypto) draws the randomness for ML-DSA-65
// key generation and hedged signing, and for SLH-DSA-SHA2-128s key generation
// and opt_rand, through PQCLEAN_randombytes. PQClean's own randombytes.c (a
// direct OS RNG call) is not built; this shim routes every request through the
// node's GetStrongRandBytes instead, so PQ keys and signatures use the same
// RNG as everything else in the node: hardware and OS entropy, the
// strengthened persisted state and the per-process key (src/random.h).
//
// GetStrongRandBytes serves at most 32 bytes per call (one CSHA512 output
// block, random.cpp ProcRand), so longer requests are served in 32-byte
// chunks. GetStrongRandBytes never fails (it aborts the process if the OS RNG
// is unusable, as the rest of the node does), so the PQClean-style return code
// is always 0; callers still check it, so a future failing RNG fails closed.
extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n)
{
    std::span<unsigned char> out{output, n};
    while (!out.empty()) {
        const size_t chunk{std::min<size_t>(out.size(), 32)};
        GetStrongRandBytes(out.first(chunk));
        out = out.subspan(chunk);
    }
    return 0;
}
