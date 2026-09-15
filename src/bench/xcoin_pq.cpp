// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Post-quantum signature verification, the two algorithms of the witness v3
// script tree (contrib/regenesis/REGENESIS.md section 4). These numbers set
// XCOIN_V3_VALIDATION_WEIGHT_MLDSA and XCOIN_V3_VALIDATION_WEIGHT_SLH: the
// weights are a consensus constant, so the ratio between them must match the
// ratio of the verification costs measured here, on a release build, with
// this tree's own PQClean code. Re-run with:
//
//   build/bin/bench_bitcoin -filter='XcoinVerify.*'

#include <bench/bench.h>
#include <pqkey.h>
#include <slhkey.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <vector>

namespace {
// Fixed seeds: the same key pair every run, so the numbers are comparable.
CPQKey MLDSAKey(CPQPubKey& pub)
{
    std::array<unsigned char, 32> seed{};
    seed.fill(0x2b);
    CPQKey key;
    pub = key.MakeKeyFromSeed(seed);
    return key;
}

CSLHKey SLHKey(CSLHPubKey& pub)
{
    std::array<unsigned char, SLH_SEED_SIZE> seed{};
    seed.fill(0x5a);
    CSLHKey key;
    pub = key.MakeKeyFromSeed(seed);
    return key;
}

const uint256 DIGEST{uint256::ONE};
} // namespace

// One ML-DSA-65 (FIPS 204) verification of a 32-byte digest: the everyday
// leaf's OP_CHECKSIG.
static void XcoinVerifyMLDSA65(benchmark::Bench& bench)
{
    CPQPubKey pub;
    const CPQKey key{MLDSAKey(pub)};
    assert(pub.IsValid());
    std::vector<unsigned char> sig;
    assert(key.Sign(DIGEST, sig));
    assert(pub.Verify(DIGEST, sig));
    bench.run([&] {
        const bool ok{pub.Verify(DIGEST, sig)};
        assert(ok);
    });
}

// One SLH-DSA-SHA2-128s (FIPS 205, pure mode, empty context) verification of a
// 32-byte digest: the fallback leaf's OP_CHECKSIG, and the block's worst case.
static void XcoinVerifySLHDSA128s(benchmark::Bench& bench)
{
    CSLHPubKey pub;
    const CSLHKey key{SLHKey(pub)};
    assert(pub.IsValid());
    std::vector<unsigned char> sig;
    assert(key.Sign(DIGEST, sig));
    assert(pub.Verify(DIGEST, sig));
    bench.run([&] {
        const bool ok{pub.Verify(DIGEST, sig)};
        assert(ok);
    });
}

BENCHMARK(XcoinVerifyMLDSA65);
BENCHMARK(XcoinVerifySLHDSA128s);
