// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ML-KEM-768 as the hybrid v2 transport (XIP-4, HX1) uses it, with the
// vendored mlkem-native in portable C. Per handshake the responder runs
// GenerateKeyPair and Decaps, the initiator Encapsulate (the section 7.2 key
// check included). The deterministic variants time the library alone, without
// the GetStrongRandBytes calls. Re-run with:
//
//   build/bin/bench_bitcoin -filter='MLKEM768.*'

#include <bench/bench.h>
#include <crypto/mlkem768.h>

#include <array>
#include <cassert>
#include <cstddef>

namespace {
constexpr std::array<std::byte, mlkem768::SEED_SIZE> Seed(unsigned char fill)
{
    std::array<std::byte, mlkem768::SEED_SIZE> seed{};
    seed.fill(std::byte{fill});
    return seed;
}
} // namespace

static void MLKEM768KeyGen(benchmark::Bench& bench)
{
    auto d{Seed(0x2b)};
    const auto z{Seed(0x5a)};
    bench.run([&] {
        const auto key_pair{mlkem768::KeyGen(d, z)};
        assert(key_pair);
        d[0] = key_pair->ek[0];
    });
}

static void MLKEM768Encaps(benchmark::Bench& bench)
{
    const auto key_pair{mlkem768::KeyGen(Seed(0x2b), Seed(0x5a))};
    assert(key_pair);
    auto m{Seed(0x77)};
    bench.run([&] {
        const auto enc{mlkem768::Encaps(key_pair->ek, m)};
        assert(enc);
        m[0] = enc->ct[0];
    });
}

static void MLKEM768Decaps(benchmark::Bench& bench)
{
    const auto key_pair{mlkem768::KeyGen(Seed(0x2b), Seed(0x5a))};
    assert(key_pair);
    const auto enc{mlkem768::Encaps(key_pair->ek, Seed(0x77))};
    assert(enc);
    bench.run([&] {
        const auto shared_secret{mlkem768::Decaps(*key_pair->dk, enc->ct)};
        assert(shared_secret && **shared_secret == *enc->shared_secret);
    });
}

static void MLKEM768GenerateKeyPair(benchmark::Bench& bench)
{
    bench.run([&] {
        const auto key_pair{mlkem768::GenerateKeyPair()};
        assert(key_pair);
    });
}

static void MLKEM768Encapsulate(benchmark::Bench& bench)
{
    const auto key_pair{mlkem768::KeyGen(Seed(0x2b), Seed(0x5a))};
    assert(key_pair);
    bench.run([&] {
        const auto enc{mlkem768::Encapsulate(key_pair->ek)};
        assert(enc);
    });
}

BENCHMARK(MLKEM768KeyGen);
BENCHMARK(MLKEM768Encaps);
BENCHMARK(MLKEM768Decaps);
BENCHMARK(MLKEM768GenerateKeyPair);
BENCHMARK(MLKEM768Encapsulate);
