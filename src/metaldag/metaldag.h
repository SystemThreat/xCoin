// Copyright (c) 2026 The Xcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MetalDAG — Xcoin's memory-hard, Apple-Silicon-favoring proof-of-work
// (Ethash-family). Light-cache verification: a node recomputes only the ~128 DAG
// items a given (header,nonce) touches, from a small per-epoch cache, so no
// multi-GB DAG is needed to VERIFY (only mining builds the full DAG).
//
// Cross-checked byte-for-byte against the Metal GPU miner kernel — see
// metaldag/metaldag-ref.cpp and metaldag/metaldag_bench.swift.

#ifndef BITCOIN_METALDAG_METALDAG_H
#define BITCOIN_METALDAG_METALDAG_H

#include <uint256.h>

#include <chrono>
#include <cstdint>
#include <limits>

class CBlockHeader;
namespace Consensus { struct Params; }

namespace metaldag {

//! Ethash-family constants (the vetted crypto — do not change).
static constexpr uint32_t HASH_BYTES = 64;
static constexpr uint32_t MIX_BYTES = 128;
static constexpr uint32_t WORD_BYTES = 4;
static constexpr uint32_t DATASET_PARENTS = 256;
static constexpr uint32_t CACHE_ROUNDS = 3;
static constexpr uint32_t ACCESSES = 64;

//! Per-epoch sizing resolved from consensus params + the header's epoch.
struct EpochSizing {
    uint64_t epoch{0};
    uint64_t cache_size{0}; //!< bytes (verification cache; ~DAG/divisor)
    uint64_t full_size{0};  //!< bytes (the full DAG a miner holds)
};

//! Hard ceiling on the verification cache a single header may request, enforced
//! before allocation. Bounds worst-case memory from a hostile or garbage nTime
//! even if upstream timestamp gating is bypassed or params are misconfigured —
//! a header deriving a larger cache is treated as failing PoW, never built (C-01).
//! Absolute backstop on cache size, reachable only if the node's clock is absurdly
//! wrong: the primary bound is relative to wall-clock and lives in PoWHash. This used
//! to be 1 GiB, which the real chain would have crossed at epoch 993 (~38 years in),
//! halting every node with no soft-fork way back — raising a cache cap relaxes
//! consensus. 64 GiB is not crossed until ~epoch 65,500, roughly 4500 AD, and it is
//! the first limit the schedule meets: dataset indices are 64-bit (metaldag.cpp,
//! audit finding C4), so the 512 GiB DAG of epoch 4065 does not bind before it.
static constexpr uint64_t METALDAG_MAX_CACHE_BYTES = 64ull * 1024 * 1024 * 1024; // 64 GiB

//! Resolve the epoch and DAG/cache sizing for a header time under these params.
EpochSizing GetEpochSizing(uint32_t nTime, const Consensus::Params& params);

//! Compute the MetalDAG proof-of-work hash of a header (light verification).
//! The returned 256-bit value is compared against the nBits target exactly like
//! a SHA-256d block hash was. Deterministic; safe to call from any thread.
uint256 PoWHash(const CBlockHeader& header, const Consensus::Params& params);

//! How many per-epoch verification caches a node keeps resident, evicting the
//! least recently USED (audit finding 2, 2026-09-14: evicting the lowest epoch
//! let a peer alternate two old epochs and force a rebuild per header).
static constexpr size_t METALDAG_CACHE_ENTRIES = 6;

//! Whether the verification cache for the epoch of a header dated nTime is
//! resident, i.e. verifying such a header costs a hashimoto, not a cache build.
bool CacheResident(uint32_t nTime, const Consensus::Params& params);

//! Budget for building "cold" epoch caches at the request of the network: at
//! most one per interval. Cold = outside the window a node has any honest reason
//! to hash right now (see MayVerifyFromNetwork). Not consensus: it only decides
//! whether a message is processed now or dropped without punishment.
class CacheBuildBudget
{
    const int64_t m_interval_seconds;
    int64_t m_last_build{std::numeric_limits<int64_t>::min() / 2};
public:
    explicit CacheBuildBudget(std::chrono::seconds interval) : m_interval_seconds(interval.count()) {}
    //! Consume the budget if a cold build may start at wall-clock now_seconds.
    bool Take(int64_t now_seconds)
    {
        if (now_seconds - m_last_build < m_interval_seconds) return false;
        m_last_build = now_seconds;
        return true;
    }
};

//! Whether verifying `header` on behalf of an unauthenticated peer is affordable
//! right now. True when its epoch cache is resident, or when its epoch lies in the
//! hot window [epoch(best_header_time) - 1, epoch(now) + 1] (the only epochs an
//! honest chain can ask for: headers extend the best header, and no valid header
//! is dated more than two hours ahead). Any other epoch is cold: allowed only if
//! `budget` grants a build. A refusal is a "not now", never a verdict on validity.
bool MayVerifyFromNetwork(const CBlockHeader& header, const Consensus::Params& params, uint32_t best_header_time, int64_t now, CacheBuildBudget& budget);

} // namespace metaldag

#endif // BITCOIN_METALDAG_METALDAG_H
