// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <metaldag/metaldag.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // NEX mainnet uses an anchored ASERT controller from block 1. The target is
    // derived from total schedule drift since genesis, never from the previous
    // target, so a slow block cannot trigger a difficulty-collapse feedback loop.
    if (pindexLast->nHeight + 1 >= params.nASERTActivationHeight) {
        return AsertGetNextWorkRequired(pindexLast, params);
    }

    // --- Pre-ASERT: classic Bitcoin-style retarget every DifficultyAdjustmentInterval() blocks ---

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

// Anchored ASERT: the aserti3-2d reference algorithm (Bitcoin Cash, 2020-11-15),
// anchored at the genesis block, with no per-block clamp (founder decision
// 2026-09-14: the clamp changed the shape of a recovery, not its length, and
// its only protection, against a timestamp lie, is already bounded by the
// two-hour future-time rule; matching the reference exactly lets the rule be
// pinned by vectors, src/test/pow_tests.cpp asert_reference_vectors).
//
// Every target is calculated from the genesis target and the chain's cumulative
// departure from its ideal 300-second schedule. This is intentionally stateless:
// schedule error does not compound and there is no emergency cliff after a long
// solve. In the reference's terms the anchor is block 1 and the anchor's parent
// is genesis, so time_diff counts from the genesis timestamp and there are
// height_diff = nHeight intervals of nPowTargetSpacing in the ideal schedule.
// A two-hour half-life is responsive to miners joining/leaving while damping the
// extreme variance of a small, memory-hard mining network.
unsigned int AsertGetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    assert(params.nASERTHalfLife > 0);
    const CBlockIndex* anchor = pindexLast->GetAncestor(0);
    assert(anchor != nullptr);

    arith_uint256 target;
    target.SetCompact(anchor->nBits);

    const int64_t height_diff = pindexLast->nHeight - anchor->nHeight;
    const int64_t time_diff = pindexLast->GetBlockTime() - anchor->GetBlockTime();
    const int64_t schedule_error = time_diff - height_diff * params.nPowTargetSpacing;

    // Signed 16.16 fixed point. Floor division is required for negative values
    // because C++ integer division truncates toward zero.
    const int64_t numerator = schedule_error * 65536;
    int64_t exponent = numerator / params.nASERTHalfLife;
    if (numerator < 0 && numerator % params.nASERTHalfLife != 0) --exponent;
    const int64_t shifts = exponent >> 16;
    const uint64_t frac = static_cast<uint16_t>(exponent);

    // Approximate 2^(frac/65536), with factor represented as unsigned 16.16.
    const uint64_t factor = 65536 +
        ((195766423245049ULL * frac +
          971821376ULL * frac * frac +
          5127ULL * frac * frac * frac + (1ULL << 47)) >> 48);

    // Divide before multiplying so easy targets near 2^255 cannot overflow the
    // 256-bit accumulator. ASERT only needs compact-target precision here; the
    // discarded low 16 bits are far below nBits' 24-bit mantissa precision.
    target >>= 16;
    target *= factor;
    if (shifts < 0) {
        const int64_t right = -shifts;
        if (right >= 256) return arith_uint256{1}.GetCompact();
        target >>= right;
    } else {
        if (shifts >= 256 || target > (bnPowLimit >> shifts)) {
            target = bnPowLimit;
        } else {
            target <<= shifts;
        }
    }

    if (target == 0) target = 1;
    if (target > bnPowLimit) target = bnPowLimit;
    return target.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for BIP94 chains (regtest with -test=bip94)
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    const arith_uint256 pow_limit = UintToArith256(params.powLimit);

    // ASERT changes every block. Full validation recomputes the exact expected
    // nBits; this range check only protects headers-first synchronization, and it
    // may reject nothing an honest chain can produce. Under the reference rule
    // (no per-block clamp) an EASIER next block is bounded only by powLimit: a
    // block found after a long gap is eased in proportion to the whole gap. A
    // HARDER next block is bounded by the timestamp rules: the schedule error
    // can fall by at most one block's timestamp swing, which is the previous
    // block's two-hour future allowance plus the median-time-past lag (about
    // 1,500 s at the target spacing) plus one spacing, about 9,000 s, or a
    // factor of 2^(9000/7200) = 2.4 at the two-hour half-life. 4x leaves margin.
    if (height >= params.nASERTActivationHeight) {
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);
        if (observed_new_target > pow_limit) return false;

        arith_uint256 old_target;
        old_target.SetCompact(old_nbits);
        const arith_uint256 hardest_allowed{old_target / 4};
        arith_uint256 minimum_new;
        minimum_new.SetCompact(hardest_allowed.GetCompact());
        if (minimum_new > observed_new_target) return false;

        return true;
    }

    // Pre-ASERT: classic Bitcoin logic
    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;
        if (largest_difficulty_target > pow_limit) largest_difficulty_target = pow_limit;

        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;
        if (smallest_difficulty_target > pow_limit) smallest_difficulty_target = pow_limit;

        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

// MetalDAG consensus PoW: the header's memory-hard PoW hash must meet the target.
bool CheckProofOfWork(const CBlockHeader& header, unsigned int nBits, const Consensus::Params& params)
{
    // The genesis block is the hardcoded root of trust — exempt from PoW.
    if (header.GetHash() == params.hashGenesisBlock) return true;
    if (EnableFuzzDeterminism()) return (header.GetHash().data()[31] & 0x80) == 0;
    // No wall clock here (audit finding 6): this predicate also runs at startup over
    // stored headers the block index does not already vouch for (LoadBlockIndex) and
    // over every block read from disk, and a lagging clock must not make a node
    // reject its own chain. The clock-relative guards that keep an attacker-chosen
    // nTime from forcing a huge MetalDAG cache build live at the entry points
    // instead: net_processing rations cold epochs before hashing, and
    // AcceptBlockHeader / ProcessNewBlock / TestBlockValidity apply the
    // time-too-new rule before the proof-of-work check.
    return CheckProofOfWorkImpl(metaldag::PoWHash(header, params), nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
