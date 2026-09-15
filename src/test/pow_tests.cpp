// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <metaldag/metaldag.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    // Height chosen so height+1 is a NEX retarget boundary (50-block interval).
    pindexLast.nHeight = 32249;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    // NEX's 15000s target timespan clamps this huge historical timespan to 4x,
    // so the target quadruples (upstream expected 0x1d00d86a under 2016-block
    // retargets).
    unsigned int expected_nbits = 0x1d03fffcU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    // On mainnet PermittedDifficultyTransition is the ASERT headers-sync range
    // check: any easier target up to powLimit is permitted (the reference rule has
    // no per-block clamp), so this 4x easier step is permitted.
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, 0x1d01fffeU));
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, 0x1e0fffffU)); // powLimit itself
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, 0x1e100000U)); // past powLimit
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2049; // height+1 on a NEX 50-block retarget boundary
    pindexLast.nTime = 1233061996;  // Block #2015
    // Start at the NEX powLimit (0x1e0fffff) so the upper clamp binds: the 4x
    // slowdown would quadruple the target past the limit.
    pindexLast.nBits = 0x1e0fffff;
    unsigned int expected_nbits = 0x1e0fffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68549; // height+1 on a NEX 50-block retarget boundary
    // 3000s actual timespan: under NEX's 15000s target this is below the
    // timespan/4 floor, so the target divides by exactly 4 (same expected
    // value as upstream, where the historical timestamps hit the same floor).
    pindexLast.nTime = nLastRetargetTime + 3000;
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    // On mainnet PermittedDifficultyTransition is the ASERT headers-sync range
    // check: a harder next block is bounded at 4x per block (the most the timestamp
    // rules let the schedule error fall in one step, with margin), so this exactly
    // 4x-harder step is permitted and an 8x-harder one is not.
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    arith_uint256 eight_times_harder;
    eight_times_harder.SetCompact(pindexLast.nBits);
    eight_times_harder /= 8;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, eight_times_harder.GetCompact()));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46349; // height+1 on a NEX 50-block retarget boundary
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    // On mainnet PermittedDifficultyTransition is the ASERT headers-sync range
    // check: easier is permitted up to powLimit, so this 4x easier step passes.
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits+1));
}

BOOST_AUTO_TEST_CASE(asert_tracks_schedule_without_oscillation)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    consensus.nASERTHalfLife = 2 * 60 * 60;

    arith_uint256 base = UintToArith256(consensus.powLimit) / 16;
    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nTime = 1'800'000'000;
    genesis.nBits = base.GetCompact();

    CBlockIndex on_time;
    on_time.pprev = &genesis;
    on_time.nHeight = 1;
    on_time.nTime = genesis.nTime + consensus.nPowTargetSpacing;
    on_time.nBits = genesis.nBits;
    BOOST_CHECK_EQUAL(AsertGetNextWorkRequired(&on_time, consensus), genesis.nBits);

    // One half-life behind schedule makes the next target approximately 2x easier.
    CBlockIndex late;
    late.pprev = &genesis;
    late.nHeight = 1;
    late.nBits = genesis.nBits;
    late.nTime = on_time.nTime + consensus.nASERTHalfLife;
    arith_uint256 late_target;
    late_target.SetCompact(AsertGetNextWorkRequired(&late, consensus));
    BOOST_CHECK(late_target > base * 199 / 100);
    BOOST_CHECK(late_target < base * 201 / 100);

    // One half-life ahead makes it approximately 2x harder.
    CBlockIndex fast;
    fast.pprev = &genesis;
    fast.nHeight = 1;
    fast.nBits = genesis.nBits;
    fast.nTime = on_time.nTime - consensus.nASERTHalfLife;
    arith_uint256 fast_target;
    fast_target.SetCompact(AsertGetNextWorkRequired(&fast, consensus));
    BOOST_CHECK(fast_target > base * 49 / 100);
    BOOST_CHECK(fast_target < base * 51 / 100);
}

BOOST_AUTO_TEST_CASE(asert_long_gap_eases_in_proportion)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    arith_uint256 base = UintToArith256(consensus.powLimit) / 16;
    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nTime = 1'800'000'000;
    genesis.nBits = base.GetCompact();

    CBlockIndex delayed;
    delayed.pprev = &genesis;
    delayed.nHeight = 1;
    delayed.nTime = genesis.nTime + consensus.nPowTargetSpacing + 95 * 60;
    delayed.nBits = genesis.nBits;

    arith_uint256 next;
    next.SetCompact(AsertGetNextWorkRequired(&delayed, consensus));
    // 95 minutes late is 2^(95/120) = 1.73x easier: proportional to the lateness,
    // nothing like the retired EDA's cliff.
    BOOST_CHECK(next > base * 172 / 100);
    BOOST_CHECK(next < base * 174 / 100);

    // Six hours late is 2^3 = 8x easier: no per-block clamp (founder decision
    // 2026-09-14, the reference rule), the whole gap is answered by the next block.
    delayed.nTime = genesis.nTime + consensus.nPowTargetSpacing + 6 * 60 * 60;
    next.SetCompact(AsertGetNextWorkRequired(&delayed, consensus));
    BOOST_CHECK(next > base * 799 / 100);
    BOOST_CHECK(next < base * 801 / 100);

    // Twenty hours late asks for 1024x, and powLimit (16x base here) is the only ceiling.
    delayed.nTime = genesis.nTime + consensus.nPowTargetSpacing + 20 * 60 * 60;
    BOOST_CHECK_EQUAL(AsertGetNextWorkRequired(&delayed, consensus), UintToArith256(consensus.powLimit).GetCompact());
}

// The reference algorithm, pinned. Every vector was computed by an independent
// big-integer transcription of the aserti3-2d specification (Bitcoin Cash,
// 2020-11-15-asert.md) at xCoin's parameters: 300 s spacing, 7200 s half-life,
// mainnet powLimit, genesis time 1,800,000,000. In the reference's terms the
// anchor is block 1 and the anchor's parent is genesis, so time_delta is measured
// from the genesis timestamp and height_delta + 1 = nHeight of the last block.
// Heights are powers of two so that a single skip pointer reaches genesis.
BOOST_AUTO_TEST_CASE(asert_reference_vectors)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE_EQUAL(consensus.nPowTargetSpacing, 300);
    BOOST_REQUIRE_EQUAL(consensus.nASERTHalfLife, 7200);
    BOOST_REQUIRE_EQUAL(UintToArith256(consensus.powLimit).GetCompact(), 0x1e0fffffU);
    struct Vector { uint32_t anchor_bits; int height; int64_t time_delta; uint32_t expected_bits; };
    static const Vector vectors[] = {
{0x1e0fffffU, 1, 300, 0x1e0fffffU},
    {0x1e0fffffU, 1, 0, 0x1e0f8b9fU},
    {0x1e0fffffU, 1, 600, 0x1e0fffffU},
    {0x1e0fffffU, 1, 7500, 0x1e0fffffU},
    {0x1e0fffffU, 1, -6900, 0x1e07ffffU},
    {0x1e0fffffU, 1, 21900, 0x1e0fffffU},
    {0x1e0fffffU, 1, 72300, 0x1e0fffffU},
    {0x1e0fffffU, 64, 19200, 0x1e0fffffU},
    {0x1e0fffffU, 64, 12000, 0x1e07ffffU},
    {0x1e0fffffU, 64, -9600, 0x1e00ffffU},
    {0x1e0fffffU, 64, -25234, 0x1d38d63cU},
    {0x1e0fffffU, 1024, 235200, 0x1d03ffffU},
    {0x1e0fffffU, 1024, 240200, 0x1d067923U},
    {0x1e0fffffU, 1024, 255200, 0x1d1b6f1eU},
    {0x1e0fffffU, 524288, 157070400, 0x1a3ffffcU},
    {0x1e0fffffU, 524288, 157070399, 0x1a3ffe3cU},
    {0x1e0fffffU, 524288, 157193856, 0x1d008db5U},
    {0x1e0fffffU, 32, 32, 0x1e065e83U},
    {0x1e0fffffU, 64, 200064, 0x1e0fffffU},
    {0x1e0fffffU, 1, -1439700, 0x050fffffU},
    {0x1e0fffffU, 1, -1835800, 0x01010000U},
    {0x1e0fffffU, 2, -3000, 0x1e0b500fU},
    {0x1e0fffffU, 4096, 4096, 0x0903bcffU},
    {0x1d3fffffU, 1, 21900, 0x1e01ffffU},
    {0x1d3fffffU, 1, -21300, 0x1d07ffffU},
    {0x1d3fffffU, 1, 3900, 0x1d5a807eU},
    {0x1d3fffffU, 1, 72300, 0x1e0fffffU},
    {0x1d3fffffU, 1, 43500, 0x1e0fffffU},
    {0x1d3fffffU, 1, 36301, 0x1e08002fU},
    {0x1d3fffffU, 2, 9600, 0x1e009838U},
    {0x1d3fffffU, 1, 6000, 0x1d6ecc3eU},
    {0x1d3fffffU, 1, 72300, 0x1e0fffffU},
    {0x1d3fffffU, 1, 300, 0x1d3fffffU},
    {0x1d3fffffU, 1024, 336077, 0x1e0407a3U},
    };
    for (const Vector& v : vectors) {
        CBlockIndex genesis;
        genesis.nHeight = 0;
        genesis.nTime = 1'800'000'000;
        genesis.nBits = v.anchor_bits;
        CBlockIndex last;
        last.pprev = &genesis;
        last.pskip = &genesis; // GetAncestor(0) takes the skip when nHeight is a power of two
        last.nHeight = v.height;
        last.nTime = static_cast<uint32_t>(genesis.nTime + v.time_delta);
        last.nBits = v.anchor_bits; // the previous block's own nBits play no part in the reference rule
        BOOST_REQUIRE(last.GetAncestor(0) == &genesis);
        BOOST_CHECK_MESSAGE(AsertGetNextWorkRequired(&last, consensus) == v.expected_bits,
                            strprintf("height %d, time_delta %d: got 0x%08x, reference 0x%08x", v.height, v.time_delta, AsertGetNextWorkRequired(&last, consensus), v.expected_bits));
    }
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    // Both checks below guard the pre-ASERT retarget path. NEX chains with
    // ASERT active from genesis (nASERTActivationHeight <= 1) never run it:
    // ASERT anchors to the genesis nBits, clamps to powLimit, and divides
    // before multiplying, so an easy genesis target or a powLimit near 2^255
    // cannot overflow there.
    if (consensus.nASERTActivationHeight > 1) {
        BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);
    }

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting && consensus.nASERTActivationHeight > 1) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

// MetalDAG refuses to size a cache for a header dated beyond anything the node
// could accept (now + 2 * MAX_FUTURE_BLOCK_TIME, plus one epoch of slack), so an
// attacker-chosen nTime cannot force a multi-GiB cache build. The bound follows
// wall-clock, so it never binds on the real chain — the halt the old absolute 1 GiB
// cap scheduled for epoch 993 (~2064) no longer exists. This header is ten years out:
// its cache would be ~290 MiB, far under any absolute cap, and it is the relative
// rule that refuses it.
// Audit finding 2: the verification cache evicts least recently USED, so alternating
// two old epochs no longer rebuilds one per header, and cold epochs are rationed.
BOOST_AUTO_TEST_CASE(metaldag_cache_lru_and_cold_epoch_budget)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& params{chainParams->GetConsensus()};
    const uint64_t epoch_seconds = params.metaldagEpochSeconds ? static_cast<uint64_t>(params.metaldagEpochSeconds) : uint64_t{1209600};
    const auto at_epoch = [&](uint64_t epoch) {
        CBlockHeader h;
        h.nTime = static_cast<uint32_t>(params.metaldagBaseTime + epoch * epoch_seconds + 1);
        return h;
    };
    // Touch epochs 0..N-1: all resident.
    for (uint64_t e = 0; e < metaldag::METALDAG_CACHE_ENTRIES; ++e) metaldag::PoWHash(at_epoch(e), params);
    for (uint64_t e = 0; e < metaldag::METALDAG_CACHE_ENTRIES; ++e) BOOST_CHECK(metaldag::CacheResident(at_epoch(e).nTime, params));
    // Re-use epoch 0, then add one more: the least recently used (epoch 1) goes, not the lowest key.
    metaldag::PoWHash(at_epoch(0), params);
    metaldag::PoWHash(at_epoch(metaldag::METALDAG_CACHE_ENTRIES), params);
    BOOST_CHECK(metaldag::CacheResident(at_epoch(0).nTime, params));
    BOOST_CHECK(!metaldag::CacheResident(at_epoch(1).nTime, params));
    BOOST_CHECK(metaldag::CacheResident(at_epoch(metaldag::METALDAG_CACHE_ENTRIES).nTime, params));

    // The network gate: with the best header in epoch 20 and the clock in epoch 20, epochs
    // 19..21 are hot and always verified; a resident epoch is always verified; any other epoch
    // takes the budget once per interval.
    metaldag::CacheBuildBudget budget{std::chrono::seconds{30}};
    const uint32_t best_time{at_epoch(20).nTime};
    const int64_t now{static_cast<int64_t>(at_epoch(20).nTime) + 100};
    for (uint64_t e : {19U, 20U, 21U}) BOOST_CHECK(metaldag::MayVerifyFromNetwork(at_epoch(e), params, best_time, now, budget));
    BOOST_CHECK(metaldag::MayVerifyFromNetwork(at_epoch(0), params, best_time, now, budget));   // resident from above
    BOOST_CHECK(!metaldag::CacheResident(at_epoch(10).nTime, params));
    BOOST_CHECK(metaldag::MayVerifyFromNetwork(at_epoch(10), params, best_time, now, budget));  // cold: takes the budget
    BOOST_CHECK(!metaldag::MayVerifyFromNetwork(at_epoch(11), params, best_time, now, budget)); // cold: budget spent
    BOOST_CHECK(!metaldag::MayVerifyFromNetwork(at_epoch(11), params, best_time, now + 29, budget));
    BOOST_CHECK(metaldag::MayVerifyFromNetwork(at_epoch(11), params, best_time, now + 30, budget)); // interval elapsed
    BOOST_CHECK(metaldag::MayVerifyFromNetwork(at_epoch(21), params, best_time, now + 31, budget)); // hot never needs it
}

BOOST_AUTO_TEST_CASE(metaldag_far_future_is_refused_before_hashing)
{
    // Audit finding 6: PoWHash itself consults no clock any more (stored headers must
    // verify whatever the clock says); a header naming an epoch beyond anything this node
    // could accept is refused by the network gate without consuming the cold-build budget.
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params{chainParams->GetConsensus()};
    CBlockHeader far;
    far.nTime = static_cast<uint32_t>(GetTime() + int64_t{10} * 365 * 24 * 3600);
    far.nBits = 0x1e0fffff;
    metaldag::CacheBuildBudget budget{std::chrono::seconds{30}};
    const int64_t now{GetTime()};
    BOOST_CHECK(!metaldag::MayVerifyFromNetwork(far, params, static_cast<uint32_t>(now), now, budget));
    // The budget is intact: a genuinely cold (past) epoch still gets its one build.
    CBlockHeader past;
    past.nTime = static_cast<uint32_t>(params.metaldagBaseTime);
    BOOST_CHECK(metaldag::CacheResident(past.nTime, params) || metaldag::MayVerifyFromNetwork(past, params, static_cast<uint32_t>(now), now, budget));
}

// Audit finding C4: hashimoto_light used to reduce the dataset index modulo
// (uint32_t)(n / 2), which wraps once the full DAG holds 2^32 item pairs. On the
// 4 GiB + 128 MiB/epoch schedule that is epoch 4065 (item count 4,296,015,853,
// truncated to 1,048,557), ~156 years after the base time and out of reach of a
// 32-bit nTime (epoch 2072 at most on mainnet), long before the 64 GiB cache cap
// (epoch 65,504). The index is 64-bit now; this pins both the schedule facts and
// the arithmetic: two DAG sizes whose item counts agree modulo 2^32 (61 and
// 61 + 2^32 items, both prime so largest_prime_sized keeps them) share one
// 192-byte epoch-0 cache and used to hash identically; they must not.
BOOST_AUTO_TEST_CASE(metaldag_dataset_index_is_not_truncated_to_32_bits)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& main{chainParams->GetConsensus()};
    const uint64_t epoch_seconds{static_cast<uint64_t>(main.metaldagEpochSeconds)};
    const auto sizing_at_epoch = [&](uint64_t epoch) {
        Consensus::Params p{main};
        p.metaldagBaseTime = 0;
        // Bypass the 32-bit nTime by moving the schedule's base instead of the header time.
        p.metaldagDagInitBytes = main.metaldagDagInitBytes + main.metaldagDagGrowthBytes * static_cast<int64_t>(epoch);
        return metaldag::GetEpochSizing(0, p);
    };
    const auto item_pairs = [](const metaldag::EpochSizing& e) { return e.full_size / metaldag::HASH_BYTES / 2; };
    // The schedule does pass 2^32 item pairs, at epoch 4065, with the cache still far under its cap...
    BOOST_CHECK_LT(item_pairs(sizing_at_epoch(4064)), uint64_t{1} << 32);
    BOOST_CHECK_EQUAL(item_pairs(sizing_at_epoch(4064)), 4294967291ULL);
    BOOST_CHECK_GT(item_pairs(sizing_at_epoch(4065)), uint64_t{1} << 32);
    BOOST_CHECK_EQUAL(item_pairs(sizing_at_epoch(4065)), 4296015853ULL);
    BOOST_CHECK_LT(sizing_at_epoch(4065).cache_size, metaldag::METALDAG_MAX_CACHE_BYTES);
    // ...but no header can name that epoch: nTime is 32-bit, so every reachable epoch
    // stays below the old wrap (no PoW hash of any expressible header changed).
    const uint64_t last_reachable_epoch{(uint64_t{std::numeric_limits<uint32_t>::max()} - static_cast<uint64_t>(main.metaldagBaseTime)) / epoch_seconds};
    BOOST_CHECK_LT(last_reachable_epoch, 4065U);
    BOOST_CHECK_LT(item_pairs(metaldag::GetEpochSizing(std::numeric_limits<uint32_t>::max(), main)), uint64_t{1} << 32);

    // The arithmetic itself, past 2^32 item pairs. Divisor chosen so both DAGs derive a
    // 192-byte (3-item) cache: 61 * 128 / 32 = 244 -> 3 items; (61 + 2^32) * 128 / (2^31 - 1)
    // = 256 -> 4 items, not prime -> 3 items. Same epoch (0) and seed, so the cache is identical.
    Consensus::Params small{main};
    small.metaldagBaseTime = 0;
    small.metaldagDagGrowthBytes = 0;
    small.metaldagDagInitBytes = int64_t{61} * metaldag::MIX_BYTES;
    small.metaldagCacheDivisor = 32;
    Consensus::Params large{small};
    large.metaldagDagInitBytes = (int64_t{61} + (int64_t{1} << 32)) * metaldag::MIX_BYTES;
    large.metaldagCacheDivisor = std::numeric_limits<int32_t>::max();
    const metaldag::EpochSizing es{metaldag::GetEpochSizing(0, small)};
    const metaldag::EpochSizing el{metaldag::GetEpochSizing(0, large)};
    BOOST_REQUIRE_EQUAL(item_pairs(es), 61U);
    BOOST_REQUIRE_EQUAL(item_pairs(el), 61ULL + (uint64_t{1} << 32));
    BOOST_REQUIRE_EQUAL(es.cache_size, 192U);
    BOOST_REQUIRE_EQUAL(el.cache_size, 192U);
    BOOST_REQUIRE_EQUAL(es.epoch, el.epoch);
    CBlockHeader h;
    h.nVersion = 1;
    h.nTime = 0;
    h.nBits = 0x1e0fffff;
    h.nNonce = 42;
    const uint256 hash_small{metaldag::PoWHash(h, small)};
    const uint256 hash_large{metaldag::PoWHash(h, large)};
    BOOST_CHECK(hash_small != hash_large); // equal under the old (uint32_t) modulus
    BOOST_CHECK_EQUAL(metaldag::PoWHash(h, large), hash_large); // deterministic
}

BOOST_AUTO_TEST_SUITE_END()
