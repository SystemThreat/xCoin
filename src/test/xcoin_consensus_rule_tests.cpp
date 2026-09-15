// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus rules of the fork that had no test at all (audit finding T2): one
// test per rule, each building an invalid block or header and asserting the
// exact rejection reason the node reports.
//
//   bad-pow-algo            nVersion bits 28..29 before multi-algorithm activation
//   bad-checkpoint-release  a release checkpoint naming another block at that height
//   bad-cb-amount           a coinbase paying subsidy + fees + 1 (era boundary too)
//   bad-blk-sigops          the block sigop budget, PQ inputs charged PQ_SIGOPS_COST
//   bad-blk-weight          a 64,000,004 WU block (and bad-blk-length at 16,000,001 B)
//   bad-diffbits / ASERT    live ASERT through ContextualCheckBlockHeader, both clamps
//   MetalDAG                sizing at epoch >= 1 and PoW vectors from metaldag-ref.cpp
//
// Rules that a stock regtest node can never reach (release checkpoints, the
// multi-algorithm bits, ASERT: regtest has fPowNoRetargeting and an activation
// height of INT_MAX) run on a fixture whose ChainstateManager is built on a
// private, editable copy of the regtest parameters. No chain parameter is
// changed for anyone else.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <kernel/chainparams.h>
#include <metaldag/metaldag.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <scheduler.h>
#include <script/script.h>
#include <test/util/common.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

using node::BlockAssembler;
using node::BlockManager;
using node::KernelNotifications;
using node::RegenerateCommitments;

namespace {

/** A copy of a chain's parameters whose consensus block a test may edit. */
class EditableChainParams : public CChainParams
{
public:
    explicit EditableChainParams(const CChainParams& base) : CChainParams(base) {}
    Consensus::Params& MutableConsensus() { return consensus; }
};

/** A regtest node whose ChainstateManager runs on a private copy of the regtest
 *  parameters (EditableChainParams). ChainTestingSetup builds the manager on the
 *  process-global parameters, which are const; this rebuilds it the same way on
 *  the copy, so a test can add a release checkpoint, activate the multi-algorithm
 *  bits or switch ASERT on without touching any chain's real parameters. */
struct EditableRegTestSetup : public ChainTestingSetup {
    std::unique_ptr<EditableChainParams> m_params;

    EditableRegTestSetup() : ChainTestingSetup{ChainType::REGTEST}
    {
        m_params = std::make_unique<EditableChainParams>(Params());
        m_node.chainman.reset();
        RebuildChainman();
    }

    ~EditableRegTestSetup()
    {
        // The manager holds a reference to m_params: take it down first, in the
        // order ChainTestingSetup itself uses (it repeats these harmlessly).
        if (m_node.scheduler) m_node.scheduler->stop();
        if (m_node.validation_signals) m_node.validation_signals->FlushBackgroundCallbacks();
        m_node.chainman.reset();
    }

    Consensus::Params& MutableConsensus() { return m_params->MutableConsensus(); }

    /** Build the manager on m_params (mirrors ChainTestingSetup::m_make_chainman) and
     *  load the chainstate: the genesis block only. */
    void RebuildChainman()
    {
        Assert(!m_node.chainman);
        ChainstateManager::Options chainman_opts{
            .chainparams = *m_params,
            .datadir = m_args.GetDataDirNet(),
            .check_block_index = 1,
            .notifications = *m_node.notifications,
            .signals = m_node.validation_signals.get(),
            .worker_threads_num = 2,
        };
        const BlockManager::Options blockman_opts{
            .chainparams = chainman_opts.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = chainman_opts.notifications,
            .block_tree_db_params = DBParams{
                .path = m_args.GetDataDirNet() / "blocks" / "index",
                .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                .memory_only = true,
            },
        };
        m_node.chainman = std::make_unique<ChainstateManager>(*Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        LoadVerifyActivateChainstate();
    }

    int Height() { return WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight()); }
    uint256 TipHash() { return WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()); }

    /** A block template on the active tip, coinbase to the test key, dummy extranonce. */
    CBlock Template()
    {
        BlockAssembler::Options options;
        options.coinbase_output_script = GetTestPQScript();
        options.include_dummy_extranonce = true;
        return BlockAssembler{m_node.chainman->ActiveChainstate(), nullptr, options}.CreateNewBlock()->block;
    }

    /** Grind the MetalDAG proof of work for the block's own nBits. */
    void Mine(CBlock& block)
    {
        RegenerateCommitments(block, *m_node.chainman);
        while (!CheckProofOfWork(block, block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
    }

    /** What AcceptBlockHeader says about a header: "accepted" or the reject reason. */
    std::string Header(const CBlockHeader& header)
    {
        BlockValidationState state;
        const bool ok{m_node.chainman->ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state)};
        BOOST_CHECK_EQUAL(ok, state.IsValid());
        return ok ? std::string{"accepted"} : state.GetRejectReason();
    }

    /** Process a full block; true when it became the tip. */
    bool Process(const CBlock& block)
    {
        bool new_block{false};
        const bool ok{m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block)};
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        return ok && TipHash() == block.GetHash();
    }
};

/** TestBlockValidity's verdict on a block: "valid" or the reject reason. */
std::string Validity(Chainstate& chainstate, const CBlock& block)
{
    LOCK(cs_main);
    const BlockValidationState state{TestBlockValidity(chainstate, block, /*check_pow=*/false, /*check_merkle_root=*/true)};
    return state.IsValid() ? std::string{"valid"} : state.GetRejectReason();
}

/** Re-commit and re-mine a block edited by a test (TestChain100Setup fixtures). */
void Remine(CBlock& block, ChainstateManager& chainman)
{
    RegenerateCommitments(block, chainman);
    while (!CheckProofOfWork(block, block.nBits, chainman.GetConsensus())) ++block.nNonce;
}

/** The reject reason ProcessNewBlock leaves on a full block, and whether the tip moved. */
struct Processed {
    bool accepted;
    int height;
};
Processed ProcessBlock(TestChain100Setup& setup, const CBlock& block)
{
    bool new_block{false};
    const bool ok{setup.m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block)};
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    LOCK(cs_main);
    return {ok && setup.m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash(), setup.m_node.chainman->ActiveHeight()};
}

} // namespace

// ───────────────────────────── bad-pow-algo ─────────────────────────────

BOOST_FIXTURE_TEST_SUITE(xcoin_consensus_rule_tests, EditableRegTestSetup)

// Header nVersion bits 28..29 carry the proof-of-work algorithm id (REGENESIS.md
// section 7). Until multi_algo_activation_height (0 = inactive on every chain)
// the id must be 0 (MetalDAG): a header carrying 1, 2 or 3 is refused with
// bad-pow-algo; from the activation height the same header is accepted.
BOOST_AUTO_TEST_CASE(bad_pow_algo_before_activation)
{
    BOOST_CHECK_EQUAL(Params().GetConsensus().multi_algo_activation_height, 0);
    BOOST_CHECK(!Params().GetConsensus().MultiAlgoActiveAt(std::numeric_limits<int>::max()));
    BOOST_CHECK_EQUAL(Consensus::GetPowAlgoId(0x40000000), Consensus::POW_ALGO_METALDAG); // VERSIONBITS_TOP_BITS alone
    BOOST_CHECK_EQUAL(Consensus::GetPowAlgoId(0x50000000), Consensus::POW_ALGO_AUXPOW_SHA256D);
    BOOST_CHECK_EQUAL(Consensus::GetPowAlgoId(0x60000000), Consensus::POW_ALGO_RESERVED_2);
    BOOST_CHECK_EQUAL(Consensus::GetPowAlgoId(0x70000000), Consensus::POW_ALGO_RESERVED_3);
    BOOST_CHECK_EQUAL(Consensus::GetPowAlgoId(0x4fffffff), Consensus::POW_ALGO_METALDAG); // every deployment bit set, id still 0

    const CBlock tmpl{Template()};
    BOOST_REQUIRE_EQUAL(Consensus::GetPowAlgoId(tmpl.nVersion), Consensus::POW_ALGO_METALDAG);

    std::vector<CBlock> tagged;
    for (const uint32_t algo : {Consensus::POW_ALGO_AUXPOW_SHA256D, Consensus::POW_ALGO_RESERVED_2, Consensus::POW_ALGO_RESERVED_3}) {
        CBlock block{tmpl};
        block.nVersion = (block.nVersion & ~Consensus::POW_ALGO_ID_MASK) | static_cast<int32_t>(algo << Consensus::POW_ALGO_ID_SHIFT);
        BOOST_REQUIRE_EQUAL(Consensus::GetPowAlgoId(block.nVersion), algo);
        Mine(block); // the proof of work itself is fine: only the id is wrong
        BOOST_CHECK_EQUAL(Header(block), "bad-pow-algo");
        BOOST_CHECK(!Process(block));
        BOOST_CHECK_EQUAL(Height(), 0);
        tagged.push_back(block);
    }

    // Activation at height 2: a height-1 header is still before it.
    MutableConsensus().multi_algo_activation_height = 2;
    BOOST_CHECK(!MutableConsensus().MultiAlgoActiveAt(1));
    BOOST_CHECK(MutableConsensus().MultiAlgoActiveAt(2));
    BOOST_CHECK_EQUAL(Header(tagged[0]), "bad-pow-algo");

    // Activation at height 1: the id bits are live and the same header is accepted.
    MutableConsensus().multi_algo_activation_height = 1;
    BOOST_CHECK_EQUAL(Header(tagged[0]), "accepted");
    LOCK(cs_main);
    const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(tagged[0].GetHash())};
    BOOST_REQUIRE(index != nullptr);
    BOOST_CHECK_EQUAL(index->nHeight, 1);
    BOOST_CHECK(index->IsValid(BLOCK_VALID_TREE));
}

// ───────────────────────── bad-checkpoint-release ─────────────────────────

// A release checkpoint (REGENESIS.md section 6) pins the block hash this build
// expects at a height. A header at that height with another hash is refused with
// bad-checkpoint-release; heights without a checkpoint are unconstrained, and the
// pinned block itself is accepted. Regtest ships no checkpoints, so this runs on
// the editable copy.
BOOST_AUTO_TEST_CASE(bad_checkpoint_release)
{
    BOOST_CHECK(Params().GetConsensus().release_checkpoints.empty());
    {
        Consensus::Params copy{Params().GetConsensus()};
        copy.release_checkpoints = {{10, uint256::ONE}};
        BOOST_CHECK(copy.ReleaseCheckpointAllows(10, uint256::ONE));
        BOOST_CHECK(!copy.ReleaseCheckpointAllows(10, uint256::ZERO));
        BOOST_CHECK(copy.ReleaseCheckpointAllows(9, uint256::ZERO));
        BOOST_CHECK(copy.ReleaseCheckpointAllows(11, uint256::ZERO));
        BOOST_CHECK(Params().GetConsensus().ReleaseCheckpointAllows(10, uint256::ZERO)); // empty map: never refuses
    }

    CBlock block1{Template()};
    Mine(block1);
    BOOST_REQUIRE(Process(block1));
    BOOST_REQUIRE_EQUAL(Height(), 1);

    CBlock block2{Template()};
    Mine(block2);
    BOOST_REQUIRE(block2.GetHash() != uint256::ONE);

    // This build "saw" another block at height 2: the header is refused, the block
    // does not extend the chain and is not even added to the index.
    MutableConsensus().release_checkpoints = {{2, uint256::ONE}};
    BOOST_CHECK_EQUAL(Header(block2), "bad-checkpoint-release");
    BOOST_CHECK(!Process(block2));
    BOOST_CHECK_EQUAL(Height(), 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block2.GetHash())) == nullptr);

    // A checkpoint at another height says nothing about height 2 ...
    MutableConsensus().release_checkpoints = {{3, uint256::ONE}};
    BOOST_CHECK_EQUAL(Header(block2), "accepted");
    // ... and the pinned block itself passes.
    MutableConsensus().release_checkpoints = {{2, block2.GetHash()}};
    BOOST_CHECK(Process(block2));
    BOOST_CHECK_EQUAL(Height(), 2);
    BOOST_CHECK_EQUAL(TipHash(), block2.GetHash());

    // Height 3 pinned to a hash no block will have (the template is built first:
    // the assembler's own TestBlockValidity would refuse it too).
    CBlock block3{Template()};
    Mine(block3);
    MutableConsensus().release_checkpoints = {{2, block2.GetHash()}, {3, uint256::ONE}};
    BOOST_CHECK_EQUAL(Header(block3), "bad-checkpoint-release");
    BOOST_CHECK(!Process(block3));
    BOOST_CHECK_EQUAL(Height(), 2);
}

// ─────────────────────── bad-diffbits and live ASERT ───────────────────────

// Anchored ASERT (pow.cpp) through ContextualCheckBlockHeader. Regtest never runs
// it (fPowNoRetargeting, activation at INT_MAX), so the editable copy switches it
// on from block 1 with the regtest 2 h half-life. The anchor is the genesis
// target, which on regtest is powLimit, so the controller can only ever ask for
// harder blocks; there is no per-block clamp (the reference rule), so a block
// dated far behind schedule takes the next target straight back to powLimit and
// a block dated far ahead of it (as far as the median-time-past rule allows)
// takes it straight to the exact ASERT value. Every header is validated by the
// node, the accepted blocks extend the chain, and a header with any other nBits
// is bad-diffbits.
BOOST_AUTO_TEST_CASE(asert_live_through_header_validation)
{
    Consensus::Params& consensus{MutableConsensus()};
    consensus.fPowNoRetargeting = false;
    consensus.nASERTActivationHeight = 1;
    BOOST_REQUIRE_EQUAL(consensus.nASERTHalfLife, 2 * 60 * 60);
    BOOST_REQUIRE_EQUAL(consensus.nPowTargetSpacing, 300);
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const uint32_t limit_bits{pow_limit.GetCompact()};
    const int64_t genesis_time{m_node.chainman->GetParams().GenesisBlock().GetBlockTime()};
    BOOST_REQUIRE_EQUAL(m_node.chainman->GetParams().GenesisBlock().nBits, limit_bits); // the anchor

    const auto target_of = [](uint32_t bits) { arith_uint256 t; t.SetCompact(bits); return t; };
    const auto expected_bits = [&](const CBlockHeader& header) {
        LOCK(cs_main);
        return GetNextWorkRequired(m_node.chainman->ActiveTip(), &header, consensus);
    };
    /** Mine the next block dated `time` with the node's expected nBits and connect it. */
    const auto extend = [&](int64_t time) {
        CBlock block{Template()};
        block.nTime = static_cast<uint32_t>(time);
        block.nBits = expected_bits(block);
        Mine(block);
        BOOST_REQUIRE_EQUAL(Header(block), "accepted");
        BOOST_REQUIRE(Process(block));
        return block;
    };

    // Block 1: any nBits but the expected one is refused, whatever its proof of work.
    {
        CBlock block{Template()};
        block.nTime = static_cast<uint32_t>(genesis_time + 300);
        BOOST_CHECK_EQUAL(expected_bits(block), limit_bits);
        block.nBits = limit_bits - 1; // a harder target than asked for, still meets its own PoW
        Mine(block);
        BOOST_CHECK_EQUAL(Header(block), "bad-diffbits");
        BOOST_CHECK(!Process(block));
        BOOST_CHECK_EQUAL(Height(), 0);
    }

    // Blocks 1..50 one second apart: the chain runs ahead of its 300 s schedule and
    // ASERT tightens the target a little every block, from powLimit downwards.
    uint32_t prev_bits{limit_bits};
    for (int h = 1; h <= 50; ++h) {
        const CBlock block{extend(genesis_time + h)};
        if (h == 1) {
            BOOST_CHECK_EQUAL(block.nBits, limit_bits); // block 1 is judged on the genesis, which is on schedule
        } else {
            BOOST_CHECK(target_of(block.nBits) < target_of(prev_bits));
        }
        prev_bits = block.nBits;
    }
    BOOST_CHECK_EQUAL(Height(), 50);
    // 49 blocks of -299 s each: about -14,650 s, or 2^(-2.03) of the anchor.
    BOOST_CHECK(target_of(prev_bits) < pow_limit / 4);
    BOOST_CHECK(target_of(prev_bits) > pow_limit / 5);

    // Block 51 dated 20,000 s late: the chain is now behind schedule (+4,750 s), so
    // the target for block 52 is the exact ASERT value, which on a powLimit anchor
    // is powLimit itself: the whole gap is answered by the next block, no clamp.
    const CBlock late{extend(genesis_time + 50 + 20000)};
    BOOST_CHECK(target_of(late.nBits) < target_of(prev_bits)); // its own nBits still follows block 50's early time
    BOOST_CHECK(target_of(late.nBits) > target_of(prev_bits) / 2);
    {
        CBlock probe{Template()};
        const uint32_t bits52{expected_bits(probe)};
        BOOST_CHECK_EQUAL(bits52, limit_bits);
        BOOST_CHECK_EQUAL(bits52, AsertGetNextWorkRequired(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()), consensus));
    }
    // Block 52, dated at the median time past plus one (about 20,000 s BEFORE
    // block 51: the chain is far ahead of schedule again), is mined at powLimit;
    // block 53's target is then the exact ASERT value for that early time, about
    // a quarter of powLimit, in one step (an 8x swing, which the clamp forbade).
    const int64_t mtp{WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetMedianTimePast())};
    BOOST_REQUIRE(mtp < genesis_time + 50 + 20000);
    const CBlock block52{extend(mtp + 1)};
    BOOST_CHECK_EQUAL(block52.nBits, limit_bits);
    const CBlock block53{extend(mtp + 2)};
    BOOST_CHECK(target_of(block53.nBits) < pow_limit / 4);
    BOOST_CHECK(target_of(block53.nBits) > pow_limit / 5);
    BOOST_CHECK_EQUAL(block53.nBits, AsertGetNextWorkRequired(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->pprev), consensus));
    // Block 54: exact ASERT again, a little harder still (one more early block).
    const CBlock block54{extend(mtp + 3)};
    BOOST_CHECK(target_of(block54.nBits) < target_of(block53.nBits));
    BOOST_CHECK(target_of(block54.nBits) > target_of(block53.nBits) * 9 / 10);
    BOOST_CHECK_EQUAL(block54.nBits, AsertGetNextWorkRequired(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->pprev), consensus));

    // A long outage: block 55 is dated 200,000 s late (its own nBits still follows
    // block 54's early time); the very next target is powLimit and stays there while
    // the chain remains behind schedule.
    int64_t t{mtp + 3 + 200000};
    uint32_t bits{extend(t).nBits};
    BOOST_CHECK(target_of(bits) < pow_limit / 4);
    for (int i = 0; i < 6; ++i) {
        t += 300;
        const CBlock block{extend(t)};
        BOOST_CHECK_EQUAL(block.nBits, limit_bits);
        bits = block.nBits;
    }
    BOOST_CHECK_EQUAL(bits, limit_bits);
    BOOST_CHECK_EQUAL(Height(), 61);
}

// The reference rule on the function itself, beyond one half-life (pow_tests
// covers one and pins the vectors): three half-lives late is 8x, three early is an
// eighth, and the previous block's own nBits play no part, because ASERT is
// absolute in the schedule error since the anchor. Mainnet parameters, no chain.
BOOST_AUTO_TEST_CASE(asert_unclamped_beyond_one_half_life)
{
    const Consensus::Params consensus{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    BOOST_REQUIRE_EQUAL(consensus.nASERTActivationHeight, 1);
    const int64_t half_life{consensus.nASERTHalfLife};
    const arith_uint256 anchor_target{UintToArith256(consensus.powLimit) / 64};
    CBlockIndex anchor;
    anchor.nHeight = 0;
    anchor.nTime = 1'800'000'000;
    anchor.nBits = anchor_target.GetCompact();

    const auto target_of = [](uint32_t bits) { arith_uint256 t; t.SetCompact(bits); return t; };
    const auto compact = [](const arith_uint256& t) { return t.GetCompact(); };
    const auto next_after = [&](int64_t time, uint32_t prev_bits) {
        CBlockIndex last;
        last.pprev = &anchor;
        last.nHeight = 1;
        last.nTime = static_cast<uint32_t>(time);
        last.nBits = prev_bits;
        return AsertGetNextWorkRequired(&last, consensus);
    };
    const int64_t on_time{anchor.nTime + consensus.nPowTargetSpacing};
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};

    // Three half-lives late: 8x easier, within rounding of the compact encoding.
    const arith_uint256 late3{target_of(next_after(on_time + 3 * half_life, anchor.nBits))};
    BOOST_CHECK(late3 > anchor_target * 799 / 100);
    BOOST_CHECK(late3 < anchor_target * 801 / 100);
    // Three half-lives early: an eighth.
    const arith_uint256 early3{target_of(next_after(on_time - 3 * half_life, anchor.nBits))};
    BOOST_CHECK(early3 > anchor_target * 100 / 801);
    BOOST_CHECK(early3 < anchor_target * 100 / 799);
    // The previous block's nBits are irrelevant: the same lateness from a block
    // whose own target was 4x or a quarter of the anchor's gives the same answer.
    BOOST_CHECK_EQUAL(next_after(on_time + 3 * half_life, compact(anchor_target * 4)), next_after(on_time + 3 * half_life, anchor.nBits));
    BOOST_CHECK_EQUAL(next_after(on_time - 3 * half_life, compact(anchor_target / 4)), next_after(on_time - 3 * half_life, anchor.nBits));
    // Half a half-life late is about 2^0.5 easier.
    const arith_uint256 half{target_of(next_after(on_time + half_life / 2, anchor.nBits))};
    BOOST_CHECK(half > anchor_target * 140 / 100);
    BOOST_CHECK(half < anchor_target * 143 / 100);
    // powLimit is the only ceiling: six half-lives late asks for 64x the anchor's
    // target, exactly powLimit here; ten half-lives late is capped there.
    const uint32_t limit_bits{compact(pow_limit)};
    BOOST_CHECK_EQUAL(next_after(on_time + 6 * half_life, anchor.nBits), limit_bits);
    BOOST_CHECK_EQUAL(next_after(on_time + 10 * half_life, anchor.nBits), limit_bits);
    BOOST_CHECK_EQUAL(next_after(on_time + 10 * half_life, compact(pow_limit / 2)), limit_bits);
}

BOOST_AUTO_TEST_SUITE_END()

// ───────────────────────────── bad-cb-amount ─────────────────────────────

BOOST_FIXTURE_TEST_SUITE(xcoin_consensus_rule_chain_tests, TestChain100Setup)

namespace {
/** Spend the fixture's coinbase `n` back to the test key, paying `fee`. */
CMutableTransaction SpendCoinbase(const TestChain100Setup& setup, size_t n, CAmount fee)
{
    const CTransactionRef& coinbase{setup.m_coinbase_txns.at(n)};
    BOOST_REQUIRE(IsTestPQScript(coinbase->vout[0].scriptPubKey));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{coinbase->GetHash(), 0});
    tx.vout.emplace_back(coinbase->vout[0].nValue - fee, GetTestPQScript());
    SignTestPQInput(tx, 0, coinbase->vout[0]);
    return tx;
}

/** Set the coinbase's first output to `value` and re-mine. */
void PayCoinbase(CBlock& block, CAmount value, ChainstateManager& chainman)
{
    CMutableTransaction cb{*block.vtx[0]};
    cb.vout[0].nValue = value;
    block.vtx[0] = MakeTransactionRef(std::move(cb));
    Remine(block, chainman);
}
} // namespace

// ConnectBlock: the coinbase may pay at most subsidy + fees (bad-cb-amount). One
// satoshi over is refused at height 101, at the first era boundary (regtest 151,
// where the subsidy halves to 25 XCF and the old 50 XCF rate is over-payment),
// and the exact amount is accepted. After EMISSION_END_HEIGHT the limit is the
// fees alone: that height (3,358,350 on regtest) cannot be mined here, so the
// subsidy side of it is checked on GetBlockSubsidy directly.
BOOST_AUTO_TEST_CASE(bad_cb_amount)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    const Consensus::Params& consensus{m_node.chainman->GetConsensus()};
    const CAmount fee{12345};
    {
        const CAmount subsidy{GetBlockSubsidy(101, consensus)};
        BOOST_REQUIRE_EQUAL(subsidy, 50 * COIN);
        // CreateBlock adds the spend after the template, so its coinbase pays the
        // subsidy alone; set the limit, subsidy + fees, explicitly.
        CBlock base{CreateBlock({SpendCoinbase(*this, 0, fee)}, GetTestPQScript(), chainstate)};
        BOOST_REQUIRE_EQUAL(base.vtx[0]->GetValueOut(), subsidy);
        PayCoinbase(base, subsidy + fee, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, base), "valid");

        CBlock over{base};
        PayCoinbase(over, subsidy + fee + 1, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, over), "bad-cb-amount");
        const Processed p{ProcessBlock(*this, over)};
        BOOST_CHECK(!p.accepted);
        BOOST_CHECK_EQUAL(p.height, 100);
        {
            LOCK(cs_main);
            const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(over.GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
        }
        // Under-payment is the miner's loss, never invalid.
        CBlock under{base};
        PayCoinbase(under, subsidy + fee - 1, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, under), "valid");
        BOOST_CHECK(ProcessBlock(*this, base).accepted);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight()), 101);
    }

    // The first regtest era boundary: block 151 pays 25 XCF.
    mineBlocks(49);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight()), 150);
    BOOST_REQUIRE_EQUAL(GetBlockSubsidy(150, consensus), 50 * COIN);
    BOOST_REQUIRE_EQUAL(GetBlockSubsidy(151, consensus), 25 * COIN);
    {
        CBlock base{CreateBlock({SpendCoinbase(*this, 1, fee)}, GetTestPQScript(), chainstate)};
        PayCoinbase(base, 25 * COIN + fee, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, base), "valid");
        CBlock old_rate{base};
        PayCoinbase(old_rate, 50 * COIN + fee, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, old_rate), "bad-cb-amount");
        CBlock over{base};
        PayCoinbase(over, 25 * COIN + fee + 1, *m_node.chainman);
        BOOST_CHECK_EQUAL(Validity(chainstate, over), "bad-cb-amount");
        BOOST_CHECK(!ProcessBlock(*this, over).accepted);
        BOOST_CHECK(ProcessBlock(*this, base).accepted);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight()), 151);
    }

    // Past the end of emission the coinbase limit is the fees: no subsidy at all.
    BOOST_CHECK_EQUAL(consensus.EmissionEndHeight(), 3358350);
    BOOST_CHECK_GT(GetBlockSubsidy(consensus.EmissionEndHeight(), consensus), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensus.EmissionEndHeight() + 1, consensus), 0);
}

// ───────────────────────────── bad-blk-sigops ─────────────────────────────

namespace {
/** `n` OP_CHECKMULTISIG opcodes: 20 legacy sigops each (MAX_PUBKEYS_PER_MULTISIG,
 *  the inaccurate count CheckBlock uses). */
CScript CheckMultisigs(size_t n)
{
    CScript script;
    for (size_t i = 0; i < n; ++i) script << OP_CHECKMULTISIG;
    return script;
}
} // namespace

// The block sigop budget, MAX_BLOCK_SIGOPS_COST = 1,280,000. Legacy sigops in a
// scriptSig cost 4 each and are counted context-free by CheckBlock, so 320,001 of
// them (16,001 OP_CHECKMULTISIG bytes) are bad-blk-sigops before any script runs;
// 320,000 fill the budget exactly and pass CheckBlock. ConnectBlock then adds
// PQ_SIGOPS_COST for every post-quantum input (v2 and v3 alike): the same block
// with its one ML-DSA input is over by exactly that and refused, one opcode fewer
// and the budget holds. A block over the budget through PQ inputs alone cannot be
// built: 640,000 inputs of at least 5.3 kB of witness each are far over the
// 64,000,000 WU weight limit, which is checked first. The construction is the one
// upstream's feature_block.py uses; the spend's witness signature stays valid
// because the v2 sighash does not commit to the scriptSig.
BOOST_AUTO_TEST_CASE(bad_blk_sigops)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    const Consensus::Params& consensus{m_node.chainman->GetConsensus()};
    BOOST_REQUIRE_EQUAL(MAX_BLOCK_SIGOPS_COST, 1280000);
    BOOST_REQUIRE_EQUAL(PQ_SIGOPS_COST, 2);
    constexpr size_t budget_opcodes{MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR / MAX_PUBKEYS_PER_MULTISIG}; // 16,000

    const auto block_with = [&](size_t opcodes) {
        CMutableTransaction tx{SpendCoinbase(*this, 0, COIN)};
        tx.vin[0].scriptSig = CheckMultisigs(opcodes);
        BOOST_REQUIRE_EQUAL(GetLegacySigOpCount(CTransaction{tx}), opcodes * MAX_PUBKEYS_PER_MULTISIG);
        return CreateBlock({tx}, GetTestPQScript(), chainstate);
    };
    const auto check_block = [&](const CBlock& block) {
        BlockValidationState state;
        return CheckBlock(block, state, consensus, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true) ? std::string{"ok"} : state.GetRejectReason();
    };

    // Context-free: one opcode over the budget.
    const CBlock over{block_with(budget_opcodes + 1)};
    BOOST_CHECK_EQUAL(check_block(over), "bad-blk-sigops");
    BOOST_CHECK_EQUAL(Validity(chainstate, over), "bad-blk-sigops");
    // ProcessNewBlock runs CheckBlock before AcceptBlock: the block is refused
    // outright and, like any block failing the context-free checks, never indexed.
    const Processed p{ProcessBlock(*this, over)};
    BOOST_CHECK(!p.accepted);
    BOOST_CHECK_EQUAL(p.height, 100);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(over.GetHash())) == nullptr);

    // Exactly the budget in legacy sigops passes CheckBlock; ConnectBlock charges the
    // ML-DSA input PQ_SIGOPS_COST on top and refuses the block.
    const CBlock full{block_with(budget_opcodes)};
    BOOST_CHECK_EQUAL(check_block(full), "ok");
    BOOST_CHECK_EQUAL(Validity(chainstate, full), "bad-blk-sigops");

    // One opcode fewer (budget - 20 + 2 <= budget): the sigop budget holds and the
    // block fails later, on the script itself (a witness spend's scriptSig must be
    // empty), which is a different reason.
    const CBlock under{block_with(budget_opcodes - 1)};
    BOOST_CHECK_EQUAL(check_block(under), "ok");
    const std::string under_reason{Validity(chainstate, under)};
    BOOST_CHECK(under_reason != "bad-blk-sigops");
    BOOST_CHECK(under_reason != "valid");
    BOOST_CHECK_MESSAGE(under_reason.find("script-verify-flag-failed") != std::string::npos, under_reason);

    // The per-input charge itself, on a witness v2 and a witness v3 spend.
    {
        const script_verify_flags sigop_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
        CCoinsView dummy;
        CCoinsViewCache coins{&dummy};
        const CTransactionRef& cb{m_coinbase_txns.at(1)};
        AddCoins(coins, *cb, 2);
        CMutableTransaction to_v3;
        to_v3.vin.emplace_back(COutPoint{cb->GetHash(), 0});
        to_v3.vout.emplace_back(cb->vout[0].nValue - COIN, GetTestXcoinV3Script());
        SignTestPQInput(to_v3, 0, cb->vout[0]);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction{to_v3}, coins, sigop_flags), PQ_SIGOPS_COST);
        AddCoins(coins, CTransaction{to_v3}, 3);
        CMutableTransaction from_v3;
        from_v3.vin.emplace_back(COutPoint{to_v3.GetHash(), 0});
        from_v3.vout.emplace_back(to_v3.vout[0].nValue - COIN, GetTestPQScript());
        SignTestXcoinV3Input(from_v3, 0, {to_v3.vout[0]});
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction{from_v3}, coins, sigop_flags), PQ_SIGOPS_COST);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(*cb, coins, sigop_flags), 0); // a coinbase is never charged
    }
}

// ────────────────────── bad-blk-weight and bad-blk-length ──────────────────────

namespace {
/** Pad a transaction with `n` zero-value witness v2 outputs (43 bytes, 172 WU each;
 *  regtest has no output-value floor) and one OP_RETURN output of `tune` data bytes
 *  (11 + tune bytes) so a block can be brought to an exact weight. */
void PadOutputs(CMutableTransaction& tx, size_t n, size_t tune)
{
    tx.vout.resize(1);
    tx.vout.reserve(n + 2);
    const CScript pq{GetTestPQScript()};
    for (size_t i = 0; i < n; ++i) tx.vout.emplace_back(0, pq);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(tune, 0x58));
}
} // namespace

// MAX_BLOCK_WEIGHT is 64,000,000 WU (REGENESIS.md section 0, frozen 2026-09-07).
// A block of exactly that weight is valid and connects; the smallest step over it
// (one more scriptPubKey byte: 4 WU) is bad-blk-weight in ContextualCheckBlock,
// refused by ProcessNewBlock and marked failed. The block's witness is chosen to
// be a multiple of 4 bytes (two ML-DSA inputs) so the cap is reachable exactly.
// Separately, CheckBlock's context-free size rule: a block whose non-witness
// serialization is over 16,000,000 bytes is bad-blk-length before its
// transactions are even looked at.
BOOST_AUTO_TEST_CASE(bad_blk_weight_and_length)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    BOOST_REQUIRE_EQUAL(MAX_BLOCK_WEIGHT, 64000000U);
    BOOST_REQUIRE_EQUAL(m_node.chainman->GetConsensus().minOutputValueSat, 0);
    mineBlocks(1); // coinbases 1 and 2 are both mature at height 102

    const CTransactionRef& cb0{m_coinbase_txns.at(0)};
    const CTransactionRef& cb1{m_coinbase_txns.at(1)};
    const auto build = [&](size_t pad, size_t tune) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{cb0->GetHash(), 0});
        tx.vin.emplace_back(COutPoint{cb1->GetHash(), 0});
        tx.vout.emplace_back(cb0->vout[0].nValue + cb1->vout[0].nValue - COIN, GetTestPQScript());
        PadOutputs(tx, pad, tune);
        SignTestPQInput(tx, 0, cb0->vout[0]);
        SignTestPQInput(tx, 1, cb1->vout[0]);
        return CreateBlock({tx}, GetTestPQScript(), chainstate);
    };

    // Measure once, then solve for the exact cap: weight = 4 * base + witness bytes.
    const CBlock probe{build(0, 0)};
    const int64_t probe_weight{GetBlockWeight(probe)};
    const int64_t witness_bytes{probe_weight - 4 * static_cast<int64_t>(::GetSerializeSize(TX_NO_WITNESS(probe)))};
    BOOST_REQUIRE_EQUAL(witness_bytes % 4, 0);
    const int64_t missing{static_cast<int64_t>(MAX_BLOCK_WEIGHT) - probe_weight};
    BOOST_REQUIRE_GT(missing, 0);
    BOOST_REQUIRE_EQUAL(missing % 4, 0);
    // Each padding output is 172 WU; the vout count's varint grows by 2 bytes (8 WU)
    // past 65,535 entries, so measure again with the count fixed (one output fewer
    // if that pushed it over) and finish with the OP_RETURN's data bytes (4 WU each).
    size_t pad{static_cast<size_t>(missing / 172)};
    if (GetBlockWeight(build(pad, 0)) > MAX_BLOCK_WEIGHT) --pad;
    const CBlock nearly{build(pad, 0)};
    const int64_t remainder{static_cast<int64_t>(MAX_BLOCK_WEIGHT) - GetBlockWeight(nearly)};
    BOOST_REQUIRE(remainder >= 0 && remainder % 4 == 0 && remainder / 4 <= 75);
    const size_t tune{static_cast<size_t>(remainder / 4)};

    const CBlock at_cap{build(pad, tune)};
    BOOST_CHECK_EQUAL(GetBlockWeight(at_cap), MAX_BLOCK_WEIGHT);
    BOOST_CHECK_LE(::GetSerializeSize(TX_NO_WITNESS(at_cap)) * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT);
    BOOST_CHECK_EQUAL(Validity(chainstate, at_cap), "valid");

    const CBlock over_cap{build(pad, tune + 1)};
    BOOST_CHECK_EQUAL(GetBlockWeight(over_cap), MAX_BLOCK_WEIGHT + 4);
    BOOST_CHECK_LE(::GetSerializeSize(TX_NO_WITNESS(over_cap)) * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT); // not the size rule
    BOOST_CHECK_EQUAL(Validity(chainstate, over_cap), "bad-blk-weight");
    {
        BlockValidationState state;
        BOOST_CHECK(CheckBlock(over_cap, state, m_node.chainman->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true)); // context-free checks pass
    }
    BOOST_CHECK(!ProcessBlock(*this, over_cap).accepted);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 101);
        const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(over_cap.GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
    }
    BOOST_CHECK(ProcessBlock(*this, at_cap).accepted);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight()), 102);

    // bad-blk-length: the non-witness serialization over MAX_BLOCK_WEIGHT / 4 bytes.
    // (The padding transaction itself stays under the per-transaction size rule,
    // which CheckBlock only reaches after the block's own.)
    const size_t base_size{::GetSerializeSize(TX_NO_WITNESS(nearly))};
    const size_t length_pad{pad + (MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR + 1 - base_size + 42) / 43};
    const CBlock too_long{build(length_pad, 0)};
    BOOST_CHECK_GT(::GetSerializeSize(TX_NO_WITNESS(too_long)) * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT);
    BOOST_CHECK_LE(::GetSerializeSize(TX_NO_WITNESS(*too_long.vtx[1])) * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT);
    {
        BlockValidationState state;
        BOOST_CHECK(!CheckBlock(too_long, state, m_node.chainman->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-length");
    }
    BOOST_CHECK_EQUAL(Validity(chainstate, too_long), "bad-blk-length");
}

BOOST_AUTO_TEST_SUITE_END()

// ───────────────────────────── MetalDAG ─────────────────────────────

BOOST_FIXTURE_TEST_SUITE(xcoin_consensus_rule_metaldag_tests, BasicTestingSetup)

// Epoch sizing past epoch 0 and the proof-of-work hash under it. The sizes are
// the Ethash rule (largest prime item count under DAG_INIT + GROWTH * epoch and
// under its 1/128 cache), computed independently and pinned. The PoW vectors were
// produced by the canonical reference verifier, metaldag/metaldag-ref.cpp
// (mkcache + hashimoto_light), driven with the node's epoch glue: the seed is a
// keccak256 chain from 32 zero bytes, one step per epoch; the hashimoto header
// input is keccak256 of the 76-byte header prefix; the nonce is nNonce as a
// little-endian uint64. Each vector is a header with nVersion 0x40000000,
// hashPrevBlock all 0x11, hashMerkleRoot all 0x22, nBits 0x207fffff, nNonce
// 12345, dated one second into the epoch under regtest's flat 1 MiB DAG and
// under a DAG that grows 256 KiB per epoch (a 1 MiB start, cache divisor 128).
BOOST_AUTO_TEST_CASE(metaldag_epoch_one_and_beyond)
{
    const Consensus::Params main{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    BOOST_REQUIRE_EQUAL(main.metaldagDagInitBytes, int64_t{4} * 1024 * 1024 * 1024);
    BOOST_REQUIRE_EQUAL(main.metaldagDagGrowthBytes, int64_t{128} * 1024 * 1024);
    BOOST_REQUIRE_EQUAL(main.metaldagCacheDivisor, 128);
    const auto main_at = [&](uint64_t epoch) {
        return metaldag::GetEpochSizing(static_cast<uint32_t>(main.metaldagBaseTime + epoch * main.metaldagEpochSeconds + 1), main);
    };
    struct Expected { uint64_t epoch, full, cache; };
    for (const Expected e : {Expected{0, 4294962304, 33554368}, Expected{1, 4429182848, 34600256}, Expected{2, 4563402112, 35650624},
                             Expected{10, 5637143936, 44039104}, Expected{100, 17716739968, 138411584}}) {
        const auto s{main_at(e.epoch)};
        BOOST_CHECK_EQUAL(s.epoch, e.epoch);
        BOOST_CHECK_EQUAL(s.full_size, e.full);
        BOOST_CHECK_EQUAL(s.cache_size, e.cache);
        BOOST_CHECK_EQUAL(s.full_size % metaldag::MIX_BYTES, 0U);
        BOOST_CHECK_EQUAL(s.cache_size % metaldag::HASH_BYTES, 0U);
    }
    // The last second of an epoch still belongs to it.
    BOOST_CHECK_EQUAL(metaldag::GetEpochSizing(static_cast<uint32_t>(main.metaldagBaseTime + main.metaldagEpochSeconds - 1), main).epoch, 0U);
    BOOST_CHECK_EQUAL(metaldag::GetEpochSizing(static_cast<uint32_t>(main.metaldagBaseTime + main.metaldagEpochSeconds), main).epoch, 1U);

    // Regtest: 1 MiB, flat, 1,000 s epochs.
    const Consensus::Params regtest{CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus()};
    BOOST_REQUIRE_EQUAL(regtest.metaldagEpochSeconds, 1000);
    BOOST_REQUIRE_EQUAL(regtest.metaldagDagGrowthBytes, 0);
    Consensus::Params growing{regtest};
    growing.metaldagDagGrowthBytes = 256 * 1024;

    const auto header_at = [](const Consensus::Params& params, uint64_t epoch) {
        CBlockHeader h;
        h.nVersion = 0x40000000;
        std::fill(h.hashPrevBlock.begin(), h.hashPrevBlock.end(), 0x11);
        std::fill(h.hashMerkleRoot.begin(), h.hashMerkleRoot.end(), 0x22);
        h.nTime = static_cast<uint32_t>(params.metaldagBaseTime + epoch * params.metaldagEpochSeconds + 1);
        h.nBits = 0x207fffff;
        h.nNonce = 12345;
        return h;
    };
    struct Vector { const Consensus::Params* params; uint64_t epoch, full, cache; const char* pow; };
    for (const Vector v : {
             Vector{&regtest, 0, 1048448, 8128, "de67c2f5b18f6ccfab13d8a8bb52a57ef77355470a5ebeffee6ca5db558f793c"},
             Vector{&regtest, 1, 1048448, 8128, "2c259e8b088b1a9ce1d128f0237e5983e50c6a03d1a968a25a148cb589ecfcb3"},
             Vector{&regtest, 2, 1048448, 8128, "8a250c0106451bd14ebdd030c8bec808006d1678e7ab05ce969b78f9bddbbe5d"},
             Vector{&growing, 1, 1308544, 10048, "4787371666e75de2056b58b188f31591d4525012754a38294cd4312d9717eeab"},
             Vector{&growing, 3, 1833856, 14272, "966a7f48d5cccb4685d755e0c643a89739b774691e30ba87fa27598ecdc879f2"},
         }) {
        const CBlockHeader header{header_at(*v.params, v.epoch)};
        const auto s{metaldag::GetEpochSizing(header.nTime, *v.params)};
        BOOST_CHECK_EQUAL(s.epoch, v.epoch);
        BOOST_CHECK_EQUAL(s.full_size, v.full);
        BOOST_CHECK_EQUAL(s.cache_size, v.cache);
        BOOST_CHECK_EQUAL(HexStr(metaldag::PoWHash(header, *v.params)), v.pow); // the reference's byte order, not GetHex()'s
    }
    // The same header hashes differently in every epoch (the seed rotates) and the
    // hash is not the SHA-256d block hash.
    const CBlockHeader e1{header_at(regtest, 1)};
    BOOST_CHECK(metaldag::PoWHash(e1, regtest) != metaldag::PoWHash(header_at(regtest, 2), regtest));
    BOOST_CHECK(metaldag::PoWHash(e1, regtest) != metaldag::PoWHash(e1, growing)); // a larger DAG at epoch 1
    BOOST_CHECK(metaldag::PoWHash(e1, regtest) != e1.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
