// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The settlement levy (contrib/regenesis/REGENESIS.md section 6, stage B4):
// every non-coinbase transaction pays a fee of at least ceil(sum of outputs *
// levy_bp / 10,000), paid to the miner through the ordinary fee mechanism.
// Arithmetic, the consensus check, the chain parameters, mempool rejection
// and block rejection ("bad-txns-levy").

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/levy.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/common.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

using Consensus::SettlementLevyUncapped;
namespace {
// The arithmetic under the cap every chain ships (SETTLEMENT_LEVY_CAP_SAT); the rate varies per test.
constexpr CAmount SettlementLevy(CAmount value_out, int64_t bp) { return Consensus::SettlementLevy(value_out, bp, Consensus::SETTLEMENT_LEVY_CAP_SAT); }
constexpr CAmount SettlementLevyFromInputs(CAmount value_in, int64_t bp) { return Consensus::SettlementLevyFromInputs(value_in, bp, Consensus::SETTLEMENT_LEVY_CAP_SAT); }
} // namespace
using node::BlockAssembler;

namespace {
/** BasicTestingSetup selects mainnet by default; the regtest knob -levybp
 *  is exercised through RegTestOptions below. */
struct LevyBasicSetup : public BasicTestingSetup {
    LevyBasicSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(xcoin_levy_tests, LevyBasicSetup)

// ceil(value * bp / 10,000) in integers: exact boundaries, rounding up, no
// levy on nothing, the full range up to MAX_MONEY at 100%.
BOOST_AUTO_TEST_CASE(levy_arithmetic)
{
    constexpr int64_t bp{Consensus::SETTLEMENT_LEVY_BP};
    BOOST_CHECK_EQUAL(bp, 5);
    BOOST_CHECK_EQUAL(Consensus::LEVY_DENOMINATOR, 10'000);

    // Exact multiples: 10,000 sat owes 5 sat; 2,000 sat owes exactly 1 sat.
    BOOST_CHECK_EQUAL(SettlementLevy(10'000, bp), 5);
    BOOST_CHECK_EQUAL(SettlementLevy(2'000, bp), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(20'000, bp), 10);
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(COIN, bp), 50'000);       // 1 XID -> 0.0005 XID proportional...
    BOOST_CHECK_EQUAL(SettlementLevy(COIN, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT); // ...but consensus caps it at 0.0001 XID
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(50 * COIN, bp), 2'500'000); // 50 XID -> 0.025 XID proportional
    BOOST_CHECK_EQUAL(SettlementLevy(50 * COIN, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT);
    // Rounding up: one satoshi over a boundary costs a whole extra satoshi.
    BOOST_CHECK_EQUAL(SettlementLevy(1, bp), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(1'999, bp), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(2'001, bp), 2);
    BOOST_CHECK_EQUAL(SettlementLevy(3'999, bp), 2);
    BOOST_CHECK_EQUAL(SettlementLevy(4'000, bp), 2);
    BOOST_CHECK_EQUAL(SettlementLevy(4'001, bp), 3);
    BOOST_CHECK_EQUAL(SettlementLevy(10'001, bp), 6);
    // Nothing moved, or no levy: nothing owed.
    BOOST_CHECK_EQUAL(SettlementLevy(0, bp), 0);
    BOOST_CHECK_EQUAL(SettlementLevy(-1, bp), 0);
    BOOST_CHECK_EQUAL(SettlementLevy(10'000, 0), 0);
    BOOST_CHECK_EQUAL(SettlementLevy(10'000, -5), 0);
    // Other rates and the range: 1 bp, 100 bp, 100%.
    BOOST_CHECK_EQUAL(SettlementLevy(10'000, 1), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(9'999, 1), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(10'000, 100), 100);
    // The raw proportional arithmetic, uncapped: unchanged, and still overflow-free.
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(MAX_MONEY, Consensus::SETTLEMENT_LEVY_BP_MAX), MAX_MONEY);
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(MAX_MONEY, bp), 5'000'000'000'000LL); // 50,000 XID, uncapped
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(MAX_MONEY - 1, bp), 5'000'000'000'000LL); // rounds up to the same
    // What consensus actually charges: the cap, 0.0001 XID, however much moves.
    BOOST_CHECK_EQUAL(SettlementLevy(MAX_MONEY, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT);
    BOOST_CHECK_EQUAL(SettlementLevy(MAX_MONEY - 1, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT);
    BOOST_CHECK_EQUAL(SettlementLevy(20'000'000, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT); // 0.2 XID: the crossover
    BOOST_CHECK_EQUAL(SettlementLevy(19'999'999, bp), 10'000); // one sat below: still exactly the cap value
    BOOST_CHECK_EQUAL(SettlementLevy(19'998'000, bp), 9'999);  // and below that, proportional again
    // Brute-force agreement with the definition on a range that crosses many boundaries.
    for (CAmount v = 0; v < 50'000; ++v) {
        const CAmount expected{(v * bp + Consensus::LEVY_DENOMINATOR - 1) / Consensus::LEVY_DENOMINATOR};
        BOOST_REQUIRE_EQUAL(SettlementLevy(v, bp), expected);
    }
    // Sum of outputs: the levy is on the total, so splitting a payment never
    // lowers it and rounding is applied once, to the sum.
    BOOST_CHECK_EQUAL(SettlementLevy(1 + 1 + 1'998, bp), 1);
    BOOST_CHECK_EQUAL(SettlementLevy(1, bp) + SettlementLevy(1, bp) + SettlementLevy(1'998, bp), 3);

    // The wallet's fixed point: the smallest fee f with f >= levy(value_in - f).
    for (const CAmount in : {CAmount{1}, CAmount{2}, CAmount{1'999}, CAmount{2'000}, CAmount{2'001}, CAmount{10'005}, CAmount{10'006}, 50 * COIN, 50 * COIN + 1, MAX_MONEY}) {
        const CAmount f{SettlementLevyFromInputs(in, bp)};
        BOOST_CHECK_GE(f, SettlementLevy(in - f, bp));
        if (f > 0) BOOST_CHECK_LT(f - 1, SettlementLevy(in - (f - 1), bp));
    }
    BOOST_CHECK_EQUAL(SettlementLevyFromInputs(0, bp), 0);
    BOOST_CHECK_EQUAL(SettlementLevyFromInputs(10'005, bp), 5);
    BOOST_CHECK_EQUAL(SettlementLevyFromInputs(50 * COIN, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT); // was 2,498,751 uncapped
}

// Consensus::CheckSettlementLevy on synthetic transactions: exact boundary,
// coinbase exemption, a disabled levy, multiple outputs summed.
BOOST_AUTO_TEST_CASE(levy_consensus_check)
{
    constexpr int64_t bp{Consensus::SETTLEMENT_LEVY_BP};
    const auto check = [&](const CMutableTransaction& mtx, CAmount fee, int64_t rate) {
        TxValidationState state;
        const bool ok{Consensus::CheckSettlementLevy(CTransaction{mtx}, fee, Consensus::SettlementLevyRule{0, rate, Consensus::SETTLEMENT_LEVY_CAP_SAT}, state)};
        return ok ? std::string{"ok"} : state.GetRejectReason();
    };

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(10'000, GetTestPQScript());
    BOOST_CHECK_EQUAL(check(tx, 5, bp), "ok");
    BOOST_CHECK_EQUAL(check(tx, 6, bp), "ok");
    BOOST_CHECK_EQUAL(check(tx, 4, bp), "bad-txns-levy");
    BOOST_CHECK_EQUAL(check(tx, 0, bp), "bad-txns-levy");
    BOOST_CHECK_EQUAL(check(tx, 0, 0), "ok"); // -levybp=0 (regtest tests only)

    // Multiple outputs: the levy is on the sum (20,003 sat -> 11 sat), not on each output.
    tx.vout.emplace_back(10'001, GetTestPQScript());
    tx.vout.emplace_back(2, GetTestPQScript());
    BOOST_CHECK_EQUAL(SettlementLevy(20'003, bp), 11);
    BOOST_CHECK_EQUAL(check(tx, 11, bp), "ok");
    BOOST_CHECK_EQUAL(check(tx, 10, bp), "bad-txns-levy");

    // A zero-value data output changes nothing.
    tx.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{'x'});
    BOOST_CHECK_EQUAL(check(tx, 11, bp), "ok");
    BOOST_CHECK_EQUAL(check(tx, 10, bp), "bad-txns-levy");

    // Coinbases are the only exemption (they pay no fee).
    CMutableTransaction cb;
    cb.vin.emplace_back();
    cb.vout.emplace_back(33 * COIN, GetTestPQScript());
    BOOST_CHECK(CTransaction{cb}.IsCoinBase());
    BOOST_CHECK_EQUAL(check(cb, 0, bp), "ok");
}

// LEVY_BP is a consensus chain parameter: 5 on mainnet, the dress rehearsal
// and regtest, with a regtest-only override for tests (0 disables; range-checked).
// No chain charges a levy at genesis: one row, height 0, zero rate, zero cap
// (founder decision 2026-09-14). Regtest enables it for a test with -levybp.
BOOST_AUTO_TEST_CASE(levy_chainparams)
{
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET}) {
        const auto p{CreateChainParams(*m_node.args, type)};
        const auto& sched{p->GetConsensus().settlementLevySchedule};
        BOOST_REQUIRE_EQUAL(sched.size(), 1U);
        BOOST_CHECK_EQUAL(sched[0].startHeight, 0);
        BOOST_CHECK_EQUAL(sched[0].bp, 0);
        BOOST_CHECK_EQUAL(sched[0].capSat, 0);
        BOOST_CHECK_EQUAL(p->GetConsensus().SettlementLevyAt(0).bp, Consensus::SETTLEMENT_LEVY_GENESIS_BP);
        BOOST_CHECK_EQUAL(p->GetConsensus().SettlementLevyAt(Consensus::EMISSION_END_HEIGHT).capSat, Consensus::SETTLEMENT_LEVY_GENESIS_CAP_SAT);     // the last subsidy block
        BOOST_CHECK_EQUAL(p->GetConsensus().SettlementLevyAt(Consensus::EMISSION_END_HEIGHT + 1).capSat, Consensus::SETTLEMENT_LEVY_GENESIS_CAP_SAT); // fees only from here
        BOOST_CHECK_EQUAL(Consensus::SettlementLevy(MAX_MONEY, p->GetConsensus().SettlementLevyAt(1)), 0);
    }
    CChainParams::RegTestOptions opts;
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).bp, 0);     // as mainnet
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).capSat, 0);
    opts.levy_bp = 0;                                                                              // explicit off: the same
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).bp, 0);
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).capSat, 0);
    opts.levy_bp = Consensus::SETTLEMENT_LEVY_BP;                                                  // the reference rule, under the reference cap
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).bp, 5);
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).capSat, Consensus::SETTLEMENT_LEVY_CAP_SAT);
    opts.levy_bp = 250;
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).bp, 250);
    opts.levy_bp = Consensus::SETTLEMENT_LEVY_BP_MAX;
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().SettlementLevyAt(0).bp, 10'000);
    opts.levy_bp = Consensus::SETTLEMENT_LEVY_BP_MAX + 1;
    BOOST_CHECK_THROW(CChainParams::RegTest(opts), std::runtime_error);
    opts.levy_bp = -1;
    BOOST_CHECK_THROW(CChainParams::RegTest(opts), std::runtime_error);
    // The unit-test harness injects nothing: the fixture's chain is the genesis rule.
    BOOST_CHECK_EQUAL(Params().GetConsensus().SettlementLevyAt(0).bp, 0);
    BOOST_CHECK_EQUAL(Params().GetConsensus().SettlementLevyAt(0).capSat, 0);
}

// Coinbase maturity is 1,000 on every chain, regtest included. -coinbasematurity is the
// regtest knob the test harness uses to keep the inherited fixtures at 100.
BOOST_AUTO_TEST_CASE(coinbase_maturity_chainparams)
{
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET}) {
        BOOST_CHECK_EQUAL(CreateChainParams(*m_node.args, type)->GetConsensus().coinbaseMaturity, 1'000);
    }
    CChainParams::RegTestOptions opts;
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().coinbaseMaturity, 1'000);
    opts.coinbase_maturity = 100;
    BOOST_CHECK_EQUAL(CChainParams::RegTest(opts)->GetConsensus().coinbaseMaturity, 100);
    opts.coinbase_maturity = 0;
    BOOST_CHECK_THROW(CChainParams::RegTest(opts), std::runtime_error);
    // The unit-test harness runs with -coinbasematurity=100 unless a test opts out.
    BOOST_CHECK_EQUAL(Params().GetConsensus().coinbaseMaturity, 100);
}

// The levy is a schedule keyed by height so that raising it later is a table
// row plus a deployment (a soft fork under charter section 7) and nothing
// else. A row that lowers the rate or the cap would be a hard fork; the
// validator that chainparams asserts refuses it.
BOOST_AUTO_TEST_CASE(levy_schedule_soft_fork_only)
{
    using Consensus::SettlementLevyRule;
    const auto main{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& sched{main->GetConsensus().settlementLevySchedule};
    BOOST_REQUIRE_EQUAL(sched.size(), 1U);
    BOOST_CHECK_EQUAL(sched[0].startHeight, 0);
    BOOST_CHECK_EQUAL(sched[0].bp, 0);
    BOOST_CHECK_EQUAL(sched[0].capSat, 0);
    BOOST_CHECK(Consensus::SettlementLevyScheduleIsSoftForkOnly(sched));

    // Switching the levy on later is a soft fork from the zero row: a later row may
    // raise either number, and the rule at a height is the last row at or below it.
    Consensus::Params p{main->GetConsensus()};
    p.settlementLevySchedule = {Consensus::SETTLEMENT_LEVY_GENESIS_RULE, {1'000'000, 5, 10'000}, {2'000'000, 5, 100'000}, {3'000'000, 10, 100'000}};
    BOOST_CHECK(Consensus::SettlementLevyScheduleIsSoftForkOnly(p.settlementLevySchedule));
    BOOST_CHECK_EQUAL(p.SettlementLevyAt(0).capSat, 0);
    BOOST_CHECK_EQUAL(Consensus::SettlementLevy(MAX_MONEY, p.SettlementLevyAt(999'999)), 0);      // before activation: nothing owed
    BOOST_CHECK_EQUAL(p.SettlementLevyAt(1'000'000).capSat, 10'000);
    BOOST_CHECK_EQUAL(Consensus::SettlementLevy(COIN, p.SettlementLevyAt(1'000'000)), 10'000);   // the reference rule, cap binds
    BOOST_CHECK_EQUAL(p.SettlementLevyAt(2'000'000).capSat, 100'000);
    BOOST_CHECK_EQUAL(p.SettlementLevyAt(2'999'999).bp, 5);
    BOOST_CHECK_EQUAL(p.SettlementLevyAt(3'000'000).bp, 10);
    BOOST_CHECK_EQUAL(Consensus::SettlementLevy(COIN, p.SettlementLevyAt(2'000'000)), 50'000);   // 1 XID under the raised cap: proportional again
    BOOST_CHECK_EQUAL(Consensus::SettlementLevy(COIN, p.SettlementLevyAt(3'000'000)), 100'000);  // 10 bp of 1 XID: the raised cap binds

    // ...but never lower one, never go backwards, never start anywhere but height 0.
    const std::vector<std::vector<SettlementLevyRule>> refused{
        {{0, 5, 10'000}, {1'000'000, 5, 1'000}},                        // lowers the cap
        {{0, 5, 10'000}, {1'000'000, 1, 10'000}},                       // lowers the rate
        {{0, 5, 10'000}, {1'000'000, 5, 10'000}, {500'000, 6, 10'000}}, // out of order
        {{0, 0, 0}, {1'000'000, 5, 10'000}, {2'000'000, 0, 0}},        // switching it back off: a hard fork
        {{1, 5, 10'000}},                                               // no rule at height 0
        {},                                                             // no rule at all
        {{0, Consensus::SETTLEMENT_LEVY_BP_MAX + 1, 10'000}},           // rate out of range
    };
    for (const auto& bad : refused) BOOST_CHECK(!Consensus::SettlementLevyScheduleIsSoftForkOnly(bad));
}

BOOST_AUTO_TEST_SUITE_END()

// ── Mempool and block enforcement on a regtest chain with the levy enabled at the reference rate ──

namespace {
struct LevyChainSetup : public TestChain100Setup {
    LevyChainSetup() : LevyChainSetup{TestOpts{.extra_args = {"-levybp=5"}}} {}
    explicit LevyChainSetup(TestOpts opts) : TestChain100Setup{ChainType::REGTEST, std::move(opts)} {}

    /** Spend the whole block-1 coinbase (an ordinary 50 XID era-0 coinbase to
     *  the shared test key) into the given outputs, whose sum determines the fee. */
    CMutableTransaction Spend(const std::vector<CTxOut>& outputs)
    {
        const CTransactionRef& cb{m_coinbase_txns[0]};
        return CreateValidTransaction({cb}, {COutPoint{cb->GetHash(), 0}}, /*input_height=*/1, {coinbaseKey}, outputs, std::nullopt, std::nullopt).first;
    }
    CMutableTransaction SpendWithFee(CAmount fee)
    {
        return Spend({CTxOut{m_coinbase_txns[0]->vout[0].nValue - fee, GetTestPQScript()}});
    }
    std::string Accept(const CMutableTransaction& tx)
    {
        LOCK(cs_main);
        const MempoolAcceptResult r{m_node.chainman->ProcessTransaction(MakeTransactionRef(tx), /*test_accept=*/true)};
        return r.m_result_type == MempoolAcceptResult::ResultType::VALID ? std::string{"ok"} : r.m_state.GetRejectReason();
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(xcoin_levy_chain_tests, LevyChainSetup)

BOOST_AUTO_TEST_CASE(levy_mempool_boundary)
{
    constexpr int64_t bp{5};
    BOOST_REQUIRE_EQUAL(m_node.chainman->GetConsensus().SettlementLevyAt(0).bp, bp);
    const CAmount in{m_coinbase_txns[0]->vout[0].nValue};
    BOOST_REQUIRE_EQUAL(in, 50 * COIN);

    // The exact boundary. With the cap (a1dd35a) the smallest fee that covers the
    // levy on what is left is the cap itself: 49.9999 XID out owes 0.0001 XID.
    const CAmount f_min{SettlementLevyFromInputs(in, bp)};
    BOOST_CHECK_EQUAL(f_min, Consensus::SETTLEMENT_LEVY_CAP_SAT);
    BOOST_CHECK_EQUAL(f_min, 10'000);
    BOOST_CHECK_EQUAL(SettlementLevy(in - f_min, bp), f_min);
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(f_min)), "ok");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(f_min + 1)), "ok");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(2'500'000)), "ok");      // what the uncapped 5 bp would have asked for
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(f_min - 1)), "bad-txns-levy");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(1'000)), "bad-txns-levy");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(0)), "bad-txns-levy");

    // The levy is on the sum of the outputs, capped once. At this size every
    // split sits far above the 0.2 XID crossover, so the sum owes the cap
    // whichever way it is cut; the uncapped 5 bp on 49.975 XID, 2,498,750 sat,
    // is the figure the cap replaced.
    const CAmount out_total{in - 2'500'000};
    BOOST_CHECK_EQUAL(SettlementLevyUncapped(out_total, bp), 2'498'750);
    BOOST_CHECK_EQUAL(SettlementLevy(out_total, bp), Consensus::SETTLEMENT_LEVY_CAP_SAT);
    const auto split = [&](CAmount total) { // three outputs, none dust, summing to total
        return Spend({CTxOut{total - 1'100'000, GetTestPQScript()}, CTxOut{1'000'000, GetTestPQScript()}, CTxOut{100'000, GetTestPQScript()}});
    };
    BOOST_CHECK_EQUAL(Accept(split(out_total)), "ok");           // fee 2,500,000 >= 10,000
    BOOST_CHECK_EQUAL(Accept(split(in - f_min)), "ok");          // fee exactly the cap
    BOOST_CHECK_EQUAL(Accept(split(in - f_min + 1)), "bad-txns-levy"); // one satoshi short
}

BOOST_AUTO_TEST_CASE(levy_block_rejected_and_fee_paid_to_miner)
{
    constexpr int64_t bp{5};
    const CAmount in{m_coinbase_txns[0]->vout[0].nValue};
    const CAmount f_min{SettlementLevyFromInputs(in, bp)};
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    const uint256 tip_before{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    const int height_before{WITH_LOCK(cs_main, return chainstate.m_chain.Height())};

    // A block carrying a transaction one satoshi short of the levy is invalid
    // (ConnectBlock, "bad-txns-levy"): TestBlockValidity says so, and processing
    // it leaves the tip alone and marks the block failed.
    const CMutableTransaction bad{SpendWithFee(f_min - 1)};
    CBlock bad_block{CreateBlock({bad}, GetTestPQScript(), chainstate)};
    {
        LOCK(cs_main);
        const BlockValidationState state{TestBlockValidity(chainstate, bad_block, /*check_pow=*/true, /*check_merkle_root=*/true)};
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-levy");
    }
    m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(bad_block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), tip_before);
        const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(bad_block.GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
    }

    // The same spend at the boundary enters the mempool, the block assembler
    // mines it, and its fee reaches the miner through the coinbase: nothing
    // is burned. (The fixture's CreateBlock deliberately assembles without
    // the mempool, so the block is built here with it.)
    const CMutableTransaction good{SpendWithFee(f_min)};
    {
        LOCK(cs_main);
        const MempoolAcceptResult r{m_node.chainman->ProcessTransaction(MakeTransactionRef(good))};
        BOOST_REQUIRE(r.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(r.m_base_fees.value(), f_min);
    }
    BlockAssembler::Options options;
    options.coinbase_output_script = GetTestPQScript();
    options.include_dummy_extranonce = true;
    CBlock good_block{BlockAssembler{chainstate, m_node.mempool.get(), options}.CreateNewBlock()->block};
    // The assembler hands back a template with no merkle root: filling it in
    // is the miner's job (node::AddMerkleRootAndCoinbase, RegenerateCommitments),
    // and CreateNewBlock's own TestBlockValidity runs with check_merkle_root=false.
    // Do it here, then grind the header-based PoW (MetalDAG), not the SHA-256d hash.
    good_block.hashMerkleRoot = BlockMerkleRoot(good_block);
    while (!CheckProofOfWork(good_block, good_block.nBits, m_node.chainman->GetConsensus())) ++good_block.nNonce;
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(good_block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(chainstate.m_chain.Height(), height_before + 1);
    BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), good_block.GetHash());
    BOOST_REQUIRE_EQUAL(good_block.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(good_block.vtx[1]->GetHash(), CTransaction{good}.GetHash());
    const CAmount subsidy{GetBlockSubsidy(height_before + 1, m_node.chainman->GetConsensus())};
    BOOST_CHECK_EQUAL(good_block.vtx[0]->GetValueOut(), subsidy + f_min);
    BOOST_CHECK(m_node.mempool->size() == 0);
}

// Audit finding C7: the mempool checks the levy only at admission, against the
// row for Height() + 1. A transaction that satisfied the row it was admitted
// under but not the row in force at the template height (a later schedule row
// raising the rate or the cap) must be skipped by the block assembler, not
// included: ConnectBlock would reject the block ("bad-txns-levy") and
// CreateNewBlock's own TestBlockValidity would throw, so no template could be
// built until the transaction expired. Modelled by placing a transaction one
// satoshi short of the current row straight into the mempool (addUnchecked
// bypasses admission, as a row boundary would), next to one that pays it.
BOOST_AUTO_TEST_CASE(levy_assembler_skips_mempool_entry_short_of_the_template_row)
{
    constexpr int64_t bp{5};
    const CAmount in{m_coinbase_txns[0]->vout[0].nValue};
    const CAmount f_min{SettlementLevyFromInputs(in, bp)};
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};

    // One satoshi short of the row in force at the next height, entered without admission.
    const CMutableTransaction stale{SpendWithFee(f_min - 1)};
    BOOST_CHECK_EQUAL(Accept(stale), "bad-txns-levy"); // admission would refuse it today
    TestMemPoolEntryHelper entry;
    TryAddToMempool(*m_node.mempool, entry.Fee(f_min - 1).SpendsCoinbase(true).FromTx(stale));
    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 1U);

    // A spend of the same coin that pays the row exactly, for the second half.
    const CMutableTransaction good{Spend({CTxOut{in - f_min - 1'000'000, GetTestPQScript()}, CTxOut{1'000'000, GetTestPQScript()}})};
    BOOST_CHECK_EQUAL(SettlementLevy(CTransaction{good}.GetValueOut(), bp), f_min);

    BlockAssembler::Options options;
    options.coinbase_output_script = GetTestPQScript();
    options.include_dummy_extranonce = true;
    options.test_block_validity = true; // the throw the finding describes comes from here

    // With only the stale entry in the pool the template is the coinbase alone.
    {
        std::unique_ptr<node::CBlockTemplate> tmpl;
        BlockAssembler assembler{chainstate, m_node.mempool.get(), options};
        BOOST_REQUIRE_NO_THROW(tmpl = assembler.CreateNewBlock());
        BOOST_REQUIRE(tmpl);
        BOOST_CHECK_EQUAL(tmpl->block.vtx.size(), 1U);
    }

    // Replace it by the paying spend of the same coin: that one is mined.
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{stale}, MemPoolRemovalReason::REPLACED));
    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 0U);
    TryAddToMempool(*m_node.mempool, entry.Fee(f_min).SpendsCoinbase(true).FromTx(good));
    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 1U);
    {
        std::unique_ptr<node::CBlockTemplate> tmpl;
        BlockAssembler assembler{chainstate, m_node.mempool.get(), options};
        BOOST_REQUIRE_NO_THROW(tmpl = assembler.CreateNewBlock());
        BOOST_REQUIRE(tmpl);
        BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2U);
        BOOST_CHECK_EQUAL(tmpl->block.vtx[1]->GetHash(), CTransaction{good}.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ── The chain as it ships: no levy. A regtest node with no -levybp is the genesis rule. ──

namespace {
struct NoLevyChainSetup : public LevyChainSetup {
    NoLevyChainSetup() : LevyChainSetup{TestOpts{}} {}
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(xcoin_no_levy_chain_tests, NoLevyChainSetup)

BOOST_AUTO_TEST_CASE(genesis_rule_charges_nothing)
{
    const Consensus::SettlementLevyRule rule{m_node.chainman->GetConsensus().SettlementLevyAt(m_node.chainman->ActiveHeight() + 1)};
    BOOST_CHECK_EQUAL(rule.bp, 0);
    BOOST_CHECK_EQUAL(rule.capSat, 0);
    const CAmount in{m_coinbase_txns[0]->vout[0].nValue};
    BOOST_REQUIRE_EQUAL(in, 50 * COIN);

    // Fees that the reference levy would have refused are consensus-valid here; what
    // stops a cheap spend is relay policy (the byte floor, DEFAULT_MIN_RELAY_TX_FEE:
    // 1 sat/vB, so about 1,440 sat for this 1-in-1-out ML-DSA spend), never bad-txns-levy.
    const CFeeRate relay_floor{m_node.mempool->m_opts.min_relay_feerate};
    BOOST_CHECK_EQUAL(relay_floor.GetFeePerK(), DEFAULT_MIN_RELAY_TX_FEE);
    const CAmount floor_fee{relay_floor.GetFee(GetVirtualTransactionSize(CTransaction{SpendWithFee(0)}))};
    BOOST_CHECK(floor_fee > 1'000);   // an ML-DSA spend is far larger than a Bitcoin one
    BOOST_CHECK(floor_fee < 9'999);   // and still well under the reference levy's cap
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(9'999)), "ok");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(floor_fee + 1)), "ok");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(floor_fee)), "ok");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(floor_fee - 1)), "min relay fee not met");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(200)), "min relay fee not met");
    BOOST_CHECK_EQUAL(Accept(SpendWithFee(0)), "min relay fee not met");
    TxValidationState state;
    BOOST_CHECK(Consensus::CheckSettlementLevy(CTransaction{SpendWithFee(0)}, /*txfee=*/0, rule, state));
    BOOST_CHECK(Consensus::CheckSettlementLevy(CTransaction{SpendWithFee(floor_fee - 1)}, /*txfee=*/floor_fee - 1, rule, state));
    BOOST_CHECK(Consensus::CheckSettlementLevy(CTransaction{Spend({CTxOut{in, GetTestPQScript()}})}, /*txfee=*/0, rule, state));

    // And a block carrying a spend just above the floor connects: the assembler
    // includes it and the miner is paid the fee, not a levy.
    const CAmount fee{floor_fee + 1};
    const CMutableTransaction tx{SpendWithFee(fee)};
    {
        LOCK(cs_main);
        BOOST_REQUIRE(m_node.chainman->ProcessTransaction(MakeTransactionRef(tx), /*test_accept=*/false).m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BlockAssembler::Options options;
    options.coinbase_output_script = GetTestPQScript();
    options.include_dummy_extranonce = true;
    options.test_block_validity = true;
    const auto tmpl{BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()};
    BOOST_REQUIRE(tmpl);
    BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(tmpl->block.vtx[1]->GetHash(), CTransaction{tx}.GetHash());
    BOOST_REQUIRE_EQUAL(tmpl->vTxFees.size(), 1U); // fees are recorded per non-coinbase transaction
    BOOST_CHECK_EQUAL(tmpl->vTxFees[0], fee);
}

BOOST_AUTO_TEST_SUITE_END()
