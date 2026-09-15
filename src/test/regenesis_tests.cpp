// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Re-genesis stage A1 (contrib/regenesis/REGENESIS.md sections 2 and 3):
// the emission table; stage A1b: the FINAL schedule (no premine, 14 XCF halved
// every 750,000 blocks until it reaches zero) and block 1 an ordinary block on
// every chain (no distribution, nothing carried in: 35c4fda, 7263c5d).
// Stage A2 (sections 0 and 5): block weight and the per-block data-carrier cap.
// Stage A3 (sections 1, 3 and 8): the charter commitment, the currency id and
// the genesis tooling.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/charter.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <coins.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <metaldag/metaldag.h>
#include <kernel/notifications_interface.h>
#include <net.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/xcoin_v3.h>
#include <span.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using node::BlockAssembler;
using node::RegenerateCommitments;

namespace {
CTxOut PQOut(CAmount value, unsigned char fill)
{
    return CTxOut{value, CScript() << OP_2 << std::vector<unsigned char>(32, fill)};
}

CTxOut NullDataOut(CAmount value = 0)
{
    return CTxOut{value, CScript() << OP_RETURN << std::vector<unsigned char>{'x', 'a', 't'}};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(regenesis_tests, BasicTestingSetup)

// (a) sum(subsidies from height 1 to EMISSION_END_HEIGHT) == 21,000,000 XCF exactly.
// There is no premine and nothing is carried in; the dust is minted exactly once, on
// the last block.
BOOST_AUTO_TEST_CASE(emission_sums_to_cap_mainnet)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& cp{params->GetConsensus()};
    BOOST_CHECK_EQUAL(cp.emissionTable.size(), static_cast<size_t>(Consensus::NUM_EMISSION_ERAS));
    BOOST_CHECK_EQUAL(cp.emissionClosingDustSat, Consensus::EMISSION_CLOSING_DUST_SAT);
    BOOST_CHECK_EQUAL(cp.EmissionEndHeight(), Consensus::EMISSION_END_HEIGHT);

    std::vector<CAmount> rates;
    for (const auto& era : cp.emissionTable) rates.push_back(era.baseSubsidy);
    CAmount emitted{0};
    int off_rate_blocks{0};
    for (int h = Consensus::EMISSION_START_HEIGHT; h <= Consensus::EMISSION_END_HEIGHT; ++h) {
        const CAmount s{GetBlockSubsidy(h, cp)};
        emitted += s;
        if (std::find(rates.begin(), rates.end(), s) == rates.end()) {
            ++off_rate_blocks;
            BOOST_CHECK_EQUAL(h, Consensus::EMISSION_END_HEIGHT);
        }
    }
    // The dust block, and only it (a schedule that divided the cap exactly would leave no dust).
    BOOST_CHECK_EQUAL(off_rate_blocks, Consensus::EMISSION_CLOSING_DUST_SAT > 0 ? 1 : 0);
    BOOST_CHECK(Consensus::EMISSION_CLOSING_DUST_SAT > 0); // 0.09 XCF, pinned in subsidy_at_era_boundaries
    BOOST_CHECK_EQUAL(emitted, Consensus::TOTAL_EMISSION_SAT);
    BOOST_CHECK_EQUAL(emitted, Consensus::MAX_SUPPLY_SAT);
    BOOST_CHECK_EQUAL(Consensus::MAX_SUPPLY_SAT, MAX_MONEY);

}

// The regtest table has the mainnet shape (50 XCF for one 150-block era, three halvings,
// 6.25 XCF until the cap; the remainder divides exactly, so the dust is 0), from height 1
// like every chain, and closes on the cap too.
BOOST_AUTO_TEST_CASE(emission_sums_to_cap_regtest)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const auto& cp{params->GetConsensus()};
    BOOST_CHECK_EQUAL(cp.emissionTable.size(), 4U);
    BOOST_CHECK_EQUAL(cp.EmissionEndHeight(), 3358350);
    BOOST_CHECK_EQUAL(cp.emissionClosingDustSat, 0);
    CAmount minted{0};
    for (int h = 0; h <= cp.EmissionEndHeight() + 10; ++h) minted += GetBlockSubsidy(h, cp);
    BOOST_CHECK_EQUAL(minted, Consensus::MAX_SUPPLY_SAT);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), 50 * COIN); // block 1 is an ordinary block
    BOOST_CHECK_EQUAL(GetBlockSubsidy(150, cp), 50 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(151, cp), 25 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(300, cp), 25 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(301, cp), CAmount{1'250'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(450, cp), CAmount{1'250'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(451, cp), CAmount{625'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(601, cp), CAmount{625'000'000LL}); // era 3 runs past its 150-block span
    BOOST_CHECK_EQUAL(GetBlockSubsidy(3358350, cp), CAmount{625'000'000LL}); // last block; no dust on regtest
    BOOST_CHECK_EQUAL(GetBlockSubsidy(3358351, cp), 0);
}

// (b) subsidy at every era boundary and at the dust block.
BOOST_AUTO_TEST_CASE(subsidy_at_era_boundaries)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& cp{params->GetConsensus()};
    for (int i = 0; i < Consensus::NUM_EMISSION_ERAS; ++i) {
        const auto& era{Consensus::EMISSION_TABLE[i]};
        const bool last{i == Consensus::NUM_EMISSION_ERAS - 1};
        // Eras 0-2 are exactly 3 years; era 3 starts after the third halving and runs to the cap.
        const int blocks{era.endHeight - era.startHeight + 1};
        if (last) {
            BOOST_CHECK(blocks >= Consensus::EMISSION_ERA_BLOCKS);
        } else {
            BOOST_CHECK_EQUAL(blocks, Consensus::EMISSION_ERA_BLOCKS);
        }
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.startHeight, cp), era.baseSubsidy);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.startHeight + 1, cp), era.baseSubsidy);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.endHeight - 1, cp), era.baseSubsidy);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.endHeight, cp), era.baseSubsidy + (last ? Consensus::EMISSION_CLOSING_DUST_SAT : 0));
        // The block before an era pays the previous era's subsidy (block 0 pays none).
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.startHeight - 1, cp), i == 0 ? 0 : Consensus::EMISSION_TABLE[i - 1].baseSubsidy);
        // The block after an era pays the next era's subsidy (none after the last).
        BOOST_CHECK_EQUAL(GetBlockSubsidy(era.endHeight + 1, cp), last ? 0 : Consensus::EMISSION_TABLE[i + 1].baseSubsidy);
        // Every era pays exactly half of the previous one.
        if (i > 0) BOOST_CHECK_EQUAL(era.baseSubsidy, Consensus::EMISSION_TABLE[i - 1].baseSubsidy / 2);
    }
    // The FINAL schedule (founder decision 2026-09-14): 14 XCF, halved every 750,000
    // blocks in whole satoshis until the shift reaches zero — 31 eras; the last
    // subsidy block also mints the 0.09 XCF remainder so the total is the cap exactly.
    BOOST_CHECK_EQUAL(Consensus::NUM_EMISSION_ERAS, 31);
    BOOST_CHECK_EQUAL(Consensus::EMISSION_ERA_BLOCKS, 750'000);
    BOOST_CHECK_EQUAL(Consensus::EMISSION_START_HEIGHT, 1);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), 14 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, cp), CAmount{1'400'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(750'000, cp), 14 * COIN);                // last block of era 0
    BOOST_CHECK_EQUAL(GetBlockSubsidy(750'001, cp), 7 * COIN);                 // first halving
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1'500'001, cp), CAmount{350'000'000LL}); // 3.5 XCF
    BOOST_CHECK_EQUAL(GetBlockSubsidy(5'250'000, cp), CAmount{21'875'000LL});  // era 6 ends here (the 49th year): 0.21875 XCF
    BOOST_CHECK_EQUAL(GetBlockSubsidy(5'250'001, cp), CAmount{10'937'500LL});  // era 7: 0.109375 XCF, fading
    BOOST_CHECK_EQUAL(GetBlockSubsidy(7'500'001, cp), CAmount{1'367'187LL});   // era 10: the first halving that rounds down (2,734,375 / 2)
    BOOST_CHECK_EQUAL(GetBlockSubsidy(22'500'001, cp), 1);                     // era 30: one satoshi
    // Pinned FINAL values: 14 x 750,000 x 2 = 21,000,000 less the rounding of thirty
    // halvings, 0.09 XCF, minted with the final subsidy at height 23,250,000 (~2248).
    BOOST_CHECK_EQUAL(Consensus::EMISSION_END_HEIGHT, 23'250'000);
    BOOST_CHECK_EQUAL(Consensus::EMISSION_CLOSING_DUST_SAT, CAmount{9'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(23'249'999, cp), 1);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT, cp), CAmount{1 + 9'000'000LL});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT + 1, cp), 0);
    // Era 0 mints exactly half the cap.
    BOOST_CHECK_EQUAL(CAmount{14 * COIN} * Consensus::EMISSION_ERA_BLOCKS, Consensus::MAX_SUPPLY_SAT / 2);
}

// (c) nothing at 0 and 1, nothing after the end.
BOOST_AUTO_TEST_CASE(subsidy_zero_outside_schedule)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& cp{params->GetConsensus()};
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, cp), 0);
    // No chain carries anything in or has a block-1 distribution (35c4fda,
    // 7263c5d), so block 1 is an ordinary era-0 block and pays the era subsidy:
    // 14 XCF here, 50 XCF on regtest (emission_sums_to_cap_regtest).
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), Consensus::EMISSION_TABLE[0].baseSubsidy);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), 14 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT + 1, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT + 1000, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(std::numeric_limits<int>::max(), cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(-1, cp), 0);
    // limit falls through to the ordinary era subsidy.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), GetBlockSubsidy(1, cp));
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), 14 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, cp), GetBlockSubsidy(2, cp));
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT + 1, cp), 0);
    // A chain without a table pays no subsidy anywhere.
    Consensus::Params empty{cp};
    empty.emissionTable.clear();
    empty.emissionClosingDustSat = 0;
    BOOST_CHECK_EQUAL(empty.EmissionEndHeight(), Consensus::EMISSION_START_HEIGHT - 1); // 0: no block ever pays
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, empty), 0);
}

// The v2 mainnet has its own network identity (review follow-up, stage B4):
// magic 'X','P','A',0x03 — the v1 chain's 'X','P','A',0x02 is nobody's on this
// tree, so a regenesis node can never peer with a v1 node — while the P2P port
// (9333) and the address HRP (xpa) stay. And a mainnet node built while
// GENESIS_IS_FINAL is false (the v1 genesis stands in) refuses to start unless
// -allowunfinalgenesis is given (kernel/chainparams.h,
// CheckGenesisFinalityForStartup, applied by AppInitParameterInteraction).
BOOST_AUTO_TEST_CASE(mainnet_v2_identity_and_startup_gate)
{
    const auto main{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto testnet{CreateChainParams(*m_node.args, ChainType::TESTNET)};
    const auto regtest{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const MessageStartChars v2_magic{'X', 'P', 'A', 0x03};
    const MessageStartChars v1_magic{'X', 'P', 'A', 0x02};
    BOOST_CHECK(main->MessageStart() == v2_magic);
    BOOST_CHECK(GetNetworkForMagic(v2_magic) == ChainType::MAIN);
    BOOST_CHECK(!GetNetworkForMagic(v1_magic));
    BOOST_CHECK(main->MessageStart() != testnet->MessageStart());
    BOOST_CHECK(main->MessageStart() != regtest->MessageStart());
    BOOST_CHECK_EQUAL(main->GetDefaultPort(), 9333);
    BOOST_CHECK_EQUAL(main->Bech32HRP(), "xpa");

    // The startup gate: mainnet + placeholder genesis refuses unless overridden;
    // the other chains and a final genesis never refuse.
    BOOST_CHECK(!main->GenesisIsFinal()); // until cutover step 3 pastes the xcoin-genesis output
    BOOST_CHECK_EQUAL(main->GenesisBlock().GetHash(), Consensus::V1_GENESIS_HASH);
    const std::optional<std::string> refusal{CheckGenesisFinalityForStartup(*main, /*allow_unfinal_genesis=*/false)};
    BOOST_REQUIRE(refusal.has_value());
    BOOST_CHECK(refusal->find("GENESIS_IS_FINAL") != std::string::npos);
    BOOST_CHECK(refusal->find("-allowunfinalgenesis") != std::string::npos);
    BOOST_CHECK(refusal->find(Consensus::V1_GENESIS_HASH.ToString()) != std::string::npos);
    BOOST_CHECK(!CheckGenesisFinalityForStartup(*main, /*allow_unfinal_genesis=*/true));
    // Testnet A's genesis is final (re-mined 2026-09-14); the startup gate itself
    // is mainnet-only by design.
    BOOST_CHECK(testnet->GenesisIsFinal());
    BOOST_CHECK(testnet->GenesisBlock().GetHash() != Consensus::V1_GENESIS_HASH);
    BOOST_CHECK(!CheckGenesisFinalityForStartup(*testnet, false));
    BOOST_CHECK(!CheckGenesisFinalityForStartup(*regtest, false));
    // The unit-test harness itself runs with the override (setup_common.cpp);
    // a real mainnet nexd from this tree exits before any networking.
    BOOST_CHECK(m_node.args->GetBoolArg("-allowunfinalgenesis", false));
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Stage A2: block weight (REGENESIS.md section 0) and the data-carrier cap
// (section 5).

namespace {
/** An OP_RETURN output whose scriptPubKey is exactly `script_bytes` long
 *  (>= 1; sizes 78 and 259 are not reachable with one push and are avoided by
 *  the callers). */
CTxOut DataCarrierOut(size_t script_bytes, unsigned char fill = 0x58)
{
    CScript spk;
    spk << OP_RETURN;
    if (script_bytes > 1) {
        size_t data{0};
        if (script_bytes <= 77) data = script_bytes - 2;        // direct push: 1 opcode byte
        else if (script_bytes <= 258) data = script_bytes - 3;  // OP_PUSHDATA1
        else data = script_bytes - 4;                           // OP_PUSHDATA2
        spk << std::vector<unsigned char>(data, fill);
    }
    BOOST_REQUIRE_EQUAL(spk.size(), script_bytes);
    return CTxOut{0, spk};
}

/** OP_RETURN outputs whose scriptPubKeys sum to exactly `total` bytes, each at
 *  most 9,000 bytes (the v1 inscription used ~9.9 KB outputs) and at least 260. */
std::vector<CTxOut> DataCarrierOuts(uint64_t total)
{
    std::vector<CTxOut> outs;
    while (total > 0) {
        size_t chunk;
        if (total <= 9000) {
            chunk = total;
        } else if (total < 9000 + 260) {
            chunk = total / 2; // split so the remainder is also >= 260
        } else {
            chunk = 9000;
        }
        BOOST_REQUIRE(chunk >= 1 && chunk != 78 && chunk != 259);
        outs.push_back(DataCarrierOut(chunk));
        total -= chunk;
    }
    return outs;
}

/** Append OP_RETURN outputs to the block's coinbase, refresh the witness
 *  commitment and merkle root, and re-grind the (regtest, powLimit) PoW. */
void AddCoinbaseData(CBlock& block, const std::vector<CTxOut>& outs, ChainstateManager& chainman)
{
    CMutableTransaction cb{*block.vtx[0]};
    cb.vout.insert(cb.vout.end(), outs.begin(), outs.end());
    block.vtx[0] = MakeTransactionRef(std::move(cb));
    RegenerateCommitments(block, chainman);
    while (!CheckProofOfWork(block, block.nBits, chainman.GetConsensus())) ++block.nNonce;
}

std::string Validity(Chainstate& chainstate, const CBlock& block)
{
    LOCK(cs_main);
    const BlockValidationState state{TestBlockValidity(chainstate, block, /*check_pow=*/false, /*check_merkle_root=*/true)};
    return state.IsValid() ? std::string{"valid"} : state.GetRejectReason();
}
} // namespace

BOOST_AUTO_TEST_SUITE(regenesis_datacarrier_tests)

// The constants the spec fixes (section 0 and 5) and their derived values.
BOOST_AUTO_TEST_CASE(constants)
{
    // 64M WU frozen by the founder on 2026-09-07 (REGENESIS.md section 0): the ceiling
    // is set generously AT GENESIS because raising a block limit is a hard fork while
    // lowering one is a soft fork. The two validation weights in xcoin_v3.h were scaled
    // 4x alongside it so the 25.3 s worst-case CPU bound did not move.
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 64000000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 64000000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SIGOPS_COST, 1280000);         // 16x Bitcoin's 80,000, with the weight
    BOOST_CHECK_EQUAL(MAX_STANDARD_TX_SIGOPS_COST, 256000U);    // MAX_BLOCK_SIGOPS_COST / 5
    // The mining default sits under the 33.5 MB transport wall; consensus stays at 64M WU.
    BOOST_CHECK_EQUAL(DEFAULT_BLOCK_MAX_WEIGHT, 4'000'000U);
    BOOST_CHECK_LT(DEFAULT_BLOCK_MAX_WEIGHT, MAX_BLOCK_WEIGHT);
    // Data carriage, lowered from 100,000 on 2026-09-09. The cap is a stated
    // capacity — one hundred anchors of one MAX_OP_RETURN_RELAY each — not a
    // round number, so the two constants may never drift apart.
    BOOST_CHECK_EQUAL(DATACARRIER_ANCHOR_BYTES, 80U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_DATACARRIER_ANCHORS, 100U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_DATACARRIER_BYTES, 8000U);
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, DATACARRIER_ANCHOR_BYTES);
    // No height is exempt: nothing is inscribed in block 1 and the exemption
    // (and its constant) is gone, so the hole where block 1's miner could write
    // ~63 MB into the chain forever cannot come back by accident.
    BOOST_CHECK(MAX_PROTOCOL_MESSAGE_LENGTH >= MAX_BLOCK_SERIALIZED_SIZE); // the buffer admits a maximum block ...
    // ... but the transports do not (v1 MAX_SIZE 32 MiB, BIP324 v2 16,777,215 bytes), so the
    // mining policy is capped at what they carry (audit finding 8).
    BOOST_CHECK(MAX_RELAYABLE_BLOCK_WEIGHT + 13 <= 16'777'215U);
    BOOST_CHECK(DEFAULT_BLOCK_MAX_WEIGHT <= MAX_RELAYABLE_BLOCK_WEIGHT);
    BOOST_CHECK(MAX_RELAYABLE_BLOCK_WEIGHT < MAX_BLOCK_WEIGHT);
    BOOST_CHECK(DEFAULT_COINBASE_DATACARRIER_RESERVE >= MINIMUM_WITNESS_COMMITMENT);
}

// GetBlockDataCarrierBytes counts the scriptPubKey bytes of every OP_RETURN
// output, over every transaction, and nothing else.
BOOST_AUTO_TEST_CASE(data_carrier_bytes)
{
    BOOST_CHECK(IsDataCarrierOutput(DataCarrierOut(1)));
    BOOST_CHECK(IsDataCarrierOutput(DataCarrierOut(80)));
    BOOST_CHECK(!IsDataCarrierOutput(PQOut(COIN, 0x11)));
    BOOST_CHECK(!IsDataCarrierOutput(CTxOut{0, CScript{}}));

    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout = {PQOut(50 * COIN, 0x11), DataCarrierOut(38), DataCarrierOut(1)};
    BOOST_CHECK_EQUAL(GetTransactionDataCarrierBytes(CTransaction{cb}), 39U);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout = {DataCarrierOut(80), PQOut(COIN, 0x22), DataCarrierOut(9000), DataCarrierOut(300)};
    BOOST_CHECK_EQUAL(GetTransactionDataCarrierBytes(CTransaction{tx}), 9380U);

    CMutableTransaction plain;
    plain.vin.resize(1);
    plain.vout = {PQOut(COIN, 0x33)};
    BOOST_CHECK_EQUAL(GetTransactionDataCarrierBytes(CTransaction{plain}), 0U);

    CBlock block;
    block.vtx = {MakeTransactionRef(cb), MakeTransactionRef(tx), MakeTransactionRef(plain)};
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(block), 39U + 9380U);

    // The helper used below produces exact totals.
    for (const uint64_t total : {1U, 77U, 79U, 260U, 9000U, 9001U, 9259U, 9260U, 100000U, 100001U}) {
        const auto outs{DataCarrierOuts(total)};
        uint64_t sum{0};
        for (const CTxOut& o : outs) sum += o.scriptPubKey.size();
        BOOST_CHECK_EQUAL(sum, total);
    }
}

// Every height is capped, block 1 included (35c4fda: nothing is inscribed, so
// the exemption block 1 once had is gone): 8,000 bytes accepted, 8,001 rejected
// with bad-blk-datacarrier, both through TestBlockValidity and ProcessNewBlock.
BOOST_FIXTURE_TEST_CASE(cap_applies_at_every_height, RegTestingSetup)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    BlockAssembler::Options options;
    options.coinbase_output_script = GetTestPQScript();
    options.include_dummy_extranonce = true;

    // Height 1, well over the cap: refused like any other block, marked invalid,
    // and the chain stays at the genesis.
    {
        auto block{std::make_shared<CBlock>(BlockAssembler{chainstate, nullptr, options}.CreateNewBlock()->block)};
        AddCoinbaseData(*block, DataCarrierOuts(3 * MAX_BLOCK_DATACARRIER_BYTES), *m_node.chainman);
        BOOST_CHECK(GetBlockDataCarrierBytes(*block) > 3 * MAX_BLOCK_DATACARRIER_BYTES);
        BOOST_CHECK_EQUAL(Validity(chainstate, *block), "bad-blk-datacarrier");
        bool new_block{false};
        BOOST_CHECK(!m_node.chainman->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 0);
        const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
    }
    // Height 1, exactly at the cap: valid, and it extends the chain.
    {
        const CBlock tmpl1{BlockAssembler{chainstate, nullptr, options}.CreateNewBlock()->block};
        auto block{std::make_shared<CBlock>(tmpl1)};
        AddCoinbaseData(*block, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - GetBlockDataCarrierBytes(tmpl1)), *m_node.chainman);
        BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(*block), MAX_BLOCK_DATACARRIER_BYTES);
        BOOST_CHECK_EQUAL(Validity(chainstate, *block), "valid");
        bool new_block{false};
        BOOST_CHECK(m_node.chainman->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 1);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(), block->GetHash());
    }

    // Height 2: the template's coinbase already carries the witness commitment
    // (38 bytes of OP_RETURN), so top it up to exactly the cap.
    const CBlock tmpl{BlockAssembler{chainstate, nullptr, options}.CreateNewBlock()->block};
    const uint64_t present{GetBlockDataCarrierBytes(tmpl)};
    BOOST_CHECK_EQUAL(present, MINIMUM_WITNESS_COMMITMENT);

    auto at_cap{std::make_shared<CBlock>(tmpl)};
    AddCoinbaseData(*at_cap, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - present), *m_node.chainman);
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(*at_cap), MAX_BLOCK_DATACARRIER_BYTES);
    BOOST_CHECK_EQUAL(Validity(chainstate, *at_cap), "valid");

    auto over_cap{std::make_shared<CBlock>(tmpl)};
    AddCoinbaseData(*over_cap, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - present + 1), *m_node.chainman);
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(*over_cap), MAX_BLOCK_DATACARRIER_BYTES + 1);
    BOOST_CHECK_EQUAL(Validity(chainstate, *over_cap), "bad-blk-datacarrier");

    // The same block far over the cap (an inscription-sized payload) is also rejected.
    auto far_over{std::make_shared<CBlock>(tmpl)};
    AddCoinbaseData(*far_over, DataCarrierOuts(3 * MAX_BLOCK_DATACARRIER_BYTES), *m_node.chainman);
    BOOST_CHECK_EQUAL(Validity(chainstate, *far_over), "bad-blk-datacarrier");

    // End to end: the over-cap block is refused by AcceptBlock (the rule lives
    // in ContextualCheckBlock, like bad-blk-weight, so ProcessNewBlock itself
    // fails), marked invalid and does not extend the chain; the at-cap block does.
    {
        bool new_block{false};
        BOOST_CHECK(!m_node.chainman->ProcessNewBlock(over_cap, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 1);
        const CBlockIndex* index{m_node.chainman->m_blockman.LookupBlockIndex(over_cap->GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
    }
    {
        bool new_block{false};
        BOOST_CHECK(m_node.chainman->ProcessNewBlock(at_cap, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 2);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(), at_cap->GetHash());
    }
}

namespace {
/** A transaction spending the fixture's coinbase `n` (50 XCF to the test PQ
 *  key) back to the test key, carrying `data_bytes` of OP_RETURN outputs and
 *  paying `fee`. */
CMutableTransaction SpendWithData(const TestChain100Setup& setup, size_t n, uint64_t data_bytes, CAmount fee)
{
    const CTransactionRef& coinbase{setup.m_coinbase_txns.at(n)};
    BOOST_REQUIRE(IsTestPQScript(coinbase->vout[0].scriptPubKey));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{coinbase->GetHash(), 0});
    tx.vout.emplace_back(coinbase->vout[0].nValue - fee, GetTestPQScript());
    const auto data{DataCarrierOuts(data_bytes)};
    tx.vout.insert(tx.vout.end(), data.begin(), data.end());
    SignTestPQInput(tx, 0, coinbase->vout[0]);
    return tx;
}
} // namespace

// The cap is over the whole block: OP_RETURN bytes in ordinary transactions
// count together with the coinbase's.
BOOST_FIXTURE_TEST_CASE(cap_spans_all_transactions, TestChain100Setup)
{
    mineBlocks(10); // coinbases 1..10 are mature at height 111
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    const CAmount fee{10000};
    const uint64_t tx_data{3000};
    const std::vector<CMutableTransaction> txns{SpendWithData(*this, 0, tx_data, fee), SpendWithData(*this, 1, tx_data / 2, fee)};

    const CBlock base{CreateBlock(txns, GetTestPQScript(), chainstate)};
    const uint64_t present{GetBlockDataCarrierBytes(base)};
    BOOST_CHECK_EQUAL(present, MINIMUM_WITNESS_COMMITMENT + tx_data + tx_data / 2);
    BOOST_CHECK_EQUAL(Validity(chainstate, base), "valid");

    CBlock at_cap{base};
    AddCoinbaseData(at_cap, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - present), *m_node.chainman);
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(at_cap), MAX_BLOCK_DATACARRIER_BYTES);
    BOOST_CHECK_EQUAL(Validity(chainstate, at_cap), "valid");

    // One more byte, put in a transaction rather than in the coinbase.
    const std::vector<CMutableTransaction> txns_plus{SpendWithData(*this, 0, tx_data + 1, fee), txns[1]};
    CBlock over_cap{CreateBlock(txns_plus, GetTestPQScript(), chainstate)};
    AddCoinbaseData(over_cap, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - present), *m_node.chainman);
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(over_cap), MAX_BLOCK_DATACARRIER_BYTES + 1);
    BOOST_CHECK_EQUAL(Validity(chainstate, over_cap), "bad-blk-datacarrier");

    // Only the coinbase's own bytes: the block assembler reserve is what a
    // template pays for, the rule itself counts exactly what is there.
    CBlock coinbase_only{CreateBlock({}, GetTestPQScript(), chainstate)};
    AddCoinbaseData(coinbase_only, DataCarrierOuts(MAX_BLOCK_DATACARRIER_BYTES - MINIMUM_WITNESS_COMMITMENT + 1), *m_node.chainman);
    BOOST_CHECK_EQUAL(Validity(chainstate, coinbase_only), "bad-blk-datacarrier");
}

// The block assembler keeps templates under the cap: with four 2,000-byte
// carriers in the mempool it includes three (plus the 1,000-byte coinbase
// reserve) and skips the fourth, and the template passes TestBlockValidity.
BOOST_FIXTURE_TEST_CASE(assembler_respects_cap, TestChain100Setup)
{
    mineBlocks(10); // coinbases 1..10 are mature at height 111
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    CTxMemPool& pool{*Assert(m_node.mempool)};
    const uint64_t tx_data{2000};
    BOOST_REQUIRE(3 * tx_data + DEFAULT_COINBASE_DATACARRIER_RESERVE <= MAX_BLOCK_DATACARRIER_BYTES);
    BOOST_REQUIRE(4 * tx_data + DEFAULT_COINBASE_DATACARRIER_RESERVE > MAX_BLOCK_DATACARRIER_BYTES);

    std::vector<Txid> txids;
    {
        LOCK2(cs_main, pool.cs);
        TestMemPoolEntryHelper entry;
        for (size_t n = 0; n < 4; ++n) {
            // Equal fees, so the assembler's order is the mempool's: whichever
            // it picks, exactly three fit.
            const CMutableTransaction tx{SpendWithData(*this, n, tx_data, COIN)};
            txids.push_back(tx.GetHash());
            TryAddToMempool(pool, entry.Fee(COIN).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
            BOOST_REQUIRE(pool.GetIter(tx.GetHash()).has_value());
        }
    }

    BlockAssembler::Options options;
    options.coinbase_output_script = GetTestPQScript();
    options.include_dummy_extranonce = true;
    const auto tmpl{BlockAssembler{chainstate, &pool, options}.CreateNewBlock()}; // runs TestBlockValidity
    BOOST_REQUIRE(tmpl);
    const CBlock& block{tmpl->block};
    BOOST_CHECK_EQUAL(block.vtx.size(), 1U + 3U);
    BOOST_CHECK_EQUAL(GetBlockDataCarrierBytes(block), MINIMUM_WITNESS_COMMITMENT + 3 * tx_data);
    BOOST_CHECK(GetBlockDataCarrierBytes(block) + DEFAULT_COINBASE_DATACARRIER_RESERVE - MINIMUM_WITNESS_COMMITMENT <= MAX_BLOCK_DATACARRIER_BYTES);
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        BOOST_CHECK(std::find(txids.begin(), txids.end(), block.vtx[i]->GetHash()) != txids.end());
    }
    // The template leaves the merkle root to the miner; fill it in for a full validity check.
    CBlock mined{block};
    mined.hashMerkleRoot = BlockMerkleRoot(mined);
    BOOST_CHECK_EQUAL(Validity(chainstate, mined), "valid");
}

BOOST_AUTO_TEST_SUITE_END()


// ---------------------------------------------------------------------------
// Stage A3: the charter commitment and the currency id (REGENESIS.md section 1)
// and the genesis tooling (section 8).

namespace {
charter::Digest Sha256Digest(std::span<const unsigned char> a, std::span<const unsigned char> b = {})
{
    charter::Digest out;
    CSHA256 hasher;
    hasher.Write(a.data(), a.size());
    if (!b.empty()) hasher.Write(b.data(), b.size());
    hasher.Finalize(out.data());
    return out;
}

std::vector<unsigned char> HeaderBytes(const CBlockHeader& header)
{
    DataStream ss;
    ss << header;
    return {UCharCast(ss.data()), UCharCast(ss.data()) + ss.size()};
}

std::span<const unsigned char> Bytes(std::string_view s)
{
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

constexpr std::string_view CHARTER_HASH_HEX{"415b1dbc7ff2cd14b747b300ecd95862540e12305a801bb2bfed8b93c5d84689"}; // shasum -a 256 contrib/regenesis/CHARTER.md (section 4 rewritten 2026-09-14)
constexpr std::string_view V1_HEADER_SHA256_HEX{"fe5787421dc40ac6a6e8df6b83bc41660df0fc0f22d95fde3d0c32530ae2d16d"};
} // namespace

BOOST_FIXTURE_TEST_SUITE(regenesis_charter_tests, BasicTestingSetup)

// CHARTER_HASH is recomputed from contrib/regenesis/CHARTER.md, which the build
// embeds byte for byte: any edit of the charter fails here until the constant
// in consensus/params.h is changed on purpose. The text must be as the spec
// commits it: UTF-8, LF line endings, no trailing whitespace.
BOOST_AUTO_TEST_CASE(charter_hash_matches_file)
{
    const std::string_view text{charter::Text()};
    BOOST_REQUIRE(!text.empty());
    BOOST_CHECK(text.starts_with("# The xCoin Charter\n"));
    BOOST_CHECK_EQUAL(text.back(), '\n');
    BOOST_CHECK_MESSAGE(text.find('\r') == std::string_view::npos, "CHARTER.md must use LF line endings");
    for (size_t pos{0}; pos < text.size();) {
        const size_t nl{text.find('\n', pos)};
        const std::string_view line{text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos)};
        BOOST_CHECK_MESSAGE(line.empty() || (line.back() != ' ' && line.back() != '\t'), "trailing whitespace in CHARTER.md line: " << line);
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    // The charter names its cap. Its lineage is the new genesis (section 3),
    // not the first chain's, so the v1 hash is deliberately absent.
    BOOST_CHECK(text.find(Consensus::V1_GENESIS_HASH.GetHex()) == std::string_view::npos);
    BOOST_CHECK(text.find("21,000,000 XCF") != std::string_view::npos);

    const charter::Digest recomputed{Sha256Digest(Bytes(text))};
    BOOST_CHECK(charter::TextHash() == recomputed);
    BOOST_CHECK_MESSAGE(Consensus::CHARTER_HASH == recomputed,
                        "contrib/regenesis/CHARTER.md changed: its SHA-256 is now " << charter::DigestHex(recomputed)
                        << " but Consensus::CHARTER_HASH is " << charter::DigestHex(Consensus::CHARTER_HASH));
    BOOST_CHECK_EQUAL(charter::DigestHex(Consensus::CHARTER_HASH), CHARTER_HASH_HEX);
    BOOST_CHECK_EQUAL(charter::DigestHex(recomputed), HexStr(recomputed));
}

// The v1 genesis header is pinned as raw bytes; its double SHA-256 is the v1
// block hash and its single SHA-256 is the lineage field of the commitment.
// Mainnet compiles that header as its placeholder genesis until the v2 genesis
// is final: identifiable, but unlaunchable (block 1 is refused).
BOOST_AUTO_TEST_CASE(v1_genesis_header_pinned)
{
    const CBlockHeader v1{charter::V1GenesisHeader()};
    BOOST_CHECK_EQUAL(v1.GetHash(), Consensus::V1_GENESIS_HASH);
    BOOST_CHECK_EQUAL(v1.nVersion, 1);
    BOOST_CHECK(v1.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(v1.hashMerkleRoot, uint256{"fac4f4af0516d1005efde194571656e20369eccd2c97bddd74a055b900692c88"});
    BOOST_CHECK_EQUAL(v1.nTime, 1788220800U);
    BOOST_CHECK_EQUAL(v1.nBits, 0x1e0fffffU);
    BOOST_CHECK_EQUAL(v1.nNonce, 1112945U);
    BOOST_CHECK(HeaderBytes(v1) == std::vector<unsigned char>(Consensus::V1_GENESIS_HEADER.begin(), Consensus::V1_GENESIS_HEADER.end()));
    BOOST_CHECK_EQUAL(charter::DigestHex(charter::V1GenesisHeaderSha256()), V1_HEADER_SHA256_HEX);
    BOOST_CHECK(charter::HeaderSha256(v1) == charter::V1GenesisHeaderSha256());
    BOOST_CHECK(charter::HeaderSha256(v1) == Sha256Digest(Consensus::V1_GENESIS_HEADER));

    const auto main{CreateChainParams(*m_node.args, ChainType::MAIN)};
    BOOST_CHECK(!main->GenesisIsFinal());
    BOOST_CHECK_EQUAL(main->GenesisBlock().GetHash(), Consensus::V1_GENESIS_HASH);
    BOOST_CHECK_EQUAL(main->GetConsensus().hashGenesisBlock, Consensus::V1_GENESIS_HASH);
    BOOST_CHECK(HeaderBytes(main->GenesisBlock()) == HeaderBytes(v1));
    BOOST_CHECK(!charter::HasCommitment(*main->GenesisBlock().vtx[0]));
    BOOST_CHECK_EQUAL(main->GetConsensus().metaldagBaseTime, 1788220800);
    // Only testnet A has a final (charter-committing) genesis so far
    // (regenesis_testnet_a_tests); mainnet's is still the v1 placeholder.
    for (const ChainType type : {ChainType::MAIN, ChainType::REGTEST}) {
        const auto p{CreateChainParams(*m_node.args, type)};
        BOOST_CHECK_MESSAGE(!p->GenesisIsFinal(), ChainTypeToString(type) + " claims a final genesis");
        BOOST_CHECK_MESSAGE(!charter::HasCommitment(*p->GenesisBlock().vtx[0]), ChainTypeToString(type) + " genesis carries a charter output");
    }
}

// OP_RETURN <"XCOIN/charter/1" || CHARTER_HASH>: 47 bytes of payload, a 49-byte
// script (a coinbase output in block 0: the 80-byte data-carrier relay policy does
// not apply to it, the 8,000-byte consensus block cap does), never a distribution
// output. No lineage digest: this chain starts from scratch (35c4fda). The tag
// names the project, never the ticker.
BOOST_AUTO_TEST_CASE(charter_commitment_output)
{
    const std::vector<unsigned char> payload{charter::CommitmentPayload()};
    BOOST_REQUIRE_EQUAL(payload.size(), 47U);
    BOOST_CHECK_EQUAL(std::string(payload.begin(), payload.begin() + 15), "XCOIN/charter/1");
    BOOST_CHECK_EQUAL(std::string(payload.begin(), payload.begin() + 15), Consensus::CHARTER_COMMITMENT_TAG);
    BOOST_CHECK(std::string(payload.begin(), payload.begin() + 15).find("XCF") == std::string::npos); // never the ticker
    BOOST_CHECK(std::equal(payload.begin() + 15, payload.end(), Consensus::CHARTER_HASH.begin(), Consensus::CHARTER_HASH.end()));
    BOOST_CHECK_EQUAL(HexStr(payload), "58434f494e2f636861727465722f31" + std::string{CHARTER_HASH_HEX});

    const CScript script{charter::CommitmentScript()};
    BOOST_REQUIRE_EQUAL(script.size(), 49U); // OP_RETURN <push 47> <payload>: 47 fits a direct push opcode
    BOOST_CHECK_EQUAL(script[0], OP_RETURN);
    BOOST_CHECK_EQUAL(script[1], 47);
    BOOST_CHECK(std::equal(script.begin() + 2, script.end(), payload.begin(), payload.end()));
    BOOST_CHECK(script.size() <= MAX_BLOCK_DATACARRIER_BYTES); // a block-0 coinbase output: the consensus cap applies, the relay policy does not
    const CTxOut out{0, script};
    BOOST_CHECK(IsDataCarrierOutput(out));

    CMutableTransaction cb;
    cb.vin.emplace_back();
    cb.vout.push_back(out);
    BOOST_CHECK(charter::HasCommitment(CTransaction{cb}));
    cb.vout.insert(cb.vout.begin(), PQOut(1, 0x11)); // any position
    BOOST_CHECK(charter::HasCommitment(CTransaction{cb}));
    cb.vout.back().nValue = 1; // the value matters
    BOOST_CHECK(!charter::HasCommitment(CTransaction{cb}));
    cb.vout.back().nValue = 0;
    std::vector<unsigned char> altered{payload};
    altered[20] ^= 0x01; // the payload matters
    cb.vout.back().scriptPubKey = CScript() << OP_RETURN << altered;
    BOOST_CHECK(!charter::HasCommitment(CTransaction{cb}));
    BOOST_CHECK(!charter::HasCommitment(CTransaction{CMutableTransaction{}}));
}

// charter::CreateGenesisBlock: the v2 genesis form. One coinbase in the Bitcoin
// genesis shape (486604799 <4> <message>), one zero-value charter output,
// nothing minted, and a coinbase that CheckBlock (which the node runs on the
// genesis at startup) accepts. CURRENCY_ID = SHA-256(header || charter text).
BOOST_AUTO_TEST_CASE(charter_genesis_block)
{
    // No numeral (this is the genesis, not a second one), the supply in its
    // smallest unit, and no charter hash (the coinbase output carries all 32 bytes).
    const std::string message{charter::GenesisMessage("2026-10-01")};
    BOOST_CHECK_EQUAL(message, "Hic experimentum prosperat - 2026-10-01 - 2,100,000,000,000,000 sats, 21M XCF");
    BOOST_CHECK_EQUAL(message.size(), 77U);
    BOOST_CHECK(message.find(std::string{CHARTER_HASH_HEX.substr(0, 16)}) == std::string::npos);

    const CBlock g{charter::CreateGenesisBlock(message, 1790000000, 7, 0x1e0fffff, 1)};
    BOOST_REQUIRE_EQUAL(g.vtx.size(), 1U);
    const CTransaction& cb{*g.vtx[0]};
    BOOST_CHECK(cb.IsCoinBase());
    BOOST_CHECK_EQUAL(cb.version, 1U);
    BOOST_REQUIRE_EQUAL(cb.vin.size(), 1U);
    BOOST_CHECK_EQUAL(cb.vin[0].scriptSig.size(), 7U + 2U + message.size()); // 04ffff001d 0104, then OP_PUSHDATA1 <len> <message>: 86
    BOOST_CHECK_EQUAL(HexStr(std::vector<unsigned char>(cb.vin[0].scriptSig.begin(), cb.vin[0].scriptSig.begin() + 7)), "04ffff001d0104"); // as the v1 (and Bitcoin) genesis
    BOOST_CHECK(std::string(cb.vin[0].scriptSig.begin(), cb.vin[0].scriptSig.end()).find(message) != std::string::npos);
    BOOST_REQUIRE_EQUAL(cb.vout.size(), 1U);
    BOOST_CHECK_EQUAL(cb.vout[0].nValue, 0);
    BOOST_CHECK(cb.vout[0].scriptPubKey == charter::CommitmentScript());
    BOOST_CHECK(charter::HasCommitment(cb));
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(cb, state, /*permit_v2_outputs=*/true));
    // ...which is why the message carries 16 hex characters of the charter hash and not 64:
    // with the full digest the scriptSig is 143 bytes and every node would refuse its own genesis.
    const CBlock too_long{charter::CreateGenesisBlock("Hic experimentum prosperat II - 2026-10-01 - 21,000,000 XCF - charter " + charter::DigestHex(Consensus::CHARTER_HASH),
                                                      1790000000, 7, 0x1e0fffff, 1)};
    TxValidationState long_state;
    BOOST_CHECK(!CheckTransaction(*too_long.vtx[0], long_state, /*permit_v2_outputs=*/true));
    BOOST_CHECK_EQUAL(long_state.GetRejectReason(), "bad-cb-length");

    BOOST_CHECK_EQUAL(g.nVersion, 1);
    BOOST_CHECK_EQUAL(g.nTime, 1790000000U);
    BOOST_CHECK_EQUAL(g.nBits, 0x1e0fffffU);
    BOOST_CHECK_EQUAL(g.nNonce, 7U);
    BOOST_CHECK(g.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(g.hashMerkleRoot, cb.GetHash().ToUint256());
    BOOST_CHECK_EQUAL(g.hashMerkleRoot, BlockMerkleRoot(g));
    // Deterministic, and every field matters.
    BOOST_CHECK_EQUAL(charter::CreateGenesisBlock(message, 1790000000, 7, 0x1e0fffff, 1).GetHash(), g.GetHash());
    BOOST_CHECK(charter::CreateGenesisBlock(message, 1790000000, 8, 0x1e0fffff, 1).GetHash() != g.GetHash());
    BOOST_CHECK(charter::CreateGenesisBlock(message, 1790000001, 7, 0x1e0fffff, 1).GetHash() != g.GetHash());
    BOOST_CHECK(charter::CreateGenesisBlock(message + "!", 1790000000, 7, 0x1e0fffff, 1).hashMerkleRoot != g.hashMerkleRoot);

    const std::vector<unsigned char> header_bytes{HeaderBytes(g)};
    BOOST_REQUIRE_EQUAL(header_bytes.size(), 80U);
    const charter::Digest id{charter::CurrencyId(g)};
    BOOST_CHECK(id == Sha256Digest(header_bytes, Bytes(charter::Text())));
    BOOST_CHECK(id != charter::CurrencyId(charter::CreateGenesisBlock(message, 1790000000, 8, 0x1e0fffff, 1)));
    // The id the RPC reports while the v1 placeholder stands in (not to be attested).
    // It is SHA-256(v1 header || charter text), so it moves with every charter edit;
    // re-pinned 2026-09-14 for charter 415b1dbc... (section 4: the 14 XCF schedule).
    BOOST_CHECK_EQUAL(charter::DigestHex(charter::CurrencyId(charter::V1GenesisHeader())), "53a3c8998b634b1960bc2de712c474f063e5b728c19cab8fc338b597dd1b9559");
}

// The mining path xcoin-genesis uses, in-process on regtest's 1 MiB DAG:
// metaldag::PoWHash under metaldagBaseTime = nTime, accepted by
// CheckProofOfWorkImpl — exactly what the node verifies for every header.
BOOST_AUTO_TEST_CASE(genesis_tool_mining_path)
{
    Consensus::Params params{CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus()};
    const uint32_t n_time{1788220800}; // in the past, so the node's wall-clock gate is not in the way
    params.metaldagBaseTime = n_time;
    params.hashGenesisBlock.SetNull();
    const uint32_t n_bits{0x207fffff};
    BOOST_REQUIRE(DeriveTarget(n_bits, params.powLimit));
    BOOST_CHECK_EQUAL(metaldag::GetEpochSizing(n_time, params).epoch, 0U);

    CBlock g{charter::CreateGenesisBlock(charter::GenesisMessage("2026-09-01"), n_time, 0, n_bits, 1)};
    uint64_t attempts{0};
    while (!CheckProofOfWorkImpl(metaldag::PoWHash(g, params), n_bits, params)) {
        ++g.nNonce;
        BOOST_REQUIRE_LT(++attempts, 10000U);
    }
    const CBlockHeader header{g};
    BOOST_CHECK(CheckProofOfWork(header, n_bits, params)); // the node's header check, no genesis exemption in play
    BOOST_CHECK(metaldag::PoWHash(header, params) != header.GetHash()); // MetalDAG, not SHA-256d
    CBlockHeader other{header};
    other.nNonce += 1;
    BOOST_CHECK(metaldag::PoWHash(other, params) != metaldag::PoWHash(header, params));
    other = header;
    other.nTime += 1;
    BOOST_CHECK(metaldag::PoWHash(other, params) != metaldag::PoWHash(header, params));
    // metaldagBaseTime is part of the answer: the same header in another epoch hashes differently.
    Consensus::Params shifted{params};
    shifted.metaldagBaseTime = n_time - params.metaldagEpochSeconds;
    BOOST_CHECK_EQUAL(metaldag::GetEpochSizing(n_time, shifted).epoch, 1U);
    BOOST_CHECK(metaldag::PoWHash(header, shifted) != metaldag::PoWHash(header, params));
}

// getcharter: {charter_hash, currency_id, genesis_hash, v1_genesis_hash, genesis_is_final}.
BOOST_FIXTURE_TEST_CASE(getcharter_rpc, TestingSetup)
{
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getcharter";
    request.params = UniValue{UniValue::VARR};
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const UniValue result{tableRPC.execute(request)};
    BOOST_REQUIRE(result.isObject());
    BOOST_CHECK_EQUAL(result.getKeys().size(), 5U);
    BOOST_CHECK_EQUAL(result.find_value("charter_hash").get_str(), CHARTER_HASH_HEX);
    BOOST_CHECK_EQUAL(result.find_value("currency_id").get_str(), charter::DigestHex(charter::CurrencyId(Params().GenesisBlock())));
    BOOST_CHECK_EQUAL(result.find_value("genesis_hash").get_str(), Params().GenesisBlock().GetHash().GetHex());
    BOOST_CHECK_EQUAL(result.find_value("v1_genesis_hash").get_str(), Consensus::V1_GENESIS_HASH.GetHex());
    BOOST_CHECK_EQUAL(result.find_value("genesis_is_final").get_bool(), false);
}

// Addresses on the v3-only chains (REGENESIS.md sections 3 and 4): mainnet and the
// rehearsal chain refuse a first-chain xpa1z/txa1z string wherever an address is
// parsed and name the xpa1r/txa1r of the SAME key; validateaddress reports that
// address, a raw witness v2 script or a bare key hash. Regtest, which still has
// witness v2 outputs, keeps accepting them.
BOOST_FIXTURE_TEST_CASE(v2_address_refused_where_the_chain_forbids_v2, TestingSetup)
{
    constexpr std::string_view V2_MAIN{"xpa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5sdnc0av"};
    constexpr std::string_view KEY_HASH{"a158ac5047845bfdedad6e2e3e074b2bac33cefa7440b6b3aba668b40bd8bce9"};
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN); // the fixture's default chain

    // Mainnet admits only witness v3 outputs, so a v2 address is refused where it is parsed.
    std::string error;
    const CTxDestination refused{DecodeDestination(std::string{V2_MAIN}, error)};
    BOOST_CHECK(!IsValidDestination(refused));
    BOOST_CHECK_MESSAGE(error.find("witness v3") != std::string::npos, error);

    // The rehearsal chain refuses the same way, in its own HRP; regtest does not.
    const auto rehearsal{CreateChainParams(*m_node.args, ChainType::TESTNET)};
    const auto regtest{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const uint256 key_hash{ParseHex(std::string{KEY_HASH})};
    WitnessV2PQ v2;
    std::copy(key_hash.begin(), key_hash.end(), v2.begin());
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeDestination(v2, *rehearsal), *rehearsal, error)));
    BOOST_CHECK_MESSAGE(error.find("witness v3") != std::string::npos, error);
    BOOST_CHECK(std::holds_alternative<WitnessV2PQ>(DecodeDestination(EncodeDestination(v2, *regtest), *regtest, error)));

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "validateaddress";
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(std::string{V2_MAIN});
    const UniValue validate{tableRPC.execute(request)};
    BOOST_CHECK_EQUAL(validate.find_value("isvalid").get_bool(), false);
    BOOST_CHECK_MESSAGE(validate.find_value("error").get_str().find("witness v3") != std::string::npos, validate.find_value("error").get_str());
}

// The output rule of REGENESIS.md section 3: after genesis, mainnet and the
// rehearsal chain admit only witness v3 and OP_RETURN outputs; regtest and the
// inherited test chains still admit witness v2 so the shared fixtures work.
// Coinbase maturity (founder decision 2026-09-14): 1,000 blocks on mainnet and
// testnet A — about 3.5 days at 300 s, against Bitcoin's 100 (~16.7 h) — so a
// mined reward cannot be spent, and then reorganised away, inside a window that
// rented hashrate could afford. Every chain, regtest included (founder, 2026-09-14:
// "update to 1000 coinbase maturity too"); the test harness passes
// -coinbasematurity=100 on regtest so the inherited fixtures keep mining 100 blocks.
// Audit findings 1 and 3 (2026-09-14). BIP34 never applies to a genesis block: a chain
// whose BIP34 height were 0 rejected its own genesis on -reindex and then asserted on a
// null tip. And headers sync needs a non-zero commitment period on every chain, or the
// first low-work headers batch from a peer asserts.
BOOST_AUTO_TEST_CASE(every_chain_survives_reindex_and_headers_sync)
{
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(*m_node.args, type)};
        BOOST_CHECK_MESSAGE(params->GetConsensus().BIP34Height >= 1, ChainTypeToString(type) + ": BIP34 must not apply to the genesis block");
        BOOST_CHECK_MESSAGE(params->HeadersSync().commitment_period > 0, ChainTypeToString(type) + ": headers-sync commitment period unset");
        BOOST_CHECK_MESSAGE(params->HeadersSync().redownload_buffer_size > 0, ChainTypeToString(type) + ": headers-sync redownload buffer unset");
        // The genesis coinbase does not start with the height-0 push (OP_0), so BIP34 at
        // height 0 would have rejected it: the rule above is what keeps -reindex alive.
        const CScript& sig{params->GenesisBlock().vtx[0]->vin[0].scriptSig};
        BOOST_CHECK_MESSAGE(!sig.empty() && sig[0] != OP_0, ChainTypeToString(type));
    }
}

BOOST_AUTO_TEST_CASE(coinbase_maturity_by_chain)
{
    BOOST_CHECK_EQUAL(Consensus::COINBASE_MATURITY_MAINNET, 1'000);
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(*m_node.args, type)};
        // m_node.args carries the harness's -coinbasematurity=100, which only regtest reads.
        const int expect{type == ChainType::REGTEST ? COINBASE_MATURITY : Consensus::COINBASE_MATURITY_MAINNET};
        BOOST_CHECK_MESSAGE(params->GetConsensus().coinbaseMaturity == expect, ChainTypeToString(type));
    }
    BOOST_CHECK_EQUAL(CChainParams::RegTest(CChainParams::RegTestOptions{})->GetConsensus().coinbaseMaturity, Consensus::COINBASE_MATURITY_MAINNET);
    // The consensus check itself, with mainnet's value: a coinbase mined at height 1
    // is spendable at height 1,001 and not one block sooner.
    CCoinsView dummy;
    CCoinsViewCache view{&dummy};
    const COutPoint prevout{Txid::FromUint256(uint256::ONE), 0};
    view.AddCoin(prevout, Coin{CTxOut{14 * COIN, GetTestPQScript()}, /*nHeightIn=*/1, /*fCoinBaseIn=*/true}, false);
    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(14 * COIN - 10'000, GetTestPQScript());
    const auto check{[&](int spend_height) {
        TxValidationState state;
        CAmount fee{0};
        return Consensus::CheckTxInputs(CTransaction{tx}, state, view, spend_height, Consensus::COINBASE_MATURITY_MAINNET, fee) ? std::string{"ok"} : state.GetRejectReason();
    }};
    BOOST_CHECK_EQUAL(check(1'000), "bad-txns-premature-spend-of-coinbase"); // depth 999
    BOOST_CHECK_EQUAL(check(1'001), "ok");                                   // depth 1,000
    BOOST_CHECK_EQUAL(check(101), "bad-txns-premature-spend-of-coinbase");   // Bitcoin's 100 would have let this through
}

BOOST_AUTO_TEST_CASE(v3_only_output_rule_by_chain)
{
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(*m_node.args, type)};
        const bool expect_v2{type != ChainType::MAIN && type != ChainType::TESTNET};
        BOOST_CHECK_MESSAGE(params->GetConsensus().permitV2Outputs == expect_v2, ChainTypeToString(type));
    }

    const auto check{[](const CTxOut& out, bool permit_v2) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.push_back(out);
        TxValidationState state;
        const bool ok{CheckTransaction(CTransaction{tx}, state, permit_v2)};
        return ok ? std::string{"valid"} : state.GetRejectReason();
    }};
    const CTxOut v2{PQOut(1 * COIN, 0x11)};
    const CTxOut v3{1 * COIN, (CScript() << OP_3 << std::vector<unsigned char>(32, 0x11))};
    BOOST_CHECK_EQUAL(check(v3, false), "valid");
    BOOST_CHECK_EQUAL(check(v3, true), "valid");
    BOOST_CHECK_EQUAL(check(NullDataOut(), false), "valid");
    BOOST_CHECK_EQUAL(check(v2, true), "valid");
    BOOST_CHECK_EQUAL(check(v2, false), "bad-txout-not-pq");
    // v0/v1 stay invalid either way.
    BOOST_CHECK_EQUAL(check(CTxOut{1 * COIN, CScript() << OP_0 << std::vector<unsigned char>(20, 0x11)}, true), "bad-txout-not-pq");
    BOOST_CHECK_EQUAL(check(CTxOut{1 * COIN, CScript() << OP_1 << std::vector<unsigned char>(32, 0x11)}, false), "bad-txout-not-pq");

    // -permitv2outputs is a regtest-only relay knob: refused everywhere else, and it can
    // never turn on relaying an output the chain's own consensus rejects.
    const auto permit{[](ChainType type, const std::vector<std::string>& extra) {
        ArgsManager args;
        SetupChainParamsBaseOptions(args);
        args.AddArg("-permitv2outputs", "", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        std::vector<const char*> argv{"test"};
        for (const std::string& a : extra) argv.push_back(a.c_str());
        std::string error;
        BOOST_REQUIRE_MESSAGE(args.ParseParameters(argv.size(), argv.data(), error), error);
        const auto params{CreateChainParams(args, type)};
        kernel::MemPoolOptions opts;
        const auto result{::ApplyArgsManOptions(args, *params, opts)};
        return result ? (opts.permit_v2_outputs ? "on" : "off") : "refused";
    }};
    BOOST_CHECK_EQUAL(permit(ChainType::REGTEST, {"-permitv2outputs=1"}), "on");
    BOOST_CHECK_EQUAL(permit(ChainType::REGTEST, {"-permitv2outputs=0"}), "off");
    BOOST_CHECK_EQUAL(permit(ChainType::REGTEST, {}), "off"); // default off even where v2 is valid
    BOOST_CHECK_EQUAL(permit(ChainType::MAIN, {"-permitv2outputs=1"}), "refused");
    BOOST_CHECK_EQUAL(permit(ChainType::MAIN, {"-permitv2outputs=0"}), "refused");
    BOOST_CHECK_EQUAL(permit(ChainType::TESTNET, {"-permitv2outputs=1"}), "refused");
    BOOST_CHECK_EQUAL(permit(ChainType::MAIN, {}), "off");
    BOOST_CHECK_EQUAL(permit(ChainType::TESTNET, {}), "off");
}

// The block assembler's DEFAULT coinbase placeholder (node/types.h) has to be a
// valid output type on EVERY chain, because getblocktemplate builds its template
// with it — rpc/mining.cpp passes no coinbase_output_script, since pool software
// builds its own coinbase from coinbasevalue — and then runs TestBlockValidity
// over that template. A placeholder the chain refuses therefore makes
// getblocktemplate fail at every height and no pool can mine at all. It was
// `OP_2 <32 zero bytes>` until stage T2, which stage B5 had made invalid on
// mainnet and on the rehearsal chain (the PQ-only output rule of section 3).
// The output-value floor (consensus): on mainnet and the rehearsal chain every
// output that is not OP_RETURN carries at least MIN_OUTPUT_VALUE_SAT; regtest
// disables it so the shared fixtures still build sub-floor outputs. A PQ output
// costs ~5.4 kB of witness to spend, so anything smaller can never be spent for
// less than it is worth and exists only to bloat the UTXO set. The floor is the
// levy floor: 10,000 sat = 0.0001 XCF.
BOOST_AUTO_TEST_CASE(min_output_value_rule)
{
    BOOST_CHECK_EQUAL(Consensus::MIN_OUTPUT_VALUE_SAT, 10'000);
    for (const ChainType type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(*m_node.args, type)};
        const int64_t expect{type == ChainType::REGTEST ? int64_t{0} : Consensus::MIN_OUTPUT_VALUE_SAT};
        BOOST_CHECK_MESSAGE(params->GetConsensus().minOutputValueSat == expect, ChainTypeToString(type));
    }

    const auto check{[](const CTxOut& out, int64_t min_value) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.push_back(out);
        TxValidationState state;
        const bool ok{CheckTransaction(CTransaction{tx}, state, /*permit_v2_outputs=*/false, min_value)};
        return ok ? std::string{"valid"} : state.GetRejectReason();
    }};
    const CScript v3_script{(CScript() << OP_3 << std::vector<unsigned char>(32, 0x11))};
    BOOST_CHECK_EQUAL(check(CTxOut{9'999, v3_script}, 10'000), "bad-txout-below-min");
    BOOST_CHECK_EQUAL(check(CTxOut{10'000, v3_script}, 10'000), "valid");
    BOOST_CHECK_EQUAL(check(CTxOut{0, v3_script}, 10'000), "bad-txout-below-min");
    BOOST_CHECK_EQUAL(check(NullDataOut(), 10'000), "valid");         // OP_RETURN carries no value: exempt
    BOOST_CHECK_EQUAL(check(CTxOut{0, v3_script}, 0), "valid");       // 0 disables the rule (regtest)
    BOOST_CHECK_EQUAL(check(CTxOut{9'999, v3_script}, 0), "valid");
}

// Coinbase exemption from the output-value floor (founder decision 2026-09-15):
// from era 18 (height 13,500,001) the subsidy, 5,340 sat, is under the 10,000-sat
// floor, so without an exemption an otherwise empty block could not claim it. A
// coinbase whose non-OP_RETURN outputs number exactly one may pay that output
// any value from 1 sat; a coinbase with two or more spendable outputs is held to
// the floor on every one of them (the reward cannot be sprayed into the UTXO
// set as sub-floor outputs), and a non-coinbase transaction is never exempt.
// The rule is context-free (CheckTransaction), so it is exercised here with the
// mainnet floor and, through the emission table, at every era of the schedule.
BOOST_AUTO_TEST_CASE(min_output_value_coinbase_exemption)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& cp{params->GetConsensus()};
    const int64_t floor{cp.minOutputValueSat};
    BOOST_REQUIRE_EQUAL(floor, Consensus::MIN_OUTPUT_VALUE_SAT);

    const CScript v3_script{(CScript() << OP_3 << std::vector<unsigned char>(32, 0x22))};
    // A coinbase of the shape the block assembler and the pool build: BIP34 height
    // in the scriptSig, the spendable outputs given, then the witness-commitment
    // OP_RETURN (NULL_DATA never counts against the exemption).
    const auto coinbase{[&](int height, const std::vector<CAmount>& values, bool with_commitment = true) {
        CMutableTransaction tx;
        tx.vin.emplace_back();
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << height << OP_0;
        for (const CAmount v : values) tx.vout.emplace_back(v, v3_script);
        if (with_commitment) tx.vout.push_back(NullDataOut());
        return CTransaction{tx};
    }};
    const auto check{[&](const CTransaction& tx) {
        TxValidationState state;
        const bool ok{CheckTransaction(tx, state, cp.permitV2Outputs, floor)};
        return ok ? std::string{"valid"} : state.GetRejectReason();
    }};

    const int era18{13'500'001};
    BOOST_REQUIRE_EQUAL(GetBlockSubsidy(era18, cp), 5'340);
    BOOST_CHECK(coinbase(era18, {5'340}).IsCoinBase());
    // One spendable output: exempt, whatever it pays from 1 sat up.
    BOOST_CHECK_EQUAL(check(coinbase(era18, {5'340})), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(era18, {5'340}, /*with_commitment=*/false)), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(era18, {1})), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(1, {14 * COIN})), "valid");
    // A zero-value spendable output is bloat with nothing behind it: never allowed.
    BOOST_CHECK_EQUAL(check(coinbase(era18, {0})), "bad-txout-below-min");
    // Two spendable outputs: the floor applies to every one of them.
    BOOST_CHECK_EQUAL(check(coinbase(era18, {5'340, 10'000})), "bad-txout-below-min");
    BOOST_CHECK_EQUAL(check(coinbase(era18, {10'000, 5'340})), "bad-txout-below-min");
    BOOST_CHECK_EQUAL(check(coinbase(era18, {2'670, 2'670})), "bad-txout-below-min");
    BOOST_CHECK_EQUAL(check(coinbase(1, {7 * COIN, 7 * COIN})), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(1, {14 * COIN - 10'000, 10'000})), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(1, {14 * COIN - 9'999, 9'999})), "bad-txout-below-min");
    // Extra OP_RETURN outputs do not turn a single-output coinbase into a multi-output one.
    {
        CMutableTransaction tx{coinbase(era18, {5'340})};
        tx.vout.push_back(NullDataOut());
        tx.vout.push_back(NullDataOut());
        BOOST_CHECK_EQUAL(check(CTransaction{tx}), "valid");
    }
    // A non-coinbase transaction is never exempt, single output or not.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(9'999, v3_script);
        BOOST_CHECK_EQUAL(check(CTransaction{tx}), "bad-txout-below-min");
        tx.vout.push_back(NullDataOut());
        BOOST_CHECK_EQUAL(check(CTransaction{tx}), "bad-txout-below-min");
        tx.vout[0].nValue = 10'000;
        BOOST_CHECK_EQUAL(check(CTransaction{tx}), "valid");
    }
    // The floor being disabled (regtest) still accepts everything, coinbase or not.
    {
        TxValidationState state;
        BOOST_CHECK(CheckTransaction(coinbase(era18, {0, 0}), state, /*permit_v2_outputs=*/true, /*min_output_value=*/0));
    }

    // Through the emission table: at every era, first and last block, a
    // single-output coinbase paying exactly GetBlockSubsidy(height) — plus, on the
    // final block, the closing remainder, which GetBlockSubsidy already includes —
    // passes the context-free check. Eras 0-17 pay over the floor; eras 18-30 rely
    // on the exemption, era 30 paying one satoshi.
    int eras_under_floor{0};
    for (int i = 0; i < Consensus::NUM_EMISSION_ERAS; ++i) {
        const auto& era{Consensus::EMISSION_TABLE[i]};
        for (const int height : {era.startHeight, era.startHeight + 1, era.endHeight - 1, era.endHeight}) {
            const CAmount subsidy{GetBlockSubsidy(height, cp)};
            BOOST_REQUIRE_GE(subsidy, 1);
            BOOST_CHECK_MESSAGE(check(coinbase(height, {subsidy})) == "valid", strprintf("era %d height %d subsidy %d", i, height, subsidy));
        }
        if (era.baseSubsidy < floor) ++eras_under_floor;
    }
    BOOST_CHECK_EQUAL(eras_under_floor, 13); // eras 18..30
    BOOST_CHECK_EQUAL(Consensus::EMISSION_TABLE[17].baseSubsidy, 10'681); // era 17: the last era over the floor
    BOOST_CHECK_EQUAL(Consensus::EMISSION_TABLE[18].baseSubsidy, 5'340);  // era 18: the first under it
    BOOST_CHECK_EQUAL(check(coinbase(Consensus::EMISSION_END_HEIGHT, {1 + Consensus::EMISSION_CLOSING_DUST_SAT})), "valid");
    BOOST_CHECK_EQUAL(check(coinbase(Consensus::EMISSION_END_HEIGHT - 1, {1})), "valid");
    // After emission ends a fee-less block has nothing to pay, and a zero-value
    // spendable output stays refused as it was before the exemption.
    BOOST_CHECK_EQUAL(check(coinbase(Consensus::EMISSION_END_HEIGHT + 1, {0})), "bad-txout-below-min");
}

BOOST_AUTO_TEST_CASE(block_assembler_default_coinbase_is_v3)
{
    const CScript placeholder{node::BlockAssembler::Options{}.coinbase_output_script};
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(placeholder, solutions) == TxoutType::WITNESS_V3_PQ);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1U);
    BOOST_CHECK_EQUAL(solutions[0].size(), WITNESS_V3_SIZE);
    // Unspendable, as the witness v2 placeholder before it was: no xCoin leaf
    // hashes to zero, so no witness can ever produce this root.
    BOOST_CHECK(solutions[0] == std::vector<unsigned char>(WITNESS_V3_SIZE, 0));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(50 * COIN, placeholder);
    TxValidationState accepted;
    BOOST_CHECK(CheckTransaction(CTransaction{tx}, accepted, /*permit_v2_outputs=*/false));
    // The old default, on the same rule: this is what broke getblocktemplate.
    tx.vout[0].scriptPubKey = CScript() << OP_2 << std::vector<unsigned char>(32, 0);
    TxValidationState refused;
    BOOST_CHECK(!CheckTransaction(CTransaction{tx}, refused, /*permit_v2_outputs=*/false));
    BOOST_CHECK_EQUAL(refused.GetRejectReason(), "bad-txout-not-pq");
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Stage T1: xCoin testnet A (contrib/regenesis/TESTNET-A.md) — the v2 rules on a
// list) for the node that assembles block 1.

namespace {
constexpr std::string_view TESTNET_A_GENESIS_HASH_HEX{"1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9"}; // re-mined 2026-09-14 against charter 415b1dbc... (14 XCF schedule)
constexpr std::string_view TESTNET_A_POW_HASH_HEX{"000001be7d866cb919cac1221d48de803cc61e6d64c0937efb670523bfa071e6"};
constexpr std::string_view TESTNET_A_CURRENCY_ID_HEX{"fb9c965c9b2c61d9f1f3471d96a775f764389142b838f63c183913b38b71029e"};
constexpr std::string_view TESTNET_A_DISTRIBUTION_DIGEST{"915be3971dc0f28e0fef6c79ae4af7d152bf3df6bab018c8a76c2b239542551a"};  // over the CONVERTED v3 outputs, natural order
constexpr std::string_view TESTNET_A_CARRY_HASH{"f433b6eb01f4171007d5a3672d9a1937371e29a34058a82f2ac48a7172d13ce1"};        // carry.py's hash of the PRE-conversion list
constexpr uint32_t TESTNET_A_GENESIS_TIME{1789379971}; // 2026-09-14T09:59:31Z
constexpr uint32_t TESTNET_A_GENESIS_NONCE{166982};
constexpr size_t TESTNET_A_CARRIED_OUTPUTS{1533};

fs::path WriteTempFile(const fs::path& dir, const std::string& name, std::string_view content)
{
    const fs::path path{dir / fs::u8path(name)};
    BOOST_REQUIRE(WriteBinaryFile(path, std::string{content}));
    return path;
}

std::string_view BytesView(std::span<const unsigned char> data)
{
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}

std::vector<CTxOut> OutputsFromJson(std::string_view json)
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(json));
    std::vector<CTxOut> outputs;
    for (const UniValue& o : doc["outputs"].getValues()) {
        const std::vector<unsigned char> script{ParseHex(o["script_hex"].get_str())};
        outputs.emplace_back(o["value_sat"].getInt<int64_t>(), CScript(script.begin(), script.end()));
    }
    return outputs;
}

std::unique_ptr<const CChainParams> ParamsWithArgs(const std::vector<std::string>& extra, ChainType chain)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    std::vector<const char*> argv{"test"};
    for (const std::string& a : extra) argv.push_back(a.c_str());
    std::string error;
    BOOST_REQUIRE_MESSAGE(args.ParseParameters(argv.size(), argv.data(), error), error);
    return CreateChainParams(args, chain);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(regenesis_testnet_a_tests, BasicTestingSetup)

// Identity: magic 'X','T','A',0x02, P2P 19333 / RPC 19432 / datadir testneta, HRP
// "txa", no seeds; a FINAL charter genesis (the task's message with the first 16
// hex characters of CHARTER_HASH, the commitment output as the coinbase's only
// output, nothing minted, hash pinned) whose nonce is a real MetalDAG proof of
// work at testnet A's own sizing, with metaldagBaseTime = the genesis time.
BOOST_AUTO_TEST_CASE(testnet_a_identity)
{
    const auto testnet{CreateChainParams(*m_node.args, ChainType::TESTNET)};
    const auto& cp{testnet->GetConsensus()};
    BOOST_CHECK(testnet->GetChainType() == ChainType::TESTNET);
    const MessageStartChars expected_magic{'X', 'T', 'A', 0x02};
    BOOST_CHECK(testnet->MessageStart() == expected_magic);
    BOOST_CHECK(GetNetworkForMagic(testnet->MessageStart()) == ChainType::TESTNET);
    BOOST_CHECK_EQUAL(testnet->GetDefaultPort(), 19333);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::TESTNET)->RPCPort(), 19432);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::TESTNET)->DataDir(), "testneta");
    BOOST_CHECK_EQUAL(testnet->Bech32HRP(), "txa");
    BOOST_CHECK(testnet->DNSSeeds().empty());
    BOOST_CHECK(testnet->FixedSeeds().empty());
    BOOST_CHECK(testnet->IsTestChain());
    BOOST_CHECK(!testnet->IsMockableChain());
    BOOST_CHECK(!testnet->MineBlocksOnDemand());

    const CBlock& genesis{testnet->GenesisBlock()};
    if (!testnet->GenesisIsFinal()) {
        // Placeholder state (9913319): the charter moved under the mined genesis
        // (ecc7ca06 -> ba4554b7), so testnet A stands on the v1 genesis exactly as
        // mainnet does before its cutover, until it is re-mined. Everything below
        // applies again once TESTNET_GENESIS_IS_FINAL is set.
        BOOST_CHECK_EQUAL(genesis.GetHash(), Consensus::V1_GENESIS_HASH);
        BOOST_CHECK_EQUAL(cp.hashGenesisBlock, genesis.GetHash());
        BOOST_CHECK_EQUAL(cp.metaldagBaseTime, genesis.nTime);
        return;
    }
    BOOST_CHECK(testnet->GenesisIsFinal());
    BOOST_CHECK_EQUAL(genesis.GetHash().GetHex(), TESTNET_A_GENESIS_HASH_HEX);
    BOOST_CHECK_EQUAL(cp.hashGenesisBlock, genesis.GetHash());
    BOOST_CHECK(genesis.GetHash() != Consensus::V1_GENESIS_HASH);
    BOOST_CHECK(genesis.GetHash() != CreateChainParams(*m_node.args, ChainType::MAIN)->GenesisBlock().GetHash());
    BOOST_CHECK_EQUAL(genesis.nTime, TESTNET_A_GENESIS_TIME);
    BOOST_CHECK_EQUAL(genesis.nNonce, TESTNET_A_GENESIS_NONCE);
    BOOST_CHECK_EQUAL(genesis.nBits, 0x1e0fffffU);
    BOOST_CHECK_EQUAL(genesis.nBits, UintToArith256(cp.powLimit).GetCompact()); // block 1 starts at the easiest target
    BOOST_CHECK_EQUAL(genesis.nVersion, 1);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(cp.metaldagBaseTime, TESTNET_A_GENESIS_TIME);

    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    const CTransaction& cb{*genesis.vtx[0]};
    BOOST_CHECK(charter::HasCommitment(cb));
    BOOST_REQUIRE_EQUAL(cb.vout.size(), 1U);
    BOOST_CHECK_EQUAL(cb.vout[0].nValue, 0);
    BOOST_CHECK(cb.vout[0].scriptPubKey == charter::CommitmentScript());
    BOOST_CHECK_EQUAL(cb.GetValueOut(), 0);
    const std::string message{"xCoin testnet A - 2026-09-14 - 2,100,000,000,000,000 sats, 21M XCF"}; // no charter hash in the message: the coinbase output carries all 32 bytes
    const CScript& script_sig{cb.vin[0].scriptSig};
    BOOST_CHECK(std::search(script_sig.begin(), script_sig.end(), message.begin(), message.end()) != script_sig.end());
    BOOST_CHECK_LE(script_sig.size(), 100U); // bad-cb-length
    const CBlock rebuilt{charter::CreateGenesisBlock(message, genesis.nTime, genesis.nNonce, genesis.nBits, genesis.nVersion)};
    BOOST_CHECK_EQUAL(rebuilt.GetHash(), genesis.GetHash());
    BOOST_CHECK_EQUAL(rebuilt.hashMerkleRoot, genesis.hashMerkleRoot);
    BOOST_CHECK_EQUAL(BlockMerkleRoot(genesis), genesis.hashMerkleRoot);
    BOOST_CHECK_EQUAL(charter::DigestHex(charter::CurrencyId(genesis)), TESTNET_A_CURRENCY_ID_HEX);

    // The proof of work, checked as any other header would be (CheckProofOfWork
    // exempts the genesis by hash only): the node's own MetalDAG path under
    // testnet A's sizing (4 GiB DAG, 32 MiB cache, epoch 0) meets the target.
    Consensus::Params as_any_header{cp};
    as_any_header.hashGenesisBlock.SetNull();
    const uint256 pow_hash{metaldag::PoWHash(genesis, as_any_header)};
    BOOST_CHECK_EQUAL(pow_hash.GetHex(), TESTNET_A_POW_HASH_HEX);
    BOOST_CHECK(CheckProofOfWorkImpl(pow_hash, genesis.nBits, as_any_header));
    BOOST_CHECK(CheckProofOfWork(genesis, genesis.nBits, as_any_header));
    CBlockHeader other{genesis};
    other.nNonce += 1;
    BOOST_CHECK(!CheckProofOfWorkImpl(metaldag::PoWHash(other, as_any_header), other.nBits, as_any_header));
}

// Consensus exactly as mainnet: proof-of-work parameters, MetalDAG sizing and
// cadence (same epoch-0 DAG, so a mainnet miner works on testnet A until
// mainnet's epoch 1), the emission table (14 XCF from block 1, halved every
// 750,000 blocks), and no block-1 distribution: nothing is carried in on any
// public chain (35c4fda), no founder output, no premine.
BOOST_AUTO_TEST_CASE(testnet_a_rules_are_mainnet_rules)
{
    const auto testnet{CreateChainParams(*m_node.args, ChainType::TESTNET)};
    const auto main{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& t{testnet->GetConsensus()};
    const auto& m{main->GetConsensus()};
    BOOST_CHECK_EQUAL(t.powLimit, m.powLimit);
    BOOST_CHECK_EQUAL(t.powLimit, uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"});
    BOOST_CHECK_EQUAL(t.nPowTargetSpacing, m.nPowTargetSpacing);
    BOOST_CHECK_EQUAL(t.nPowTargetSpacing, 300);
    BOOST_CHECK_EQUAL(t.nPowTargetTimespan, m.nPowTargetTimespan);
    BOOST_CHECK_EQUAL(t.fPowAllowMinDifficultyBlocks, m.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK_EQUAL(t.fPowNoRetargeting, m.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(t.enforce_BIP94, m.enforce_BIP94);
    BOOST_CHECK_EQUAL(t.nASERTActivationHeight, m.nASERTActivationHeight);
    BOOST_CHECK_EQUAL(t.nASERTHalfLife, m.nASERTHalfLife);
    BOOST_CHECK_EQUAL(t.nASERTHalfLife, 2 * 60 * 60);
    BOOST_CHECK_EQUAL(t.metaldagEpochSeconds, m.metaldagEpochSeconds);
    BOOST_CHECK_EQUAL(t.metaldagDagInitBytes, m.metaldagDagInitBytes);
    BOOST_CHECK_EQUAL(t.metaldagDagGrowthBytes, m.metaldagDagGrowthBytes);
    BOOST_CHECK_EQUAL(t.metaldagCacheDivisor, m.metaldagCacheDivisor);
    const auto t_sizing{metaldag::GetEpochSizing(TESTNET_A_GENESIS_TIME, t)};
    const auto m_sizing{metaldag::GetEpochSizing(static_cast<uint32_t>(m.metaldagBaseTime), m)};
    BOOST_CHECK_EQUAL(t_sizing.epoch, 0U);
    BOOST_CHECK_EQUAL(m_sizing.epoch, 0U);
    BOOST_CHECK_EQUAL(t_sizing.full_size, m_sizing.full_size);
    BOOST_CHECK_EQUAL(t_sizing.cache_size, m_sizing.cache_size);
    BOOST_CHECK_EQUAL(metaldag::GetEpochSizing(TESTNET_A_GENESIS_TIME + 14 * 24 * 3600, t).epoch, 1U);

    BOOST_REQUIRE_EQUAL(t.emissionTable.size(), m.emissionTable.size());
    for (size_t i = 0; i < t.emissionTable.size(); ++i) {
        BOOST_CHECK_EQUAL(t.emissionTable[i].startHeight, m.emissionTable[i].startHeight);
        BOOST_CHECK_EQUAL(t.emissionTable[i].endHeight, m.emissionTable[i].endHeight);
        BOOST_CHECK_EQUAL(t.emissionTable[i].baseSubsidy, m.emissionTable[i].baseSubsidy);
    }
    BOOST_CHECK_EQUAL(t.emissionClosingDustSat, m.emissionClosingDustSat);
    BOOST_CHECK_EQUAL(t.EmissionEndHeight(), Consensus::EMISSION_END_HEIGHT);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, t), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, t), Consensus::EMISSION_ERA0_SUBSIDY_SAT); // 14 XCF from the first block
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, t), 14 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_ERA_BLOCKS + 1, t), 700000000LL); // first halving
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, t), GetBlockSubsidy(1, t));

    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 64'000'000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_DATACARRIER_BYTES, 8'000U); // 100 anchors of 80 bytes (35c4fda)
}

// The v1 genesis standing in for mainnet carries a zero-value witness v2 marker
// output that the v3-only rule would refuse; only the genesis exemption in
// CheckBlock saves it. (The carried-as-v3 rehearsal that used to live here went
// with the carry itself, 35c4fda: no chain carries anything in any more.)
BOOST_AUTO_TEST_CASE(placeholder_genesis_marker_output_exempt)
{
    const auto main{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const CBlock& main_genesis{main->GenesisBlock()};
    BOOST_REQUIRE(!main_genesis.vtx[0]->vout.empty());
    BOOST_CHECK(main_genesis.vtx[0]->vout[0].scriptPubKey.size() == 34 && main_genesis.vtx[0]->vout[0].scriptPubKey[0] == OP_2);
    BlockValidationState genesis_state;
    BOOST_CHECK(CheckBlock(main_genesis, genesis_state, main->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
    TxValidationState tx_state;
    BOOST_CHECK(!CheckTransaction(*main_genesis.vtx[0], tx_state, /*permit_v2_outputs=*/false)); // only the genesis exemption saves it
    BOOST_CHECK_EQUAL(tx_state.GetRejectReason(), "bad-txout-not-pq");
}

BOOST_AUTO_TEST_SUITE_END()
