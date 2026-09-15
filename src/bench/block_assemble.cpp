// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <vector>

using node::BlockAssembler;

static void AssembleBlock(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();

    // xCoin: the anyone-can-spend output is witness v3, not P2WSH; a P2WSH
    // output is consensus-invalid here (bad-txout-not-pq).
    CScriptWitness witness;
    witness.stack = XcoinV3OpTrueWitnessStack();
    BlockAssembler::Options options;
    options.coinbase_output_script = XcoinV3OpTrueScript();
    options.include_dummy_extranonce = true;

    // Block 1 is an ordinary block (no distribution, 7263c5d); it is mined here
    // and left unspent only so the loop below keeps its original shape.
    MineBlock(test_setup->m_node, options);

    // Collect some loose transactions that spend the coinbases of our mined blocks
    constexpr size_t NUM_BLOCKS{200};
    std::array<CTransactionRef, NUM_BLOCKS - COINBASE_MATURITY + 1> txs;
    for (size_t b{0}; b < NUM_BLOCKS; ++b) {
        CMutableTransaction tx;
        tx.vin.emplace_back(MineBlock(test_setup->m_node, options));
        tx.vin.back().scriptWitness = witness;
        tx.vout.emplace_back(1337, XcoinV3OpTrueScript());
        if (NUM_BLOCKS - b >= COINBASE_MATURITY)
            txs.at(b) = MakeTransactionRef(tx);
    }
    {
        LOCK(::cs_main);

        for (const auto& txr : txs) {
            const MempoolAcceptResult res = test_setup->m_node.chainman->ProcessTransaction(txr);
            assert(res.m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
    }

    bench.run([&] {
        PrepareBlock(test_setup->m_node, options);
    });
}
static void BlockAssemblerAddPackageTxns(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    testing_setup->PopulateMempool(det_rand, /*num_transactions=*/1000, /*submit=*/true);
    BlockAssembler::Options assembler_options;
    assembler_options.test_block_validity = false;
    assembler_options.coinbase_output_script = XcoinV3OpTrueScript();

    bench.run([&] {
        PrepareBlock(testing_setup->m_node, assembler_options);
    });
}

BENCHMARK(AssembleBlock);
BENCHMARK(BlockAssemblerAddPackageTxns);
