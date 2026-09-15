// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <blockfilter.h>
#include <chain.h>
#include <index/base.h>
#include <index/blockfilterindex.h>
#include <interfaces/chain.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <span.h>
#include <sync.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <cassert>
#include <memory>
#include <vector>

using namespace util::hex_literals;

// Very simple block filter index sync benchmark, only using coinbase outputs.
static void BlockFilterIndexSync(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<TestChain100Setup>();

    // Create more blocks
    int CHAIN_SIZE = 600;
    // xCoin: a P2WPKH coinbase output is consensus-invalid here
    // (bad-txout-not-pq), so the blocks pay the anyone-can-spend witness v3
    // script instead. The filter still indexes one output per block.
    CScript script = XcoinV3OpTrueScript();
    std::vector<CMutableTransaction> noTxns;
    for (int i = 0; i < CHAIN_SIZE - 100; i++) {
        test_setup->CreateAndProcessBlock(noTxns, script);
        SetMockTime(GetTime() + 1);
    }
    assert(WITH_LOCK(::cs_main, return test_setup->m_node.chainman->ActiveHeight() == CHAIN_SIZE));

    bench.minEpochIterations(5).run([&] {
        BlockFilterIndex filter_index(interfaces::MakeChain(test_setup->m_node), BlockFilterType::BASIC,
                                      /*n_cache_size=*/0, /*f_memory=*/false, /*f_wipe=*/true);
        assert(filter_index.Init());
        assert(!filter_index.BlockUntilSyncedToCurrentChain());
        filter_index.Sync();

        IndexSummary summary = filter_index.GetSummary();
        assert(summary.synced);
        assert(summary.best_block_hash == WITH_LOCK(::cs_main, return test_setup->m_node.chainman->ActiveTip()->GetBlockHash()));

        // Shutdown sequence (c.f. Shutdown() in init.cpp)
        filter_index.Stop();
    });
}

BENCHMARK(BlockFilterIndexSync);
