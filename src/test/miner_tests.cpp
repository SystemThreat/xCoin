// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <test/util/random.h>
#include <test/util/transaction_utils.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>
#include <pow.h>

#include <test/util/common.h>
#include <test/util/pq.h>
#include <test/util/setup_common.h>

#include <memory>
#include <optional>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;

namespace miner_tests {
// Upstream ran this suite on mainnet params, made workable by BLOCKINFO's
// pre-ground nonces. Grinding NEX mainnet MetalDAG PoW (nBits 0x1e0fffff) in a
// unit test is infeasible, so run on regtest like the other block-producing
// fixtures and grind its trivial target instead.
struct MinerTestingSetup : public TestingSetup {
    // Defer CSV so BIP68 is inactive at the heights this suite mines, matching
    // the upstream-mainnet timeline the non-final-transaction sub-test assumes
    // (a template may contain non-BIP68-final txs and still validate).
    MinerTestingSetup() : TestingSetup{ChainType::REGTEST, {.extra_args = {"-testactivationheight=csv@500000"}}} {}
    void TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool TestSequenceLocks(const CTransaction& tx, CTxMemPool& tx_mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CCoinsViewMemPool view_mempool{&m_node.chainman->ActiveChainstate().CoinsTip(), tx_mempool};
        CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
        const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(tip, view_mempool, tx)};
        return lock_points.has_value() && CheckSequenceLocksAtTip(tip, *lock_points);
    }
    CTxMemPool& MakeMempool()
    {
        // Delete the previous mempool to ensure with valgrind that the old
        // pointer is not accessed, when the new one should be accessed
        // instead.
        m_node.mempool.reset();
        bilingual_str error;
        auto opts = MemPoolOptionsForTest(m_node);
        // The "block size > limit" test creates a cluster of ~4.24M vbytes
        // (63 links of ~67,333 vbytes, ~17M WU: over the assembler's default
        // 4M WU block max weight, DEFAULT_BLOCK_MAX_WEIGHT, which is what the
        // test exercises; the consensus MAX_BLOCK_WEIGHT is 64M), so set the
        // cluster vbytes limit big enough so that the txgraph doesn't become
        // oversized.
        opts.limits.cluster_size_vbytes = 4'300'000;
        m_node.mempool = std::make_unique<CTxMemPool>(opts, error);
        Assert(error.empty());
        return *m_node.mempool;
    }
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node, /*wait_loaded=*/false);
    }
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);

constexpr static struct {
    unsigned int extranonce;
    unsigned int nonce;
} BLOCKINFO[]{{0, 3552706918},   {500, 37506755},   {1000, 948987788}, {400, 524762339},  {800, 258510074},  {300, 102309278},
              {1300, 54365202},  {600, 1107740426}, {1000, 203094491}, {900, 391178848},  {800, 381177271},  {600, 87188412},
              {0, 66522866},     {800, 874942736},  {1000, 89200838},  {400, 312638088},  {400, 66263693},   {500, 924648304},
              {400, 369913599},  {500, 47630099},   {500, 115045364},  {100, 277026602},  {1100, 809621409}, {700, 155345322},
              {800, 943579953},  {400, 28200730},   {900, 77200495},   {0, 105935488},    {400, 698721821},  {500, 111098863},
              {1300, 445389594}, {500, 621849894},  {1400, 56010046},  {1100, 370669776}, {1200, 380301940}, {1200, 110654905},
              {400, 213771024},  {1500, 120014726}, {1200, 835019014}, {1500, 624817237}, {900, 1404297},    {400, 189414558},
              {400, 293178348},  {1100, 15393789},  {600, 396764180},  {800, 1387046371}, {800, 199368303},  {700, 111496662},
              {100, 129759616},  {200, 536577982},  {500, 125881300},  {500, 101053391},  {1200, 471590548}, {900, 86957729},
              {1200, 179604104}, {600, 68658642},   {1000, 203295701}, {500, 139615361},  {900, 233693412},  {300, 153225163},
              {0, 27616254},     {1200, 9856191},   {100, 220392722},  {200, 66257599},   {1100, 145489641}, {1300, 37859442},
              {400, 5816075},    {1200, 215752117}, {1400, 32361482},  {1400, 6529223},   {500, 143332977},  {800, 878392},
              {700, 159290408},  {400, 123197595},  {700, 43988693},   {300, 304224916},  {700, 214771621},  {1100, 274148273},
              {400, 285632418},  {1100, 923451065}, {600, 12818092},   {1200, 736282054}, {1000, 246683167}, {600, 92950402},
              {1400, 29223405},  {1000, 841327192}, {700, 174301283},  {1400, 214009854}, {1000, 6989517},   {1200, 278226956},
              {700, 540219613},  {400, 93663104},   {1100, 152345635}, {1500, 464194499}, {1300, 333850111}, {600, 258311263},
              {600, 90173162},   {1000, 33590797},  {1500, 332866027}, {100, 204704427},  {1000, 463153545}, {800, 303244785},
              {600, 88096214},   {0, 137477892},    {1200, 195514506}, {300, 704114595},  {900, 292087369},  {1400, 758684870},
              {1300, 163493028}, {1200, 53151293}};

// On NEX every spendable output is WITNESS_V2_PQ locked to the shared test
// ML-DSA-65 key, and CreateNewBlock self-validates templates with script
// checks, so each mempool transaction a template may select needs a real
// witness. prevout_values must match the actual amounts being spent (the
// sighash commits to them).
static void SignPQInputs(CMutableTransaction& tx, const std::vector<CAmount>& prevout_values)
{
    assert(prevout_values.size() == tx.vin.size());
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        SignTestPQInput(tx, i, CTxOut(prevout_values[i], GetTestPQScript()));
    }
}

static std::unique_ptr<CBlockIndex> CreateBlockIndex(int nHeight, CBlockIndex* active_chain_tip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto index{std::make_unique<CBlockIndex>()};
    index->nHeight = nHeight;
    index->pprev = active_chain_tip;
    return index;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    LOCK(tx_mempool.cs);
    BOOST_CHECK(tx_mempool.size() == 0);

    // Block template should only have a coinbase when there's nothing in the mempool
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);

    // waitNext() on an empty mempool should return nullptr because there is no better template
    auto should_be_nullptr = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    BOOST_REQUIRE(should_be_nullptr == nullptr);

    // Unless fee_threshold is 0
    block_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 0});
    BOOST_REQUIRE(block_template);

    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL - 1000;
    tx.vout[0].scriptPubKey = GetTestPQScript();
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    SignPQInputs(tx, {5000000000LL});
    const auto parent_tx{entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    TryAddToMempool(tx_mempool, parent_tx);

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    const auto medium_fee_tx{entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    TryAddToMempool(tx_mempool, medium_fee_tx);

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 50k satoshi fee
    Txid hashHighFeeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 1000});
    const auto high_fee_tx{entry.Fee(50000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx)};
    TryAddToMempool(tx_mempool, high_fee_tx);

    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 4U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashHighFeeTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashMediumFeeTx);

    // Test the inclusion of package feerates in the block template and ensure they are sequential.
    const auto block_package_feerates = BlockAssembler{m_node.chainman->ActiveChainstate(), &tx_mempool, options}.CreateNewBlock()->m_package_feerates;
    BOOST_CHECK(block_package_feerates.size() == 2);

    // parent_tx and high_fee_tx are added to the block as a package.
    const auto combined_txs_fee = parent_tx.GetFee() + high_fee_tx.GetFee();
    const auto combined_txs_size = parent_tx.GetTxSize() + high_fee_tx.GetTxSize();
    FeeFrac package_feefrac{combined_txs_fee, combined_txs_size};
    // The package should be added first.
    BOOST_CHECK(block_package_feerates[0] == package_feefrac);

    // The medium_fee_tx should be added next.
    FeeFrac medium_tx_feefrac{medium_fee_tx.GetFee(), medium_fee_tx.GetTxSize()};
    BOOST_CHECK(block_package_feerates[1] == medium_tx_feefrac);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout.hash = hashHighFeeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 0 fee
    Txid hashFreeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 1000 - 50000});
    TryAddToMempool(tx_mempool, entry.Fee(0).FromTx(tx));
    // Use the virtual size: block assembly compares fee/vsize, and with the
    // witness discount the ML-DSA witness makes vsize much smaller than the
    // raw serialized size upstream used here.
    uint64_t freeTxSize(GetVirtualTransactionSize(CTransaction{tx}, /*nSigOpCost=*/0, /*bytes_per_sigop=*/0));

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee (assuming 1 child tx of the same size).
    CAmount feeToUse = blockMinFeeRate.GetFee(2*freeTxSize) - 1;

    tx.vin[0].prevout.hash = hashFreeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000 - feeToUse;
    Txid hashLowFeeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 1000 - 50000});
    TryAddToMempool(tx_mempool, entry.Fee(feeToUse).FromTx(tx));

    // waitNext() should return nullptr because there is no better template
    should_be_nullptr = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    BOOST_REQUIRE(should_be_nullptr == nullptr);

    block = block_template->getBlock();
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    tx_mempool.removeRecursive(CTransaction(tx), MemPoolRemovalReason::REPLACED);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    hashLowFeeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 1000 - 50000});
    TryAddToMempool(tx_mempool, entry.Fee(feeToUse + 2).FromTx(tx));

    // waitNext() should return if fees for the new template are at least 1 sat up
    block_template = block_template->waitNext({.fee_threshold = 1});
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashFreeTx);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashLowFeeTx);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].scriptWitness.SetNull(); // drop the stale witness before sizing; re-signed below
    tx.vout.resize(2);
    tx.vout[0].nValue = 5000000000LL - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    tx.vout[1].scriptPubKey = GetTestPQScript();
    // Increase size to avoid rounding errors: when the feerate is extremely small (i.e. 1sat/kvB), evaluating the fee
    // at smaller sizes gives us rounded values that are equal to each other, which means we incorrectly include
    // hashFreeTx2 + hashLowFeeTx2.
    BulkTransaction(tx, 4000);
    Txid hashFreeTx2 = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    feeToUse = blockMinFeeRate.GetFee(freeTxSize);
    tx.vout[0].nValue = 5000000000LL - 100000000 - feeToUse;
    Txid hashLowFeeTx2 = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 100000000});
    TryAddToMempool(tx_mempool, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();

    // Verify that this tx isn't selected.
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx2);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx2);
    }

    // This tx will be mineable, and should cause hashLowFeeTx2 to be selected
    // as well.
    tx.vin[0].prevout.n = 1;
    tx.vout[0].nValue = 100000000 - 10000; // 10k satoshi fee
    SignPQInputs(tx, {100000000});
    TryAddToMempool(tx_mempool, entry.Fee(10000).FromTx(tx));
    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 9U);
    // Upstream asserted hashLowFeeTx2 was the block's final transaction. With
    // PQ-witness sizes the cluster linearizer merges it into the hashFreeTx2
    // chunk instead of leaving it as a trailing chunk, so only check the
    // invariant the test is about: it is selected, and after its ancestor.
    std::optional<size_t> free_tx2_pos, low_fee_tx2_pos;
    for (size_t i=0; i<block.vtx.size(); ++i) {
        if (block.vtx[i]->GetHash() == hashFreeTx2) free_tx2_pos = i;
        if (block.vtx[i]->GetHash() == hashLowFeeTx2) low_fee_tx2_pos = i;
    }
    BOOST_REQUIRE(free_tx2_pos.has_value() && low_fee_tx2_pos.has_value());
    BOOST_CHECK(*free_tx2_pos < *low_fee_tx2_pos);
}

void MinerTestingSetup::TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight)
{
    Txid hash;
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.nHeight = 11;

    const CAmount BLOCKSUBSIDY = 50 * COIN;
    const CAmount LOWFEE = CENT;
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4 * COIN;

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    // NOTE: upstream had two "block sigops > limit" sub-tests here built from a
    // 1000-CHECKMULTISIG cluster. Legacy sigop-carrying scripts can only appear
    // in outputs or non-empty scriptSigs, and NEX consensus rejects both (only
    // WITNESS_V2_PQ/NULL_DATA outputs are allowed, and witness spends require
    // empty scriptSigs), so the bad-blk-sigops condition cannot be constructed
    // from otherwise-valid transactions. Those sub-tests are removed.

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // block size > limit
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout[0].nValue = BLOCKSUBSIDY;
        tx.vout[0].scriptPubKey = GetTestPQScript();
        CAmount prev_value{BLOCKSUBSIDY};
        for (unsigned int i = 0; i < 63; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            // Bulk each link of the chain with OP_RETURN padding so the
            // cluster exceeds the block weight limit (upstream used huge
            // legacy scripts, which NEX consensus forbids). The ML-DSA witness
            // adds ~5330 weight after signing: 63 * (264000 + 5330) is over
            // the assembler's default 4M WU block max weight (policy, not the
            // 64M consensus limit) but, at ~67333 vbytes each, still
            // under the 4.3M cluster vbyte cap set in MakeMempool(). (Being
            // OP_RETURN padding, each link is also over the per-block
            // MAX_BLOCK_DATACARRIER_BYTES on its own after the first, which
            // the assembler must skip just the same.)
            CMutableTransaction bulked{tx};
            BulkTransaction(bulked, 264000);
            hash = bulked.GetHash();
            SignPQInputs(bulked, {prev_value});
            prev_value = bulked.vout[0].nValue;
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).FromTx(bulked));
            BOOST_CHECK(tx_mempool.GetIter(hash).has_value());
            tx.vin[0].prevout.hash = hash;
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
        // Keep the last chain link in `tx` for the orphan sub-test below.
        tx.vout[0].scriptPubKey = GetTestPQScript();
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // orphan in tx_mempool, template creation fails
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // child with higher feerate than parent
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vin[0].prevout.hash = txFirst[1]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        tx.vout[0].scriptPubKey = GetTestPQScript();
        hash = tx.GetHash();
        SignPQInputs(tx, {BLOCKSUBSIDY});
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin.resize(2);
        tx.vin[1].prevout.hash = txFirst[0]->GetHash();
        tx.vin[1].prevout.n = 0;
        tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE; // First txn output + fresh coinbase - new txn fee
        hash = tx.GetHash();
        SignPQInputs(tx, {BLOCKSUBSIDY - HIGHFEE, BLOCKSUBSIDY});
        TryAddToMempool(tx_mempool, entry.Fee(HIGHERFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // coinbase in tx_mempool, template creation fails
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
        tx.vin[0].scriptWitness.SetNull();
        tx.vout[0].nValue = 0;
        hash = tx.GetHash();
        // give it a fee so it'll get mined
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        // Should throw bad-cb-multiple
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-cb-multiple"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // double spend txn pair in tx_mempool, template creation fails.
        // (Upstream differentiated the two txids via OP_1/OP_2 output scripts;
        // NEX only allows PQ outputs, so differentiate via the value instead.)
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].scriptSig.clear(); // witness spends require an empty scriptSig
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        tx.vout[0].scriptPubKey = GetTestPQScript();
        hash = tx.GetHash();
        SignPQInputs(tx, {BLOCKSUBSIDY});
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE - 1;
        hash = tx.GetHash();
        SignPQInputs(tx, {BLOCKSUBSIDY});
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // subsidy changing
        int nHeight = m_node.chainman->ActiveChain().Height();
        // Create an actual 209999-long block chain (without valid blocks).
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 209999) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
        // Extend to a 210000-long block chain.
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 210000) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));

        // invalid-script txn in tx_mempool, template creation fails.
        // (Upstream used an invalid P2SH spend; P2SH outputs are not allowed on
        // NEX, so pay a PQ program nobody holds the key for and "spend" it with
        // a witness that cannot satisfy it.)
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[0].scriptSig.clear();
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        const CScript unspendable_pq_script{GetScriptForDestination(WitnessV2PQ(m_rng.rand256()))};
        tx.vout[0].scriptPubKey = unspendable_pq_script;
        hash = tx.GetHash();
        SignPQInputs(tx, {BLOCKSUBSIDY});
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vout[0].nValue -= LOWFEE;
        tx.vout[0].scriptPubKey = GetTestPQScript();
        hash = tx.GetHash();
        // Sign against the shared test key/script even though the prevout is
        // the unspendable program — the witness cannot satisfy it.
        SignPQInputs(tx, {BLOCKSUBSIDY - LOWFEE});
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("block-script-verify-flag-failed"));

        // Delete the dummy blocks again.
        while (m_node.chainman->ActiveChain().Tip()->nHeight > nHeight) {
            CBlockIndex* del = m_node.chainman->ActiveChain().Tip();
            m_node.chainman->ActiveChain().SetTip(*Assert(del->pprev));
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(del->pprev->GetBlockHash());
            delete del->phashBlock;
            delete del;
        }
    }

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    // non-final txs in mempool
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
    const int flags{LOCKTIME_VERIFY_SEQUENCE};
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.version = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig.clear(); // witness spends require an empty scriptSig
    tx.vin[0].nSequence = m_node.chainman->ActiveChain().Tip()->nHeight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = GetTestPQScript();
    tx.nLockTime = 0;
    hash = tx.GetHash();
    SignPQInputs(tx, {BLOCKSUBSIDY});
    TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 2, active_chain_tip))); // Sequence locks pass on 2nd block
    }

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()+1-m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    SignPQInputs(tx, {BLOCKSUBSIDY});
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    const int SEQUENCE_LOCK_TIME = 512; // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i)
        m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i)->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 1, active_chain_tip)));
    }

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime -= SEQUENCE_LOCK_TIME; // undo tricked MTP
    }

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    hash = tx.GetHash();
    SignPQInputs(tx, {BLOCKSUBSIDY});
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // ensure tx is final for a specific case where there is no locktime and block height is zero
    tx.nLockTime = 0;
    BOOST_CHECK(IsFinalTx(CTransaction(tx), /*nBlockHeight=*/0, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()));

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    SignPQInputs(tx, {BLOCKSUBSIDY});
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    auto block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    CBlock block{block_template->getBlock()};
    BOOST_CHECK_EQUAL(block.vtx.size(), 3U);
    // However if we advance height by 1 and time by SEQUENCE_LOCK_TIME, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    }
    m_node.chainman->ActiveChain().Tip()->nHeight++;
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);

    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_CHECK_EQUAL(block.vtx.size(), 5U);
}

void MinerTestingSetup::TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    TestMemPoolEntryHelper entry;

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    tx.vout[0].scriptPubKey = GetTestPQScript();
    Txid hashFreePrioritisedTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(0).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreePrioritisedTx, 5 * COIN);

    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout[0].nValue = 5000000000LL - 1000;
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashMediumFeeTx, -5 * COIN);

    // This tx also has a low fee, but is prioritised
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 1000; // 1000 satoshi fee
    Txid hashPrioritsedChild = tx.GetHash();
    SignPQInputs(tx, {5000000000LL - 1000});
    TryAddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashPrioritsedChild, 2 * COIN);

    // Test that transaction selection properly updates ancestor fee calculations as prioritised
    // parents get included in a block. Create a transaction with two prioritised ancestors, each
    // included by itself: FreeParent <- FreeChild <- FreeGrandchild.
    // When FreeParent is added, a modified entry will be created for FreeChild + FreeGrandchild
    // FreeParent's prioritisation should not be included in that entry.
    // When FreeChild is included, FreeChild's prioritisation should also not be included.
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeParent = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeParent, 10 * COIN);

    tx.vin[0].prevout.hash = hashFreeParent;
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeChild = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeChild, 1 * COIN);

    tx.vin[0].prevout.hash = hashFreeChild;
    tx.vout[0].nValue = 5000000000LL; // 0 fee
    Txid hashFreeGrandchild = tx.GetHash();
    SignPQInputs(tx, {5000000000LL});
    TryAddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));

    auto block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashFreeParent);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashFreePrioritisedTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashPrioritsedChild);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashFreeChild);
    for (size_t i=0; i<block.vtx.size(); ++i) {
        // The FreeParent and FreeChild's prioritisations should not impact the child.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeGrandchild);
        // De-prioritised transaction should not be included.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashMediumFeeTx);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    // Note that by default, these tests run with size accounting enabled.
    // The coinbase pays the shared test PQ key: it is the only spendable
    // output type NEX consensus accepts, and the sub-tests below spend these
    // coinbases with ML-DSA witnesses.
    CScript scriptPubKey = GetTestPQScript();
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    // Create and check a simple template
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    {
        CBlock block{block_template->getBlock()};
        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "bad-txnmrklroot");
            BOOST_REQUIRE_EQUAL(debug, "hashMerkleRoot mismatch");
        }

        block.hashMerkleRoot = BlockMerkleRoot(block);

        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "");
            BOOST_REQUIRE_EQUAL(debug, "");
        }

        {
            // A block template does not have proof-of-work, but it might pass
            // verification by coincidence. Grind the nonce if needed:
            while (CheckProofOfWork(block, block.nBits, Assert(m_node.chainman)->GetParams().GetConsensus())) {
                block.nNonce++;
            }

            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = true}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "high-hash");
            BOOST_REQUIRE_EQUAL(debug, "proof of work failed");
        }
    }

    // We can't make transactions until we have inputs
    // Therefore, load 110 blocks :)
    static_assert(std::size(BLOCKINFO) == 110, "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (const auto& bi : BLOCKINFO) {
        const int current_height{mining->getTip()->height};

        /**
         * Simple block creation, nothing special yet.
         * If current_height is odd, block_template will have already been
         * set at the end of the previous loop.
         */
        if (current_height % 2 == 0) {
            block_template = mining->createNewBlock(options, /*cooldown=*/false);
            BOOST_REQUIRE(block_template);
        }

        CBlock block{block_template->getBlock()};
        CMutableTransaction txCoinbase(*block.vtx[0]);
        {
            LOCK(cs_main);
            block.nVersion = VERSIONBITS_TOP_BITS;
            // Keep the template's (real-clock) nTime. Upstream rewound it to
            // MTP+1, anchoring the chain at the 2011 regtest genesis time — but
            // then waitNext()'s regtest min-difficulty rule ("new template 20
            // minutes after the tip") always fires once mock time is reset.
            txCoinbase.version = 1;
            txCoinbase.vin[0].scriptSig = CScript{} << (current_height + 1) << bi.extranonce;
            // Keep the assembler's outputs as-is: vout[0] already pays
            // GetTestPQScript() (upstream replaced it with an anyone-can-spend
            // empty script, which NEX consensus rejects) at every height, block 1
            // included, and the witness commitment stays consistent with the
            // untouched coinbase witness.
            block.vtx[0] = MakeTransactionRef(txCoinbase);
            if (txFirst.size() == 0)
                baseheight = current_height;
            if (txFirst.size() < 4)
                txFirst.push_back(block.vtx[0]);
            block.hashMerkleRoot = BlockMerkleRoot(block);
            // BLOCKINFO's hardcoded nonces are stale under MetalDAG PoW and the
            // changed block contents; grind the consensus PoW instead (regtest
            // targets make this take only a couple of attempts).
            block.nNonce = 0;
            while (!CheckProofOfWork(block, block.nBits, Assert(m_node.chainman)->GetParams().GetConsensus())) ++block.nNonce;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        // Alternate calls between Chainman's ProcessNewBlock and submitSolution
        // via the Mining interface. The former is used by net_processing as well
        // as the submitblock RPC.
        if (current_height % 2 == 0) {
            BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(shared_pblock, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
        } else {
            BOOST_REQUIRE(block_template->submitSolution(block.nVersion, block.nTime, block.nNonce, MakeTransactionRef(txCoinbase)));
        }
        {
            LOCK(cs_main);
            // The above calls don't guarantee the tip is actually updated, so
            // we explicitly check this.
            auto maybe_new_tip{Assert(m_node.chainman)->ActiveChain().Tip()};
            BOOST_REQUIRE_EQUAL(maybe_new_tip->GetBlockHash(), block.GetHash());
        }
        if (current_height % 2 == 0) {
            block_template = block_template->waitNext();
            BOOST_REQUIRE(block_template);
        } else {
            // This just adds coverage
            mining->waitTipChanged(block.hashPrevBlock);
        }
    }

    LOCK(cs_main);

    TestBasicMining(scriptPubKey, txFirst, baseheight);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPackageSelection(scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPrioritisedMining(scriptPubKey, txFirst);
}

BOOST_AUTO_TEST_SUITE_END()
