// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <limits>
#include <string>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

// ── xCoin emission tests use BasicTestingSetup (no chain bootstrap needed) ───
// The cap is DECIDED: 100,000,000 XID of 10^8 sat (owner decision 2026-09-25).
// The SHAPE of the table is FINAL (the Annual Tenth) and generated (consensus/params.h,
// contrib/regenesis/emission.py); everything here holds for any table the
// policy generates; the shape itself is pinned in exactly one place,
// regenesis_tests/annual_tenth_emission_shape. Nothing is carried in (35c4fda):
// rows start at height 1 and block 1 is an ordinary block.
BOOST_FIXTURE_TEST_SUITE(nex_emission_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(nex_emission_era_table_consistency)
{
    // Back-to-back, non-empty rows from height 1 (genesis mints nothing), each
    // paying a positive subsidy; the last row ends at EMISSION_END_HEIGHT.
    static_assert(Consensus::NUM_EMISSION_ERAS > 0);
    BOOST_CHECK_EQUAL(Consensus::EMISSION_START_HEIGHT, 1);
    BOOST_CHECK_EQUAL(Consensus::EMISSION_TABLE[0].startHeight, Consensus::EMISSION_START_HEIGHT);
    for (int i = 0; i < Consensus::NUM_EMISSION_ERAS; ++i) {
        const auto& era = Consensus::EMISSION_TABLE[i];
        BOOST_CHECK(era.endHeight >= era.startHeight);
        BOOST_CHECK(era.baseSubsidy > 0);
        BOOST_CHECK(era.baseSubsidy <= MAX_MONEY);
        if (i > 0) BOOST_CHECK_EQUAL(era.startHeight, Consensus::EMISSION_TABLE[i - 1].endHeight + 1);
    }
    BOOST_CHECK_EQUAL(Consensus::EMISSION_TABLE[Consensus::NUM_EMISSION_ERAS - 1].endHeight, Consensus::EMISSION_END_HEIGHT);
    BOOST_CHECK(Consensus::EmissionTableWellFormed(Consensus::EMISSION_TABLE, Consensus::NUM_EMISSION_ERAS, Consensus::EMISSION_START_HEIGHT));
}

BOOST_AUTO_TEST_CASE(nex_emission_exact_total)
{
    // Sum of the table + closing dust = exactly the cap (nothing is carried in).
    CAmount totalEmission = 0;
    for (int era = 0; era < Consensus::NUM_EMISSION_ERAS; ++era) {
        const auto& e = Consensus::EMISSION_TABLE[era];
        int blocks = e.endHeight - e.startHeight + 1;
        totalEmission += e.baseSubsidy * blocks;
    }
    totalEmission += Consensus::EMISSION_CLOSING_DUST_SAT;
    BOOST_CHECK_EQUAL(totalEmission, Consensus::TOTAL_EMISSION_SAT);
    BOOST_CHECK_EQUAL(totalEmission, CAmount{10'000'000'000'000'000LL}); // 100,000,000 XID: the whole cap, no premine, nothing carried
}

BOOST_AUTO_TEST_CASE(nex_emission_via_getblocksubsidy)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& cp = chainParams->GetConsensus();

    // Genesis mints nothing; block 1 is an ordinary first-row block (no distribution).
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, cp), Consensus::EMISSION_TABLE[0].baseSubsidy);
    // Every row pays its subsidy at both ends; the next row takes over the block after.
    for (int i = 0; i < Consensus::NUM_EMISSION_ERAS; ++i) {
        const auto& e = Consensus::EMISSION_TABLE[i];
        const bool last{i == Consensus::NUM_EMISSION_ERAS - 1};
        BOOST_CHECK_EQUAL(GetBlockSubsidy(e.startHeight, cp), e.baseSubsidy);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(e.endHeight, cp), e.baseSubsidy + (last ? Consensus::EMISSION_CLOSING_DUST_SAT : 0));
        if (!last) BOOST_CHECK_EQUAL(GetBlockSubsidy(e.endHeight + 1, cp), Consensus::EMISSION_TABLE[i + 1].baseSubsidy);
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT, cp),
                      Consensus::EMISSION_TABLE[Consensus::NUM_EMISSION_ERAS - 1].baseSubsidy + Consensus::EMISSION_CLOSING_DUST_SAT);
    // After the end: fees only.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(Consensus::EMISSION_END_HEIGHT + 1, cp), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(std::numeric_limits<int>::max(), cp), 0);
    // Negative height: zero.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(-1, cp), 0);
}

BOOST_AUTO_TEST_CASE(nex_emission_total)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& cp = chainParams->GetConsensus();
    CAmount total{0};
    for (int h = 0; h <= Consensus::EMISSION_END_HEIGHT; ++h) total += GetBlockSubsidy(h, cp);
    // 100,000,000 XID emitted exactly; there is no premine and nothing is carried in.
    BOOST_CHECK_EQUAL(total, Consensus::MAX_SUPPLY_SAT);
    BOOST_CHECK_EQUAL(total, MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(nex_supply_cap_constants)
{
    // DECIDED 2026-09-25: the cap is exactly 100,000,000 XID of 10^8 sat, it is
    // also the consensus MAX_MONEY bound, and the emission is the whole of it.
    BOOST_CHECK_EQUAL(COIN, CAmount{100'000'000LL});
    BOOST_CHECK_EQUAL(Consensus::TOTAL_EMISSION_SAT, Consensus::MAX_SUPPLY_SAT);
    BOOST_CHECK_EQUAL(Consensus::MAX_SUPPLY_SAT, CAmount{10'000'000'000'000'000LL});
    BOOST_CHECK_EQUAL(Consensus::MAX_SUPPLY_SAT, 100'000'000 * COIN);
    BOOST_CHECK_EQUAL(Consensus::MAX_SUPPLY_SAT, MAX_MONEY);
    // Under one XID of rounding is all the closing remainder may be.
    BOOST_CHECK(Consensus::EMISSION_CLOSING_DUST_SAT >= 0 && Consensus::EMISSION_CLOSING_DUST_SAT < COIN);
}

BOOST_AUTO_TEST_SUITE_END()

// ── Tests that need a full chain (TestingSetup) ──────────────────────────────
BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    // These values track the regtest assumeutxo entry in kernel/chainparams.cpp.
    // hash_serialized covers the UTXO set, so it moves whenever the coinbases of
    // the deterministic test chain change (the regtest emission table, the
    // coinbase shape). The blockhash moves for that reason too, and additionally
    // whenever a header field changes: stage B4 moved the BIP9 top bits into
    // bits 31..30, so every nVersion -- and every block hash on the deterministic
    // test chain -- changed while the UTXO set stayed exactly the same. 2026-09-14:
    // the block-1 distribution was removed (35c4fda, 506d9ad, 8e440be, 7263c5d:
    // block 1 is an ordinary block) and the block hash moved with it; the UTXO
    // set at 110 still hashes the same, so hash_serialized holds.
    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "f63ca907f7d92520253c3e6f6eb706e890f18419d2d17e96970484ad65374685");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto by_hash = params->AssumeutxoForBlockhash(uint256{"0edf04b2825529cea5a28dcb2c08f3f6828030c29b1eceb3b89cd1c38719ccd2"});
    BOOST_REQUIRE(by_hash);  // a stale pin here used to read through an empty optional
    BOOST_CHECK_EQUAL(by_hash->hash_serialized.ToString(), "f63ca907f7d92520253c3e6f6eb706e890f18419d2d17e96970484ad65374685");
    BOOST_CHECK_EQUAL(by_hash->m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash().ToUint256() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash().ToUint256();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash().ToUint256();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash().ToUint256());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
