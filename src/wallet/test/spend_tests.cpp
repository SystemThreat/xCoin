// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/levy.h>
#include <policy/fees/block_policy_estimator.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
namespace {
/** A regtest chain with the mainnet 5 bp settlement levy (the harness disables it
 *  unless a test asks; xcoin_levy_tests has the same fixture). */
struct LevyChain100Setup : public TestChain100Setup {
    LevyChain100Setup() : TestChain100Setup{ChainType::REGTEST, TestOpts{.extra_args = {"-levybp=5"}}} {}
};

/** The SubtractFee scenario: a subtract-from-recipient spend of the wallet's one
 *  mature 50 XID coinbase, `leftover` under the input, never creates change and
 *  pays the leftover to the recipient rather than the miner. Returns the fee. */
CAmount CheckSubtractFeeTx(CWallet& wallet, CAmount leftover_input_amount)
{
    CRecipient recipient{WitnessV3PQ{uint256::ONE}, 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
    CCoinControl coin_control;
    coin_control.m_feerate.emplace(5000);
    coin_control.fOverrideFeeRate = true;
    // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
    coin_control.m_change_type = OutputType::XCOIN_V3;
    auto res = CreateTransaction(wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
    BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
    const auto& txr = *res;
    BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
    BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
    BOOST_CHECK_GT(txr.fee, 0);
    return txr.fee;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

// The wallet owns one mature coinbase (witness v2, 50 XID) through the
// post-quantum coinbase descriptor and spends it with an ML-DSA-65 witness.
// The change type is the witness v3 script tree, whose cost of change (about
// 1,400 vB of witness to spend) dwarfs the fee of this one-input spend, so a
// leftover of fee + 123 is still uneconomical as change. The chain's settlement
// levy (-levybp, REGENESIS.md section 6) is exercised in the LevySubtractFee
// case below.
BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, TestPQCoinbaseScript());
    mineBlocks(COINBASE_MATURITY);
    auto wallet = CreateSyncedPQWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) { return CheckSubtractFeeTx(*wallet, leftover_input_amount); };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

// The same scenario under the chain's settlement levy (REGENESIS.md section 6):
// the wallet floors the fee at the levy the outputs owe, which for a 50 XID spend
// is the per-transaction cap (0.0001 XID, above the fee-rate fee here), the
// leftover still goes to the recipient, and the node's mempool accepts the
// result: one satoshi less would be bad-txns-levy.
BOOST_FIXTURE_TEST_CASE(LevySubtractFee, LevyChain100Setup)
{
    const Consensus::SettlementLevyRule levy{m_node.chainman->GetConsensus().SettlementLevyAt(0)};
    BOOST_REQUIRE_EQUAL(levy.bp, 5);
    const CAmount levy_fee{Consensus::SettlementLevyFromInputs(50 * COIN, levy)};
    BOOST_REQUIRE_EQUAL(levy_fee, Consensus::SETTLEMENT_LEVY_CAP_SAT);

    CreateAndProcessBlock({}, TestPQCoinbaseScript());
    mineBlocks(COINBASE_MATURITY);
    auto wallet = CreateSyncedPQWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    auto check_tx = [&wallet](CAmount leftover_input_amount) { return CheckSubtractFeeTx(*wallet, leftover_input_amount); };

    const CAmount fee{check_tx(0)};
    BOOST_CHECK_EQUAL(fee, levy_fee); // the levy, not the fee rate, sets the fee
    BOOST_CHECK_EQUAL(fee, check_tx(123));
    BOOST_CHECK_EQUAL(fee, check_tx(fee));
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));

    // What the wallet builds is what the node accepts, and it is at the boundary.
    CRecipient recipient{WitnessV3PQ{uint256::ONE}, 50 * COIN, /*subtract_fee=*/true};
    CCoinControl coin_control;
    coin_control.m_feerate.emplace(5000);
    coin_control.fOverrideFeeRate = true;
    auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
    BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
    BOOST_CHECK_EQUAL(res->fee, levy_fee);
    {
        LOCK(cs_main);
        const MempoolAcceptResult r{m_node.chainman->ProcessTransaction(res->tx, /*test_accept=*/true)};
        BOOST_CHECK_MESSAGE(r.m_result_type == MempoolAcceptResult::ResultType::VALID, r.m_state.GetRejectReason());
        CMutableTransaction short_by_one{*res->tx};
        short_by_one.vout[0].nValue += 1; // the witness no longer matches, but the levy is checked first
        const MempoolAcceptResult refused{m_node.chainman->ProcessTransaction(MakeTransactionRef(short_by_one), /*test_accept=*/true)};
        BOOST_CHECK(refused.m_result_type != MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(refused.m_state.GetRejectReason(), "bad-txns-levy");
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, 50 XID each, to the wallet (total balance 200 XID):
    // four coinbases to the post-quantum coinbase descriptor, then maturity.
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, TestPQCoinbaseScript());
    mineBlocks(COINBASE_MATURITY);
    auto wallet = CreateSyncedPQWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 XID total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 XID, and the tx target is 299 XID.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::XCOIN_V3, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 XID from a wallet that only has 200 XID. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 BTC payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 XID.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 XID)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 XID.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
