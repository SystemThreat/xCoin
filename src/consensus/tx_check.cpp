// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <script/solver.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool permit_v2_outputs, int64_t min_output_value)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // xCoin PQ-only consensus rule: every output must be post-quantum locked: WITNESS_V3_PQ (the
    // script tree of REGENESIS.md section 4) or, where the chain still permits it, WITNESS_V2_PQ
    // (legacy single-key ML-DSA-65), or NULL_DATA (OP_RETURN, used for witness commitments and
    // data anchors). This enforces 100% post-quantum coverage at the consensus layer: legacy
    // Bitcoin script types (P2PKH, P2WPKH, P2TR, ...) are rejected. On mainnet and the rehearsal
    // chain no witness v2 output exists at all (nothing is carried in; REGENESIS.md section 3), so
    // a new witness v2 output there is invalid as well; spending an existing v2 output (regtest
    // and the inherited test chains) is unaffected.
    //
    // Output-value floor (Consensus::MIN_OUTPUT_VALUE_SAT): a post-quantum output
    // costs ~5.4 kB of witness to spend, so one worth less than the floor can never
    // be spent economically and only bloats the UTXO set. NULL_DATA carries no
    // value and never enters the UTXO set, so it is exempt. 0 disables the rule.
    // Coinbase exemption (founder decision 2026-09-15): a coinbase with EXACTLY ONE
    // output that is not NULL_DATA may pay that output any value from 1 sat up,
    // so that every era's subsidy is mintable by an otherwise empty block (late
    // in a schedule the subsidy may fall under the floor; the final shape never [EMISSION-SHAPE]
    // does, its smallest row paying 0.1 XID). A
    // coinbase with two or more such outputs is subject to the floor on every one
    // of them: a miner cannot split the reward into sub-floor outputs and spray
    // them into the UTXO set, and a zero-value spendable output is never allowed,
    // being bloat with nothing behind it. The rule is context-free: IsCoinBase()
    // is the transaction's shape, and the floor comes in as a parameter.
    size_t spendable_outputs{0};
    bool below_floor{false};
    bool zero_value{false};
    for (const auto& txout : tx.vout) {
        std::vector<std::vector<unsigned char>> vSolutions;
        TxoutType whichType = Solver(txout.scriptPubKey, vSolutions);
        const bool allowed{whichType == TxoutType::WITNESS_V3_PQ || whichType == TxoutType::NULL_DATA ||
                           (permit_v2_outputs && whichType == TxoutType::WITNESS_V2_PQ)};
        if (!allowed) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txout-not-pq",
                                 permit_v2_outputs ? "only witness v2/v3 post-quantum outputs and NULL_DATA are allowed"
                                                   : "only witness v3 post-quantum outputs and NULL_DATA are allowed on this chain");
        }
        if (whichType == TxoutType::NULL_DATA) continue;
        ++spendable_outputs;
        if (txout.nValue < min_output_value) below_floor = true;
        if (txout.nValue < 1) zero_value = true;
    }
    if (min_output_value > 0 && below_floor) {
        const bool coinbase_exempt{tx.IsCoinBase() && spendable_outputs == 1 && !zero_value};
        if (!coinbase_exempt) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txout-below-min",
                                 "every output that is not NULL_DATA must carry at least the chain's minimum value "
                                 "(a coinbase with exactly one such output may pay it any value from 1 sat)");
        }
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
