// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_LEVY_H
#define BITCOIN_CONSENSUS_LEVY_H

#include <consensus/amount.h>
#include <consensus/params.h>

#include <algorithm>
#include <cstdint>

/**
 * The settlement levy (contrib/regenesis/REGENESIS.md section 6).
 *
 * Every non-coinbase transaction must pay a fee of at least
 *
 *     SettlementLevy(sum of output values, rule) = min(ceil(sum * rule.bp / 10,000), rule.capSat)
 *
 * where rule is Consensus::Params::SettlementLevyAt(height). Every chain ships
 * ONE row, at height 0, with a zero rate and a zero cap: no transaction owes a
 * levy today (SETTLEMENT_LEVY_GENESIS_RULE; founder decision 2026-09-14, see
 * consensus/params.h). The arithmetic below is kept live and asserted at the
 * reference rate of 5 bp capped at 0.0001 XID (SETTLEMENT_LEVY_REFERENCE_RULE),
 * which is what regtest charges under -levybp=5. Integer arithmetic only, rounded up,
 * overflow-free for sums up to MAX_MONEY and rates up to SETTLEMENT_LEVY_BP_MAX
 * (100%): the value is split at the denominator so no product exceeds
 * 1e16 * 1e4 / 1e4 (MAX_MONEY is 10^16 sat). The levy is paid to the miner as an ordinary fee; nothing
 * is burned. Coinbases are exempt (they have no fee); nothing else is. The
 * consensus rule is enforced by Consensus::CheckSettlementLevy (tx_verify.h)
 * in ConnectBlock and in mempool acceptance.
 *
 * The fork asymmetry, which is why the chain starts at zero and why the rule is
 * a schedule: anything that LOWERS the minimum — cutting the rate, lowering the
 * cap, removing the levy — is a hard fork. Anything that RAISES it only
 * invalidates transactions that used to be valid, so it is a soft fork and is
 * available forever: add a row to settlementLevySchedule, ship a deployment.
 * SettlementLevyScheduleIsSoftForkOnly refuses a row that lowers anything, and a
 * zero genesis row is the one starting point from which every later choice is
 * a soft fork.
 */
namespace Consensus {

static constexpr int64_t LEVY_DENOMINATOR = 10'000;

/** ceil(value_out * levy_bp / 10,000), before the cap. Kept separate so the
 *  overflow-freedom of the raw arithmetic stays directly assertable. */
constexpr CAmount SettlementLevyUncapped(CAmount value_out, int64_t levy_bp)
{
    if (levy_bp <= 0 || value_out <= 0) return 0;
    const int64_t whole{value_out / LEVY_DENOMINATOR};
    const int64_t rest{value_out % LEVY_DENOMINATOR};
    return whole * levy_bp + (rest * levy_bp + LEVY_DENOMINATOR - 1) / LEVY_DENOMINATOR;
}

/** The minimum fee for outputs worth value_out: the proportional levy, capped. */
constexpr CAmount SettlementLevy(CAmount value_out, int64_t levy_bp, int64_t cap_sat)
{
    return std::min(SettlementLevyUncapped(value_out, levy_bp), cap_sat);
}
constexpr CAmount SettlementLevy(CAmount value_out, const SettlementLevyRule& rule)
{
    return SettlementLevy(value_out, rule.bp, rule.capSat);
}

/** The smallest fee f with f >= SettlementLevy(value_in - f): what a spender
 *  who lets the whole remainder of value_in go to outputs (change, sweep,
 *  subtract-fee-from-amount) has to pay, i.e. ceil(value_in * levy_bp /
 *  (10,000 + levy_bp)), capped. Wallet arithmetic, not consensus. */
constexpr CAmount SettlementLevyFromInputs(CAmount value_in, int64_t levy_bp, int64_t cap_sat)
{
    if (levy_bp <= 0 || value_in <= 0) return 0;
    const int64_t d{LEVY_DENOMINATOR + levy_bp};
    const int64_t whole{value_in / d};
    const int64_t rest{value_in % d};
    const CAmount fee{whole * levy_bp + (rest * levy_bp + d - 1) / d};
    return std::min(fee, cap_sat);
}
constexpr CAmount SettlementLevyFromInputs(CAmount value_in, const SettlementLevyRule& rule)
{
    return SettlementLevyFromInputs(value_in, rule.bp, rule.capSat);
}

// The rule every chain ships (consensus/params.h): no levy. Zero rate, zero cap, from height 0.
static_assert(SETTLEMENT_LEVY_GENESIS_RULE.bp == 0 && SETTLEMENT_LEVY_GENESIS_RULE.capSat == 0, "the chain ships without a levy");
static_assert(SettlementLevy(1, SETTLEMENT_LEVY_GENESIS_RULE) == 0 && SettlementLevy(10'000, SETTLEMENT_LEVY_GENESIS_RULE) == 0
              && SettlementLevy(MAX_MONEY, SETTLEMENT_LEVY_GENESIS_RULE) == 0 && SettlementLevyFromInputs(MAX_MONEY, SETTLEMENT_LEVY_GENESIS_RULE) == 0,
              "under the genesis rule nothing is owed, whatever moves");

// The REFERENCE rule: what -levybp=5 charges on regtest and what a future
// activation is documented against. Every arithmetic assertion below runs on it.
static constexpr SettlementLevyRule SETTLEMENT_LEVY_REFERENCE_RULE{0, SETTLEMENT_LEVY_BP, SETTLEMENT_LEVY_CAP_SAT};

static_assert(SettlementLevy(10'000, SETTLEMENT_LEVY_REFERENCE_RULE) == 5, "5 bp of 10,000 sat is 5 sat");
static_assert(SettlementLevy(1, SETTLEMENT_LEVY_REFERENCE_RULE) == 1, "the levy rounds up: 1 sat moved still costs 1 sat");
static_assert(SettlementLevy(2'000, SETTLEMENT_LEVY_REFERENCE_RULE) == 1 && SettlementLevy(2'001, SETTLEMENT_LEVY_REFERENCE_RULE) == 2, "rounds up at 2,000 sat per satoshi of levy");
static_assert(SettlementLevyUncapped(MAX_MONEY, SETTLEMENT_LEVY_BP_MAX) == MAX_MONEY, "100% of the cap is representable: the raw arithmetic does not overflow");
static_assert(SettlementLevyUncapped(MAX_MONEY, SETTLEMENT_LEVY_BP) == 5'000'000'000'000LL, "uncapped, 5 bp of 100M XID would be 50,000 XID");
static_assert(SettlementLevy(0, SETTLEMENT_LEVY_REFERENCE_RULE) == 0 && SettlementLevy(10'000, 0, SETTLEMENT_LEVY_CAP_SAT) == 0, "no outputs or no levy: nothing owed");
static_assert(SettlementLevyFromInputs(10'005, SETTLEMENT_LEVY_REFERENCE_RULE) == 5 && SettlementLevy(10'005 - 5, SETTLEMENT_LEVY_REFERENCE_RULE) == 5, "10,005 sat in: 5 sat fee covers 10,000 sat out");
static_assert(SETTLEMENT_LEVY_BP >= 0 && SETTLEMENT_LEVY_BP <= SETTLEMENT_LEVY_BP_MAX, "levy in range");

// The reference cap. 0.0001 XID, whatever the transaction moves.
static_assert(SETTLEMENT_LEVY_CAP_SAT == 10'000, "the reference cap is 0.0001 XID");
static_assert(SettlementLevy(20'000'000, SETTLEMENT_LEVY_REFERENCE_RULE) == 10'000, "0.2 XID out is exactly at the cap");
static_assert(SettlementLevy(20'000'001, SETTLEMENT_LEVY_REFERENCE_RULE) == 10'000, "one sat past the crossover is still the cap");
static_assert(SettlementLevy(1'000'000'000'000LL, SETTLEMENT_LEVY_REFERENCE_RULE) == 10'000, "10,000 XID out owes the cap, not 5 XID");
static_assert(SettlementLevy(MAX_MONEY, SETTLEMENT_LEVY_REFERENCE_RULE) == 10'000, "moving the whole supply owes the cap");
static_assert(SettlementLevyFromInputs(MAX_MONEY, SETTLEMENT_LEVY_REFERENCE_RULE) == 10'000, "the wallet-side helper respects the same cap");
// A raised cap is proportional again above the old crossover: the soft-fork lever works as intended.
static_assert(SettlementLevy(COIN, SettlementLevyRule{0, SETTLEMENT_LEVY_BP, 100'000}) == 50'000, "under a 0.001 XID cap, 1 XID owes the proportional 50,000 sat");

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_LEVY_H
