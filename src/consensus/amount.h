// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

/** The amount of satoshis in one coin (one XID: 8 decimal places). */
static constexpr CAmount COIN = 100000000;

/** No amount larger than this (in satoshi) is valid.
 *
 * On xCoin this constant IS the emission cap: 100,000,000 XID (owner decision
 * 2026-09-25; it was 21,000,000), all of it mined emission, with no premine and
 * nothing carried in from the v1 chain. consensus/params.h asserts
 * MAX_SUPPLY_SAT == MAX_MONEY, and the generated emission table plus its closing
 * remainder sum to exactly this amount. (In Bitcoin, MAX_MONEY is only a sanity
 * bound above the real supply; here the two are the same number.) It is used by
 * consensus-critical validation code, so its exact value is consensus critical.
 * 100,000,000 x 10^8 = 10^16 sat, far inside int64 (9.2 x 10^18).
 * */
static constexpr CAmount MAX_MONEY = 100000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H
