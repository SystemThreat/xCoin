// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TX_CHECK_H
#define BITCOIN_CONSENSUS_TX_CHECK_H

#include <cstdint>

/**
 * Context-independent transaction checking code that can be called outside the
 * bitcoin server and doesn't depend on chain or mempool state. Transaction
 * verification code that does call server functions or depend on server state
 * belongs in tx_verify.h/cpp instead.
 */

class CTransaction;
class TxValidationState;

/**
 * Context-free transaction checks.
 *
 * `permit_v2_outputs` selects the xCoin output rule (REGENESIS.md sections 3
 * and 4): with it set, an output may be WITNESS_V2_PQ, WITNESS_V3_PQ or
 * NULL_DATA; without it, WITNESS_V2_PQ is rejected too (`bad-txout-not-pq`),
 * because on that chain nothing is carried in and no witness v2 output exists.
 * Callers with a chain in hand pass
 * `Consensus::Params::permitV2Outputs`. There is NO DEFAULT on purpose (stage
 * B6): which of the two rules a call means is a consensus decision, so every
 * caller states it, and a caller with no chain in hand (the genesis coinbase,
 * the shared test vectors, fuzzers) has to say `true` out loud.
 *
 * `min_output_value` is the chain's output-value floor in satoshi
 * (`Consensus::Params::minOutputValueSat`): every output that is not NULL_DATA
 * must carry at least this much (`bad-txout-below-min`), except the single
 * non-NULL_DATA output of a coinbase that has exactly one, which may carry any
 * value from 1 sat (founder decision 2026-09-15: every era's subsidy stays
 * mintable by an empty block; a coinbase with two or more such outputs is held
 * to the floor on all of them). 0 disables the rule,
 * and IS the default here, unlike `permit_v2_outputs`: a caller with no chain in
 * hand (the genesis coinbase, the shared vectors, fuzzers) gets no floor, and
 * the two callers with a chain — mempool acceptance and CheckBlock — pass the
 * chain's value, CheckBlock exempting the genesis block whose marker output is
 * zero-value.
 */
bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool permit_v2_outputs, int64_t min_output_value = 0);

#endif // BITCOIN_CONSENSUS_TX_CHECK_H
