// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdint>
#include <cstdlib>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits).
 *  xCoin v2 (contrib/regenesis/REGENESIS.md section 0): 64 MB, in step with the
 *  64M WU block weight (a block of almost pure witness data approaches it). */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 64000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule).
 *  xCoin v2: 64,000,000 WU. A single-input ML-DSA-65 spend weighs ~5,650 WU,
 *  so a 300 s block holds ~11,300 PQ spends.
 *
 *  Why this number and not a smaller one (founder decision 2026-09-07). The
 *  direction of the fork is the whole argument: RAISING a block limit is a HARD
 *  fork (blocks that were invalid become valid, and old nodes reject them),
 *  while LOWERING one is a soft fork. The ceiling therefore has to be set high
 *  enough at genesis that growth never needs a hard fork, and tightened later
 *  by soft fork or by miner policy (-blockmaxweight) if it ever proves too
 *  generous. An earlier revision of this comment claimed "32M later by soft
 *  fork"; that was backwards and is the reason this constant moved before
 *  genesis rather than after it.
 *
 *  Why it stops at 64M. Every doubling past this point is paid for by the
 *  people running nodes, and that population cannot be recovered by a later
 *  parameter change even though the parameter itself is reversible. At 64M the
 *  worst case is 6.7 TB/year of chain growth and ~5.1 s to move one block on a
 *  100 Mbps link (about 1.7% of the interval, so orphan rate stays small). At
 *  128M those become 13.5 TB/year and 3.4%, and past 256M the network is
 *  datacenter-only under attack.
 *
 *  Note for anyone comparing this with Bitcoin's 4M WU: the ratio of the two
 *  limits is NOT the ratio of the two capacities. A Bitcoin 1-in-2-out P2WPKH
 *  spend is ~560 WU against ~5,650 WU here, so 16x the weight buys about 1.6x
 *  the transactions. At the previous 16M this chain carried FEWER transactions
 *  per block than Bitcoin does (2,832 against ~7,140), not more. The extra
 *  weight is absorbed entirely by post-quantum signature size. */
static const unsigned int MAX_BLOCK_WEIGHT = 64000000;
/** The maximum allowed number of signature check operations in a block (network rule).
 *  Scaled with the block weight (Bitcoin's 80,000 per 4M WU) so the sigop
 *  budget per weight unit is unchanged. ML-DSA-65 verification is ~1.5x slower
 *  than secp256k1 ECDSA, so each PQ sigcheck costs PQ_SIGOPS_COST (2): ~11,300
 *  single-sig PQ spends per block use ~22,600 of the 1,280,000 budget. */
static const int64_t MAX_BLOCK_SIGOPS_COST = 1280000;
/** Sigops cost for a single ML-DSA-65 signature verification. */
static const int64_t PQ_SIGOPS_COST = 2;
/** The maximum total size, in bytes, of the OP_RETURN (data carrier) scriptPubKeys
 *  in a block, summed over every output of every transaction (network rule,
 *  contrib/regenesis/REGENESIS.md section 5). Enforced in ContextualCheckBlock
 *  as "bad-blk-datacarrier". EVERY block obeys it, including block 1.
 *
 *  The number is a stated capacity, not a round figure. One ANCHOR is the
 *  periodic commitment a ledger above this chain writes here so that it cannot
 *  rewrite its own history and so anyone can exit it if it fails (charter
 *  section 8): a tag, a 32-byte state hash and a 36-byte content id, which is
 *  why the relay policy limit MAX_OP_RETURN_RELAY is 80 bytes. The block cap is
 *  one hundred of those.
 *
 *  Why 100 and not 1,250 (founder decision 2026-09-09, lowered from 100,000).
 *  Nothing anchors into this chain yet, and 100 per block is 1,200 ledgers
 *  settling hourly or 28,800 daily — far past anything plausible this decade.
 *  Against that, the cost of being generous is permanent: at the old cap an
 *  attacker could bury 10.5 GB a year in the chain for ~105 XID, because an
 *  OP_RETURN output is worth zero so the settlement levy on it is zero and only
 *  the byte floor applies. A young chain has no fee pressure to price that out,
 *  and NO fork ever removes bytes already written. Being too tight is
 *  recoverable by a hard fork nobody would resist; being too generous is not
 *  recoverable at all, so the error is taken on the tight side. Raising this
 *  needs a hard fork, lowering it is a soft fork. */
static const uint64_t DATACARRIER_ANCHOR_BYTES = 80;
static const uint64_t MAX_BLOCK_DATACARRIER_ANCHORS = 100;
static const uint64_t MAX_BLOCK_DATACARRIER_BYTES = MAX_BLOCK_DATACARRIER_ANCHORS * DATACARRIER_ANCHOR_BYTES; // 8,000
/** Upstream's coinbase maturity, 100. No xCoin chain uses it: every chain's consensus
 *  value is Consensus::Params::coinbaseMaturity = COINBASE_MATURITY_MAINNET (1,000),
 *  regtest included. The unit and functional test harnesses pass -coinbasematurity=100
 *  on regtest so the inherited fixtures still mine 100 blocks to a spendable coinbase;
 *  this constant is what they and the benches count with. */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 600;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
