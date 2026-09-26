// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <util/feefrac.h>

#include <cstdint>
#include <string>

class CCoinsViewCache;
class CFeeRate;
class CScript;

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create.
 *  4,000,000 WU, deliberately NOT MAX_BLOCK_WEIGHT. The consensus limit (64,000,000) exceeds what the
 *  P2P transport will carry (MAX_SIZE, 33,554,432 bytes; net.cpp rejects anything larger), so a
 *  default of MAX_BLOCK_WEIGHT builds blocks that cannot be relayed and orphans the honest miner
 *  who built them — exactly on the busiest days. 4,000,000 is the founder's 2026-09-09 decision
 *  (commit df58404, "UTXO growth: cap the block weight now"): ~708 one-input PQ spends, ~3.8 MB,
 *  ~1.1 GB/day if every block is full (~400 GB/yr; DECISIONS.md's 105 GB/yr assumed 1 MB blocks,
 *  which PQ witnesses exceed). This is policy, not consensus: raise it at any time without a fork. **/
static constexpr unsigned int DEFAULT_BLOCK_MAX_WEIGHT{4'000'000};
/** The largest block the peer-to-peer transport can carry, and therefore the ceiling for
 *  -blockmaxweight (audit finding 8). BIP324 (v2) frames a message with a 3-byte length:
 *  16,777,215 bytes of contents including 13 bytes of framing; v1 stops at MAX_SIZE
 *  (33,554,432). A block's serialized size never exceeds its weight, so 16,000,000 WU is
 *  safe on both. The consensus ceiling (MAX_BLOCK_WEIGHT, 64,000,000) stays where the
 *  founder set it; a block between the two would be valid and undeliverable, so no node
 *  running this software will build one. Raising this needs a transport, not a fork. */
static constexpr unsigned int MAX_RELAYABLE_BLOCK_WEIGHT{16'000'000};
static_assert(MAX_RELAYABLE_BLOCK_WEIGHT + 13 <= 16'777'215, "a relayable block must fit a BIP324 v2 message");
static_assert(DEFAULT_BLOCK_MAX_WEIGHT <= MAX_RELAYABLE_BLOCK_WEIGHT, "the default must itself be relayable");
static_assert(DEFAULT_BLOCK_MAX_WEIGHT <= MAX_BLOCK_WEIGHT, "mining default cannot exceed the consensus limit");
/** Default for -blockreservedweight **/
static constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
/** Default sigops cost to reserve for coinbase transaction outputs when creating block templates. */
static constexpr unsigned int DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS{400};
/** This accounts for the block header, var_int encoding of the transaction count and a minimally viable
 * coinbase transaction. It adds an additional safety margin, because even with a thorough understanding
 * of block serialization, it's easy to make a costly mistake when trying to squeeze every last byte.
 * Setting a lower value is prevented at startup. */
static constexpr unsigned int MINIMUM_BLOCK_RESERVED_WEIGHT{2000};
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code.
 *  Equal to DEFAULT_MIN_RELAY_TX_FEE (founder decision 2026-09-15): a miner running the defaults includes
 *  nothing that other nodes running the defaults would not have relayed. **/
static constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1000};
/** The maximum weight for transactions we're willing to relay/mine */
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64  */
static constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static constexpr unsigned int MAX_P2SH_SIGOPS{15};
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static constexpr unsigned int MAX_STANDARD_TX_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST/5};
/** The maximum number of potentially executed legacy signature operations in a single standard tx */
static constexpr unsigned int MAX_TX_LEGACY_SIGOPS{2'500};
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or replacement.
 *  Kept equal to DEFAULT_MIN_RELAY_TX_FEE (node/mempool_args.cpp asserts it). **/
static constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE{1000};
/** Default for -bytespersigop */
static constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};
/** Default for -permitbaremultisig */
static constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true};
/** Default for -permitv2outputs: creating NEW legacy witness v2 outputs is non-standard after
 *  the re-genesis (REGENESIS.md section 4); existing v2 outputs stay spendable regardless. */
static constexpr bool DEFAULT_PERMIT_V2_OUTPUTS{false};
/** The maximum number of witness stack items in a standard P2WSH script */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS{100};
/** The maximum size in bytes of each witness stack item in a standard P2WSH script */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE{80};
/** The maximum size in bytes of each witness stack item in a standard BIP 342 script (Taproot, leaf version 0xc0) */
static constexpr unsigned int MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE{80};
/** The maximum size of a standard witness stack item spending an xCoin witness v3 PQ or SLH leaf
 *  (a 1,952-byte ML-DSA-65 key, a 3,310-byte ML-DSA signature and a 7,857-byte SLH-DSA
 *  signature must fit; equal to the consensus limit on initial v3 elements). */
static constexpr unsigned int MAX_STANDARD_XCOIN_V3_STACK_ITEM_SIZE{MAX_XCOIN_V3_INITIAL_ELEMENT_SIZE};
/** The maximum size in bytes of a standard witnessScript */
static constexpr unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE{3600};
/** The maximum size of a standard ScriptSig */
static constexpr unsigned int MAX_STANDARD_SCRIPTSIG_SIZE{1650};
/** Min feerate for defining dust.
 * Changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
static constexpr unsigned int DUST_RELAY_TX_FEE{3000};
/** Default for -minrelaytxfee, minimum relay fee for transactions, in satoshis per kvB.
 *
 *  1,000 sat/kvB, 1 sat/vB: Bitcoin parity (founder decision 2026-09-15). xCoin transactions are
 *  about ten times the size of Bitcoin's (an ML-DSA-65 witness carries a 1,952-byte key and a
 *  3,310-byte signature), so the floor fee for a typical 1-in-2-out payment, 1,480 vB as
 *  decoderawtransaction reports it on regtest, is 1,480 sat, 0.0000148 XID. The floor is a
 *  policy default, not consensus: a release can move it as the price moves, and -minrelaytxfee
 *  overrides it on any node. DEFAULT_BLOCK_MIN_TX_FEE and DEFAULT_INCREMENTAL_RELAY_FEE follow
 *  it, and the wallet's DEFAULT_FALLBACK_FEE (wallet/wallet.h) is the same rate. */
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{1000};
static_assert(DEFAULT_BLOCK_MIN_TX_FEE == DEFAULT_MIN_RELAY_TX_FEE, "the mining floor is the relay floor");
/** Maximum number of transactions per cluster (default) */
static constexpr unsigned int DEFAULT_CLUSTER_LIMIT{64};
/** Maximum size of cluster in virtual kilobytes */
static constexpr unsigned int DEFAULT_CLUSTER_SIZE_LIMIT_KVB{101};
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static constexpr unsigned int DEFAULT_ANCESTOR_LIMIT{25};
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static constexpr unsigned int DEFAULT_DESCENDANT_LIMIT{25};
/** Default for -datacarrier */
static const bool DEFAULT_ACCEPT_DATACARRIER = true;
/**
 * Default setting for -datacarriersize in vbytes: the aggregate size of the
 * OP_RETURN scriptPubKeys (opcode, push opcodes and data) of a transaction we
 * are willing to relay and mine. xCoin v2 keeps the 80-byte limit
 * (contrib/regenesis/REGENESIS.md section 5); blocks are additionally capped
 * by consensus at MAX_BLOCK_DATACARRIER_BYTES.
 */
static const unsigned int MAX_OP_RETURN_RELAY = 80;
static_assert(MAX_OP_RETURN_RELAY == DATACARRIER_ANCHOR_BYTES,
              "the relay limit is one anchor; the block cap is MAX_BLOCK_DATACARRIER_ANCHORS of them");
/** Data-carrier bytes the block assembler reserves for the coinbase transaction
 *  (the 38-byte witness commitment output plus room for pool tags) so that a
 *  template full of OP_RETURN outputs stays under MAX_BLOCK_DATACARRIER_BYTES. */
static constexpr unsigned int DEFAULT_COINBASE_DATACARRIER_RESERVE{1000};
/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static constexpr unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT{10000};

/**
 * Maximum number of ephemeral dust outputs allowed.
 */
static constexpr unsigned int MAX_DUST_OUTPUTS_PER_TX{1};

/**
 * Mandatory script verification flags that all new transactions must comply with for
 * them to be valid. Failing one of these tests may trigger a DoS ban;
 * see CheckInputScripts() for details.
 *
 * Note that this does not affect consensus validity; see GetBlockScriptFlags()
 * for that.
 */
static constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH |
                                                             SCRIPT_VERIFY_DERSIG |
                                                             SCRIPT_VERIFY_NULLDUMMY |
                                                             SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                             SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                             SCRIPT_VERIFY_WITNESS |
                                                             SCRIPT_VERIFY_TAPROOT |
                                                             SCRIPT_VERIFY_XCOIN_V3};

/**
 * Standard script verification flags that standard transactions will comply
 * with. However we do not ban/disconnect nodes that forward txs violating
 * the additional (non-mandatory) rules here, to improve forwards and
 * backwards compatibility.
 */
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                             SCRIPT_VERIFY_STRICTENC |
                                                             SCRIPT_VERIFY_MINIMALDATA |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                             SCRIPT_VERIFY_CLEANSTACK |
                                                             SCRIPT_VERIFY_MINIMALIF |
                                                             SCRIPT_VERIFY_NULLFAIL |
                                                             SCRIPT_VERIFY_LOW_S |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                             SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                                                             SCRIPT_VERIFY_CONST_SCRIPTCODE |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
                                                             SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};

/** For convenience, standard but not mandatory verify flags. */
static constexpr script_verify_flags STANDARD_NOT_MANDATORY_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType);

/** Get the vout index numbers of all dust outputs */
std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate);

// Changing the default transaction version requires a two step process: first
// adapting relay policy by bumping TX_MAX_STANDARD_VERSION, and then later
// allowing the new transaction version in the wallet/RPC.
static constexpr decltype(CTransaction::version) TX_MIN_STANDARD_VERSION{1};
static constexpr decltype(CTransaction::version) TX_MAX_STANDARD_VERSION{3};

/**
* Check for standard transaction types
* @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, bool permit_v2_outputs, const CFeeRate& dust_relay_fee, std::string& reason);
/**
 * Check for standard transaction types
 * @param[in] mapInputs       Map of previous transactions that have outputs we're spending
 * @returns valid TxValidationState if all inputs (scriptSigs) use only standard transaction forms else returns
 * invalid TxValidationState which states why the first invalid input is not standard
 */
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
* Check if the transaction is over standard P2WSH resources limit:
* 3600bytes witnessScript size, 80bytes per witness stack element, 100 witness stack elements
* These limits are adequate for multisignatures up to n-of-100 using OP_CHECKSIG, OP_ADD, and OP_EQUAL.
*
* Also enforce a maximum stack item size limit and no annexes for tapscript spends.
*/
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
 * Check whether this transaction spends any witness program but P2A, including not-yet-defined ones.
 * May return `false` early for consensus-invalid transactions.
 */
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts);

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionInputSize(const CTxIn& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(tx, 0, 0);
}

static inline int64_t GetVirtualTransactionInputSize(const CTxIn& tx)
{
    return GetVirtualTransactionInputSize(tx, 0, 0);
}

int64_t GetSigOpsAdjustedWeight(int64_t weight, int64_t sigop_cost, unsigned int bytes_per_sigop);

static inline FeePerVSize ToFeePerVSize(FeePerWeight feerate) { return {feerate.fee, (feerate.size + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR}; }

#endif // BITCOIN_POLICY_POLICY_H
