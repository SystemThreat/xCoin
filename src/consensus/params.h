// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <script/verify_flags.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <string_view>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 * Consensus changes for which the new rules are enforced from genesis are not listed here.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    // SCRIPT_VERIFY_WITNESS is enforced from genesis, but the check for downloading
    // missing witness data is not. BIP 147 also relies on hardcoded activation height.
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    // Removing an entry may require bumping MinBIP9WarningHeight.
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /** Period of blocks to check signalling in (usually retarget period, ie params.DifficultyAdjustmentInterval()) */
    uint32_t period{2016};
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t threshold{1916};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * xCoin emission era: a contiguous [startHeight, endHeight] range of blocks
 * that all pay the same subsidy. Eras are laid out back to back from
 * EMISSION_START_HEIGHT; the closing era's last block additionally mints the
 * closing dust (see GetBlockSubsidy in validation.cpp).
 */
struct EmissionEra {
    int startHeight;          //!< First block of this era (inclusive)
    int endHeight;            //!< Last block of this era (inclusive)
    int64_t baseSubsidy;      //!< Per-block reward in satoshis
};

// ═══════════════════════════════════════════════════════════════════════════
// XCOIN (XCF) MONETARY POLICY — v2 chain (re-genesis), 21,000,000 XCF hard cap.
// Spec: contrib/regenesis/REGENESIS.md sections 2 and 3. FINAL founder
// decision 2026-09-05: NO premine, NO founder allocation and nothing carried
// in — the founder mines under the same rules as everyone else.
//
//   Block 0   : mints nothing (the genesis coinbase is unspendable by design).
//   Blocks 1+ : 14 XCF per block for 750,000 blocks (seven years and 49 days at
//               300 s), halved every 750,000 blocks in whole satoshis until the
//               shift reaches zero — 31 eras. 14 x 750,000 x 2 = 21,000,000, less
//               the rounding of thirty halvings (0.09 XCF), which the final
//               subsidy block mints as the closing remainder, so that
//
//       sum(era subsidies) + remainder == 21,000,000 XCF exactly (nothing is carried).
//
//   Seven eras of seven years carry the chain into its 49th year (the charter
//   calls them cycles); the subsidy then fades and never stops at once.
//   After EMISSION_END_HEIGHT (23,250,000, ~2248) the subsidy is zero (fees only).
//
// FINAL — founder decision 2026-09-14; generated by  python3 contrib/regenesis/emission.py
// This is the schedule the charter freezes at genesis. All 21,000,000 XCF are
// mined, none are granted.
// ═══════════════════════════════════════════════════════════════════════════

/** Nothing is carried in and nothing is pre-mined (charter sections 3 and 4):
 *  supply begins at zero, and the whole cap is the emission below. Block 1 is an
 *  ordinary block. */

/** The v1 founder script, OP_2 <SHA-256(founder ML-DSA-65 pubkey)> (witness v2):
 *  address xpa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5sdnc0av
 *  (David's founder key: NTAG 424 DNA card-bound wallet, ceremony 2026-09-01).
 *  The v1 chain paid it a block-1 founder allocation (1,000,000 XCF). This
 *  chain carries nothing in from v1 and has no founder allocation and no
 *  block-1 distribution at all (35c4fda), so nothing here ever pays this
 *  script; it is kept only so the v1 allocation stays identifiable. */
static constexpr std::array<uint8_t, 34> FOUNDER_PREMINE_SCRIPT = {
    0x52, 0x20, // OP_2, PUSH(32)
    0xa1,0x58,0xac,0x50,0x47,0x84,0x5b,0xfd,0xed,0xad,0x6e,0x2e,0x3e,0x07,0x4b,0x2b,
    0xac,0x33,0xce,0xfa,0x74,0x40,0xb6,0xb3,0xab,0xa6,0x68,0xb4,0x0b,0xd8,0xbc,0xe9,
};

/** First block that pays an era subsidy. Block 1 is an ordinary block: nothing
 *  is carried in and there is no distribution to pay, so there is nothing to
 *  special-case and mining pays 14 XCF from the very first block after genesis.
 *  Block 0 still mints nothing — the genesis coinbase carries the charter, not
 *  money. */
static constexpr int EMISSION_START_HEIGHT = 1;

/** Blocks per era: seven years and 49 days at 300 s. Every era is exactly this
 *  long; the table ends where the halving reaches zero. */
static constexpr int EMISSION_ERA_BLOCKS = 750'000;

/** 14 XCF halved thirty times: 31 eras, the last paying one satoshi. */
static constexpr int NUM_EMISSION_ERAS = 31;

/** Era-0 subsidy: exactly 14 XCF per block — and 14 x 750,000 is exactly half the cap. */
static constexpr int64_t EMISSION_ERA0_SUBSIDY_SAT = 1'400'000'000LL;

/** Mainnet emission schedule (FINAL, charter section 4). */
static constexpr EmissionEra EMISSION_TABLE[NUM_EMISSION_ERAS] = {
    //  startHeight  endHeight  baseSubsidy(sat)
    {         1,    750000, 1400000000LL },  // era  0: 14.00000000 XCF x 750,000 blocks
    {    750001,   1500000,  700000000LL },  // era  1:  7.00000000 XCF x 750,000 blocks
    {   1500001,   2250000,  350000000LL },  // era  2:  3.50000000 XCF x 750,000 blocks
    {   2250001,   3000000,  175000000LL },  // era  3:  1.75000000 XCF x 750,000 blocks
    {   3000001,   3750000,   87500000LL },  // era  4:  0.87500000 XCF x 750,000 blocks
    {   3750001,   4500000,   43750000LL },  // era  5:  0.43750000 XCF x 750,000 blocks
    {   4500001,   5250000,   21875000LL },  // era  6:  0.21875000 XCF x 750,000 blocks
    {   5250001,   6000000,   10937500LL },  // era  7:  0.10937500 XCF x 750,000 blocks
    {   6000001,   6750000,    5468750LL },  // era  8:  0.05468750 XCF x 750,000 blocks
    {   6750001,   7500000,    2734375LL },  // era  9:  0.02734375 XCF x 750,000 blocks
    {   7500001,   8250000,    1367187LL },  // era 10:  0.01367187 XCF x 750,000 blocks
    {   8250001,   9000000,     683593LL },  // era 11:  0.00683593 XCF x 750,000 blocks
    {   9000001,   9750000,     341796LL },  // era 12:  0.00341796 XCF x 750,000 blocks
    {   9750001,  10500000,     170898LL },  // era 13:  0.00170898 XCF x 750,000 blocks
    {  10500001,  11250000,      85449LL },  // era 14:  0.00085449 XCF x 750,000 blocks
    {  11250001,  12000000,      42724LL },  // era 15:  0.00042724 XCF x 750,000 blocks
    {  12000001,  12750000,      21362LL },  // era 16:  0.00021362 XCF x 750,000 blocks
    {  12750001,  13500000,      10681LL },  // era 17:  0.00010681 XCF x 750,000 blocks
    {  13500001,  14250000,       5340LL },  // era 18:  0.00005340 XCF x 750,000 blocks
    {  14250001,  15000000,       2670LL },  // era 19:  0.00002670 XCF x 750,000 blocks
    {  15000001,  15750000,       1335LL },  // era 20:  0.00001335 XCF x 750,000 blocks
    {  15750001,  16500000,        667LL },  // era 21:  0.00000667 XCF x 750,000 blocks
    {  16500001,  17250000,        333LL },  // era 22:  0.00000333 XCF x 750,000 blocks
    {  17250001,  18000000,        166LL },  // era 23:  0.00000166 XCF x 750,000 blocks
    {  18000001,  18750000,         83LL },  // era 24:  0.00000083 XCF x 750,000 blocks
    {  18750001,  19500000,         41LL },  // era 25:  0.00000041 XCF x 750,000 blocks
    {  19500001,  20250000,         20LL },  // era 26:  0.00000020 XCF x 750,000 blocks
    {  20250001,  21000000,         10LL },  // era 27:  0.00000010 XCF x 750,000 blocks
    {  21000001,  21750000,          5LL },  // era 28:  0.00000005 XCF x 750,000 blocks
    {  21750001,  22500000,          2LL },  // era 29:  0.00000002 XCF x 750,000 blocks
    {  22500001,  23250000,          1LL },  // era 30:  0.00000001 XCF x 750,000 blocks (final block also mints the remainder)
};

/** The remainder minted on top of the last subsidy block so the total is exact:
 *  0.09 XCF, the satoshis lost to rounding thirty halvings down. */
static constexpr int64_t EMISSION_CLOSING_DUST_SAT = 9'000'000LL;

/** Last block that produces a subsidy (inclusive): the final block of era 30,
 *  which pays one satoshi plus the remainder: 23,250,000 (~2248 at 300 s). */
static constexpr int EMISSION_END_HEIGHT = EMISSION_TABLE[NUM_EMISSION_ERAS - 1].endHeight;

/** Maximum possible supply: 21,000,000 XCF in satoshis. */
static constexpr int64_t MAX_SUPPLY_SAT = 2'100'000'000'000'000LL;

/** Total mined emission (era subsidies + closing dust). Nothing is carried in and
 *  nothing is pre-mined, so this is the whole cap. */
static constexpr int64_t TOTAL_EMISSION_SAT = MAX_SUPPLY_SAT;

/** Sum of an era table's per-block subsidies (without the closing dust). */
constexpr int64_t EmissionTableTotalSat(const EmissionEra* table, int n)
{
    int64_t total{0};
    for (int i = 0; i < n; ++i) total += table[i].baseSubsidy * (table[i].endHeight - table[i].startHeight + 1);
    return total;
}

/** Whether an era table is n back-to-back eras starting at start, the first
 *  n-1 exactly era_blocks long and the last one at least that long (it runs
 *  to the cap). */
constexpr bool EmissionTableContiguous(const EmissionEra* table, int n, int start, int era_blocks)
{
    for (int i = 0; i < n; ++i) {
        if (table[i].startHeight != (i == 0 ? start : table[i - 1].endHeight + 1)) return false;
        const int blocks{table[i].endHeight - table[i].startHeight + 1};
        if (i < n - 1 ? blocks != era_blocks : blocks < era_blocks) return false;
    }
    return true;
}

/** Whether every era after the first pays half of the one before it, rounded
 *  down to a whole satoshi (the rounding is what the closing remainder repays). */
constexpr bool EmissionTableHalves(const EmissionEra* table, int n)
{
    for (int i = 1; i < n; ++i) {
        if (table[i].baseSubsidy != table[i - 1].baseSubsidy / 2) return false;
    }
    return true;
}

static_assert(EmissionTableContiguous(EMISSION_TABLE, NUM_EMISSION_ERAS, EMISSION_START_HEIGHT, EMISSION_ERA_BLOCKS),
              "EMISSION_TABLE must be 31 back-to-back eras from height 1, each exactly EMISSION_ERA_BLOCKS long");
static_assert(EMISSION_TABLE[0].baseSubsidy == EMISSION_ERA0_SUBSIDY_SAT, "era 0 must pay exactly 14 XCF per block");
static_assert(EmissionTableHalves(EMISSION_TABLE, NUM_EMISSION_ERAS), "each era must pay half of the previous one, rounded down");
static_assert(EMISSION_TABLE[NUM_EMISSION_ERAS - 1].baseSubsidy == 1, "the table ends exactly where the halving reaches zero");
static_assert(EMISSION_ERA0_SUBSIDY_SAT * EMISSION_ERA_BLOCKS * 2 == MAX_SUPPLY_SAT, "era 0 mints exactly half the cap");
static_assert(EMISSION_CLOSING_DUST_SAT >= 0 && EMISSION_CLOSING_DUST_SAT < 100000000LL,
              "the closing remainder is the rounding of thirty halvings, under one XCF, not an era");
static_assert(EmissionTableTotalSat(EMISSION_TABLE, NUM_EMISSION_ERAS) + EMISSION_CLOSING_DUST_SAT == TOTAL_EMISSION_SAT,
              "EMISSION_TABLE + closing dust must equal the cap");

// ═══════════════════════════════════════════════════════════════════════════
// CHARTER — REGENESIS.md section 1 (see consensus/charter.h).
//
// The charter (contrib/regenesis/CHARTER.md) is the currency; the v2 genesis
// coinbase commits to it, and the currency id is SHA-256(genesis header ||
// charter text). The v1 chain is history, not lineage: nothing of it is
// carried in and the commitment does not reference it (charter section 3,
// 35c4fda). Its genesis header is pinned below only so the v1 chain stays
// identifiable (getcharter reports it, and mainnet refuses to run on it).
// ═══════════════════════════════════════════════════════════════════════════

/** SHA-256 of contrib/regenesis/CHARTER.md exactly as committed (UTF-8, LF line
 *  endings, no trailing whitespace), as the plain 32-byte digest in natural
 *  order — what `shasum -a 256 contrib/regenesis/CHARTER.md` prints:
 *      415b1dbc7ff2cd14b747b300ecd95862540e12305a801bb2bfed8b93c5d84689
 *  (charter as committed in 21f4c5b: section 4 is the 14 XCF schedule halved
 *  every 750,000 blocks; sections 3 and 4 say nothing is carried from the v1
 *  chain. Deliberately NOT a uint256: uint256{"hex"} stores the bytes
 *  reversed, the block-hash display convention, which is wrong for a document digest.)
 *  regenesis_charter_tests recomputes it from the file embedded at build time,
 *  so any edit of the charter fails the unit suite until this constant is
 *  updated on purpose. Committed in the genesis coinbase's OP_RETURN charter
 *  output (charter::CommitmentPayload); the coinbase message does not repeat it. */
static constexpr std::array<uint8_t, 32> CHARTER_HASH = {
    0x41, 0x5b, 0x1d, 0xbc, 0x7f, 0xf2, 0xcd, 0x14, 0xb7, 0x47, 0xb3, 0x00, 0xec, 0xd9, 0x58, 0x62,
    0x54, 0x0e, 0x12, 0x30, 0x5a, 0x80, 0x1b, 0xb2, 0xbf, 0xed, 0x8b, 0x93, 0xc5, 0xd8, 0x46, 0x89,
};

/** Block hash of the v1 chain's genesis. Nothing of the v1 chain is carried into
 *  this one (charter section 3); the hash is pinned so the v1 chain stays
 *  identifiable: getcharter reports it and mainnet refuses to start on it. */
static constexpr uint256 V1_GENESIS_HASH{"0000012c4eed54ed3b23812bc956b667c4fc6cde87c33c2bee26e7b9989ca3bc"};

/** The v1 genesis header, all 80 serialized bytes (version 1, null prev,
 *  merkle fac4f4af…2c88, nTime 1788220800, nBits 0x1e0fffff, nNonce 1112945).
 *  SHA-256d of these bytes is V1_GENESIS_HASH. The charter commitment output no
 *  longer references it (35c4fda: no lineage field); kept as raw bytes so the v1
 *  genesis can be identified without the v1 chain params (xcoin-genesis prints
 *  its SHA-256, regenesis_tests pins it). */
static constexpr std::array<uint8_t, 80> V1_GENESIS_HEADER = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x88, 0x2c, 0x69, 0x00, 0xb9, 0x55, 0xa0, 0x74, 0xdd, 0xbd, 0x97, 0x2c,
    0xcd, 0xec, 0x69, 0x03, 0xe2, 0x56, 0x16, 0x57, 0x94, 0xe1, 0xfd, 0x5e, 0x00, 0xd1, 0x16, 0x05,
    0xaf, 0xf4, 0xc4, 0xfa, 0x80, 0x15, 0x96, 0x6a, 0xff, 0xff, 0x0f, 0x1e, 0x71, 0xfb, 0x10, 0x00,
};

/** Tag that opens the genesis coinbase's charter output:
 *  OP_RETURN <"XCOIN/charter/1" || CHARTER_HASH>, 47 bytes. There is no lineage
 *  field: this chain starts from scratch (charter section 3).
 *  Named after the project, never the ticker: a consensus tag may not follow a
 *  rename (REGENESIS.md section 4, naming rule). */
static constexpr std::string_view CHARTER_COMMITMENT_TAG{"XCOIN/charter/1"};

// ═══════════════════════════════════════════════════════════════════════════
// SETTLEMENT LEVY — REGENESIS.md section 6.
//
// The machinery: every non-coinbase transaction must pay a fee of at least
//     min(ceil(sum of its output values * bp / 10,000), cap)
// under the schedule row in force at its height (consensus/levy.h;
// "bad-txns-levy" otherwise). The levy is an ordinary fee: it goes to the
// miner through the normal fee mechanism and is never burned.
//
// The rule the chain ships with: NONE. The genesis schedule row is zero rate,
// zero cap (SETTLEMENT_LEVY_GENESIS_RULE), so no transaction owes a levy and
// fees are set by relay policy and the fee market alone, as on Bitcoin.
// Founder decision 2026-09-14 (contrib/regenesis/DECISIONS.md): a minimum fee
// fixed in satoshi cannot know what a satoshi is worth, its cap made it a flat
// fee above 0.2 XCF, it threatened every pre-signed transaction, and the fork
// asymmetry decides the rest — a levy can be switched ON later by soft fork
// (add a row, ship a deployment) but never switched OFF without a hard fork,
// so the chain starts without one. The code, the schedule and the tests stay
// in the tree, dormant, so that switching it on is a table row and nothing else.
// ═══════════════════════════════════════════════════════════════════════════

/** The rate the chain ships with: zero. See SETTLEMENT_LEVY_GENESIS_RULE (levy.h). */
static constexpr int64_t SETTLEMENT_LEVY_GENESIS_BP = 0;
/** The cap the chain ships with: zero (no levy). */
static constexpr int64_t SETTLEMENT_LEVY_GENESIS_CAP_SAT = 0;

/** REFERENCE rate in basis points of a transaction's total output value: 5 bp
 *  = 0.05%. Not charged by any chain today. It is the rate every levy test runs
 *  at (regtest -levybp=5) and the rate a future soft-fork activation is
 *  documented against (REGENESIS.md section 6). */
static constexpr int64_t SETTLEMENT_LEVY_BP = 5;
/** Largest representable levy (100%): keeps every intermediate product inside
 *  int64 for values up to MAX_MONEY (consensus/levy.h). */
static constexpr int64_t SETTLEMENT_LEVY_BP_MAX = 10'000;
/** REFERENCE cap: no transaction owes more than this under the reference rate,
 *  however much it moves. 0.0001 XCF. Not charged by any chain today; the cap
 *  regtest uses when a test enables the levy with -levybp. Raising a cap is a
 *  soft fork, lowering one a hard fork (consensus/levy.h). */
static constexpr int64_t SETTLEMENT_LEVY_CAP_SAT = 10'000;

/** One row of the settlement-levy schedule: from startHeight on, a non-coinbase
 *  transaction's fee must reach min(ceil(outputs x bp / 10,000), capSat). */
struct SettlementLevyRule {
    int startHeight;
    int64_t bp;
    int64_t capSat;
};

/** The rule every chain ships: no levy. Zero rate, zero cap, from height 0.
 *  Switching a levy on later is a soft fork (a later row that raises either
 *  number); switching one off would be a hard fork, which is why the chain
 *  starts here. The arithmetic and its assertions live in consensus/levy.h. */
static constexpr SettlementLevyRule SETTLEMENT_LEVY_GENESIS_RULE{0, SETTLEMENT_LEVY_GENESIS_BP, SETTLEMENT_LEVY_GENESIS_CAP_SAT};

/** Whether a levy schedule can only ever have been reached by soft forks: one
 *  row at height 0, strictly ascending heights, every rate in range, and every
 *  later row raising the rate or the cap and lowering neither. A row that
 *  lowers either would be a hard fork (charter section 7) and is refused here,
 *  so a future raise is a table row plus a deployment and nothing else. */
inline bool SettlementLevyScheduleIsSoftForkOnly(const std::vector<SettlementLevyRule>& schedule)
{
    if (schedule.empty() || schedule.front().startHeight != 0) return false;
    for (size_t i = 0; i < schedule.size(); ++i) {
        const SettlementLevyRule& r{schedule[i]};
        if (r.bp < 0 || r.bp > SETTLEMENT_LEVY_BP_MAX || r.capSat < 0) return false;
        if (i > 0) {
            const SettlementLevyRule& prev{schedule[i - 1]};
            if (r.startHeight <= prev.startHeight || r.bp < prev.bp || r.capSat < prev.capSat) return false;
        }
    }
    return true;
}
/** Minimum value of any output that is not NULL_DATA, in satoshi (consensus):
 *  10,000 sat = 0.0001 XCF, the same number as the settlement-levy floor. A
 *  post-quantum output costs ~5.4 kB of witness to spend, so anything smaller
 *  can never be spent for less than it is worth; it exists only to bloat the
 *  UTXO set, which every full node carries forever. 0 disables the rule
 *  (regtest, so the inherited fixtures still build sub-floor outputs).
 *  Coinbase exemption (founder decision 2026-09-15): a coinbase whose
 *  non-NULL_DATA outputs number exactly one may pay that output any value
 *  from 1 sat, because from era 18 (height 13,500,001) the subsidy, 5,340 sat,
 *  is under the floor and an otherwise empty block could not claim it; every
 *  era's subsidy, down to era 30's single satoshi, must be mintable with zero
 *  fees. A coinbase with two or more spendable outputs is held to the floor
 *  on every one of them, so the reward cannot be sprayed into the UTXO set as
 *  sub-floor outputs (consensus/tx_check.cpp).
 *  Raising this is a soft fork; lowering it is a hard fork. */
static constexpr int64_t MIN_OUTPUT_VALUE_SAT = 10'000;

/** Coinbase maturity on mainnet and testnet A, in blocks: 1,000 — about 3.5 days
 *  at 300 s, against Bitcoin's 100 (~16.7 h at its interval). Founder decision
 *  2026-09-14: a mined reward cannot be spent, and then reorganised away, inside
 *  a window that rented hashrate could afford. Raising this later is a soft fork;
 *  lowering it is a hard fork. */
static constexpr int COINBASE_MATURITY_MAINNET = 1'000;

// ═══════════════════════════════════════════════════════════════════════════
// MULTI-ALGORITHM PROOF OF WORK — reserved at genesis, REGENESIS.md section 7
// (stage B4). Header nVersion layout on this chain:
//
//     bits 31..30 = 01      BIP9 top bits (VERSIONBITS_TOP_BITS = 0x40000000)
//     bits 29..28 = algo id (POW_ALGO_ID_MASK): 0 = MetalDAG, 1 = AuxPoW /
//                           SHA-256d merged with Bitcoin, 2..3 reserved
//     bits 27..0  =         BIP9 deployment bits
//
// The algorithm id must be 0 until Params::multi_algo_activation_height
// (0 = inactive on every chain); ContextualCheckBlockHeader rejects anything
// else with "bad-pow-algo". No AuxPoW validation exists yet: the fields below
// only reserve the parameter space so activation is a parameter change.
// ═══════════════════════════════════════════════════════════════════════════

static constexpr int POW_ALGO_ID_SHIFT = 28;
static constexpr int32_t POW_ALGO_ID_MASK = 0x30000000;
enum PowAlgo : uint32_t {
    POW_ALGO_METALDAG = 0,
    POW_ALGO_AUXPOW_SHA256D = 1,
    POW_ALGO_RESERVED_2 = 2,
    POW_ALGO_RESERVED_3 = 3,
};
/** The PoW-algorithm id carried in a header version (bits 28..29). */
constexpr uint32_t GetPowAlgoId(int32_t nVersion)
{
    return (static_cast<uint32_t>(nVersion) & static_cast<uint32_t>(POW_ALGO_ID_MASK)) >> POW_ALGO_ID_SHIFT;
}
/** Per-algorithm difficulty parameters (each algorithm keeps its own target). */
struct PowAlgoParams {
    uint256 powLimit;
    int64_t nASERTHalfLife{0};
    int64_t nPowTargetSpacing{0};
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;

    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, script_verify_flags> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV, segwit and taproot activations. */
    int MinBIP9WarningHeight;
    std::array<BIP9Deployment,MAX_VERSION_BITS_DEPLOYMENTS> vDeployments;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. With
      * fPowAllowMinDifficultyBlocks this also enforces the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    /** Block height at which ASERT per-block difficulty adjustment activates. */
    int nASERTActivationHeight;
    /** ASERT target-doubling half-life, in seconds. */
    int64_t nASERTHalfLife;
    /** MetalDAG memory-hard PoW sizing (Ethash-family). Epoch is time-based:
     *  epoch = nTime / metaldagEpochSeconds. DAG (and its verification cache) grow
     *  by metaldagDagGrowthBytes each epoch so the working set drifts past GPU VRAM
     *  tiers over time while Apple Silicon unified memory keeps mining efficient. */
    int64_t metaldagBaseTime{0};      //!< epoch counts from here (the genesis time), not from 1970
    int64_t metaldagEpochSeconds{0};
    int64_t metaldagDagInitBytes{0};
    int64_t metaldagDagGrowthBytes{0};
    int32_t metaldagCacheDivisor{128};
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /** Emission schedule of this chain: back-to-back eras from
     *  EMISSION_START_HEIGHT (mainnet and the test networks: EMISSION_TABLE;
     *  regtest: the same shape with 150-block eras, see kernel/chainparams.cpp). */
    std::vector<EmissionEra> emissionTable;
    /** Minted on top of the last block of the last era so the schedule closes exactly. */
    int64_t emissionClosingDustSat{0};
    /** Last block with a subsidy (inclusive); EMISSION_START_HEIGHT - 1 without a table. */
    int EmissionEndHeight() const
    {
        return emissionTable.empty() ? EMISSION_START_HEIGHT - 1 : emissionTable.back().endHeight;
    }

    /** Whether a block after the genesis block may CREATE a legacy witness v2
     *  output (REGENESIS.md sections 3 and 4). False on mainnet and on the
     *  rehearsal chain, where nothing is carried in and no witness v2 output
     *  exists anywhere: creating one there is `bad-txout-not-pq`. True on regtest and
     *  the inherited test chains, whose fixtures still pay v2 scripts. The
     *  genesis coinbase is exempt on every chain: its zero-value marker output
     *  is part of the chain's permanent identity. The v2 SPEND rule is
     *  untouched everywhere. */
    bool permitV2Outputs{true};

    /** Settlement levy (REGENESIS.md section 6) as a schedule keyed by height:
     *  the rule in force for a block is the last row whose startHeight is at or
     *  below its height. Every chain starts with one row, {0, 5 bp, 10,000 sat};
     *  a future raise is a new row (a soft fork). bp 0 disables the rule
     *  (regtest -levybp=0 only). Chainparams asserts the schedule is
     *  soft-fork-only. */
    std::vector<SettlementLevyRule> settlementLevySchedule;

    /** The levy rule in force for a block at this height. */
    SettlementLevyRule SettlementLevyAt(int height) const
    {
        SettlementLevyRule rule{0, 0, 0};
        for (const SettlementLevyRule& r : settlementLevySchedule) {
            if (r.startHeight > height) break;
            rule = r;
        }
        return rule;
    }

    /** Minimum value of any non-NULL_DATA output in satoshi; 0 disables the
     *  rule. Mainnet and the rehearsal chain use MIN_OUTPUT_VALUE_SAT; regtest
     *  and the inherited test chains leave it at 0. Enforced in CheckTransaction
     *  for every transaction except the genesis coinbase, and except the single
     *  spendable output of a coinbase that has exactly one (founder decision
     *  2026-09-15: the subsidy is under the floor from era 18, and every era's
     *  subsidy must be mintable with zero fees; see MIN_OUTPUT_VALUE_SAT). */
    int64_t minOutputValueSat{0};

    /** Blocks a coinbase output must wait before it can be spent. Mainnet and
     *  testnet A, regtest: COINBASE_MATURITY_MAINNET, 1,000. Regtest tests override it with
     *  -coinbasematurity (the harness passes 100 for the inherited fixtures). */
    int coinbaseMaturity{COINBASE_MATURITY_MAINNET};

    /** Release checkpoints: {height, block hash} pairs compiled into THIS build.
     *  There is no key, no signer, no message and nothing anybody can
     *  transmit — a release simply records
     *  which block it saw at a height, and a node running that release refuses
     *  a header that disagrees. It is a release parameter, auditable by anyone
     *  reading the source, and it binds only people who choose to run the
     *  build; charter section 8 forbids an administrative key at this layer and
     *  this is not one.
     *
     *  This is the ONLY protection a node syncing from scratch has. A rolling
     *  reorg limit cannot help it (it holds no tip of its own to defend) and
     *  nMinimumChainWork cannot bind until the chain has real depth, so without
     *  this a fresh node follows whatever chain reaches it first, however
     *  cheaply mined. Add the newest entry at EVERY release once the chain has
     *  depth (REGENESIS.md section 6, cutover checklist step 6).
     *
     *  Empty = no constraint, which is correct for a chain that does not exist
     *  yet and for regtest. */
    std::map<int, uint256> release_checkpoints;

    /** False only when a release checkpoint exists at exactly this height and
     *  names a different block. Heights with no checkpoint are unconstrained,
     *  so this is O(log n) and never rejects on an empty map. */
    bool ReleaseCheckpointAllows(int height, const uint256& hash) const
    {
        const auto it{release_checkpoints.find(height)};
        return it == release_checkpoints.end() || it->second == hash;
    }

    /** Multi-algorithm proof of work (REGENESIS.md section 7), reserved:
     *  pow_algos[i] are the difficulty parameters of algorithm id i (index 0 =
     *  MetalDAG, always the chain's own powLimit / ASERT half-life / spacing),
     *  pow_share[i] its target share of blocks in basis points (sums to 10,000),
     *  max_consecutive_same_algo caps a run of blocks from one algorithm (0 =
     *  no cap) and multi_algo_activation_height activates the id bits (0 =
     *  inactive: every header must carry algorithm id 0). */
    std::vector<PowAlgoParams> pow_algos;
    std::vector<uint32_t> pow_share;
    uint32_t max_consecutive_same_algo{0};
    int multi_algo_activation_height{0};
    bool MultiAlgoActiveAt(int height) const
    {
        return multi_algo_activation_height > 0 && height >= multi_algo_activation_height;
    }

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
