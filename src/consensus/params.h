// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
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
// XCOIN (XID) MONETARY POLICY — v2 chain (re-genesis), 100,000,000 XID hard cap.
// Spec: contrib/regenesis/REGENESIS.md sections 2 and 3; charter sections 2 and 4.
//
// DECIDED (owner decision 2026-09-25): the cap is exactly 100,000,000 XID with 8
// decimals (1 XID = 100,000,000 sat), replacing 21,000,000. NO premine, NO founder
// allocation and nothing carried in (founder decision 2026-09-05): the founder
// mines under the same rules as everyone else. Block 0 mints nothing (the genesis
// coinbase is unspendable by design); every block from EMISSION_START_HEIGHT pays
// the subsidy of its EMISSION_TABLE row, and the last subsidy block also mints
// EMISSION_CLOSING_DUST_SAT, so that
//
//       sum(row subsidies) + closing dust == MAX_SUPPLY_SAT == MAX_MONEY exactly.
//
// After EMISSION_END_HEIGHT the subsidy is zero (fees only).
//
// FINAL (owner decision 2026-09-25): the Annual Tenth, charter section 4. The table
// below is generated from contrib/regenesis/emission-policy.json: 6.25, 12.5, 25 XID [EMISSION-SHAPE]
// for 20,000 blocks each, 50 XID to block 220,000, then 110,000-block steps 10% lower
// each (never under 1.5 XID, never more than a tenth of what is left per step), a
// 0.1 XID tail; 65 rows, the last subsidy block (35,375,353) also minting the
// 0.0166 XID remainder. The table is a lookup; the words in charter section 4 are
// re-derived and checked against it by regenesis_tests (annual_tenth_emission_shape).
// Nothing outside the generated block depends on the shape in code.
// ═══════════════════════════════════════════════════════════════════════════

/** Nothing is carried in and nothing is pre-mined (charter sections 3 and 4):
 *  supply begins at zero, and the whole cap is the emission below. Block 1 is an
 *  ordinary block. */

/** The v1 founder script, OP_2 <SHA-256(founder ML-DSA-65 pubkey)> (witness v2):
 *  address xpa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5sdnc0av
 *  (David's founder key: NTAG 424 DNA card-bound wallet, ceremony 2026-09-01).
 *  The v1 chain paid it a block-1 founder allocation (1,000,000 coins). This
 *  chain carries nothing in from v1 and has no founder allocation and no
 *  block-1 distribution at all (35c4fda), so nothing here ever pays this
 *  script; it is kept only so the v1 allocation stays identifiable. */
static constexpr std::array<uint8_t, 34> FOUNDER_PREMINE_SCRIPT = {
    0x52, 0x20, // OP_2, PUSH(32)
    0xa1,0x58,0xac,0x50,0x47,0x84,0x5b,0xfd,0xed,0xad,0x6e,0x2e,0x3e,0x07,0x4b,0x2b,
    0xac,0x33,0xce,0xfa,0x74,0x40,0xb6,0xb3,0xab,0xa6,0x68,0xb4,0x0b,0xd8,0xbc,0xe9,
};

/** First block that pays a subsidy. Block 1 is an ordinary block: nothing is
 *  carried in and there is no distribution to pay, so there is nothing to
 *  special-case and mining pays the first row's subsidy from the very first
 *  block after genesis. Block 0 still mints nothing — the genesis coinbase
 *  carries the charter, not money. */
static constexpr int EMISSION_START_HEIGHT = 1;

/** Maximum possible supply: exactly 100,000,000 XID in satoshis (10^16), equal to
 *  MAX_MONEY (consensus/amount.h). DECIDED 2026-09-25; not part of the provisional
 *  shape. */
static constexpr int64_t MAX_SUPPLY_SAT = 10'000'000'000'000'000LL;

/** Total mined emission (row subsidies + closing dust). Nothing is carried in and
 *  nothing is pre-mined, so this is the whole cap. */
static constexpr int64_t TOTAL_EMISSION_SAT = MAX_SUPPLY_SAT;

/** Sum of an era table's per-block subsidies (without the closing dust). */
constexpr int64_t EmissionTableTotalSat(const EmissionEra* table, int n)
{
    int64_t total{0};
    for (int i = 0; i < n; ++i) total += table[i].baseSubsidy * (table[i].endHeight - table[i].startHeight + 1);
    return total;
}

/** Whether an era table is n non-empty rows laid back to back from start, each
 *  paying a positive subsidy no larger than the cap. Holds for every shape. */
constexpr bool EmissionTableWellFormed(const EmissionEra* table, int n, int start)
{
    if (n <= 0) return false;
    for (int i = 0; i < n; ++i) {
        if (table[i].startHeight != (i == 0 ? start : table[i - 1].endHeight + 1)) return false;
        if (table[i].endHeight < table[i].startHeight) return false;
        if (table[i].baseSubsidy <= 0 || table[i].baseSubsidy > MAX_SUPPLY_SAT) return false;
    }
    return true;
}

/** Whether an era table is n back-to-back eras starting at start, the first
 *  n-1 exactly era_blocks long and the last one at least that long (it may run
 *  to the cap). A halving-shape check (the generated block and regtest use it). */
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
 *  down to a whole satoshi (the rounding is what the closing remainder repays).
 *  A halving-shape check. */
constexpr bool EmissionTableHalves(const EmissionEra* table, int n)
{
    for (int i = 1; i < n; ++i) {
        if (table[i].baseSubsidy != table[i - 1].baseSubsidy / 2) return false;
    }
    return true;
}

// BEGIN GENERATED EMISSION TABLE ────────────────────────────────────────────
// Generated by  python3 contrib/regenesis/emission.py --write-params
// from          contrib/regenesis/emission-policy.json
// policy        "The Annual Tenth (g4-D3): 50 XID for two years of 110,000 blocks after a 60,000-block ramp, then 10% less every 110,000 blocks, never below 1.5 XID, no step pays more than a tenth of what is left, 0.1 XID tail"
// status        FINAL (owner decision 2026-09-25: the Annual Tenth, g4-D3; ticker XID, cap 100,000,000, no founder lock)
// [EMISSION-SHAPE] this whole block states the emission shape; it is regenerated, never edited.

/** Whether this table's SHAPE is final: true only when the policy status starts
 *  with FINAL. While it is false, kernel/chainparams.cpp refuses to compile
 *  GENESIS_IS_FINAL = true (except in a local -DXCOIN_REHEARSAL_BUILD=ON build),
 *  xcoin-genesis refuses -chain=main without -allowprovisional, and charter
 *  section 4 must carry its PROVISIONAL comment (regenesis_tests). */
static constexpr bool EMISSION_SHAPE_IS_FINAL = true;

/** Rows in EMISSION_TABLE. */
static constexpr int NUM_EMISSION_ERAS = 65;

/** Mainnet (and testnet A) emission schedule: back-to-back rows from height 1. */
static constexpr EmissionEra EMISSION_TABLE[NUM_EMISSION_ERAS] = {
    //  startHeight  endHeight  baseSubsidy(sat)
    {         1,     20000,  625000000LL },  // era  0:  6.25000000 XID x 20,000 blocks
    {     20001,     40000, 1250000000LL },  // era  1: 12.50000000 XID x 20,000 blocks
    {     40001,     60000, 2500000000LL },  // era  2: 25.00000000 XID x 20,000 blocks
    {     60001,    220000, 5000000000LL },  // era  3: 50.00000000 XID x 160,000 blocks
    {    220001,    330000, 4500000000LL },  // era  4: 45.00000000 XID x 110,000 blocks
    {    330001,    440000, 4050000000LL },  // era  5: 40.50000000 XID x 110,000 blocks
    {    440001,    550000, 3645000000LL },  // era  6: 36.45000000 XID x 110,000 blocks
    {    550001,    660000, 3281000000LL },  // era  7: 32.81000000 XID x 110,000 blocks
    {    660001,    770000, 2953000000LL },  // era  8: 29.53000000 XID x 110,000 blocks
    {    770001,    880000, 2658000000LL },  // era  9: 26.58000000 XID x 110,000 blocks
    {    880001,    990000, 2393000000LL },  // era 10: 23.93000000 XID x 110,000 blocks
    {    990001,   1100000, 2154000000LL },  // era 11: 21.54000000 XID x 110,000 blocks
    {   1100001,   1210000, 1939000000LL },  // era 12: 19.39000000 XID x 110,000 blocks
    {   1210001,   1320000, 1746000000LL },  // era 13: 17.46000000 XID x 110,000 blocks
    {   1320001,   1430000, 1572000000LL },  // era 14: 15.72000000 XID x 110,000 blocks
    {   1430001,   1540000, 1415000000LL },  // era 15: 14.15000000 XID x 110,000 blocks
    {   1540001,   1650000, 1274000000LL },  // era 16: 12.74000000 XID x 110,000 blocks
    {   1650001,   1760000, 1147000000LL },  // era 17: 11.47000000 XID x 110,000 blocks
    {   1760001,   1870000, 1033000000LL },  // era 18: 10.33000000 XID x 110,000 blocks
    {   1870001,   1980000,  930000000LL },  // era 19:  9.30000000 XID x 110,000 blocks
    {   1980001,   2090000,  837000000LL },  // era 20:  8.37000000 XID x 110,000 blocks
    {   2090001,   2200000,  754000000LL },  // era 21:  7.54000000 XID x 110,000 blocks
    {   2200001,   2310000,  679000000LL },  // era 22:  6.79000000 XID x 110,000 blocks
    {   2310001,   2420000,  612000000LL },  // era 23:  6.12000000 XID x 110,000 blocks
    {   2420001,   2530000,  551000000LL },  // era 24:  5.51000000 XID x 110,000 blocks
    {   2530001,   2640000,  496000000LL },  // era 25:  4.96000000 XID x 110,000 blocks
    {   2640001,   2750000,  447000000LL },  // era 26:  4.47000000 XID x 110,000 blocks
    {   2750001,   2860000,  403000000LL },  // era 27:  4.03000000 XID x 110,000 blocks
    {   2860001,   2970000,  363000000LL },  // era 28:  3.63000000 XID x 110,000 blocks
    {   2970001,   3080000,  327000000LL },  // era 29:  3.27000000 XID x 110,000 blocks
    {   3080001,   3190000,  295000000LL },  // era 30:  2.95000000 XID x 110,000 blocks
    {   3190001,   3300000,  266000000LL },  // era 31:  2.66000000 XID x 110,000 blocks
    {   3300001,   3410000,  240000000LL },  // era 32:  2.40000000 XID x 110,000 blocks
    {   3410001,   3520000,  216000000LL },  // era 33:  2.16000000 XID x 110,000 blocks
    {   3520001,   3630000,  195000000LL },  // era 34:  1.95000000 XID x 110,000 blocks
    {   3630001,   3740000,  176000000LL },  // era 35:  1.76000000 XID x 110,000 blocks
    {   3740001,   3850000,  159000000LL },  // era 36:  1.59000000 XID x 110,000 blocks
    {   3850001,  31460000,  150000000LL },  // era 37:  1.50000000 XID x 27,610,000 blocks
    {  31460001,  31570000,  148490909LL },  // era 38:  1.48490909 XID x 110,000 blocks
    {  31570001,  31680000,  133641818LL },  // era 39:  1.33641818 XID x 110,000 blocks
    {  31680001,  31790000,  120277636LL },  // era 40:  1.20277636 XID x 110,000 blocks
    {  31790001,  31900000,  108249872LL },  // era 41:  1.08249872 XID x 110,000 blocks
    {  31900001,  32010000,   97424885LL },  // era 42:  0.97424885 XID x 110,000 blocks
    {  32010001,  32120000,   87682397LL },  // era 43:  0.87682397 XID x 110,000 blocks
    {  32120001,  32230000,   78914157LL },  // era 44:  0.78914157 XID x 110,000 blocks
    {  32230001,  32340000,   71022741LL },  // era 45:  0.71022741 XID x 110,000 blocks
    {  32340001,  32450000,   63920467LL },  // era 46:  0.63920467 XID x 110,000 blocks
    {  32450001,  32560000,   57528420LL },  // era 47:  0.57528420 XID x 110,000 blocks
    {  32560001,  32670000,   51775578LL },  // era 48:  0.51775578 XID x 110,000 blocks
    {  32670001,  32780000,   46598021LL },  // era 49:  0.46598021 XID x 110,000 blocks
    {  32780001,  32890000,   41938218LL },  // era 50:  0.41938218 XID x 110,000 blocks
    {  32890001,  33000000,   37744397LL },  // era 51:  0.37744397 XID x 110,000 blocks
    {  33000001,  33110000,   33969957LL },  // era 52:  0.33969957 XID x 110,000 blocks
    {  33110001,  33220000,   30572961LL },  // era 53:  0.30572961 XID x 110,000 blocks
    {  33220001,  33330000,   27515665LL },  // era 54:  0.27515665 XID x 110,000 blocks
    {  33330001,  33440000,   24764099LL },  // era 55:  0.24764099 XID x 110,000 blocks
    {  33440001,  33550000,   22287689LL },  // era 56:  0.22287689 XID x 110,000 blocks
    {  33550001,  33660000,   20058920LL },  // era 57:  0.20058920 XID x 110,000 blocks
    {  33660001,  33770000,   18053028LL },  // era 58:  0.18053028 XID x 110,000 blocks
    {  33770001,  33880000,   16247725LL },  // era 59:  0.16247725 XID x 110,000 blocks
    {  33880001,  33990000,   14622953LL },  // era 60:  0.14622953 XID x 110,000 blocks
    {  33990001,  34100000,   13160657LL },  // era 61:  0.13160657 XID x 110,000 blocks
    {  34100001,  34210000,   11844592LL },  // era 62:  0.11844592 XID x 110,000 blocks
    {  34210001,  34320000,   10660132LL },  // era 63:  0.10660132 XID x 110,000 blocks
    {  34320001,  35375353,   10000000LL },  // era 64:  0.10000000 XID x 1,055,353 blocks (the last block also mints the closing remainder)
};

/** Minted on top of the last subsidy block so the total is exactly the cap:
 *  0.01660000 XID (1,660,000 sat). */
static constexpr int64_t EMISSION_CLOSING_DUST_SAT = 1'660'000LL;
// END GENERATED EMISSION TABLE ──────────────────────────────────────────────

/** Last block that produces a subsidy (inclusive): the last row's last block,
 *  which also mints the closing dust. */
static constexpr int EMISSION_END_HEIGHT = EMISSION_TABLE[NUM_EMISSION_ERAS - 1].endHeight;

// Shape-independent: these hold for whatever table the policy generates.
static_assert(EmissionTableWellFormed(EMISSION_TABLE, NUM_EMISSION_ERAS, EMISSION_START_HEIGHT),
              "EMISSION_TABLE must be non-empty rows laid back to back from height 1, each paying a positive subsidy");
static_assert(EMISSION_CLOSING_DUST_SAT >= 0 && EMISSION_CLOSING_DUST_SAT < 100'000'000LL,
              "the closing remainder is rounding, under one XID, not an era");
static_assert(EmissionTableTotalSat(EMISSION_TABLE, NUM_EMISSION_ERAS) + EMISSION_CLOSING_DUST_SAT == TOTAL_EMISSION_SAT,
              "EMISSION_TABLE + closing dust must equal the cap");
static_assert(MAX_SUPPLY_SAT == 100'000'000LL * COIN && COIN == 100'000'000LL, "the cap is exactly 100,000,000 XID of 10^8 sat (decided 2026-09-25)");
static_assert(MAX_SUPPLY_SAT == MAX_MONEY, "the emission cap and the consensus MAX_MONEY sanity bound are the same number");

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
 *      fd9b475afdbe178864f32802726cc60c27290c09efd472d0934b1c733d3b9340
 *  (charter of 2026-09-25: section 1 names the ticker XID, section 2 caps the
 *  supply at 100,000,000 XID, and section 4 states the FINAL emission shape, [EMISSION-SHAPE]
 *  the Annual Tenth, with the SHA-256 of its 65-row table. Sections 3
 *  and 4 say nothing is carried from the v1 chain. Deliberately NOT a uint256:
 *  uint256{"hex"} stores the bytes reversed, the block-hash display convention,
 *  which is wrong for a document digest.)
 *  regenesis_charter_tests recomputes it from the file embedded at build time,
 *  so any edit of the charter fails the unit suite until this constant is
 *  updated on purpose. Committed in the genesis coinbase's OP_RETURN charter
 *  output (charter::CommitmentPayload); the coinbase message does not repeat it. */
static constexpr std::array<uint8_t, 32> CHARTER_HASH = {
    0xfd, 0x9b, 0x47, 0x5a, 0xfd, 0xbe, 0x17, 0x88, 0x64, 0xf3, 0x28, 0x02, 0x72, 0x6c, 0xc6, 0x0c,
    0x27, 0x29, 0x0c, 0x09, 0xef, 0xd4, 0x72, 0xd0, 0x93, 0x4b, 0x1c, 0x73, 0x3d, 0x3b, 0x93, 0x40,
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
// fee above 0.2 XID, it threatened every pre-signed transaction, and the fork
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
 *  however much it moves. 0.0001 XID. Not charged by any chain today; the cap
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
 *  10,000 sat = 0.0001 XID, the same number as the settlement-levy floor. A
 *  post-quantum output costs ~5.4 kB of witness to spend, so anything smaller
 *  can never be spent for less than it is worth; it exists only to bloat the
 *  UTXO set, which every full node carries forever. 0 disables the rule
 *  (regtest, so the inherited fixtures still build sub-floor outputs).
 *  Coinbase exemption (founder decision 2026-09-15): a coinbase whose
 *  non-NULL_DATA outputs number exactly one may pay that output any value
 *  from 1 sat, because late in the schedule the subsidy falls under the floor
 *  and an otherwise empty block could not claim it (the final shape never does: [EMISSION-SHAPE]
 *  its smallest row pays 0.1 XID; the exemption stays so that any table's
 *  subsidy is mintable with zero fees). A coinbase with two or more spendable outputs is held to the floor
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
     *  regtest: its own 50 / 25 / 12.5 / 6.25 fixture table with 150-block eras,
     *  closing on the same cap, see kernel/chainparams.cpp). */
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
     *  2026-09-15: the subsidy falls under the floor late in the schedule, and
     *  every era's subsidy must be mintable with zero fees; see MIN_OUTPUT_VALUE_SAT). */
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
