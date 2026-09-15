// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SCRIPT_H
#define BITCOIN_TEST_UTIL_SCRIPT_H

#include <crypto/sha256.h>
#include <script/script.h>
#include <script/verify_flags.h>
#include <script/xcoin_v3.h>
#include <uint256.h>

#include <vector>

static const std::vector<uint8_t> WITNESS_STACK_ELEM_OP_TRUE{uint8_t{OP_TRUE}};
static const CScript P2WSH_OP_TRUE{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(WITNESS_STACK_ELEM_OP_TRUE.data(), WITNESS_STACK_ELEM_OP_TRUE.size()).Finalize(hash.begin());
           return hash;
       }())};

static const std::vector<uint8_t> EMPTY{};
static const CScript P2WSH_EMPTY{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(EMPTY.data(), EMPTY.size()).Finalize(hash.begin());
           return hash;
       }())};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TRUE_STACK{{static_cast<uint8_t>(OP_TRUE)}, {}};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TWO_STACK{{static_cast<uint8_t>(OP_2)}, {}};

/** xCoin: the anyone-can-spend witness v3 output (REGENESIS.md section 4).
 *
 *  A single 0xc0 leaf whose script is just OP_TRUE, so the whole witness is
 *  {leaf script, control block} and there is no signature. This is the ONLY
 *  anyone-can-spend output this chain has: the PQ-only output rule
 *  (bad-txout-not-pq) refuses a bare OP_TRUE and a P2WSH one alike, so
 *  P2WSH_OP_TRUE above cannot be mined or relayed anywhere. Kept in step with
 *  the Python side, test_framework/xcoin.py's xcoin_v3_op_true(). */
inline const CScript& XcoinV3OpTrueScript()
{
    static const CScript spk{[] {
        const CScript leaf{CScript{} << OP_TRUE};
        const uint256 root{ComputeXcoinLeafHash(XCOIN_LEAF_PQ, std::span<const unsigned char>{leaf.data(), leaf.size()})};
        return CScript{} << OP_3 << ToByteVector(root);
    }()};
    return spk;
}

/** The witness stack spending XcoinV3OpTrueScript(): {OP_TRUE, control block}. */
inline std::vector<std::vector<unsigned char>> XcoinV3OpTrueWitnessStack()
{
    std::vector<unsigned char> control;
    control.push_back(XCOIN_LEAF_PQ);
    control.insert(control.end(), XCOIN_V3_NOKEY.begin(), XCOIN_V3_NOKEY.end());
    return {{static_cast<unsigned char>(OP_TRUE)}, std::move(control)};
}

/** Flags that are not forbidden by an assert in script validation */
bool IsValidFlagCombination(script_verify_flags flags);

#endif // BITCOIN_TEST_UTIL_SCRIPT_H
