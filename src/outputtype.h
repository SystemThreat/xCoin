// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OUTPUTTYPE_H
#define BITCOIN_OUTPUTTYPE_H

#include <addresstype.h>
#include <script/signingprovider.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class OutputType {
    LEGACY,
    P2SH_SEGWIT,
    BECH32,
    BECH32M,
    XCOIN_V2, //!< xCoin legacy witness v2: OP_2 <SHA256(ML-DSA-65 pubkey)>, descriptor pq(KEY); spendable forever, non-standard to create
    XCOIN_V3, //!< xCoin witness v3 post-quantum script tree, descriptor pqtr(TREE); the default
    UNKNOWN,
};

/** The output types a new xCoin wallet creates descriptors for: only the post-quantum
 *  ones. The chain refuses every other script type at consensus (bad-txout-not-pq), so an
 *  ECDSA descriptor could never hold coins and would only sit in backups. Both post-quantum
 *  types are created: pqtr() is the default address type, and a pq() (v2) descriptor is how
 *  a wallet recognises v2 coins where they exist (regtest); on a chain that refuses new v2
 *  outputs (Consensus::Params::permitV2Outputs false: mainnet, testnet A) the v2 descriptor
 *  is not created at all, since it could never receive (audit finding 12). */
static constexpr auto XCOIN_OUTPUT_TYPES = std::array{
    OutputType::XCOIN_V2,
    OutputType::XCOIN_V3,
};

static constexpr auto OUTPUT_TYPES = std::array{
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
    OutputType::BECH32M,
    OutputType::XCOIN_V2,
    OutputType::XCOIN_V3,
};

std::optional<OutputType> ParseOutputType(std::string_view str);
const std::string& FormatOutputType(OutputType type);
std::string FormatAllOutputTypes();

/**
 * Get a destination of the requested type (if possible) to the specified script.
 * This function will automatically add the script (and any other
 * necessary scripts) to the keystore.
 */
CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType);

/** Get the OutputType for a CTxDestination */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

#endif // BITCOIN_OUTPUTTYPE_H
