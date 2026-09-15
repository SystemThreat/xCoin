// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CHARTER_H
#define BITCOIN_CONSENSUS_CHARTER_H

#include <primitives/block.h>
#include <script/script.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

class CTransaction;

/**
 * The charter and the currency id (contrib/regenesis/REGENESIS.md section 1).
 *
 * contrib/regenesis/CHARTER.md is the currency. Its SHA-256 is compiled in as
 * Consensus::CHARTER_HASH and the text itself is embedded at build time
 * (byte for byte, so the digest can be recomputed by the unit suite and the
 * currency id by the node). The v2 genesis coinbase commits to it:
 *
 *   scriptSig message : "Hic experimentum prosperat - <date> - 2,100,000,000,000,000 sats, 21M XCF"
 *   output            : OP_RETURN <"XCOIN/charter/1" || CHARTER_HASH>   (47 bytes)
 *
 * and CURRENCY_ID = SHA-256(v2 genesis header (80 bytes) || charter text).
 *
 * The message carries no digest at all: a coinbase scriptSig is capped at 100
 * bytes by the unchanged bad-cb-length rule (consensus/tx_check.cpp), which
 * CheckBlock applies to the genesis too, and the full charter hash is already
 * committed in the output of the very same transaction. The message is 77
 * characters and says only what a human would want to read.
 *
 * Digests here are plain SHA-256 outputs in natural byte order (what shasum
 * and OpenTimestamps show), so they are std::array<uint8_t, 32>, not uint256
 * (whose hex form is byte-reversed). Block hashes stay uint256.
 */
namespace charter {

using Digest = std::array<uint8_t, 32>;

/** Natural-order hex of a digest (the shasum form). */
std::string DigestHex(const Digest& digest);

/** The charter text (contrib/regenesis/CHARTER.md) exactly as embedded at build time. */
std::string_view Text();

/** SHA-256 of Text(). Equal to Consensus::CHARTER_HASH (regenesis_charter_tests). */
Digest TextHash();

/** Single SHA-256 over the 80 serialized bytes of a block header. */
Digest HeaderSha256(const CBlockHeader& header);

/** The v1 chain's genesis header, deserialized from Consensus::V1_GENESIS_HEADER. */
CBlockHeader V1GenesisHeader();

/** SHA-256(Consensus::V1_GENESIS_HEADER). Not part of the commitment any more (there is
 *  no lineage field, 35c4fda); kept so the v1 genesis can be identified (xcoin-genesis
 *  prints it, regenesis_tests pins it). */
Digest V1GenesisHeaderSha256();

/** "XCOIN/charter/1" || CHARTER_HASH: 15 + 32 = 47 bytes. No lineage field: this chain
 *  starts from scratch and references nothing before itself (charter section 3). */
std::vector<unsigned char> CommitmentPayload();

/** The genesis coinbase's charter output: OP_RETURN PUSH(47) <CommitmentPayload()> (49 bytes;
 *  a coinbase output in block 0, so the 80-byte data-carrier relay policy does not apply, and it
 *  is well inside the consensus per-block cap of MAX_BLOCK_DATACARRIER_BYTES, 8,000 bytes,
 *  which every block including the genesis obeys). */
CScript CommitmentScript();

/** Whether a transaction (the genesis coinbase) carries a zero-value output
 *  whose script is exactly CommitmentScript(), in any position. */
bool HasCommitment(const CTransaction& tx);

/** Leading hex characters of CHARTER_HASH an earlier genesis message design carried.
 *  GenesisMessage() no longer repeats any of the digest (the full 32 bytes are in the
 *  coinbase's own output); the constant is unused and kept only for reference. */
constexpr size_t GENESIS_MESSAGE_HASH_CHARS{16};

/** The genesis coinbase message for a date written as YYYY-MM-DD:
 *  "Hic experimentum prosperat - <date> - 2,100,000,000,000,000 sats, 21M XCF"
 *  (77 characters; the scriptSig built by CreateGenesisBlock is then 86 bytes:
 *  04ffff001d (5) + 0104 (2) + OP_PUSHDATA1 77 <message> (79), under the 100-byte
 *  bad-cb-length cap). */
std::string GenesisMessage(std::string_view date);

/** Build a v2 genesis block: one coinbase whose scriptSig is
 *  486604799 <4> <message> (the Bitcoin genesis form), and whose only output is
 *  the zero-value charter commitment. Mints nothing. The header is left for the
 *  caller to mine (xcoin-genesis) or to verify against the compiled-in hash. */
CBlock CreateGenesisBlock(std::string_view message, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion);

/** CURRENCY_ID = SHA-256(80-byte genesis header || charter text). */
Digest CurrencyId(const CBlockHeader& genesis_header);

} // namespace charter

#endif // BITCOIN_CONSENSUS_CHARTER_H
