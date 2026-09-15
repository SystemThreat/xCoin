// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/charter.h>

#include <consensus/charter_text.h> // generated from contrib/regenesis/CHARTER.md at build time
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>

#include <span>
#include <string>

namespace charter {

namespace {
Digest Sha256(std::span<const unsigned char> a, std::span<const unsigned char> b = {})
{
    Digest out;
    CSHA256 hasher;
    hasher.Write(a.data(), a.size());
    if (!b.empty()) hasher.Write(b.data(), b.size());
    hasher.Finalize(out.data());
    return out;
}

std::span<const unsigned char> TextBytes()
{
    return {UCharCast(xat::charter_text::CHARTER.data()), xat::charter_text::CHARTER.size()};
}

std::vector<unsigned char> SerializeHeader(const CBlockHeader& header)
{
    DataStream ss;
    ss << header;
    return {UCharCast(ss.data()), UCharCast(ss.data()) + ss.size()};
}
} // namespace

std::string DigestHex(const Digest& digest)
{
    // Natural byte order (no util dependency in consensus code).
    static constexpr char HEX[]{"0123456789abcdef"};
    std::string out;
    out.reserve(2 * digest.size());
    for (const uint8_t b : digest) {
        out.push_back(HEX[b >> 4]);
        out.push_back(HEX[b & 0x0f]);
    }
    return out;
}

std::string_view Text()
{
    const auto bytes{TextBytes()};
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

Digest TextHash()
{
    return Sha256(TextBytes());
}

Digest HeaderSha256(const CBlockHeader& header)
{
    return Sha256(SerializeHeader(header));
}

CBlockHeader V1GenesisHeader()
{
    DataStream ss{std::span<const uint8_t>{Consensus::V1_GENESIS_HEADER}};
    CBlockHeader header;
    ss >> header;
    return header;
}

Digest V1GenesisHeaderSha256()
{
    return Sha256(Consensus::V1_GENESIS_HEADER);
}

std::vector<unsigned char> CommitmentPayload()
{
    std::vector<unsigned char> payload;
    payload.reserve(Consensus::CHARTER_COMMITMENT_TAG.size() + 64);
    payload.insert(payload.end(), Consensus::CHARTER_COMMITMENT_TAG.begin(), Consensus::CHARTER_COMMITMENT_TAG.end());
    payload.insert(payload.end(), Consensus::CHARTER_HASH.begin(), Consensus::CHARTER_HASH.end());
    // No lineage field. Founder decision 2026-09-09: this chain starts from
    // scratch and the charter (section 3) says no earlier chain has any claim
    // on it, so the genesis block references nothing before itself. The
    // payload is 47 bytes: the tag and the charter hash.
    return payload;
}

CScript CommitmentScript()
{
    return CScript() << OP_RETURN << CommitmentPayload();
}

bool HasCommitment(const CTransaction& tx)
{
    const CScript expected{CommitmentScript()};
    for (const CTxOut& out : tx.vout) {
        if (out.nValue == 0 && out.scriptPubKey == expected) return true;
    }
    return false;
}

std::string GenesisMessage(std::string_view date)
{
    // No numeral: this is the genesis, not a second one. The number is the
    // whole supply in its smallest unit, 21,000,000 x 10^8. The charter hash is
    // NOT repeated here — the full 32 bytes are in the coinbase's own output.
    return "Hic experimentum prosperat - " + std::string{date} + " - 2,100,000,000,000,000 sats, 21M XCF";
}

CBlock CreateGenesisBlock(std::string_view message, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
                                       << std::vector<unsigned char>(message.begin(), message.end());
    txNew.vout.emplace_back(0, CommitmentScript());

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

Digest CurrencyId(const CBlockHeader& genesis_header)
{
    return Sha256(SerializeHeader(genesis_header), TextBytes());
}

} // namespace charter
