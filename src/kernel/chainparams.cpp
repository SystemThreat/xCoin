// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <limits>
#include <arith_uint256.h>
#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/charter.h>
#include <consensus/merkle.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/log.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace util::hex_literals;

/**
 * PQ genesis transaction (v1 form, still used by the test networks and, as a
 * placeholder, by mainnet until the v2 genesis is mined). Genesis creates no
 * spendable supply: its single zero-value witness-v2 output is only a
 * deterministic marker. Supply begins at zero; block 1 is an ordinary block
 * that pays the era-0 subsidy like every block after it (nothing is carried
 * in, no founder allocation, no block-1 distribution: 7263c5d).
 */

// ═══════════════════════════════════════════════════════════════════════════
// xCoin mainnet genesis blocks.
//
// v1 chain (launched 2026-09-01): FINAL, history. Nothing of it is carried
// into this chain and the charter commitment does not reference it (35c4fda);
// its header is pinned as Consensus::V1_GENESIS_HEADER / V1_GENESIS_HASH only
// so it stays identifiable (getcharter, the mainnet startup gate below).
// nBits 0x1e0fffff = easy-start.
static constexpr const char* V1_GENESIS_MESSAGE = "Hic experimentum prosperat - 2026-09-01 - 2,100,000,000,000,000 sats, 21M XAT";
static constexpr uint32_t V1_GENESIS_TIME  = 1788220800; // 2026-09-01 00:00:00 UTC
static constexpr uint32_t V1_GENESIS_NONCE = 1112945;
static constexpr uint32_t V1_GENESIS_BITS  = 0x1e0fffff;
static constexpr std::string_view V1_GENESIS_MERKLE = "fac4f4af0516d1005efde194571656e20369eccd2c97bddd74a055b900692c88";

// v2 chain (the re-genesis, REGENESIS.md sections 1 and 8): NOT YET MINED.
// Cutover step 3 runs
//     xcoin-genesis -time=<T>            (T = the announced genesis time)
// which builds the charter genesis (charter::CreateGenesisBlock: coinbase
// message charter::GenesisMessage(<date>), "Hic experimentum prosperat - <date>
// - 2,100,000,000,000,000 sats, 21M XCF" — the message carries no digest; the
// full CHARTER_HASH is in the OP_RETURN charter output, the coinbase's only
// output; nothing minted), mines the nonce with MetalDAG at metaldagBaseTime = T
// and prints these lines ready to paste. Paste them, set GENESIS_IS_FINAL = true,
// rebuild, and the assertions below pin the result. Until then mainnet compiles
// the v1 genesis as a placeholder: the binary links, `getcharter` reports
// genesis_is_final=false, and the node refuses to start on mainnet
// (CheckGenesisFinalityForStartup, below), so nothing starts by accident.
static constexpr bool GENESIS_IS_FINAL = false;
static constexpr std::string_view FINAL_GENESIS_MESSAGE = ""; // charter::GenesisMessage("<YYYY-MM-DD>")
static constexpr uint32_t FINAL_GENESIS_TIME  = 0;
static constexpr uint32_t FINAL_GENESIS_NONCE = 0;
static constexpr uint32_t FINAL_GENESIS_BITS  = 0x1e0fffff;
static constexpr std::string_view FINAL_GENESIS_HASH   = "";
static constexpr std::string_view FINAL_GENESIS_MERKLE = "";

// ═══════════════════════════════════════════════════════════════════════════
// xCoin testnet A (contrib/regenesis/TESTNET-A.md): the v2 rules on a separate
// dress-rehearsal chain — the mainnet emission table (block 1 an ordinary block,
// no distribution), the data-carrier cap, the 64M WU consensus block weight,
// 300 s, ASERT 2 h, MetalDAG at the mainnet sizing with metaldagBaseTime = the
// testnet genesis time, powLimit 0x1e0fffff — with its own magic, ports, HRP and
// genesis. FINAL for testnet A; re-mined 2026-09-14 against charter 415b1dbc...
// with
//     xcoin-genesis -chain=test -time=1789379971 -threads=8 \
//         -message="xCoin testnet A - 2026-09-14 - 2,100,000,000,000,000 sats, 21M XCF"
// (mainnet and testnet A share the MetalDAG sizing and powLimit; the tool sets
// metaldagBaseTime = -time). The coinbase message carries no digest: the full
// CHARTER_HASH is committed in the OP_RETURN charter output, the coinbase's
// only output, OP_RETURN <"XCOIN/charter/1" || CHARTER_HASH> (47 bytes, no
// lineage field). Nothing is minted. Because the output commits to the charter,
// any change to CHARTER.md moves this chain's merkle root and genesis hash: the
// assert at the bottom of CTestNetParams fires until the genesis is re-mined
// (xcoin-genesis -chain=test, paste NONCE / HASH / MERKLE, wipe the rehearsal
// datadirs and re-mine from height 0).
static constexpr std::string_view TESTNET_GENESIS_MESSAGE = "xCoin testnet A - 2026-09-14 - 2,100,000,000,000,000 sats, 21M XCF";
static constexpr uint32_t TESTNET_GENESIS_TIME  = 1789379971; // 2026-09-14T09:59:31Z
static constexpr uint32_t TESTNET_GENESIS_NONCE = 166982; // 166,896 hashes at ~3.3 kH/s on 8 CPU threads (2026-09-14 re-mine, charter 415b1dbc)
static constexpr uint32_t TESTNET_GENESIS_BITS  = 0x1e0fffff;
static constexpr std::string_view TESTNET_GENESIS_HASH   = "1dc4131ed2649a4782fbb8b25423e970084c7d217f730651d93cf09f6a43ccb9"; // MetalDAG PoW hash 000001be7d866cb919cac1...
// CURRENCY_ID (SHA-256(header || charter text), `nex-cli -testnet getcharter`) = fb9c965c9b2c61d9f1f3471d96a775f764389142b838f63c183913b38b71029e
static constexpr std::string_view TESTNET_GENESIS_MERKLE = "9ad269fbcffc895fb038b4c9e0a932461665e9434a662226f044ffe3267a4d66";
// Re-mined 2026-09-14 against charter 415b1dbc... (section 4, the 14 XCF schedule; the
// earlier genesis of the day was bound to ba4554b7...). Should the charter change again
// before launch: xcoin-genesis -chain=test, paste the printed constants, keep this true.
static constexpr bool TESTNET_GENESIS_IS_FINAL = true;

// ═══════════════════════════════════════════════════════════════════════════

struct GenesisAllocation {
    const char* label;
    CAmount amount;
    const char* pqPubKeyHash;  // 32-byte witness-v2 program
};

// A zero-value marker retained as part of the permanent genesis identity.
static const GenesisAllocation GENESIS_ALLOCATIONS[] = {
    {"genesis-marker", 0LL, "c6f0b134b1f0534668f1ec535b6b62601c6919f3a18ff2e5fe4fb2a65fdd81fa"},
};
static_assert(sizeof(GENESIS_ALLOCATIONS) / sizeof(GENESIS_ALLOCATIONS[0]) == 1,
              "Genesis must have exactly 1 allocation");

static CBlock CreatePQGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
        << std::vector<unsigned char>((const unsigned char*)pszTimestamp,
                                      (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    // Create genesis outputs
    constexpr int numAlloc = sizeof(GENESIS_ALLOCATIONS) / sizeof(GENESIS_ALLOCATIONS[0]);
    txNew.vout.resize(numAlloc);
    CAmount totalGenesis = 0;
    for (int i = 0; i < numAlloc; ++i) {
        const auto& alloc = GENESIS_ALLOCATIONS[i];
        txNew.vout[i].nValue = alloc.amount;
        totalGenesis += alloc.amount;

        // Witness v2 PQ script: OP_2 <32-byte pubkey hash>
        auto hashBytes = ParseHex(alloc.pqPubKeyHash);
        txNew.vout[i].scriptPubKey = CScript() << OP_2 << hashBytes;
    }

    // Genesis must mint no spendable supply.
    assert(totalGenesis == 0LL);

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/** Install the mainnet emission schedule (consensus/params.h); the test
 *  networks run the same table. */
static void SetMainnetEmission(Consensus::Params& consensus)
{
    consensus.emissionTable.assign(std::begin(Consensus::EMISSION_TABLE), std::end(Consensus::EMISSION_TABLE));
    consensus.emissionClosingDustSat = Consensus::EMISSION_CLOSING_DUST_SAT;
}

/** Reserve the multi-algorithm proof-of-work parameter space (REGENESIS.md
 *  section 7) without activating anything: one algorithm (MetalDAG, id 0) with
 *  the chain's own difficulty parameters, the whole share, no run cap, and
 *  multi_algo_activation_height 0 so every header must carry algorithm id 0. */
static void ReserveMultiAlgoPow(Consensus::Params& consensus)
{
    consensus.pow_algos = {Consensus::PowAlgoParams{consensus.powLimit, consensus.nASERTHalfLife, consensus.nPowTargetSpacing}};
    consensus.pow_share = {10'000};
    consensus.max_consecutive_same_algo = 0;
    consensus.multi_algo_activation_height = 0;
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.nSubsidyHalvingInterval = 360000;
        consensus.BIP34Height = 1; // from block 1: the genesis coinbase carries the charter, not a height (audit finding 1: -reindex must not reject its own genesis)
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // Xcoin easy-start powLimit (~0x1e0fffff): low difficulty floor so a fresh
        // chain bootstraps on modest hashpower; anchored ASERT follows aggregate
        // MetalDAG work without compounding single-block variance.
        consensus.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 300 * 50; // 50 blocks x 300s = 15000s retarget
        consensus.nPowTargetSpacing = 300; // 5-minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nASERTActivationHeight = 1;   // New genesis: ASERT from block 1.
        consensus.nASERTHalfLife = 2 * 60 * 60; // 2h: responsive without EDA cliffs.
        // MetalDAG PoW: 4 GiB DAG at launch (16 GB Mac floor), +128 MiB/epoch, ~14-day epochs.
        // Epoch 0 starts at the genesis time (the v2 time once it is final).
        consensus.metaldagBaseTime      = GENESIS_IS_FINAL ? FINAL_GENESIS_TIME : V1_GENESIS_TIME;
        consensus.metaldagEpochSeconds  = 14 * 24 * 3600; // ~14 days
        consensus.metaldagDagInitBytes  = int64_t{4} * 1024 * 1024 * 1024; // 4 GiB
        consensus.metaldagDagGrowthBytes = int64_t{128} * 1024 * 1024;     // +128 MiB/epoch
        consensus.metaldagCacheDivisor  = 128;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 27; // bits 28..29 are the PoW-algorithm id (REGENESIS.md section 7)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815; // 90%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        // NEX: Bootstrap values — set after chain has sufficient depth.
        // After 1000+ blocks: run `nex-cli getblockchaininfo` and update:
        //   nMinimumChainWork = chainwork value from a trusted block
        //   defaultAssumeValid = hash of a trusted block (e.g., block 1000)
        // For genesis launch, zeros are acceptable — nodes verify everything from genesis.
        consensus.nMinimumChainWork = uint256{};  // SET AFTER CHAIN DEPTH > 1000
        consensus.defaultAssumeValid = uint256{}; // SET AFTER CHAIN DEPTH > 1000

        // Emission: 14 XCF, halved every 750,000 blocks until it reaches zero (charter
        // section 4; consensus/params.h).
        SetMainnetEmission(consensus);
        // Only witness v3 (post-quantum script tree) outputs may be created after the
        // genesis block: bad-txout-not-pq. This chain has no witness v2 output at all.
        consensus.permitV2Outputs = false;
        // Settlement levy: none at genesis (zero rate, zero cap); switching one on
        // later is a soft fork, a table row plus a deployment (REGENESIS.md section 6).
        consensus.settlementLevySchedule = {Consensus::SETTLEMENT_LEVY_GENESIS_RULE};
        assert(Consensus::SettlementLevyScheduleIsSoftForkOnly(consensus.settlementLevySchedule));
        consensus.minOutputValueSat = Consensus::MIN_OUTPUT_VALUE_SAT;
        consensus.coinbaseMaturity = Consensus::COINBASE_MATURITY_MAINNET; // 1,000 blocks, ~3.5 days
        // Release checkpoints — NONE YET; this chain does not exist until genesis.
        // Add the newest {height, hash} at EVERY release once the chain has depth:
        //     consensus.release_checkpoints = { {10000, uint256{"..."}}, };
        // There is no key and nothing to sign; a release states which block it saw,
        // and only binds people who choose to run that build. It is the sole
        // protection for a node syncing from scratch. See REGENESIS.md section 6.
        consensus.release_checkpoints = {};

        // Multi-algorithm PoW: reserved, inactive (section 7).
        ReserveMultiAlgoPow(consensus);

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        // xCoin v2 mainnet magic — 'X','P','A',\x03: the re-genesis chain has its
        // own network identity, so a v2 node can never peer with the v1 chain
        // (which uses 'X','P','A',\x02) or the retired NEX chain (NEX\x02). The
        // P2P port (9333) and the address HRP (xpa) are unchanged.
        pchMessageStart[0] = 0x58;  // 'X'
        pchMessageStart[1] = 0x50;  // 'P'
        pchMessageStart[2] = 0x41;  // 'A'
        pchMessageStart[3] = 0x03;
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        m_genesis_is_final = GENESIS_IS_FINAL;
        if constexpr (GENESIS_IS_FINAL) {
            // The v2 genesis: charter commitment in the coinbase, MetalDAG-mined by xcoin-genesis.
            genesis = charter::CreateGenesisBlock(FINAL_GENESIS_MESSAGE, FINAL_GENESIS_TIME, FINAL_GENESIS_NONCE, FINAL_GENESIS_BITS, 1);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == Assert(uint256::FromHex(FINAL_GENESIS_HASH)).value());
            assert(genesis.hashMerkleRoot == Assert(uint256::FromHex(FINAL_GENESIS_MERKLE)).value());
            assert(charter::HasCommitment(*genesis.vtx[0]));
            assert(consensus.hashGenesisBlock != Consensus::V1_GENESIS_HASH);
        } else {
            // Placeholder until the cutover: the v1 genesis, so the chain is identifiable but unlaunchable.
            genesis = CreatePQGenesisBlock(V1_GENESIS_MESSAGE, V1_GENESIS_TIME, V1_GENESIS_NONCE, V1_GENESIS_BITS, 1);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == Consensus::V1_GENESIS_HASH);
            assert(genesis.hashMerkleRoot == uint256{V1_GENESIS_MERKLE});
        }

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // Xcoin DNS seeds. A new node resolves these at startup and dials whatever
        // comes back; this is the ONLY way a stranger finds the network, because
        // there is nobody to hand them an -addnode by hand.
        //
        // Each name must be a DNS-ONLY record (grey cloud on Cloudflare) whose
        // A/AAAA answers are nodes actually listening on 9333. A PROXIED record
        // returns the CDN's anycast addresses, which do not run nexd, and every
        // connection attempt fails silently — the single most likely way this
        // breaks on launch day. The trailing dot forces an absolute lookup so a
        // user's search domain cannot rewrite the name.
        // Five names across five domains. This list FREEZES at genesis: adding a
        // hostname later needs a new release and every already-shipped binary
        // never learns it, so the cost of an extra name today is zero and the
        // cost of a missing one is permanent. For comparison, Litecoin ships 5
        // and 2 answer; Namecoin ships 6 and 2 answer; Vertcoin ships 5 and 1.
        //
        // Each name must be DNS-ONLY (grey cloud). A proxied record returns the
        // CDN's anycast addresses, which do not run nexd, and every new node
        // then dials Cloudflare on 9333 forever.
        //
        // Core asks for "x9.<name>" first — SeedsServiceFlags() is
        // NODE_NETWORK|NODE_WITNESS = 9 — so each zone needs a WILDCARD
        // "*.seed.<domain>" alongside the bare record. If x9. does not resolve,
        // Core falls back to an ADDR_FETCH connection to the bare name on the
        // P2P port, so the bare name must point at a node that is actually
        // listening, not merely at something that answers DNS.
        //
        // Spread the zones across more than one DNS provider: five names on one
        // Cloudflare account is one account termination away from five failures.
        vSeeds.emplace_back("seed.xcoinproject.com.");
        vSeeds.emplace_back("seed.superknet.com.");
        vSeeds.emplace_back("seed.xcoinminer.com.");
        vSeeds.emplace_back("seed.minedifferent.com.");
        vSeeds.emplace_back("seed.movepunk.com.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,55);  // NEX: 'M' prefix for P2SH
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,181);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x4E, 0x58, 0x50};  // NEX: "nxpb" serialization
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x4E, 0x58, 0x53};  // NEX: "nxpv" serialization

        bech32_hrp = "xpa";  // Xcoin PQ addresses: xpa1... (witness v2 = xpa1z...)

        // Fixed seeds: compiled-in addresses, used when DNS answers nothing —
        // a lapsed domain, a captive network, a censored resolver. Generated by
        // contrib/seeds/generate-seeds.py from contrib/seeds/nodes_main.txt.
        //
        // Exactly one entry today (172.96.186.49:9333), which is also the only
        // machine on the network that listens: the founder's Mac node runs
        // listen=0. One entry is a single point of failure, not a seed set —
        // regenerate nodes_main.txt and rebuild as soon as a second reachable
        // node exists. Bitcoin's inherited 2,059 mainnet seeds were removed here;
        // they answer on port 8333 and would fail this chain's magic anyway.
        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        // NEX: Bootstrap values — set after chain has sufficient depth.
        // After 1000+ blocks: run `nex-cli getblockchaininfo` and update:
        //   nMinimumChainWork = chainwork value from a trusted block
        //   defaultAssumeValid = hash of a trusted block (e.g., block 1000)
        // After 10000+ blocks: populate chainTxData with real statistics.
        // For genesis launch, zeros are acceptable — nodes verify everything from genesis.
        chainTxData = ChainTxData{
            0,    // nTime — SET to timestamp of a recent trusted block
            0,    // nTxCount — SET to total tx count at that block
            0,    // dTxRate — SET to average tx/second over recent history
        };

        // Headers-sync DoS parameters (headerssync.cpp asserts these are non-zero;
        // a mainnet node without them aborts on its first header sync). Generated
        // by contrib/devtools/headerssync-params.py on 2026-09-14 with this chain's
        // inputs: BLOCK_INTERVAL 300 s, GENESIS_TIME 2026-09-14, TIME 2028-10-10,
        // MINCHAINWORK_HEADERS 218,016 (the projected height at TIME — this chain's
        // nMinimumChainWork is zero, so there is no minchainwork height to read).
        // Re-run the script when nMinimumChainWork is set or the horizon passes.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 211,
            .redownload_buffer_size = 4822, // 4822/211 = ~22.9 commitments
        };
    }
};

/**
 * xCoin testnet A (-testnet / -chain=test): the v2 consensus rules exactly as
 * mainnet on a separate dress-rehearsal chain (contrib/regenesis/TESTNET-A.md). What
 * differs from mainnet is identity only: magic 'X','T','A',0x02, P2P port
 * 19333 (RPC 19432, chainparamsbase.cpp), bech32 HRP "txa" (addresses read
 * txa1r…), no seeds, and its own charter genesis mined at powLimit
 * (TESTNET_GENESIS_* above).
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.nSubsidyHalvingInterval = 360000;
        consensus.BIP34Height = 1; // from block 1: the genesis coinbase carries the charter, not a height (audit finding 1: -reindex must not reject its own genesis)
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // Proof of work exactly as mainnet: easy-start powLimit, 300 s blocks,
        // anchored ASERT (2 h half-life) from block 1, no min-difficulty blocks.
        consensus.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 300 * 50;
        consensus.nPowTargetSpacing = 300;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nASERTActivationHeight = 1;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        // MetalDAG exactly as mainnet (4 GiB launch DAG, +128 MiB per ~14-day
        // epoch); epoch 0 starts at the testnet A genesis time. The epoch seed
        // depends only on the epoch number, so a miner built for mainnet
        // computes the same epoch-0 DAG here until mainnet's epoch 1 begins.
        consensus.metaldagBaseTime      = TESTNET_GENESIS_IS_FINAL ? TESTNET_GENESIS_TIME : V1_GENESIS_TIME;
        consensus.metaldagEpochSeconds  = 14 * 24 * 3600;
        consensus.metaldagDagInitBytes  = int64_t{4} * 1024 * 1024 * 1024; // 4 GiB
        consensus.metaldagDagGrowthBytes = int64_t{128} * 1024 * 1024;     // +128 MiB/epoch
        consensus.metaldagCacheDivisor  = 128;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 27; // bits 28..29 are the PoW-algorithm id (REGENESIS.md section 7)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815; // 90%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // The mainnet emission table (14 XCF, halved every 750,000 blocks).
        SetMainnetEmission(consensus);
        consensus.permitV2Outputs = false; // as mainnet: v2 outputs are invalid
        consensus.settlementLevySchedule = {Consensus::SETTLEMENT_LEVY_GENESIS_RULE}; // as mainnet: no levy
        assert(Consensus::SettlementLevyScheduleIsSoftForkOnly(consensus.settlementLevySchedule));
        consensus.minOutputValueSat = Consensus::MIN_OUTPUT_VALUE_SAT; // as mainnet
        consensus.coinbaseMaturity = Consensus::COINBASE_MATURITY_MAINNET; // as mainnet
        ReserveMultiAlgoPow(consensus);                              // as mainnet: reserved, inactive

        // testnet A magic: 'X','T','A',\x02 (mainnet is 'X','P','A',\x03).
        pchMessageStart[0] = 0x58; // 'X'
        pchMessageStart[1] = 0x54; // 'T'
        pchMessageStart[2] = 0x41; // 'A'
        pchMessageStart[3] = 0x02;
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        m_genesis_is_final = TESTNET_GENESIS_IS_FINAL;
        if constexpr (TESTNET_GENESIS_IS_FINAL) {
            // The testnet charter genesis, MetalDAG-mined by xcoin-genesis -chain=test.
            genesis = charter::CreateGenesisBlock(TESTNET_GENESIS_MESSAGE, TESTNET_GENESIS_TIME, TESTNET_GENESIS_NONCE, TESTNET_GENESIS_BITS, 1);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == Assert(uint256::FromHex(TESTNET_GENESIS_HASH)).value());
            assert(genesis.hashMerkleRoot == Assert(uint256::FromHex(TESTNET_GENESIS_MERKLE)).value());
            assert(charter::HasCommitment(*genesis.vtx[0]));
            assert(consensus.hashGenesisBlock != Consensus::V1_GENESIS_HASH);
        } else {
            // Placeholder until testnet is re-mined: the v1 genesis, exactly as mainnet
            // stands in before its own cutover — identifiable, unlaunchable.
            genesis = CreatePQGenesisBlock(V1_GENESIS_MESSAGE, V1_GENESIS_TIME, V1_GENESIS_NONCE, V1_GENESIS_BITS, 1);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == Consensus::V1_GENESIS_HASH);
            assert(genesis.hashMerkleRoot == uint256{V1_GENESIS_MERKLE});
        }

        // One DNS seed: node two of the rehearsal (contrib/regenesis/vps). A plain A
        // record is enough for a seed lookup; -addnode / -connect still work
        // (TESTNET-A.md). No fixed seeds: the rehearsal has no fixed set of peers.
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("testnet.superknet.com.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,57);   // NEX testnet P2SH
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x4E, 0x54, 0x50};  // NEX testnet: "tNXP" serialization
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x4E, 0x54, 0x53};  // NEX testnet: "tNXS" serialization

        bech32_hrp = "txa";  // testnet A PQ addresses: txa1r...

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{0, 0, 0};

        // Anti-DoS headers sync (headerssync.cpp asserts a non-zero commitment
        // period; a chain without one crashes on the first low-work headers batch,
        // audit finding 3). Same spacing and zero minimum chain work as mainnet, so
        // the same numbers; re-run contrib/devtools/headerssync-params.py when
        // nMinimumChainWork is set.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 211,
            .redownload_buffer_size = 4822, // 4822/211 = ~22.9 commitments
        };
    }
};

/**
 * Regtest emission: the mainnet shape (one era at the era-0 rate, three
 * halvings on eras of the same length, the last rate running until the cap,
 * dust on the final block) with Bitcoin-regtest 150-block eras and S0 = 50 XCF,
 * so fixtures keep the familiar 50 XCF coinbase for heights 1..150 and the
 * first halving at 151 (block 1 is an ordinary block; the eras start at height
 * 1 like every chain's). The 6.25 XCF tail divides the remainder exactly, so
 * the regtest dust is 0.
 */
static constexpr int REGTEST_EMISSION_ERA_BLOCKS = 150;
static constexpr int64_t REGTEST_EMISSION_CLOSING_DUST_SAT = 0LL;
static constexpr int REGTEST_NUM_EMISSION_ERAS = 4; // regtest keeps its own 50 / 25 / 12.5 / 6.25 table for the inherited fixtures
static constexpr Consensus::EmissionEra REGTEST_EMISSION_TABLE[REGTEST_NUM_EMISSION_ERAS] = {
    //  startHeight  endHeight  baseSubsidy(sat)
    {         1,       150,  5000000000LL },  // era  0: 50.00000000 XCF x 150 blocks
    {       151,       300,  2500000000LL },  // era  1: 25.00000000 XCF x 150 blocks
    {       301,       450,  1250000000LL },  // era  2: 12.50000000 XCF x 150 blocks
    {       451,   3358350,   625000000LL },  // era  3: 6.25000000 XCF x 3,357,900 blocks (runs to the cap)
};
// Regtest emission starts at height 1 like every chain: block 1 is an ordinary block.
static_assert(Consensus::EmissionTableContiguous(REGTEST_EMISSION_TABLE, REGTEST_NUM_EMISSION_ERAS, Consensus::EMISSION_START_HEIGHT, REGTEST_EMISSION_ERA_BLOCKS),
              "regtest emission table must be four back-to-back eras from height 1: three of 150 blocks, the last at least that long");
static_assert(REGTEST_EMISSION_TABLE[0].baseSubsidy == 50 * COIN, "regtest era 0 pays 50 XCF");
static_assert(Consensus::EmissionTableHalves(REGTEST_EMISSION_TABLE, REGTEST_NUM_EMISSION_ERAS), "regtest eras halve exactly");
static_assert(Consensus::EmissionTableTotalSat(REGTEST_EMISSION_TABLE, REGTEST_NUM_EMISSION_ERAS) + REGTEST_EMISSION_CLOSING_DUST_SAT == Consensus::MAX_SUPPLY_SAT,
              "regtest emission must be exactly 21,000,000 XCF");

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 300 * 50;
        consensus.nPowTargetSpacing = 300;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.nASERTActivationHeight = std::numeric_limits<int>::max();
        consensus.nASERTHalfLife = 2 * 60 * 60;
        // MetalDAG PoW: tiny FLAT DAG so regtest builds caches instantly. Growth is 0
        // because regtest blocks are timestamped at real (2026) time while genesis is
        // dated 2011 — any growth would balloon the DAG. Size stays 1 MiB; the epoch
        // still advances (rotating the seed) to exercise cache transitions.
        consensus.metaldagBaseTime      = 1296688602;        // regtest genesis time
        consensus.metaldagEpochSeconds  = 1000;
        consensus.metaldagDagInitBytes  = 1 * 1024 * 1024;   // 1 MiB, flat
        consensus.metaldagDagGrowthBytes = 0;
        consensus.metaldagCacheDivisor  = 128;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 27; // bits 28..29 are the PoW-algorithm id (REGENESIS.md section 7)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        consensus.emissionTable.assign(std::begin(REGTEST_EMISSION_TABLE), std::end(REGTEST_EMISSION_TABLE));
        consensus.emissionClosingDustSat = REGTEST_EMISSION_CLOSING_DUST_SAT;
        // Settlement levy: none, as on mainnet, unless a test enables it with -levybp
        // (the rate in bp; the levy tests pass 5). An enabled levy runs under the
        // reference cap so the tests exercise the same arithmetic a future activation would.
        if (opts.levy_bp && (*opts.levy_bp < 0 || *opts.levy_bp > Consensus::SETTLEMENT_LEVY_BP_MAX)) {
            throw std::runtime_error(strprintf("-levybp must be between 0 and %d", Consensus::SETTLEMENT_LEVY_BP_MAX));
        }
        consensus.settlementLevySchedule = {opts.levy_bp && *opts.levy_bp > 0
                                                ? Consensus::SettlementLevyRule{0, *opts.levy_bp, Consensus::SETTLEMENT_LEVY_CAP_SAT}
                                                : Consensus::SETTLEMENT_LEVY_GENESIS_RULE};
        assert(Consensus::SettlementLevyScheduleIsSoftForkOnly(consensus.settlementLevySchedule));
        consensus.minOutputValueSat = 0; // regtest: the shared fixtures build sub-floor outputs; the rule is unit-tested directly
        // Coinbase maturity: the mainnet 1,000 unless a test overrides it (-coinbasematurity; the
        // harness passes 100 so the inherited fixtures still mine 100 blocks to a spendable coinbase).
        if (opts.coinbase_maturity && *opts.coinbase_maturity < 1) {
            throw std::runtime_error("-coinbasematurity must be at least 1");
        }
        consensus.coinbaseMaturity = opts.coinbase_maturity.value_or(Consensus::COINBASE_MATURITY_MAINNET);
        ReserveMultiAlgoPow(consensus);

        pchMessageStart[0] = 0x4e;
        pchMessageStart[1] = 0x45;
        pchMessageStart[2] = 0x58;
        pchMessageStart[3] = 0x03;
        nDefaultPort = 19444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // Regtest genesis: PQ genesis (witness-v2 output) so it passes the
        // Xcoin PQ-only output rule. Trivial powLimit → nonce 2 is valid.
        genesis = CreatePQGenesisBlock("Xcoin XCF - post-quantum money, 21M, secured by Bitcoin - 2026-08-29",
                                       1296688602, 2, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        // NEX: genesis hash computed dynamically — asserts disabled for new chain
        // assert(consensus.hashGenesisBlock == uint256{"00000000ca679662c87c40693490f00e297a2bd357e59cab6f7814d12145d66b"});
        // assert(genesis.hashMerkleRoot == uint256{"2c62d38151df668e842eb913e9dd0b872a0f1d6dbf5998b6803e0be382e75f68"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        m_assumeutxo_data = {
            {   // For use by unit tests
                // Regenerated 2026-09-05 for the re-genesis unit-test chain
                // (TestChain100Setup + 10 blocks paying the shared test ML-DSA
                // key; block 1 is an ordinary block, 7263c5d).
                // Re-pinned in stage B4: the BIP9 top bits moved to 01 in bits
                // 31..30 to make room for the PoW-algorithm id, so every block
                // header's nVersion (and with it every block hash) changed. The
                // UTXO set itself is untouched, so hash_serialized still holds.
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"f63ca907f7d92520253c3e6f6eb706e890f18419d2d17e96970484ad65374685"}},
                .m_chain_tx_count = 111,
                // Re-pinned 2026-09-14 after the block-1 distribution was removed
                // (35c4fda, 506d9ad, 8e440be, 7263c5d); hash_serialized regenerated with it.
                .blockhash = uint256{"0edf04b2825529cea5a28dcb2c08f3f6828030c29b1eceb3b89cd1c38719ccd2"},
            },
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                // NOTE: the 200/299 entries below predate the PQ-only test
                // chain and are only consumed by functional tests; regenerate
                // them when those are adapted.
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"}},
                .m_chain_tx_count = 201,
                .blockhash = uint256{"385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"},
            },
            {
                // For use by test/functional/feature_assumeutxo.py and test/functional/tool_bitcoin_chainstate.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"}},
                .m_chain_tx_count = 334,
                .blockhash = uint256{"7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"},
            },
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0.001, // Set a non-zero rate to make it testable
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "nxrt";

        // Upstream testnet4's headers-sync parameters.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 275,
            .redownload_buffer_size = 7017, // 7017/275 = ~25.5 commitments
        };
    }
};

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<std::string> CheckGenesisFinalityForStartup(const CChainParams& params, bool allow_unfinal_genesis)
{
    if (params.GetChainType() != ChainType::MAIN || params.GenesisIsFinal() || allow_unfinal_genesis) return std::nullopt;
    return strprintf("Refusing to start on mainnet: this build's v2 genesis is not final (GENESIS_IS_FINAL is false; the v1 genesis %s stands in as a placeholder, contrib/regenesis/REGENESIS.md section 8 step 3). "
                     "Paste the xcoin-genesis output into src/kernel/chainparams.cpp and rebuild, or run the dress rehearsal with -testnet. "
                     "Only for the cutover dry run: -allowunfinalgenesis=1 overrides this refusal.",
                     params.GetConsensus().hashGenesisBlock.ToString());
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    }
    return std::nullopt;
}
