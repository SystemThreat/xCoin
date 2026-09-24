// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// xcoin-genesis: build and mine the xCoin v2 genesis block
// (contrib/regenesis/REGENESIS.md sections 1 and 8, cutover step 3).
//
// The block is charter::CreateGenesisBlock(): a coinbase whose scriptSig
// carries charter::GenesisMessage() — "Hic experimentum prosperat - <date> -
// 2,100,000,000,000,000 sats, 21M XCF" — and whose only output is the
// zero-value OP_RETURN charter commitment ("XCOIN/charter/1" || CHARTER_HASH ||
// SHA-256(v1 genesis header)). Nothing is minted. The coinbase is run through
// CheckTransaction so an over-long message (bad-cb-length, 100-byte scriptSig)
// is refused here rather than by every node at startup. The nonce is ground with the node's own
// MetalDAG path (metaldag::PoWHash + CheckProofOfWorkImpl) under the chosen
// chain's DAG sizing with metaldagBaseTime = nTime, exactly as the node will
// verify it. On success it prints the FINAL_GENESIS_* lines for
// src/kernel/chainparams.cpp, the CURRENCY_ID and the measured hash rate.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <consensus/charter.h>
#include <consensus/params.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <metaldag/metaldag.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

constexpr uint32_t DEFAULT_BITS{0x1e0fffff};
constexpr int32_t DEFAULT_VERSION{1};
//! 16x the 2^20 hashes expected at 0x1e0fffff: a bound, not a budget.
constexpr uint64_t DEFAULT_MAX_ATTEMPTS{16ull << 20};

void SetupArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);
    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-time=<unix>", "Genesis nTime in seconds since the epoch (default: now). It is also metaldagBaseTime (MetalDAG epoch 0 starts here) and the ASERT anchor. Mining refuses a stamp more than an hour old; -verify accepts any.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-message=<text>", "Coinbase text (at most 91 characters: the coinbase scriptSig is capped at 100 bytes). Default: \"Hic experimentum prosperat - <UTC date of -time> - 2,100,000,000,000,000 sats, 21M XCF\" (REGENESIS.md section 1).", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-bits=<hex>", strprintf("nBits (default: %08x)", DEFAULT_BITS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blockversion=<n>", strprintf("Header version (default: %d)", DEFAULT_VERSION), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // Not "-nonce": ArgsManager reads any -no<x> option as the negation of -<x>.
    argsman.AddArg("-startnonce=<n>", "First nonce to try (default: 0); with -verify, the nonce to check", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-threads=<n>", "Mining threads (default: every hardware thread)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxattempts=<n>", strprintf("Give up after this many hashes in total (default: %d)", DEFAULT_MAX_ATTEMPTS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-verify", "Do not mine: build the block at -startnonce, check its MetalDAG proof of work and print the paste block", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-quiet", "No progress lines", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // -chain / -testnet / -regtest: whose MetalDAG DAG sizing and powLimit apply (default: main).
    SetupChainParamsBaseOptions(argsman);
}

struct MiningState {
    std::atomic<bool> stop{false};
    std::atomic<bool> found{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint32_t> winning_nonce{0};
};

//! One worker: nonces first, first+step, first+2*step, ... up to its share of the attempt budget.
void MineTask(CBlockHeader header, const Consensus::Params& params, uint32_t first, uint32_t step, uint64_t budget, MiningState& state)
{
    uint64_t local{0};
    uint64_t reported{0};
    for (uint64_t nonce = first; nonce <= std::numeric_limits<uint32_t>::max() && local < budget; nonce += step) {
        if (state.stop.load(std::memory_order_relaxed)) break;
        header.nNonce = static_cast<uint32_t>(nonce);
        const uint256 pow_hash{metaldag::PoWHash(header, params)};
        ++local;
        if (CheckProofOfWorkImpl(pow_hash, header.nBits, params)) {
            bool expected{false};
            if (state.found.compare_exchange_strong(expected, true)) {
                state.winning_nonce.store(header.nNonce);
                state.stop.store(true);
            }
            break;
        }
        if ((local & 15) == 0) {
            state.attempts.fetch_add(local - reported, std::memory_order_relaxed);
            reported = local;
        }
    }
    state.attempts.fetch_add(local - reported, std::memory_order_relaxed);
}

std::string HeaderHex(const CBlockHeader& header)
{
    DataStream ss;
    ss << header;
    return HexStr(ss);
}

void PrintPasteBlock(const CBlock& block, const std::string& message, const Consensus::Params& params, const std::string& chain)
{
    const CBlockHeader header{block};
    const uint256 pow_hash{metaldag::PoWHash(header, params)};
    const metaldag::EpochSizing sizing{metaldag::GetEpochSizing(header.nTime, params)};
    tfm::format(std::cout, "\n");
    tfm::format(std::cout, "// xcoin-genesis (%s params, MetalDAG epoch %d: DAG %d bytes, cache %d bytes): paste into\n", chain, sizing.epoch, sizing.full_size, sizing.cache_size);
    tfm::format(std::cout, "// src/kernel/chainparams.cpp next to GENESIS_IS_FINAL and set it to true.\n");
    tfm::format(std::cout, "static constexpr bool GENESIS_IS_FINAL = true;\n");
    tfm::format(std::cout, "static constexpr std::string_view FINAL_GENESIS_MESSAGE = \"%s\";\n", message);
    tfm::format(std::cout, "static constexpr uint32_t FINAL_GENESIS_TIME  = %u; // %s\n", header.nTime, FormatISO8601DateTime(header.nTime));
    tfm::format(std::cout, "static constexpr uint32_t FINAL_GENESIS_NONCE = %u;\n", header.nNonce);
    tfm::format(std::cout, "static constexpr uint32_t FINAL_GENESIS_BITS  = 0x%08x;\n", header.nBits);
    tfm::format(std::cout, "static constexpr std::string_view FINAL_GENESIS_HASH   = \"%s\";\n", header.GetHash().GetHex());
    tfm::format(std::cout, "static constexpr std::string_view FINAL_GENESIS_MERKLE = \"%s\";\n", header.hashMerkleRoot.GetHex());
    tfm::format(std::cout, "// consensus.metaldagBaseTime = FINAL_GENESIS_TIME (%u); browser miner / pool: metaldagBaseTime = %u\n", header.nTime, header.nTime);
    tfm::format(std::cout, "// FINAL_GENESIS_VERSION        = %d\n", header.nVersion);
    tfm::format(std::cout, "// CHARTER_HASH                 = %s\n", charter::DigestHex(Consensus::CHARTER_HASH));
    tfm::format(std::cout, "// SHA-256(v1 genesis header)   = %s  (v1 genesis %s)\n", charter::DigestHex(charter::V1GenesisHeaderSha256()), Consensus::V1_GENESIS_HASH.GetHex());
    tfm::format(std::cout, "// charter output               = %s\n", HexStr(charter::CommitmentScript()));
    tfm::format(std::cout, "// coinbase txid                = %s\n", block.vtx[0]->GetHash().GetHex());
    tfm::format(std::cout, "// MetalDAG PoW hash            = %s\n", pow_hash.GetHex());
    tfm::format(std::cout, "// CURRENCY_ID                  = %s  (SHA-256(header || charter text); timestamp this and CHARTER_HASH with OpenTimestamps)\n", charter::DigestHex(charter::CurrencyId(header)));
    tfm::format(std::cout, "// header hex                   = %s\n", HeaderHex(header));
}

} // namespace

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();
    SetupArgs(args);

    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        std::string usage = CLIENT_NAME " xcoin-genesis version " + FormatFullVersion() + "\n";
        if (args.GetBoolArg("-version", false)) {
            usage += FormatParagraph(LicenseInfo());
        } else {
            usage += "\n"
                     "Builds the xCoin v2 genesis block (charter commitment in the coinbase, nothing minted) and\n"
                     "mines its nonce with the node's MetalDAG proof of work at metaldagBaseTime = -time, then prints\n"
                     "the FINAL_GENESIS_* constants for src/kernel/chainparams.cpp and the CURRENCY_ID.\n"
                     "\n"
                     "Usage:  xcoin-genesis [-time=<unix>] [-message=<text>] [-bits=<hex>] [-threads=<n>] [-maxattempts=<n>]\n"
                     "        xcoin-genesis -time=<unix> -startnonce=<n> -verify\n";
            usage += "\n" + args.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", usage);
        return argc < 2 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    try {
        // Chain: whose DAG sizing and powLimit the genesis is mined under.
        const ChainType chain_type{args.GetChainType()};
        const std::unique_ptr<const CChainParams> chainparams{CreateChainParams(args, chain_type)};
        Consensus::Params params{chainparams->GetConsensus()};

        // Header time. Default: now. The genesis nTime is the ASERT anchor: every
        // hour between it and the first mined block is an hour the difficulty
        // filter believes the chain is behind schedule, so whoever mines first
        // gets minimum-difficulty blocks until the schedule catches up — about
        // twelve per hour of gap, each worth the full subsidy. Mining therefore
        // refuses a stale or far-future stamp. -verify accepts any: it re-checks a
        // block that was already mined. The gap between mining the genesis and
        // starting the network is not something this tool can see; keep it short.
        const bool verify_mode{args.GetBoolArg("-verify", false)};
        const int64_t now{GetTime()};
        const int64_t time_arg{args.GetIntArg("-time", now)};
        if (time_arg <= 0 || time_arg > std::numeric_limits<uint32_t>::max()) {
            tfm::format(std::cerr, "Error: -time=<unix> must be a positive 32-bit timestamp\n");
            return EXIT_FAILURE;
        }
        if (!verify_mode) {
            constexpr int64_t MAX_STALE_GENESIS_TIME{60 * 60};
            if (time_arg < now - MAX_STALE_GENESIS_TIME) {
                tfm::format(std::cerr, "Error: -time=%d is %d s in the past. The genesis time anchors the difficulty filter: every hour of\n"
                                       "gap before the first block is ~12 free minimum-difficulty blocks for whoever mines first. Omit -time\n"
                                       "to use now, or pass -verify to re-check a genesis that was already mined.\n", time_arg, now - time_arg);
                return EXIT_FAILURE;
            }
            if (time_arg > now + MAX_FUTURE_BLOCK_TIME) {
                tfm::format(std::cerr, "Error: -time=%d is %d s in the future; nodes reject headers more than %d s ahead of their clock.\n",
                            time_arg, time_arg - now, MAX_FUTURE_BLOCK_TIME);
                return EXIT_FAILURE;
            }
        }
        const auto n_time{static_cast<uint32_t>(time_arg)};
        const std::string message{args.GetArg("-message", charter::GenesisMessage(FormatISO8601Date(n_time)))};
        const std::string bits_str{args.GetArg("-bits", strprintf("%08x", DEFAULT_BITS))};
        const auto bits_parsed{ToIntegral<uint32_t>(bits_str.starts_with("0x") ? bits_str.substr(2) : bits_str, /*base=*/16)};
        if (!bits_parsed) {
            tfm::format(std::cerr, "Error: -bits=%s is not a hex nBits value\n", bits_str);
            return EXIT_FAILURE;
        }
        const uint32_t n_bits{*bits_parsed};
        const int64_t version_arg{args.GetIntArg("-blockversion", DEFAULT_VERSION)};
        const int64_t nonce_arg{args.GetIntArg("-startnonce", 0)};
        if (nonce_arg < 0 || nonce_arg > std::numeric_limits<uint32_t>::max()) {
            tfm::format(std::cerr, "Error: -startnonce must be a 32-bit value\n");
            return EXIT_FAILURE;
        }
        const auto start_nonce{static_cast<uint32_t>(nonce_arg)};
        const int64_t threads_arg{args.GetIntArg("-threads", std::max(1u, std::thread::hardware_concurrency()))};
        const int n_threads{static_cast<int>(std::clamp<int64_t>(threads_arg, 1, 1024))};
        const int64_t max_attempts_arg{args.GetIntArg("-maxattempts", DEFAULT_MAX_ATTEMPTS)};
        const uint64_t max_attempts{max_attempts_arg <= 0 ? DEFAULT_MAX_ATTEMPTS : static_cast<uint64_t>(max_attempts_arg)};
        const bool quiet{args.GetBoolArg("-quiet", false)};
        const std::string chain{ChainTypeToString(chain_type)};

        // The genesis is the origin of MetalDAG time and has no predecessor to be exempt against.
        params.metaldagBaseTime = n_time;
        params.hashGenesisBlock.SetNull();
        if (!DeriveTarget(n_bits, params.powLimit)) {
            tfm::format(std::cerr, "Error: nBits %08x is not a valid target under the %s powLimit %s\n", n_bits, chain, params.powLimit.GetHex());
            return EXIT_FAILURE;
        }
        const metaldag::EpochSizing sizing{metaldag::GetEpochSizing(n_time, params)};
        if (sizing.cache_size > metaldag::METALDAG_MAX_CACHE_BYTES) {
            tfm::format(std::cerr, "Error: MetalDAG cache %d bytes exceeds the node's ceiling\n", sizing.cache_size);
            return EXIT_FAILURE;
        }

        CBlock block{charter::CreateGenesisBlock(message, n_time, start_nonce, n_bits, static_cast<int32_t>(version_arg))};
        {
            // The node runs CheckBlock on the genesis at startup: refuse a coinbase it would reject (bad-cb-length).
            TxValidationState tx_state;
            if (!CheckTransaction(*block.vtx[0], tx_state, /*permit_v2_outputs=*/true)) { // the genesis coinbase is exempt from the output rule on every chain
                tfm::format(std::cerr, "Error: the genesis coinbase is invalid (%s): scriptSig is %d bytes, the limit is 100; shorten -message (%d characters)\n",
                            tx_state.GetRejectReason(), block.vtx[0]->vin[0].scriptSig.size(), message.size());
                return EXIT_FAILURE;
            }
        }
        if (!quiet) {
            tfm::format(std::cerr, "xcoin-genesis: %s params, nTime %u (%s), nBits %08x, version %d\n", chain, n_time, FormatISO8601DateTime(n_time), n_bits, block.nVersion);
            tfm::format(std::cerr, "  message   : %s\n", message);
            tfm::format(std::cerr, "  merkle    : %s\n", block.hashMerkleRoot.GetHex());
            tfm::format(std::cerr, "  MetalDAG  : epoch %d, DAG %d bytes, verification cache %d bytes (metaldagBaseTime = nTime)\n", sizing.epoch, sizing.full_size, sizing.cache_size);
        }

        // Build the verification cache once, on this thread, so it is not counted as mining time.
        const auto cache_start{std::chrono::steady_clock::now()};
        const uint256 first_hash{metaldag::PoWHash(block, params)};
        const double cache_seconds{std::chrono::duration<double>(std::chrono::steady_clock::now() - cache_start).count()};
        if (!quiet) tfm::format(std::cerr, "  cache built in %.2f s\n", cache_seconds);

        if (args.GetBoolArg("-verify", false)) {
            const bool ok{CheckProofOfWorkImpl(first_hash, n_bits, params)};
            tfm::format(std::cout, "nonce %u: MetalDAG PoW hash %s %s the target\n", block.nNonce, first_hash.GetHex(), ok ? "meets" : "does NOT meet");
            if (!ok) return EXIT_FAILURE;
            PrintPasteBlock(block, message, params, chain);
            return EXIT_SUCCESS;
        }

        // Mine.
        MiningState state;
        const uint64_t budget_per_thread{(max_attempts + n_threads - 1) / n_threads};
        std::vector<std::thread> workers;
        workers.reserve(n_threads);
        const auto mine_start{std::chrono::steady_clock::now()};
        for (int i = 0; i < n_threads; ++i) {
            const uint64_t first{static_cast<uint64_t>(start_nonce) + static_cast<uint64_t>(i)};
            if (first > std::numeric_limits<uint32_t>::max()) break;
            workers.emplace_back(MineTask, CBlockHeader{block}, std::cref(params), static_cast<uint32_t>(first), static_cast<uint32_t>(n_threads), budget_per_thread, std::ref(state));
        }
        const double expected_attempts{std::pow(2.0, 256) / (DeriveTarget(n_bits, params.powLimit)->getdouble() + 1.0)};
        if (!quiet) tfm::format(std::cerr, "  mining with %d threads from nonce %u, at most %d hashes (expected ~%.0f at this target)\n", workers.size(), start_nonce, max_attempts, expected_attempts);

        // Progress every 10 s until every worker returns. The joiner stamps the
        // finish time so the rate excludes this loop's poll interval.
        std::chrono::steady_clock::time_point mine_end{};
        {
            std::atomic<bool> joined{false};
            std::thread joiner{[&] {
                for (auto& t : workers) t.join();
                mine_end = std::chrono::steady_clock::now();
                joined.store(true);
            }};
            auto next_report{mine_start + std::chrono::seconds{10}};
            while (!joined.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds{250});
                const auto now{std::chrono::steady_clock::now()};
                if (quiet || now < next_report) continue;
                next_report += std::chrono::seconds{10};
                const double elapsed{std::chrono::duration<double>(now - mine_start).count()};
                const uint64_t attempts{state.attempts.load(std::memory_order_relaxed)};
                tfm::format(std::cerr, "  %d hashes in %.0f s: %.1f H/s (%.0f%% of the expected work)\n", attempts, elapsed, attempts / elapsed, 100.0 * attempts / expected_attempts);
            }
            joiner.join();
        }
        const double elapsed{std::chrono::duration<double>(mine_end - mine_start).count()};
        const uint64_t attempts{state.attempts.load()};
        const double rate{elapsed > 0 ? attempts / elapsed : 0.0};

        if (!state.found.load()) {
            tfm::format(std::cerr, "xcoin-genesis: no nonce met the target within %d hashes (%.1f s, %.1f H/s on %d threads). Raise -maxattempts, change -time or -startnonce, and retry.\n", attempts, elapsed, rate, workers.size());
            return EXIT_FAILURE;
        }
        block.nNonce = state.winning_nonce.load();

        // Verify the result the way the node will, and record the rate.
        const CBlockHeader header{block};
        const uint256 pow_hash{metaldag::PoWHash(header, params)};
        if (!CheckProofOfWorkImpl(pow_hash, n_bits, params)) {
            tfm::format(std::cerr, "xcoin-genesis: internal error: winning nonce %u fails re-verification\n", block.nNonce);
            return EXIT_FAILURE;
        }
        tfm::format(std::cout, "xcoin-genesis: nonce %u found after %d hashes in %.1f s: %.1f hashes/s on %d threads (%s params)\n", block.nNonce, attempts, elapsed, rate, workers.size(), chain);
        // The node's CheckProofOfWork(header) adds a wall-clock gate (nTime <= now + 2 x MAX_FUTURE_BLOCK_TIME).
        if (static_cast<int64_t>(header.nTime) <= GetTime() + 2 * MAX_FUTURE_BLOCK_TIME) {
            tfm::format(std::cout, "node CheckProofOfWork(header): %s\n", CheckProofOfWork(header, n_bits, params) ? "OK" : "FAILED");
        } else {
            tfm::format(std::cout, "node CheckProofOfWork(header): deferred (nTime is more than %d s ahead of this clock; the PoW hash itself is verified above)\n", 2 * MAX_FUTURE_BLOCK_TIME);
        }
        PrintPasteBlock(block, message, params, chain);
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "xcoin-genesis");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "xcoin-genesis");
        return EXIT_FAILURE;
    }
}
