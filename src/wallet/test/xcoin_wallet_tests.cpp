// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stage B3 (contrib/regenesis/REGENESIS.md section 4): the built-in wallet on the
// post-quantum chain. Default witness v3 (pqtr) addresses, the legacy v2 type,
// address-reuse refusal, receiving and spending v3 and v2 coins, and PSBT signing.
// A witness v2 address is handed out, and paid, only where the node relays and
// mines new v2 outputs: regtest with -permitv2outputs=1 (the harness passes it,
// setup_common.cpp; audit finding T9). The legacy sweep tooling (sweepv2) is gone
// (founder decision 5, 2026-09-15): no chain carries coins any more.

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/levy.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/solver.h>
#include <script/xcoin_v3.h>
#include <slhkey.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace wallet {
namespace {

std::unique_ptr<CWallet> MakeDescriptorWallet(interfaces::Chain& chain)
{
    auto wallet = std::make_unique<CWallet>(&chain, "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();
    return wallet;
}

CTxDestination NewDest(CWallet& wallet, OutputType type, const std::string& label = "")
{
    auto dest = wallet.GetNewDestination(type, label);
    BOOST_REQUIRE_MESSAGE(dest, util::ErrorString(dest).original);
    return *dest;
}

std::vector<size_t> WitnessSizes(const CTransaction& tx, size_t in)
{
    std::vector<size_t> sizes;
    for (const auto& item : tx.vin[in].scriptWitness.stack) sizes.push_back(item.size());
    return sizes;
}

/** Verify input `in` of `tx` against `spent` under the standard flags. */
void CheckInput(const CTransaction& tx, size_t in, const std::vector<CTxOut>& spent)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent});
    const TransactionSignatureChecker checker(&tx, in, spent[in].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[in].scriptSig, spent[in].scriptPubKey, &tx.vin[in].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err), ScriptErrorString(err));
}

/** A regtest chain with the mainnet 5 bp settlement levy (REGENESIS.md section 6):
 *  the harness disables it unless a test asks (setup_common.cpp), and the spends
 *  below are what a user's wallet builds under the real rule. */
struct LevyChain100Setup : public TestChain100Setup {
    LevyChain100Setup() : TestChain100Setup{ChainType::REGTEST, TestOpts{.extra_args = {"-levybp=5"}}} {}
};

/** A regtest chain whose node runs the default relay policy: it does not relay or mine
 *  transactions creating new legacy witness v2 outputs. The harness passes
 *  -permitv2outputs=1 to every regtest fixture (setup_common.cpp); the later argument wins. */
struct NoV2PolicyChain100Setup : public TestChain100Setup {
    NoV2PolicyChain100Setup() : TestChain100Setup{ChainType::REGTEST, TestOpts{.extra_args = {"-permitv2outputs=0"}}} {}
};
} // namespace

BOOST_AUTO_TEST_SUITE(xcoin_wallet_tests)

// A new wallet creates descriptors for the post-quantum types only. The chain refuses
// every other script type at consensus, so an ECDSA descriptor could never hold coins
// and would only confuse a backup. pqtr() is created everywhere; pq() (v2) only where the
// chain still accepts new v2 outputs (regtest), never on mainnet or testnet A (audit
// finding 12). This fixture runs on mainnet parameters.
BOOST_FIXTURE_TEST_CASE(only_post_quantum_descriptors_by_default, TestingSetup)
{
    auto wallet = MakeDescriptorWallet(*m_node.chain);
    LOCK(wallet->cs_wallet);
    BOOST_REQUIRE(!Params().GetConsensus().permitV2Outputs);
    for (bool internal : {false, true}) {
        BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::XCOIN_V3, internal));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::XCOIN_V2, internal));
        for (OutputType t : {OutputType::LEGACY, OutputType::P2SH_SEGWIT, OutputType::BECH32, OutputType::BECH32M}) {
            BOOST_CHECK(!wallet->GetScriptPubKeyMan(t, internal));
        }
    }
    BOOST_CHECK_EQUAL(wallet->GetActiveScriptPubKeyMans().size(), 2U);
    BOOST_CHECK(wallet->GetNewDestination(OutputType::XCOIN_V3, ""));
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::XCOIN_V2, "")); // refused, not silently unpayable
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::LEGACY, ""));

    // The inherited tests ask for every type explicitly; that path still works.
    auto legacy = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(legacy->cs_wallet);
    legacy->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    legacy->SetupDescriptorScriptPubKeyMans(OUTPUT_TYPES);
    // ... minus the v2 pair, which this chain never creates (mainnet parameters here).
    BOOST_CHECK_EQUAL(legacy->GetActiveScriptPubKeyMans().size(), 2 * (OUTPUT_TYPES.size() - 1));
}

BOOST_FIXTURE_TEST_CASE(default_v3_addresses_and_reuse_refusal, TestingSetup)
{
    auto wallet = MakeDescriptorWallet(*m_node.chain);
    BOOST_CHECK(wallet->m_default_address_type == OutputType::XCOIN_V3);
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::XCOIN_V3, /*internal=*/false));
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::XCOIN_V3, /*internal=*/true));
    BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::XCOIN_V2, /*internal=*/false)); // mainnet: no v2 (audit finding 12)

    // The default type is the post-quantum script tree; mainnet addresses read xpa1r...
    const CTxDestination d3 = NewDest(*wallet, wallet->m_default_address_type);
    BOOST_CHECK(std::holds_alternative<WitnessV3PQ>(d3));
    BOOST_CHECK(EncodeDestination(d3).rfind("xpa1r", 0) == 0);
    BOOST_CHECK(GetScriptForDestination(d3).IsPayToXcoinV3());
    // A legacy v2 address is refused on this chain: nobody could pay it.
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::XCOIN_V2, ""));
    // The wallet knows the tree behind a v3 address.
    {
        LOCK(wallet->cs_wallet);
        auto provider = wallet->GetSolvingProvider(GetScriptForDestination(d3));
        BOOST_REQUIRE(provider);
        XcoinV3SpendData spenddata;
        BOOST_REQUIRE(provider->GetXcoinV3SpendData(uint256{std::get<WitnessV3PQ>(d3)}, spenddata));
        BOOST_CHECK_EQUAL(spenddata.scripts.size(), 2U);
        bool has_pq{false}, has_slh{false};
        for (const auto& [key, _] : spenddata.scripts) {
            has_pq |= key.second == XCOIN_LEAF_PQ;
            has_slh |= key.second == XCOIN_LEAF_SLH;
        }
        BOOST_CHECK(has_pq && has_slh);
        const auto desc = InferDescriptor(GetScriptForDestination(d3), *provider);
        // Siblings are inferred in hash order, so either leaf may come first.
        BOOST_CHECK_MESSAGE(desc->ToString().rfind("pqtr({", 0) == 0, desc->ToString());
        BOOST_CHECK(desc->ToString().find("pq(") != std::string::npos && desc->ToString().find("slh(") != std::string::npos);
        BOOST_CHECK(desc->IsSolvable());
        FlatSigningProvider reparsed_keys, reparsed_out;
        std::string reparse_error;
        auto reparsed = Parse(desc->ToString(), reparsed_keys, reparse_error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(reparsed.size() == 1, reparse_error);
        std::vector<CScript> reparsed_scripts;
        BOOST_CHECK(reparsed[0]->Expand(0, reparsed_keys, reparsed_scripts, reparsed_out));
        BOOST_CHECK(reparsed_scripts.at(0) == GetScriptForDestination(d3));
    }

    // Never the same v3 address twice: many addresses, all distinct ...
    std::set<CTxDestination> handed_out{d3};
    for (int i = 0; i < 45; ++i) {
        const CTxDestination d = NewDest(*wallet, OutputType::XCOIN_V3);
        BOOST_CHECK(std::holds_alternative<WitnessV3PQ>(d));
        BOOST_CHECK(handed_out.insert(d).second);
    }
    // ... change addresses are distinct from them and from each other ...
    for (int i = 0; i < 5; ++i) {
        auto change = wallet->GetNewChangeDestination(OutputType::XCOIN_V3);
        BOOST_REQUIRE(change);
        BOOST_CHECK(std::holds_alternative<WitnessV3PQ>(*change));
        BOOST_CHECK(handed_out.insert(*change).second);
    }
    // ... a reserved-then-returned v3 address is burned, not handed out again ...
    {
        ReserveDestination reserved(wallet.get(), OutputType::XCOIN_V3);
        auto r = reserved.GetReservedDestination(/*internal=*/false);
        BOOST_REQUIRE(r);
        const CTxDestination returned = *r;
        reserved.ReturnDestination();
        const CTxDestination next = NewDest(*wallet, OutputType::XCOIN_V3);
        BOOST_CHECK(!(next == returned));
        BOOST_CHECK(handed_out.insert(next).second);
    }
    // ... and even if the descriptor's index is rewound (as a corrupted or restored wallet
    // might do), the wallet refuses to hand out an address it already gave out.
    {
        auto* spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::XCOIN_V3, /*internal=*/false));
        BOOST_REQUIRE(spkm);
        WalletDescriptor rewound = WITH_LOCK(spkm->cs_desc_man, return spkm->GetWalletDescriptor());
        BOOST_CHECK_GT(rewound.next_index, 0);
        rewound.next_index = 0;
        BOOST_REQUIRE(spkm->UpdateWalletDescriptor(rewound));
        const CTxDestination fresh = NewDest(*wallet, OutputType::XCOIN_V3);
        BOOST_CHECK(handed_out.insert(fresh).second);
        BOOST_CHECK(!(fresh == d3));
    }
}

BOOST_FIXTURE_TEST_CASE(spend_v3_spend_v2_and_psbt, LevyChain100Setup)
{
    // Every fee below must reach the settlement levy on what the transaction moves.
    const Consensus::SettlementLevyRule levy{m_node.chainman->GetConsensus().SettlementLevyAt(0)};
    BOOST_REQUIRE_EQUAL(levy.bp, 5);
    const auto levy_owed = [&](const CTransactionRef& tx) { return Consensus::SettlementLevy(tx->GetValueOut(), levy); };
    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const auto tip_info = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return std::make_pair(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(tip_info.first, tip_info.second);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    const CTxDestination dest3 = NewDest(*wallet, OutputType::XCOIN_V3, "receive v3");
    const CTxDestination dest2 = NewDest(*wallet, OutputType::XCOIN_V2, "receive v2");

    // Two coinbases: one to the v3 address, one to the legacy v2 address; then maturity.
    const CBlock block3 = CreateAndProcessBlock({}, GetScriptForDestination(dest3));
    const CBlock block2 = CreateAndProcessBlock({}, GetScriptForDestination(dest2));
    mineBlocks(COINBASE_MATURITY);
    const CTransactionRef cb3 = block3.vtx[0];
    const CTransactionRef cb2 = block2.vtx[0];
    {
        // The wallet is not attached to validation notifications: move its tip and rescan.
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    }
    {
        WalletRescanReserver reserver(*wallet);
        reserver.reserve();
        const uint256 genesis = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Genesis()->GetBlockHash());
        const CWallet::ScanResult result = wallet->ScanForWalletTransactions(genesis, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_REQUIRE(result.status == CWallet::ScanResult::SUCCESS);
    }
    {
        LOCK(wallet->cs_wallet);
        const Balance bal = GetBalance(*wallet);
        BOOST_CHECK_EQUAL(bal.m_mine_trusted, cb3->vout[0].nValue + cb2->vout[0].nValue);
        BOOST_CHECK(wallet->IsMine(cb3->vout[0]));
        BOOST_CHECK(wallet->IsMine(cb2->vout[0]));
    }

    // Spend the v3 coin: [pubkey, sig, leaf script, control] through the ML-DSA leaf, change to v3.
    const CTxDestination payee = NewDest(*wallet, OutputType::XCOIN_V3, "payee");
    CTransactionRef spend3;
    {
        CCoinControl cc;
        cc.m_feerate = CFeeRate(1000);
        cc.fOverrideFeeRate = true;
        cc.m_allow_other_inputs = false;
        cc.Select(COutPoint(cb3->GetHash(), 0));
        auto res = CreateTransaction(*wallet, {CRecipient{payee, 10 * COIN, /*subtract_fee=*/false}}, /*change_pos=*/std::nullopt, cc);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        spend3 = res->tx;
        BOOST_REQUIRE_EQUAL(spend3->vin.size(), 1U);
        BOOST_CHECK(WitnessSizes(*spend3, 0) == std::vector<size_t>({PQ_PUBKEY_SIZE, PQ_SIGNATURE_SIZE, 34, 65}));
        CheckInput(*spend3, 0, {cb3->vout[0]});
        BOOST_CHECK_GT(res->fee, 0);
        BOOST_CHECK_GE(res->fee, levy_owed(spend3));
        BOOST_REQUIRE(res->change_pos);
        BOOST_CHECK(spend3->vout[*res->change_pos].scriptPubKey.IsPayToXcoinV3());
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsMine(spend3->vout[*res->change_pos]));
        // Standard: a v3 spend with v3 outputs relays under the default policy.
        std::string reason;
        BOOST_CHECK_MESSAGE(IsStandardTx(*spend3, MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, /*permit_v2_outputs=*/false, CFeeRate{DUST_RELAY_TX_FEE}, reason), reason);
    }
    // Spend the v2 coin: [sig || hashtype, pubkey].
    {
        CCoinControl cc;
        cc.m_feerate = CFeeRate(1000);
        cc.fOverrideFeeRate = true;
        cc.m_allow_other_inputs = false;
        cc.Select(COutPoint(cb2->GetHash(), 0));
        auto res = CreateTransaction(*wallet, {CRecipient{payee, 10 * COIN, /*subtract_fee=*/false}}, /*change_pos=*/std::nullopt, cc);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        BOOST_CHECK(WitnessSizes(*res->tx, 0) == std::vector<size_t>({PQ_SIGNATURE_SIZE + 1, PQ_PUBKEY_SIZE}));
        CheckInput(*res->tx, 0, {cb2->vout[0]});
        BOOST_CHECK_GE(res->fee, levy_owed(res->tx));
    }
    // PSBT: an unsigned v3 spend is signed and finalized by the wallet (SIGHASH_DEFAULT).
    {
        CCoinControl cc;
        cc.m_feerate = CFeeRate(1000);
        cc.fOverrideFeeRate = true;
        cc.m_allow_other_inputs = false;
        cc.Select(COutPoint(cb3->GetHash(), 0));
        auto res = CreateTransaction(*wallet, {CRecipient{payee, 1 * COIN, /*subtract_fee=*/false}}, /*change_pos=*/std::nullopt, cc, /*sign=*/false);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        BOOST_CHECK_GE(res->fee, levy_owed(res->tx));
        BOOST_CHECK(res->tx->vin[0].scriptWitness.IsNull());
        PartiallySignedTransaction psbtx(CMutableTransaction{*res->tx});
        bool complete{false};
        const auto err = wallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false);
        BOOST_CHECK(!err);
        BOOST_CHECK(complete);
        CMutableTransaction final_tx;
        BOOST_REQUIRE(FinalizeAndExtractPSBT(psbtx, final_tx));
        BOOST_CHECK(WitnessSizes(CTransaction{final_tx}, 0) == std::vector<size_t>({PQ_PUBKEY_SIZE, PQ_SIGNATURE_SIZE, 34, 65}));
        CheckInput(CTransaction{final_tx}, 0, {cb3->vout[0]});
    }
}

// Audit finding T9: on regtest the chain permits new witness v2 outputs, but the node
// relays and mines them only when started with -permitv2outputs=1. Without the flag the
// wallet refuses to hand out a v2 address (receive and change) and to pay one, naming the
// flag; the change type falls back to v3; and a v2 coin the wallet already holds stays
// recognised and spendable.
BOOST_FIXTURE_TEST_CASE(v2_addresses_only_where_the_node_permits_them, NoV2PolicyChain100Setup)
{
    BOOST_REQUIRE(Params().GetConsensus().permitV2Outputs);
    BOOST_CHECK(!m_node.chain->permitV2Outputs());
    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Height()),
                                      WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    BOOST_CHECK(!wallet->PermitsV2Outputs());
    const std::string flag{"-permitv2outputs=1"};
    BOOST_CHECK(CWallet::V2OutputsNotPermittedError().original.find(flag) != std::string::npos);

    // The v2 descriptor still exists (the chain permits v2 outputs, and a wallet must
    // recognise v2 coins it received under the flag), but no v2 address is handed out.
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::XCOIN_V2, /*internal=*/false));
    BOOST_CHECK(wallet->GetNewDestination(OutputType::XCOIN_V3, ""));
    {
        auto refused = wallet->GetNewDestination(OutputType::XCOIN_V2, "");
        BOOST_REQUIRE(!refused);
        BOOST_CHECK_MESSAGE(util::ErrorString(refused).original.find(flag) != std::string::npos, util::ErrorString(refused).original);
        auto refused_change = wallet->GetNewChangeDestination(OutputType::XCOIN_V2);
        BOOST_REQUIRE(!refused_change);
        BOOST_CHECK(util::ErrorString(refused_change).original.find(flag) != std::string::npos);
        BOOST_CHECK(wallet->TransactionChangeType(OutputType::XCOIN_V2, {}) == OutputType::XCOIN_V3);
    }

    // A v2 coin received anyway (a descriptor-level address, as a wallet created under the
    // flag would have handed out): the wallet sees it and spends it to a v3 payee ...
    auto* spkm2 = wallet->GetScriptPubKeyMan(OutputType::XCOIN_V2, /*internal=*/false);
    const CTxDestination dest2 = *Assert(spkm2->GetNewDestination(OutputType::XCOIN_V2));
    BOOST_REQUIRE(std::holds_alternative<WitnessV2PQ>(dest2));
    const CBlock block2 = CreateAndProcessBlock({}, GetScriptForDestination(dest2));
    mineBlocks(COINBASE_MATURITY);
    const CTransactionRef cb2 = block2.vtx[0];
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    }
    {
        WalletRescanReserver reserver(*wallet);
        reserver.reserve();
        const uint256 genesis = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Genesis()->GetBlockHash());
        const CWallet::ScanResult result = wallet->ScanForWalletTransactions(genesis, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_REQUIRE(result.status == CWallet::ScanResult::SUCCESS);
    }
    const CTxDestination payee = NewDest(*wallet, OutputType::XCOIN_V3, "payee");
    CCoinControl cc;
    cc.m_feerate = CFeeRate(1000);
    cc.fOverrideFeeRate = true;
    cc.m_allow_other_inputs = false;
    cc.Select(COutPoint(cb2->GetHash(), 0));
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsMine(cb2->vout[0]));
        BOOST_CHECK_EQUAL(GetBalance(*wallet).m_mine_trusted, cb2->vout[0].nValue);
    }
    {
        auto res = CreateTransaction(*wallet, {CRecipient{payee, 10 * COIN, /*subtract_fee=*/false}}, /*change_pos=*/std::nullopt, cc);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        BOOST_CHECK(WitnessSizes(*res->tx, 0) == std::vector<size_t>({PQ_SIGNATURE_SIZE + 1, PQ_PUBKEY_SIZE}));
        CheckInput(*res->tx, 0, {cb2->vout[0]});
        // ... with v3 change, whatever -changetype says ...
        for (const CTxOut& out : res->tx->vout) BOOST_CHECK(out.scriptPubKey.IsPayToXcoinV3());
        std::string reason;
        BOOST_CHECK_MESSAGE(IsStandardTx(*res->tx, MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, /*permit_v2_outputs=*/false, CFeeRate{DUST_RELAY_TX_FEE}, reason), reason);
    }
    // ... but never to a v2 payee, naming the flag; the same when the v2 output is a
    // second recipient next to a v3 one.
    {
        auto res = CreateTransaction(*wallet, {CRecipient{dest2, 10 * COIN, /*subtract_fee=*/false}}, /*change_pos=*/std::nullopt, cc);
        BOOST_REQUIRE(!res);
        BOOST_CHECK_MESSAGE(util::ErrorString(res).original.find(flag) != std::string::npos, util::ErrorString(res).original);
        auto mixed = CreateTransaction(*wallet, {CRecipient{payee, 10 * COIN, false}, CRecipient{dest2, 10 * COIN, false}}, /*change_pos=*/std::nullopt, cc);
        BOOST_REQUIRE(!mixed);
        BOOST_CHECK(util::ErrorString(mixed).original.find(flag) != std::string::npos);
    }
}

// A signing wallet's public descriptors can be imported into a wallet without private keys,
// which then watches the same scripts and hands out the same addresses in the same order.
// pq()/slh() keys have no public derivation, so the export writes the derived public keys out
// as explicit key lists (audit finding W3); the private form stays the ranged xprv descriptor.
BOOST_FIXTURE_TEST_CASE(watch_only_wallet_from_exported_descriptors, TestingSetup)
{
    auto signing = MakeDescriptorWallet(*m_node.chain);
    const CTxDestination first = NewDest(*signing, OutputType::XCOIN_V3, "first");
    const CTxDestination change_first = *signing->GetNewChangeDestination(OutputType::XCOIN_V3);

    auto watch = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(watch->cs_wallet);
        watch->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        watch->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        watch->SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    }
    for (bool internal : {false, true}) {
        LOCK2(signing->cs_wallet, watch->cs_wallet);
        auto* spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(signing->GetScriptPubKeyMan(OutputType::XCOIN_V3, internal));
        BOOST_REQUIRE(spkm);
        LOCK(spkm->cs_desc_man);
        const WalletDescriptor w_desc = spkm->GetWalletDescriptor();
        std::string exported, normalized, priv;
        BOOST_REQUIRE(spkm->GetExportDescriptorString(exported));
        BOOST_REQUIRE(spkm->GetDescriptorString(normalized, /*priv=*/false));
        BOOST_REQUIRE(spkm->GetDescriptorString(priv, /*priv=*/true));
        BOOST_CHECK(exported != normalized); // the normalized form keeps the (unexpandable) xpub and range
        BOOST_CHECK(normalized.find("/*") != std::string::npos && normalized.find(',') == normalized.rfind(','));
        BOOST_CHECK(exported.find("/*") == std::string::npos && exported.find(',') != exported.rfind(','));
        BOOST_CHECK(priv != normalized && priv != exported); // the ranged xprv form
        BOOST_CHECK(priv.find("/*") != std::string::npos && priv.find(',') == priv.rfind(','));
        BOOST_CHECK(exported.rfind("pqtr({pq(keys(", 0) == 0);

        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(exported, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(parsed.size() == 1, error);
        BOOST_CHECK(keys.keys.empty() && keys.pq_keys.empty() && keys.slh_keys.empty());
        BOOST_CHECK(parsed[0]->IsRange());
        BOOST_REQUIRE(parsed[0]->RangeSize());
        BOOST_CHECK_EQUAL(*parsed[0]->RangeSize(), w_desc.range_end); // one key per cached position
        WalletDescriptor imported(std::move(parsed[0]), w_desc.creation_time, w_desc.range_start, w_desc.range_end, w_desc.next_index);
        auto res = watch->AddWalletDescriptor(imported, keys, "", internal);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        watch->AddActiveScriptPubKeyMan(res->get().GetID(), OutputType::XCOIN_V3, internal);
        BOOST_CHECK(!res->get().HavePrivateKeys());
        BOOST_CHECK_EQUAL(res->get().GetKeyPoolSize(), w_desc.range_end - w_desc.next_index);
        // Every script the signing wallet watches, the watch-only wallet watches.
        for (const CScript& spk : spkm->GetScriptPubKeys()) BOOST_CHECK(res->get().IsMine(spk));
        BOOST_CHECK_EQUAL(res->get().GetScriptPubKeys().size(), spkm->GetScriptPubKeys().size());
    }
    {
        LOCK(watch->cs_wallet);
        BOOST_CHECK(watch->IsMine(GetScriptForDestination(first)));
        BOOST_CHECK(watch->IsMine(GetScriptForDestination(change_first)));
        BOOST_CHECK(!watch->IsMine(GetScriptForDestination(NewDest(*MakeDescriptorWallet(*m_node.chain), OutputType::XCOIN_V3))));
    }
    // The same next addresses, receive and change, in the same order.
    for (int i = 0; i < 3; ++i) {
        const CTxDestination a = NewDest(*signing, OutputType::XCOIN_V3);
        const CTxDestination b = NewDest(*watch, OutputType::XCOIN_V3);
        BOOST_CHECK(a == b);
        BOOST_CHECK(std::holds_alternative<WitnessV3PQ>(b));
        const auto ca = signing->GetNewChangeDestination(OutputType::XCOIN_V3);
        const auto cb = watch->GetNewChangeDestination(OutputType::XCOIN_V3);
        BOOST_REQUIRE(ca && cb);
        BOOST_CHECK(*ca == *cb);
    }
    // Past the exported keys the watch-only wallet has no more addresses; the signing wallet keeps deriving.
    {
        auto* spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(watch->GetScriptPubKeyMan(OutputType::XCOIN_V3, /*internal=*/false));
        BOOST_REQUIRE(spkm);
        while (spkm->GetKeyPoolSize() > 0) BOOST_REQUIRE(watch->GetNewDestination(OutputType::XCOIN_V3, ""));
        BOOST_CHECK(!watch->GetNewDestination(OutputType::XCOIN_V3, ""));
        BOOST_CHECK(!spkm->CanGetAddresses());
        BOOST_CHECK(signing->GetNewDestination(OutputType::XCOIN_V3, ""));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
