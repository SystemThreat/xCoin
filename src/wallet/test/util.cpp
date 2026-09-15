// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>

#include <chain.h>
#include <key.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <array>
#include <cstddef>
#include <memory>

namespace wallet {
std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key)
{
    auto wallet = std::make_unique<CWallet>(&chain, "", CreateMockableWalletDatabase());
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        // The inherited coin-selection tests exercise ECDSA outputs the chain never sees: every type.
        wallet->SetupDescriptorScriptPubKeyMans(OUTPUT_TYPES);

        FlatSigningProvider provider;
        std::string error;
        auto descs = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
        assert(descs.size() == 1);
        auto& desc = descs.at(0);
        WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
        Assert(wallet->AddWalletDescriptor(w_desc, provider, "", false));
    }
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(cchain.Genesis()->GetBlockHash(), /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    assert(result.status == CWallet::ScanResult::SUCCESS);
    assert(result.last_scanned_block == cchain.Tip()->GetBlockHash());
    assert(*result.last_scanned_height == cchain.Height());
    assert(result.last_failed_block.IsNull());
    return wallet;
}

std::string TestPQCoinbaseDescriptor()
{
    static constexpr std::array<std::byte, 32> seed{
        std::byte{'x'}, std::byte{'c'}, std::byte{'o'}, std::byte{'i'}, std::byte{'n'}, std::byte{'-'}, std::byte{'w'}, std::byte{'a'},
        std::byte{'l'}, std::byte{'l'}, std::byte{'e'}, std::byte{'t'}, std::byte{'-'}, std::byte{'t'}, std::byte{'e'}, std::byte{'s'},
        std::byte{'t'}, std::byte{'-'}, std::byte{'p'}, std::byte{'q'}, std::byte{'-'}, std::byte{'c'}, std::byte{'o'}, std::byte{'i'},
        std::byte{'n'}, std::byte{'b'}, std::byte{'a'}, std::byte{'s'}, std::byte{'e'}, std::byte{'-'}, std::byte{'0'}, std::byte{'1'}};
    CExtKey root;
    root.SetSeed(seed);
    return "pq(" + EncodeExtKey(root) + "/0)";
}

CScript TestPQCoinbaseScript()
{
    FlatSigningProvider keys;
    FlatSigningProvider out;
    std::string error;
    auto descs = Parse(TestPQCoinbaseDescriptor(), keys, error, /*require_checksum=*/false);
    assert(descs.size() == 1);
    std::vector<CScript> scripts;
    const bool ok{descs.at(0)->Expand(0, keys, scripts, out)};
    assert(ok && scripts.size() == 1);
    return scripts.at(0);
}

void AddTestPQCoinbaseDescriptor(CWallet& wallet)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse(TestPQCoinbaseDescriptor(), provider, error, /*require_checksum=*/false);
    assert(descs.size() == 1);
    auto& desc = descs.at(0);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    Assert(wallet.AddWalletDescriptor(w_desc, provider, "", false));
}

std::unique_ptr<CWallet> CreateSyncedPQWallet(interfaces::Chain& chain, CChain& cchain)
{
    auto wallet = std::make_unique<CWallet>(&chain, "", CreateMockableWalletDatabase());
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->m_keypool_size = 5; // a witness v3 address costs an SLH-DSA key generation (~50 ms)
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    AddTestPQCoinbaseDescriptor(*wallet);
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(cchain.Genesis()->GetBlockHash(), /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    assert(result.status == CWallet::ScanResult::SUCCESS);
    assert(result.last_scanned_block == cchain.Tip()->GetBlockHash());
    assert(*result.last_scanned_height == cchain.Height());
    assert(result.last_failed_block.IsNull());
    return wallet;
}

std::shared_ptr<CWallet> TestCreateWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    auto wallet = CWallet::CreateNew(context, "", std::move(database), create_flags, _error, _warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

std::shared_ptr<CWallet> TestCreateWallet(WalletContext& context)
{
    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    return TestCreateWallet(std::move(database), context, options.create_flags);
}


std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CWallet::LoadExisting(context, "", std::move(database), error, warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context)
{
    DatabaseOptions options;
    options.require_existing = true;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    return TestLoadWallet(std::move(database), context);
}

void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Calls SyncWithValidationInterfaceQueue
    wallet->chain().waitForNotificationsIfTipChanged({});
    wallet->m_chain_notifications_handler.reset();
    WaitForDeleteWallet(std::move(wallet));
}

std::unique_ptr<WalletDatabase> DuplicateMockDatabase(WalletDatabase& database)
{
    return std::make_unique<MockableDatabase>(dynamic_cast<MockableDatabase&>(database).m_records);
}

std::string getnewaddress(CWallet& w)
{
    // xCoin: witness v3, the chain's only spendable output type
    // (REGENESIS.md section 4). A BECH32 address cannot be mined or paid here.
    constexpr auto output_type = OutputType::XCOIN_V3;
    return EncodeDestination(getNewDestination(w, output_type));
}

CTxDestination getNewDestination(CWallet& w, OutputType output_type)
{
    return *Assert(w.GetNewDestination(output_type, ""));
}

MockableCursor::MockableCursor(const MockableData& records, bool pass, std::span<const std::byte> prefix)
{
    m_pass = pass;
    std::tie(m_cursor, m_cursor_end) = records.equal_range(BytePrefix{prefix});
}

DatabaseCursor::Status MockableCursor::Next(DataStream& key, DataStream& value)
{
    if (!m_pass) {
        return Status::FAIL;
    }
    if (m_cursor == m_cursor_end) {
        return Status::DONE;
    }
    key.clear();
    value.clear();
    const auto& [key_data, value_data] = *m_cursor;
    key.write(key_data);
    value.write(value_data);
    m_cursor++;
    return Status::MORE;
}

bool MockableBatch::ReadKey(DataStream&& key, DataStream& value)
{
    if (!m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    const auto& it = m_records.find(key_data);
    if (it == m_records.end()) {
        return false;
    }
    value.clear();
    value.write(it->second);
    return true;
}

bool MockableBatch::WriteKey(DataStream&& key, DataStream&& value, bool overwrite)
{
    if (!m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    SerializeData value_data{value.begin(), value.end()};
    auto [it, inserted] = m_records.emplace(key_data, value_data);
    if (!inserted && overwrite) { // Overwrite if requested
        it->second = value_data;
        inserted = true;
    }
    return inserted;
}

bool MockableBatch::EraseKey(DataStream&& key)
{
    if (!m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    m_records.erase(key_data);
    return true;
}

bool MockableBatch::HasKey(DataStream&& key)
{
    if (!m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    return m_records.contains(key_data);
}

bool MockableBatch::ErasePrefix(std::span<const std::byte> prefix)
{
    if (!m_pass) {
        return false;
    }
    auto it = m_records.begin();
    while (it != m_records.end()) {
        auto& key = it->first;
        if (key.size() < prefix.size() || std::search(key.begin(), key.end(), prefix.begin(), prefix.end()) != key.begin()) {
            it++;
            continue;
        }
        it = m_records.erase(it);
    }
    return true;
}

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase(MockableData records)
{
    return std::make_unique<MockableDatabase>(records);
}

MockableDatabase& GetMockableDatabase(CWallet& wallet)
{
    return dynamic_cast<MockableDatabase&>(wallet.GetDatabase());
}

wallet::DescriptorScriptPubKeyMan* CreateDescriptor(CWallet& keystore, const std::string& desc_str, const bool success)
{
    keystore.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(desc_str, keys, error, false);
    Assert(success == (!parsed_descs.empty()));
    if (!success) return nullptr;
    auto& desc = parsed_descs.at(0);

    const int64_t range_start = 0, range_end = 1, next_index = 0, timestamp = 1;

    WalletDescriptor w_desc(std::move(desc), timestamp, range_start, range_end, next_index);

    LOCK(keystore.cs_wallet);
    auto spkm = Assert(keystore.AddWalletDescriptor(w_desc, keys,/*label=*/"", /*internal=*/false));
    return &spkm.value().get();
};
} // namespace wallet
