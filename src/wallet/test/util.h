// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_UTIL_H
#define BITCOIN_WALLET_TEST_UTIL_H

#include <addresstype.h>
#include <script/script.h>
#include <wallet/db.h>
#include <wallet/scriptpubkeyman.h>

#include <memory>

class ArgsManager;
class CChain;
class CKey;
enum class OutputType;
namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;
class WalletDatabase;
struct WalletContext;

static const DatabaseFormat DATABASE_FORMATS[] = {
       DatabaseFormat::SQLITE,
};

// xCoin: an unspendable REGTEST address. It is witness v3 with the all-zero
// program (no leaf hashes to zero, so nothing can ever spend it); a Bitcoin
// bcrt1q... string does not even decode on this chain, so the old constant
// made every caller pass CNoDestination. Mirrors ADDRESS_UNSPENDABLE in
// test/functional/test_framework/address.py.
const std::string ADDRESS_UNSPENDABLE = "nxrt1rqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn3x836";

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key);

/** The post-quantum stand-in for TestChain100Setup::coinbaseKey in the wallet tests.
 *  TestPQCoinbaseDescriptor() is `pq(<fixed tprv>/0)`: an ML-DSA-65 key (witness v2,
 *  REGENESIS.md section 4) derived from a fixed BIP32 root, so any number of wallets
 *  can import it (AddTestPQCoinbaseDescriptor) and each owns, and can spend, every
 *  coinbase mined to TestPQCoinbaseScript(). The shared raw test key of
 *  test/util/pq.h cannot play this role: the wallet keeps only BIP32 roots and
 *  derives its post-quantum keys from them (DerivedXcoinKeyProvider), so a raw
 *  ML-DSA secret has nowhere to live in a wallet. Regtest only (the descriptor
 *  carries the chain's extended-key prefix). */
std::string TestPQCoinbaseDescriptor();
CScript TestPQCoinbaseScript();
void AddTestPQCoinbaseDescriptor(CWallet& wallet);
/** A descriptor wallet with the chain's default post-quantum script managers, the
 *  test coinbase descriptor and a rescan of `cchain`; the keypool is kept small
 *  because every witness v3 address costs an SLH-DSA key generation. */
std::unique_ptr<CWallet> CreateSyncedPQWallet(interfaces::Chain& chain, CChain& cchain);

std::shared_ptr<CWallet> TestCreateWallet(WalletContext& context);
std::shared_ptr<CWallet> TestCreateWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags);
std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context);
std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context);
void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet);

// Creates a copy of the provided database
std::unique_ptr<WalletDatabase> DuplicateMockDatabase(WalletDatabase& database);

/** Returns a new encoded destination from the wallet (hardcoded to BECH32) */
std::string getnewaddress(CWallet& w);
/** Returns a new destination, of an specific type, from the wallet */
CTxDestination getNewDestination(CWallet& w, OutputType output_type);

using MockableData = std::map<SerializeData, SerializeData, std::less<>>;

class MockableCursor: public DatabaseCursor
{
public:
    MockableData::const_iterator m_cursor;
    MockableData::const_iterator m_cursor_end;
    bool m_pass;

    explicit MockableCursor(const MockableData& records, bool pass) : m_cursor(records.begin()), m_cursor_end(records.end()), m_pass(pass) {}
    MockableCursor(const MockableData& records, bool pass, std::span<const std::byte> prefix);
    ~MockableCursor() = default;

    Status Next(DataStream& key, DataStream& value) override;
};

class MockableBatch : public DatabaseBatch
{
private:
    MockableData& m_records;
    bool m_pass;

    bool ReadKey(DataStream&& key, DataStream& value) override;
    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite=true) override;
    bool EraseKey(DataStream&& key) override;
    bool HasKey(DataStream&& key) override;
    bool ErasePrefix(std::span<const std::byte> prefix) override;

public:
    explicit MockableBatch(MockableData& records, bool pass) : m_records(records), m_pass(pass) {}
    ~MockableBatch() = default;

    void Close() override {}

    std::unique_ptr<DatabaseCursor> GetNewCursor() override
    {
        return std::make_unique<MockableCursor>(m_records, m_pass);
    }
    std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) override {
        return std::make_unique<MockableCursor>(m_records, m_pass, prefix);
    }
    bool TxnBegin() override { return m_pass; }
    bool TxnCommit() override { return m_pass; }
    bool TxnAbort() override { return m_pass; }
    bool HasActiveTxn() override { return false; }
};

/** A WalletDatabase whose contents and return values can be modified as needed for testing
 **/
class MockableDatabase : public WalletDatabase
{
public:
    MockableData m_records;
    bool m_pass{true};

    MockableDatabase(MockableData records = {}) : WalletDatabase(), m_records(records) {}
    ~MockableDatabase() = default;

    void Open() override {}

    bool Rewrite() override { return m_pass; }
    bool Backup(const std::string& strDest) const override { return m_pass; }
    void Close() override {}

    std::string Filename() override { return "mockable"; }
    std::vector<fs::path> Files() override { return {}; }
    std::string Format() override { return "mock"; }
    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<MockableBatch>(m_records, m_pass); }
};

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase(MockableData records = {});
MockableDatabase& GetMockableDatabase(CWallet& wallet);

DescriptorScriptPubKeyMan* CreateDescriptor(CWallet& keystore, const std::string& desc_str, bool success);
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_UTIL_H
