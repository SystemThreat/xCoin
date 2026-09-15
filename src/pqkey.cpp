// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>

#include <hash.h>
#include <random.h>

#include <cstring>

// PQClean ML-DSA-65 C API
extern "C" {
#include <pqcrypto/ml-dsa-65/api.h>
}

// Verify our constants match PQClean's
static_assert(PQ_PUBKEY_SIZE == PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
              "PQ_PUBKEY_SIZE mismatch with PQClean");
static_assert(PQ_SECRETKEY_SIZE == PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
              "PQ_SECRETKEY_SIZE mismatch with PQClean");
static_assert(PQ_SIGNATURE_SIZE == PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
              "PQ_SIGNATURE_SIZE mismatch with PQClean");


// ── CPQPubKey ────────────────────────────────────────────────────────────────

bool CPQPubKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const
{
    if (!m_valid) return false;
    if (vchSig.empty() || vchSig.size() > PQ_SIGNATURE_SIZE) return false;

    // ML-DSA-65 verifies messages, not hashes. We pass the 32-byte hash as the message.
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
        vchSig.data(), vchSig.size(),
        hash.data(), hash.size(),
        m_data.data()
    ) == 0;
}

bool CPQPubKey::VerifyMessage(std::span<const unsigned char> msg,
                              std::span<const unsigned char> sig) const
{
    if (!m_valid) return false;
    if (sig.empty() || sig.size() > PQ_SIGNATURE_SIZE) return false;

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
        sig.data(), sig.size(),
        msg.data(), msg.size(),
        m_data.data()
    ) == 0;
}


// ── CPQKey ───────────────────────────────────────────────────────────────────

CPQPubKey CPQKey::MakeNewKey()
{
    MakeKeyData();
    m_seed.reset();

    std::array<unsigned char, PQ_PUBKEY_SIZE> pk;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk.data(), m_keydata->data());
    if (ret != 0) {
        ClearKeyData();
        return CPQPubKey();
    }

    return CPQPubKey(pk.data(), pk.data() + pk.size());
}

CPQPubKey CPQKey::MakeKeyFromSeed(std::span<const unsigned char> seed32)
{
    if (seed32.size() != 32) {
        ClearKeyData();
        return CPQPubKey();
    }

    MakeKeyData();

    std::array<unsigned char, PQ_PUBKEY_SIZE> pk;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
        pk.data(), m_keydata->data(), seed32.data());
    if (ret != 0) {
        ClearKeyData();
        return CPQPubKey();
    }
    // Keep the seed: it is the compact private form of the key (pq() descriptors).
    if (!m_seed) m_seed = make_secure_unique<SeedType>();
    std::memcpy(m_seed->data(), seed32.data(), m_seed->size());

    return CPQPubKey(pk.data(), pk.data() + pk.size());
}

CPQPubKey CPQKey::GetPubKey() const
{
    if (!IsValid()) return CPQPubKey();

    // ML-DSA-65 secret keys store (rho, K, tr, t0, s1, s2). The public key is
    // (rho, t1) with t1 = HighBits(A*s1 + s2). Recompute it from the secret key.
    std::array<unsigned char, PQ_PUBKEY_SIZE> pk;
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_sk_to_pk(pk.data(), m_keydata->data()) != 0) {
        return CPQPubKey();
    }
    return CPQPubKey(pk.data(), pk.data() + pk.size());
}


bool CPQKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    if (!IsValid()) return false;

    vchSig.resize(PQ_SIGNATURE_SIZE);
    size_t siglen = 0;

    // ML-DSA-65 signs messages directly. We pass the 32-byte hash as the message.
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
        vchSig.data(), &siglen,
        hash.data(), hash.size(),
        m_keydata->data()
    );

    if (ret != 0) {
        vchSig.clear();
        return false;
    }

    vchSig.resize(siglen);
    return true;
}

bool CPQKey::SignMessage(std::span<const unsigned char> msg,
                         std::vector<unsigned char>& vchSig) const
{
    if (!IsValid()) return false;

    vchSig.resize(PQ_SIGNATURE_SIZE);
    size_t siglen = 0;

    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
        vchSig.data(), &siglen,
        msg.data(), msg.size(),
        m_keydata->data()
    );

    if (ret != 0) {
        vchSig.clear();
        return false;
    }

    vchSig.resize(siglen);
    return true;
}

bool CPQKey::VerifyPubKey(const CPQPubKey& pubkey) const
{
    if (!IsValid() || !pubkey.IsValid()) return false;

    // Sign a test message with the secret key, verify with the public key.
    static const unsigned char test_msg[] = "NEX PQ key verification test";
    std::vector<unsigned char> sig;
    sig.resize(PQ_SIGNATURE_SIZE);
    size_t siglen = 0;

    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
        sig.data(), &siglen,
        test_msg, sizeof(test_msg),
        m_keydata->data()
    );
    if (ret != 0) return false;

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
        sig.data(), siglen,
        test_msg, sizeof(test_msg),
        pubkey.data()
    ) == 0;
}


// ── Free functions ───────────────────────────────────────────────────────────

CPQKey GenerateRandomPQKey() noexcept
{
    CPQKey key;
    key.MakeNewKey();
    return key;
}
