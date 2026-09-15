// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <slhkey.h>

#include <random.h>
#include <support/cleanse.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

// PQClean sphincs-sha2-128s-simple (clean) with the FIPS 205 FORS bit order;
// see src/pqcrypto/slh-dsa-sha2-128s/PQCLEAN.
extern "C" {
#include <pqcrypto/slh-dsa-sha2-128s/api.h>
}

static_assert(SLH_PUBKEY_SIZE == PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES, "SLH_PUBKEY_SIZE mismatch with PQClean");
static_assert(SLH_SECRETKEY_SIZE == PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES, "SLH_SECRETKEY_SIZE mismatch with PQClean");
static_assert(SLH_SIGNATURE_SIZE == PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES, "SLH_SIGNATURE_SIZE mismatch with PQClean");
static_assert(SLH_SEED_SIZE == PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SEEDBYTES, "SLH_SEED_SIZE mismatch with PQClean");

bool SLHPureMessage(std::vector<unsigned char>& out, std::span<const unsigned char> msg, std::span<const unsigned char> context)
{
    out.clear();
    if (context.size() > SLH_MAX_CONTEXT_SIZE) return false;
    out.reserve(2 + context.size() + msg.size());
    out.push_back(0x00);
    out.push_back(static_cast<unsigned char>(context.size()));
    out.insert(out.end(), context.begin(), context.end());
    out.insert(out.end(), msg.begin(), msg.end());
    return true;
}

bool CSLHPubKey::VerifyInternal(std::span<const unsigned char> msg, std::span<const unsigned char> sig) const
{
    if (!m_valid) return false;
    // Strict encoding: an SLH-DSA-SHA2-128s signature is always exactly SLH_SIGNATURE_SIZE bytes.
    if (sig.size() != SLH_SIGNATURE_SIZE) return false;
    // Never hand PQClean a null pointer for an empty message.
    static const unsigned char empty{0};
    const unsigned char* m{msg.empty() ? &empty : msg.data()};
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig.data(), sig.size(), m, msg.size(), m_data.data()) == 0;
}

bool CSLHPubKey::VerifyMessage(std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> context) const
{
    if (!m_valid) return false;
    if (sig.size() != SLH_SIGNATURE_SIZE) return false;
    std::vector<unsigned char> mprime;
    if (!SLHPureMessage(mprime, msg, context)) return false;
    return VerifyInternal(mprime, sig);
}

bool CSLHPubKey::Verify(const uint256& digest, std::span<const unsigned char> sig) const
{
    return VerifyMessage(std::span<const unsigned char>{digest.begin(), digest.size()}, sig, {});
}

// ── CSLHKey ──────────────────────────────────────────────────────────────────

void CSLHKey::Set(std::span<const unsigned char> sk64)
{
    if (sk64.size() != SLH_SECRETKEY_SIZE) {
        ClearKeyData();
        return;
    }
    MakeKeyData();
    std::memcpy(m_keydata->data(), sk64.data(), SLH_SECRETKEY_SIZE);
}

CSLHPubKey CSLHKey::MakeKeyFromSeed(std::span<const unsigned char> seed48)
{
    if (seed48.size() != SLH_SEED_SIZE) {
        ClearKeyData();
        return CSLHPubKey{};
    }
    MakeKeyData();
    std::array<unsigned char, SLH_PUBKEY_SIZE> pk{};
    if (PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_seed_keypair(pk.data(), m_keydata->data(), seed48.data()) != 0) {
        ClearKeyData();
        return CSLHPubKey{};
    }
    return CSLHPubKey{pk};
}

CSLHPubKey CSLHKey::MakeNewKey()
{
    // GetStrongRandBytes asserts num <= 32 (random.cpp ProcRand: one CSHA512
    // block of output per call), and the SLH-DSA key-generation seed is 48
    // bytes, so it has to be drawn in two calls. Asking for 48 at once aborts
    // the process, including in a release build.
    static_assert(SLH_SEED_SIZE == 48);
    std::array<unsigned char, SLH_SEED_SIZE> seed{};
    GetStrongRandBytes(std::span{seed}.first(32));
    GetStrongRandBytes(std::span{seed}.last(SLH_SEED_SIZE - 32));
    CSLHPubKey pub{MakeKeyFromSeed(seed)};
    memory_cleanse(seed.data(), seed.size());
    return pub;
}

CSLHPubKey CSLHKey::GetPubKey() const
{
    if (!IsValid()) return CSLHPubKey{};
    // sk = SK.seed || SK.prf || PK.seed || PK.root; pk = PK.seed || PK.root.
    return CSLHPubKey{std::span<const unsigned char>{m_keydata->data() + SLH_SECRETKEY_SIZE - SLH_PUBKEY_SIZE, SLH_PUBKEY_SIZE}};
}

bool CSLHKey::SignInternal(std::span<const unsigned char> msg, std::vector<unsigned char>& sig) const
{
    sig.clear();
    if (!IsValid()) return false;
    static const unsigned char empty{0};
    const unsigned char* m{msg.empty() ? &empty : msg.data()};
    sig.resize(SLH_SIGNATURE_SIZE);
    size_t siglen{0};
    if (PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig.data(), &siglen, m, msg.size(), m_keydata->data()) != 0 || siglen != SLH_SIGNATURE_SIZE) {
        sig.clear();
        return false;
    }
    return true;
}

bool CSLHKey::SignMessage(std::span<const unsigned char> msg, std::vector<unsigned char>& sig, std::span<const unsigned char> context) const
{
    sig.clear();
    std::vector<unsigned char> mprime;
    if (!SLHPureMessage(mprime, msg, context)) return false;
    return SignInternal(mprime, sig);
}

bool CSLHKey::Sign(const uint256& digest, std::vector<unsigned char>& sig) const
{
    return SignMessage(std::span<const unsigned char>{digest.begin(), digest.size()}, sig, {});
}
