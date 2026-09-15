// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqhd.h>

#include <pqkey.h>
#include <support/cleanse.h>

#include <span>

// PQClean's FIPS 202 SHAKE-256
extern "C" {
#include <fips202.h>
}

// ML-DSA-65 keygen with explicit seed
extern "C" {
#include <pqcrypto/ml-dsa-65/api.h>
}

void DerivePQMasterSecret(std::span<const unsigned char> masterSeed,
                          std::array<unsigned char, 32>& masterSecret)
{
    // SHAKE-256(masterSeed || "NEX-PQ-MASTER") → 32 bytes
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, masterSeed.data(), masterSeed.size());
    shake256_inc_absorb(&ctx, reinterpret_cast<const uint8_t*>(PQ_MASTER_DOMAIN.data()),
                        PQ_MASTER_DOMAIN.size());
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(masterSecret.data(), 32, &ctx);
    shake256_inc_ctx_release(&ctx);
}

bool DerivePQChildKey(const std::array<unsigned char, 32>& masterSecret,
                      uint32_t index,
                      CPQKey& key,
                      CPQPubKey& pubkey)
{
    // SHAKE-256(masterSecret || uint32_le(index) || "NEX-PQ-CHILD") → 32 bytes
    // This 32-byte child seed is used as the randomness for ML-DSA-65 keygen.
    unsigned char childSeed[32];
    unsigned char indexLE[4];
    indexLE[0] = index & 0xFF;
    indexLE[1] = (index >> 8) & 0xFF;
    indexLE[2] = (index >> 16) & 0xFF;
    indexLE[3] = (index >> 24) & 0xFF;

    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, masterSecret.data(), 32);
    shake256_inc_absorb(&ctx, indexLE, 4);
    shake256_inc_absorb(&ctx, reinterpret_cast<const uint8_t*>(PQ_CHILD_DOMAIN.data()),
                        PQ_CHILD_DOMAIN.size());
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(childSeed, 32, &ctx);
    shake256_inc_ctx_release(&ctx);

    // The 32-byte childSeed is the FIPS 204 ML-DSA.KeyGen_internal xi input.
    // crypto_sign_keypair_from_seed expands it deterministically into the key —
    // same childSeed always yields the same keypair, so a wallet can recover
    // every ML-DSA key from just the master seed phrase. No OS randomness.
    pubkey = key.MakeKeyFromSeed(std::span<const unsigned char>(childSeed, 32));

    // Zeroize the child seed (memory_cleanse: a plain memset of a dead stack
    // buffer is removed by the optimizer).
    memory_cleanse(childSeed, sizeof(childSeed));

    if (!key.IsValid() || !pubkey.IsValid()) return false;
    return true;
}

bool DerivePQKeyFromSeed(std::span<const unsigned char> masterSeed,
                         uint32_t index,
                         CPQKey& key,
                         CPQPubKey& pubkey)
{
    std::array<unsigned char, 32> masterSecret;
    DerivePQMasterSecret(masterSeed, masterSecret);

    bool ok = DerivePQChildKey(masterSecret, index, key, pubkey);

    // Zeroize master secret (memory_cleanse, see above)
    memory_cleanse(masterSecret.data(), masterSecret.size());

    return ok;
}

// ── xCoin HD derivation for descriptors ──────────────────────────────────────

namespace {
void ShakeMaterial(std::span<const unsigned char> root_privkey32, std::span<const unsigned char> root_chaincode32, std::span<const uint32_t> path, const std::string& domain, unsigned char* out, size_t outlen)
{
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, root_privkey32.data(), root_privkey32.size());
    shake256_inc_absorb(&ctx, root_chaincode32.data(), root_chaincode32.size());
    for (const uint32_t step : path) {
        const unsigned char le[4]{static_cast<unsigned char>(step & 0xFF), static_cast<unsigned char>((step >> 8) & 0xFF),
                                  static_cast<unsigned char>((step >> 16) & 0xFF), static_cast<unsigned char>((step >> 24) & 0xFF)};
        shake256_inc_absorb(&ctx, le, 4);
    }
    shake256_inc_absorb(&ctx, reinterpret_cast<const uint8_t*>(domain.data()), domain.size());
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, outlen, &ctx);
    shake256_inc_ctx_release(&ctx);
}
} // namespace

void DeriveXcoinMLDSASeed(std::span<const unsigned char> root_privkey32, std::span<const unsigned char> root_chaincode32, std::span<const uint32_t> path, std::array<unsigned char, 32>& seed_out)
{
    ShakeMaterial(root_privkey32, root_chaincode32, path, XCOIN_HD_MLDSA_SEED_DOMAIN, seed_out.data(), seed_out.size());
}

void DeriveXcoinSLHSeed(std::span<const unsigned char> root_privkey32, std::span<const unsigned char> root_chaincode32, std::span<const uint32_t> path, std::array<unsigned char, 48>& seed_out)
{
    ShakeMaterial(root_privkey32, root_chaincode32, path, XCOIN_HD_SLH_SEED_DOMAIN, seed_out.data(), seed_out.size());
}
