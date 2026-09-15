// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SLHKEY_H
#define BITCOIN_SLHKEY_H

#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

/**
 * SLH-DSA-SHA2-128s (FIPS 205) public keys and signature verification: the
 * hash-based fallback algorithm of the xCoin witness v3 script tree
 * (contrib/regenesis/REGENESIS.md section 4, leaf version XCOIN_LEAF_SLH).
 *
 *   Public key:  32 bytes   (PK.seed || PK.root)
 *   Secret key:  64 bytes   (SK.seed || SK.prf || PK.seed || PK.root)
 *   Signature:   7,856 bytes, always exactly that size
 *   Security:    NIST level 1; shares no structure with the ML-DSA lattice
 *
 * CSLHPubKey verifies (consensus); CSLHKey generates keys and signs (wallet,
 * descriptors, tests). Signing is slow (a signature costs a few hundred
 * milliseconds and is 7.9 KB), which is why the SLH leaf is the fallback, not
 * the everyday path.
 *
 * Verification is FIPS 205 slh_verify in "pure" mode: the bytes handed to
 * slh_verify_internal are M' = 0x00 || len(context) || context || M.
 * Consensus uses an empty context, so a 32-byte sighash digest is verified as
 * a signature over 0x00 || 0x00 || digest (34 bytes). That is exactly what
 * any FIPS 205 implementation produces for a raw 32-byte message with no
 * context (for example `openssl pkeyutl -sign -rawin` on OpenSSL >= 3.5), so
 * an emergency signer needs no xCoin-specific code.
 *
 * The implementation is PQClean's sphincs-sha2-128s-simple with the FIPS 205
 * FORS index bit order; see src/pqcrypto/slh-dsa-sha2-128s/PQCLEAN.
 */

/** SLH-DSA-SHA2-128s sizes (FIPS 205 Table 2 / PQClean api.h). */
static constexpr size_t SLH_PUBKEY_SIZE = 32;
static constexpr size_t SLH_SECRETKEY_SIZE = 64;
static constexpr size_t SLH_SIGNATURE_SIZE = 7856;
/** Seed for deterministic key generation: SK.seed || SK.prf || PK.seed. */
static constexpr size_t SLH_SEED_SIZE = 48;
/** FIPS 205 encodes the context length in one byte. */
static constexpr size_t SLH_MAX_CONTEXT_SIZE = 255;

/** Build the FIPS 205 pure-mode message M' = 0x00 || len(context) || context || msg.
 *  Returns false (and leaves `out` empty) if the context is longer than 255 bytes. */
bool SLHPureMessage(std::vector<unsigned char>& out, std::span<const unsigned char> msg, std::span<const unsigned char> context);

/** An encapsulated SLH-DSA-SHA2-128s public key (32 bytes). */
class CSLHPubKey
{
    std::array<unsigned char, SLH_PUBKEY_SIZE> m_data{};
    bool m_valid{false};

public:
    static constexpr unsigned int SIZE = SLH_PUBKEY_SIZE;
    static constexpr unsigned int SIGNATURE_SIZE = SLH_SIGNATURE_SIZE;

    //! Construct an invalid public key.
    CSLHPubKey() = default;

    //! Construct from raw bytes; anything but exactly 32 bytes yields an invalid key.
    explicit CSLHPubKey(std::span<const unsigned char> data) { Set(data); }

    void Set(std::span<const unsigned char> data)
    {
        if (data.size() == SIZE) {
            std::memcpy(m_data.data(), data.data(), SIZE);
            m_valid = true;
        } else {
            m_data.fill(0);
            m_valid = false;
        }
    }

    bool IsValid() const { return m_valid; }
    //! Fixed size; 0 for an invalid key.
    unsigned int size() const { return m_valid ? SIZE : 0; }
    const unsigned char* data() const { return m_data.data(); }
    const unsigned char* begin() const { return m_data.data(); }
    const unsigned char* end() const { return m_data.data() + size(); }

    /** The consensus check: FIPS 205 pure mode with an empty context over a 32-byte digest,
     *  i.e. slh_verify_internal over 0x00 || 0x00 || digest. `sig` must be exactly
     *  SLH_SIGNATURE_SIZE bytes (the interpreter strips any hash-type byte first). */
    bool Verify(const uint256& digest, std::span<const unsigned char> sig) const;

    /** FIPS 205 pure mode with an arbitrary context (at most 255 bytes). */
    bool VerifyMessage(std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> context = {}) const;

    /** FIPS 205 slh_verify_internal: no domain-separation prefix. For test vectors and the
     *  internal interface only; consensus never calls this directly. */
    bool VerifyInternal(std::span<const unsigned char> msg, std::span<const unsigned char> sig) const;

    friend bool operator==(const CSLHPubKey& a, const CSLHPubKey& b) { return a.m_valid == b.m_valid && a.m_data == b.m_data; }
    friend bool operator!=(const CSLHPubKey& a, const CSLHPubKey& b) { return !(a == b); }
    friend bool operator<(const CSLHPubKey& a, const CSLHPubKey& b) { return a.m_data < b.m_data; }
};

/** An SLH-DSA-SHA2-128s secret key (64 bytes: SK.seed || SK.prf || PK.seed || PK.root) with
 *  key generation and signing. The first SLH_SEED_SIZE (48) bytes are exactly the key-generation
 *  seed, so a key round-trips through its seed. Key material lives in secure memory.
 *
 *  Signing is FIPS 205 slh_sign (hedged: PQClean draws opt_rand from randombytes, so two
 *  signatures over the same message differ but both verify). */
class CSLHKey
{
    using KeyType = std::array<unsigned char, SLH_SECRETKEY_SIZE>;
    secure_unique_ptr<KeyType> m_keydata;

    void MakeKeyData()
    {
        if (!m_keydata) m_keydata = make_secure_unique<KeyType>();
    }
    void ClearKeyData() { m_keydata.reset(); }

public:
    CSLHKey() noexcept = default;
    CSLHKey(CSLHKey&&) noexcept = default;
    CSLHKey& operator=(CSLHKey&&) noexcept = default;
    CSLHKey& operator=(const CSLHKey& other)
    {
        if (this != &other) {
            if (other.m_keydata) {
                MakeKeyData();
                *m_keydata = *other.m_keydata;
            } else {
                ClearKeyData();
            }
        }
        return *this;
    }
    CSLHKey(const CSLHKey& other) { *this = other; }

    friend bool operator==(const CSLHKey& a, const CSLHKey& b)
    {
        return a.IsValid() == b.IsValid() && (!a.IsValid() || *a.m_keydata == *b.m_keydata);
    }

    bool IsValid() const { return !!m_keydata; }
    /** The 64-byte secret key (empty span if invalid). */
    std::span<const unsigned char> data() const { return {m_keydata ? m_keydata->data() : nullptr, m_keydata ? SLH_SECRETKEY_SIZE : 0}; }
    /** The 48-byte key-generation seed SK.seed || SK.prf || PK.seed (empty span if invalid). */
    std::span<const unsigned char> seed() const { return {m_keydata ? m_keydata->data() : nullptr, m_keydata ? SLH_SEED_SIZE : 0}; }

    /** Set from a full 64-byte secret key; anything else clears the key. */
    void Set(std::span<const unsigned char> sk64);

    /** Deterministic key generation from SK.seed || SK.prf || PK.seed (48 bytes);
     *  returns the public key (invalid, and clears this key, if the seed has the wrong size). */
    CSLHPubKey MakeKeyFromSeed(std::span<const unsigned char> seed48);
    /** Random key. */
    CSLHPubKey MakeNewKey();
    CSLHPubKey GetPubKey() const;

    /** FIPS 205 slh_sign_internal (no prefix). */
    bool SignInternal(std::span<const unsigned char> msg, std::vector<unsigned char>& sig) const;
    /** FIPS 205 pure mode: signs 0x00 || len(context) || context || msg. */
    bool SignMessage(std::span<const unsigned char> msg, std::vector<unsigned char>& sig, std::span<const unsigned char> context = {}) const;
    /** The consensus mode: pure, empty context, 32-byte digest. */
    bool Sign(const uint256& digest, std::vector<unsigned char>& sig) const;
};

#endif // BITCOIN_SLHKEY_H
