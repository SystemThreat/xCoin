// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>

#include <chainparams.h>
#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/hkdf_sha256_32.h>
#include <crypto/mlkem768.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <span.h>
#include <support/cleanse.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>

static_assert(BIP324Cipher::HX1_EK_LEN == mlkem768::ENCAPS_KEY_SIZE);
static_assert(BIP324Cipher::HX1_CT_LEN == mlkem768::CIPHERTEXT_SIZE);
static_assert(BIP324Cipher::HX1_SHARED_SECRET_LEN == mlkem768::SHARED_SECRET_SIZE);

BIP324Cipher::BIP324Cipher(const CKey& key, std::span<const std::byte> ent32) noexcept
    : m_key(key)
{
    m_our_pubkey = m_key.EllSwiftCreate(ent32);
}

BIP324Cipher::BIP324Cipher(const CKey& key, const EllSwiftPubKey& pubkey) noexcept :
    m_key(key), m_our_pubkey(pubkey) {}

BIP324Cipher::~BIP324Cipher()
{
    DiscardStage2Secret();
}

BIP324Cipher::Stage2Keys::~Stage2Keys()
{
    memory_cleanse(initiator_L.data(), initiator_L.size());
    memory_cleanse(initiator_P.data(), initiator_P.size());
    memory_cleanse(responder_L.data(), responder_L.size());
    memory_cleanse(responder_P.data(), responder_P.size());
    memory_cleanse(session_id.data(), session_id.size());
}

void BIP324Cipher::Initialize(const EllSwiftPubKey& their_pubkey, bool initiator, bool self_decrypt, V2HybridMode hybrid_mode) noexcept
{
    // Determine salt (fixed string + network magic bytes)
    const auto& message_header = Params().MessageStart();
    std::string salt = std::string{"bitcoin_v2_shared_secret"} + std::string(std::begin(message_header), std::end(message_header));

    // Perform ECDH to derive shared secret.
    ECDHSecret ecdh_secret = m_key.ComputeBIP324ECDHSecret(their_pubkey, m_our_pubkey, initiator);

    // Derive encryption keys from shared secret, and initialize stream ciphers and AEADs.
    bool side = (initiator != self_decrypt);
    CHKDF_HMAC_SHA256_L32 hkdf(UCharCast(ecdh_secret.data()), ecdh_secret.size(), salt);
    std::array<std::byte, 32> hkdf_32_okm;
    hkdf.Expand32("initiator_L", UCharCast(hkdf_32_okm.data()));
    (side ? m_send_l_cipher : m_recv_l_cipher).emplace(hkdf_32_okm, REKEY_INTERVAL);
    hkdf.Expand32("initiator_P", UCharCast(hkdf_32_okm.data()));
    (side ? m_send_p_cipher : m_recv_p_cipher).emplace(hkdf_32_okm, REKEY_INTERVAL);
    hkdf.Expand32("responder_L", UCharCast(hkdf_32_okm.data()));
    (side ? m_recv_l_cipher : m_send_l_cipher).emplace(hkdf_32_okm, REKEY_INTERVAL);
    hkdf.Expand32("responder_P", UCharCast(hkdf_32_okm.data()));
    (side ? m_recv_p_cipher : m_send_p_cipher).emplace(hkdf_32_okm, REKEY_INTERVAL);

    // Derive garbage terminators from shared secret.
    hkdf.Expand32("garbage_terminators", UCharCast(hkdf_32_okm.data()));
    std::copy(std::begin(hkdf_32_okm), std::begin(hkdf_32_okm) + GARBAGE_TERMINATOR_LEN,
        (initiator ? m_send_garbage_terminator : m_recv_garbage_terminator).begin());
    std::copy(std::end(hkdf_32_okm) - GARBAGE_TERMINATOR_LEN, std::end(hkdf_32_okm),
        (initiator ? m_recv_garbage_terminator : m_send_garbage_terminator).begin());

    // Derive session id from shared secret.
    hkdf.Expand32("session_id", UCharCast(m_session_id.data()));

    if (hybrid_mode != V2HybridMode::OFF) {
        m_stage2_secret = make_secure_unique<Stage2Secret>();
        m_stage2_secret->ecdh_secret = ecdh_secret;
        m_stage2_secret->ell_initiator = initiator ? m_our_pubkey : their_pubkey;
        m_stage2_secret->ell_responder = initiator ? their_pubkey : m_our_pubkey;
        m_stage2_secret->message_start = message_header;
        m_stage2_secret->side = side;
    }

    // Wipe all variables that contain information which could be used to re-derive encryption keys.
    memory_cleanse(ecdh_secret.data(), ecdh_secret.size());
    memory_cleanse(hkdf_32_okm.data(), sizeof(hkdf_32_okm));
    memory_cleanse(&hkdf, sizeof(hkdf));
    m_key = CKey();
}

void BIP324Cipher::DeriveStage2Keys(const MessageStartChars& message_start, std::span<const std::byte> kem_secret,
                                    std::span<const std::byte> ecdh_secret, std::span<const std::byte> ct,
                                    const EllSwiftPubKey& ell_initiator, std::span<const std::byte> ek,
                                    const EllSwiftPubKey& ell_responder, Stage2Keys& keys) noexcept
{
    assert(kem_secret.size() == HX1_SHARED_SECRET_LEN);
    assert(ecdh_secret.size() == ECDH_SECRET_SIZE);
    assert(ct.size() == HX1_CT_LEN);
    assert(ek.size() == HX1_EK_LEN);

    const std::string salt = std::string{"xcoin_v2_hybrid_mlkem768"} + std::string(std::begin(message_start), std::end(message_start));

    std::array<std::byte, HX1_SHARED_SECRET_LEN + ECDH_SECRET_SIZE + HX1_CT_LEN + EllSwiftPubKey::size() + HX1_EK_LEN + EllSwiftPubKey::size()> ikm;
    auto it = std::ranges::copy(kem_secret, ikm.begin()).out;
    it = std::ranges::copy(ecdh_secret, it).out;
    it = std::ranges::copy(ct, it).out;
    it = std::ranges::copy(ell_initiator, it).out;
    it = std::ranges::copy(ek, it).out;
    it = std::ranges::copy(ell_responder, it).out;
    assert(it == ikm.end());

    CHKDF_HMAC_SHA256_L32 hkdf(UCharCast(ikm.data()), ikm.size(), salt);
    hkdf.Expand32("xcoin_hx1_initiator_L", UCharCast(keys.initiator_L.data()));
    hkdf.Expand32("xcoin_hx1_initiator_P", UCharCast(keys.initiator_P.data()));
    hkdf.Expand32("xcoin_hx1_responder_L", UCharCast(keys.responder_L.data()));
    hkdf.Expand32("xcoin_hx1_responder_P", UCharCast(keys.responder_P.data()));
    hkdf.Expand32("xcoin_hx1_session_id", UCharCast(keys.session_id.data()));

    memory_cleanse(ikm.data(), ikm.size());
    memory_cleanse(&hkdf, sizeof(hkdf));
}

bool BIP324Cipher::SwitchToStage2(std::span<const std::byte> kem_secret, std::span<const std::byte> ct, std::span<const std::byte> ek) noexcept
{
    if (!m_stage2_secret || kem_secret.size() != HX1_SHARED_SECRET_LEN || ct.size() != HX1_CT_LEN || ek.size() != HX1_EK_LEN) {
        return false;
    }

    Stage2Keys keys;
    DeriveStage2Keys(m_stage2_secret->message_start, kem_secret, m_stage2_secret->ecdh_secret, ct,
                     m_stage2_secret->ell_initiator, ek, m_stage2_secret->ell_responder, keys);

    // Emplacing destroys each stage-1 cipher, which wipes its state, and starts the new one at packet 0.
    const bool side{m_stage2_secret->side};
    (side ? m_send_l_cipher : m_recv_l_cipher).emplace(keys.initiator_L, REKEY_INTERVAL);
    (side ? m_send_p_cipher : m_recv_p_cipher).emplace(keys.initiator_P, REKEY_INTERVAL);
    (side ? m_recv_l_cipher : m_send_l_cipher).emplace(keys.responder_L, REKEY_INTERVAL);
    (side ? m_recv_p_cipher : m_send_p_cipher).emplace(keys.responder_P, REKEY_INTERVAL);
    m_session_id = keys.session_id;

    DiscardStage2Secret();
    m_stage2 = true;
    return true;
}

void BIP324Cipher::Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept
{
    assert(output.size() == contents.size() + EXPANSION);

    // Encrypt length.
    std::byte len[LENGTH_LEN];
    len[0] = std::byte{(uint8_t)(contents.size() & 0xFF)};
    len[1] = std::byte{(uint8_t)((contents.size() >> 8) & 0xFF)};
    len[2] = std::byte{(uint8_t)((contents.size() >> 16) & 0xFF)};
    m_send_l_cipher->Crypt(len, output.first(LENGTH_LEN));

    // Encrypt plaintext.
    std::byte header[HEADER_LEN] = {ignore ? IGNORE_BIT : std::byte{0}};
    m_send_p_cipher->Encrypt(header, contents, aad, output.subspan(LENGTH_LEN));
}

uint32_t BIP324Cipher::DecryptLength(std::span<const std::byte> input) noexcept
{
    assert(input.size() == LENGTH_LEN);

    std::byte buf[LENGTH_LEN];
    // Decrypt length
    m_recv_l_cipher->Crypt(input, buf);
    // Convert to number.
    return uint32_t(buf[0]) + (uint32_t(buf[1]) << 8) + (uint32_t(buf[2]) << 16);
}

bool BIP324Cipher::Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept
{
    assert(input.size() + LENGTH_LEN == contents.size() + EXPANSION);

    std::byte header[HEADER_LEN];
    if (!m_recv_p_cipher->Decrypt(input, aad, header, contents)) return false;

    ignore = (header[0] & IGNORE_BIT) == IGNORE_BIT;
    return true;
}
