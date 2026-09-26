// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP324_H
#define BITCOIN_BIP324_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <kernel/messagestartchars.h>
#include <key.h>
#include <pubkey.h>
#include <span.h>
#include <support/allocators/secure.h>

/** The -v2hybrid mode: whether v2 connections run the HX1 hybrid post-quantum handshake (XIP-4). */
enum class V2HybridMode : uint8_t {
    OFF = 0,     //!< BIP324 exactly as before HX1
    PREFER = 1,  //!< HX1 with peers that take part, classical BIP324 with the rest
    REQUIRE = 2, //!< HX1 or no connection
};

/** The BIP324 packet cipher, encapsulating its key derivation, stream cipher, and AEAD. */
class BIP324Cipher
{
public:
    static constexpr unsigned SESSION_ID_LEN{32};
    static constexpr unsigned GARBAGE_TERMINATOR_LEN{16};
    static constexpr unsigned REKEY_INTERVAL{224};
    static constexpr unsigned LENGTH_LEN{3};
    static constexpr unsigned HEADER_LEN{1};
    static constexpr unsigned EXPANSION = LENGTH_LEN + HEADER_LEN + FSChaCha20Poly1305::EXPANSION;
    static constexpr std::byte IGNORE_BIT{0x80};

    /** ML-KEM-768 encapsulation key, ciphertext and shared secret lengths (FIPS 203, Table 3). */
    static constexpr unsigned HX1_EK_LEN{1184};
    static constexpr unsigned HX1_CT_LEN{1088};
    static constexpr unsigned HX1_SHARED_SECRET_LEN{32};

    /** The HX1 stage-2 packet keys and session id (XIP-4, "Stage-2 key schedule"). Wiped on destruction. */
    struct Stage2Keys {
        std::array<std::byte, FSChaCha20::KEYLEN> initiator_L;
        std::array<std::byte, FSChaCha20Poly1305::KEYLEN> initiator_P;
        std::array<std::byte, FSChaCha20::KEYLEN> responder_L;
        std::array<std::byte, FSChaCha20Poly1305::KEYLEN> responder_P;
        std::array<std::byte, SESSION_ID_LEN> session_id;

        ~Stage2Keys();
    };

private:
    std::optional<FSChaCha20> m_send_l_cipher;
    std::optional<FSChaCha20> m_recv_l_cipher;
    std::optional<FSChaCha20Poly1305> m_send_p_cipher;
    std::optional<FSChaCha20Poly1305> m_recv_p_cipher;

    CKey m_key;
    EllSwiftPubKey m_our_pubkey;

    std::array<std::byte, SESSION_ID_LEN> m_session_id;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_send_garbage_terminator;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_recv_garbage_terminator;

    /** What SwitchToStage2() needs from Initialize(). */
    struct Stage2Secret {
        ECDHSecret ecdh_secret;
        EllSwiftPubKey ell_initiator;
        EllSwiftPubKey ell_responder;
        MessageStartChars message_start;
        bool side;
    };

    /** Only set by Initialize() in an HX1 mode; freed (and so wiped) at the switch, the classical decision or
     *  destruction. */
    secure_unique_ptr<Stage2Secret> m_stage2_secret;

    bool m_stage2{false};

public:
    /** No default constructor; keys must be provided to create a BIP324Cipher. */
    BIP324Cipher() = delete;

    /** Initialize a BIP324 cipher with specified key and encoding entropy (testing only). */
    BIP324Cipher(const CKey& key, std::span<const std::byte> ent32) noexcept;

    /** Initialize a BIP324 cipher with specified key (testing only). */
    BIP324Cipher(const CKey& key, const EllSwiftPubKey& pubkey) noexcept;

    /** Wipes the ECDH secret if it is still kept for stage 2. */
    ~BIP324Cipher();

    /** Retrieve our public key. */
    const EllSwiftPubKey& GetOurPubKey() const noexcept { return m_our_pubkey; }

    /** Initialize when the other side's public key is received. Can only be called once.
     *
     * initiator is set to true if we are the initiator establishing the v2 P2P connection.
     * self_decrypt is only for testing, and swaps encryption/decryption keys, so that encryption
     * and decryption can be tested without knowing the other side's private key.
     * In the HX1 modes (PREFER, REQUIRE) the ECDH secret is kept, in locked memory, for SwitchToStage2(). With
     * OFF it is wiped here and nothing is kept.
     */
    void Initialize(const EllSwiftPubKey& their_pubkey, bool initiator, bool self_decrypt = false,
                    V2HybridMode hybrid_mode = V2HybridMode::OFF) noexcept;

    /** Derive the HX1 stage-2 keys from the ML-KEM shared secret, the BIP324 ECDH secret and the transcript
     *  (XIP-4, "Stage-2 key schedule"). ct, ek and both ElligatorSwift keys are the bytes that were sent. */
    static void DeriveStage2Keys(const MessageStartChars& message_start, std::span<const std::byte> kem_secret,
                                 std::span<const std::byte> ecdh_secret, std::span<const std::byte> ct,
                                 const EllSwiftPubKey& ell_initiator, std::span<const std::byte> ek,
                                 const EllSwiftPubKey& ell_responder, Stage2Keys& keys) noexcept;

    /** Replace all four ciphers and the session id with the HX1 stage-2 ones, and wipe the kept ECDH secret.
     *
     * The new ciphers start at packet 0 in both directions. The caller wipes kem_secret. Returns false and
     * changes nothing if no ECDH secret is kept (Initialize() ran with OFF, or the secret was already used or
     * discarded) or a length is wrong.
     */
    [[nodiscard]] bool SwitchToStage2(std::span<const std::byte> kem_secret, std::span<const std::byte> ct,
                                      std::span<const std::byte> ek) noexcept;

    /** Wipe the ECDH secret kept for stage 2, for a session that stays classical. */
    void DiscardStage2Secret() noexcept { m_stage2_secret.reset(); }

    /** Whether the ECDH secret is kept for stage 2. */
    bool HasStage2Secret() const noexcept { return m_stage2_secret != nullptr; }

    /** Whether the ciphers and session id are the stage-2 ones. */
    bool IsStage2() const noexcept { return m_stage2; }

    /** Determine whether this cipher is fully initialized. */
    explicit operator bool() const noexcept { return m_send_l_cipher.has_value(); }

    /** Encrypt a packet. Only after Initialize().
     *
     * It must hold that output.size() == contents.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept;

    /** Decrypt the length of a packet. Only after Initialize().
     *
     * It must hold that input.size() == LENGTH_LEN.
     */
    unsigned DecryptLength(std::span<const std::byte> input) noexcept;

    /** Decrypt a packet. Only after Initialize().
     *
     * It must hold that input.size() + LENGTH_LEN == contents.size() + EXPANSION.
     * Contents.size() must equal the length returned by DecryptLength.
     */
    bool Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept;

    /** Get the Session ID, the stage-2 one after SwitchToStage2(). Only after Initialize(). */
    std::span<const std::byte> GetSessionID() const noexcept { return m_session_id; }

    /** Get the Garbage Terminator to send. Only after Initialize(). */
    std::span<const std::byte> GetSendGarbageTerminator() const noexcept { return m_send_garbage_terminator; }

    /** Get the expected Garbage Terminator to receive. Only after Initialize(). */
    std::span<const std::byte> GetReceiveGarbageTerminator() const noexcept { return m_recv_garbage_terminator; }
};

#endif // BITCOIN_BIP324_H
