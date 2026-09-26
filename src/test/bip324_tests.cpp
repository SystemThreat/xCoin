// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>
#include <chainparams.h>
#include <crypto/hkdf_sha256_32.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <key.h>
#include <pubkey.h>
#include <span.h>
#include <support/lockedpool.h>
#include <test/data/hx1_handshake_vectors.json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct BIP324Test : BasicTestingSetup {
void TestBIP324PacketVector(
    uint32_t in_idx,
    const std::string& in_priv_ours_hex,
    const std::string& in_ellswift_ours_hex,
    const std::string& in_ellswift_theirs_hex,
    bool in_initiating,
    const std::string& in_contents_hex,
    uint32_t in_multiply,
    const std::string& in_aad_hex,
    bool in_ignore,
    const std::string& mid_send_garbage_hex,
    const std::string& mid_recv_garbage_hex,
    const std::string& out_session_id_hex,
    const std::string& out_ciphertext_hex,
    const std::string& out_ciphertext_endswith_hex)
{
    // Convert input from hex to char/byte vectors/arrays.
    const auto in_priv_ours = ParseHex(in_priv_ours_hex);
    const auto in_ellswift_ours = ParseHex<std::byte>(in_ellswift_ours_hex);
    const auto in_ellswift_theirs = ParseHex<std::byte>(in_ellswift_theirs_hex);
    const auto in_contents = ParseHex<std::byte>(in_contents_hex);
    const auto in_aad = ParseHex<std::byte>(in_aad_hex);
    const auto mid_send_garbage = ParseHex<std::byte>(mid_send_garbage_hex);
    const auto mid_recv_garbage = ParseHex<std::byte>(mid_recv_garbage_hex);
    const auto out_session_id = ParseHex<std::byte>(out_session_id_hex);
    const auto out_ciphertext = ParseHex<std::byte>(out_ciphertext_hex);
    const auto out_ciphertext_endswith = ParseHex<std::byte>(out_ciphertext_endswith_hex);

    // Load keys
    CKey key;
    key.Set(in_priv_ours.begin(), in_priv_ours.end(), true);
    EllSwiftPubKey ellswift_ours(in_ellswift_ours);
    EllSwiftPubKey ellswift_theirs(in_ellswift_theirs);

    // Instantiate encryption BIP324 cipher.
    BIP324Cipher cipher(key, ellswift_ours);
    BOOST_CHECK(!cipher);
    BOOST_CHECK(cipher.GetOurPubKey() == ellswift_ours);
    cipher.Initialize(ellswift_theirs, in_initiating);
    BOOST_CHECK(cipher);

    // Compare session variables.
    BOOST_CHECK(std::ranges::equal(out_session_id, cipher.GetSessionID()));
    BOOST_CHECK(std::ranges::equal(mid_send_garbage, cipher.GetSendGarbageTerminator()));
    BOOST_CHECK(std::ranges::equal(mid_recv_garbage, cipher.GetReceiveGarbageTerminator()));

    // Vector of encrypted empty messages, encrypted in order to seek to the right position.
    std::vector<std::vector<std::byte>> dummies(in_idx);

    // Seek to the numbered packet.
    for (uint32_t i = 0; i < in_idx; ++i) {
        dummies[i].resize(cipher.EXPANSION);
        cipher.Encrypt({}, {}, true, dummies[i]);
    }

    // Construct contents and encrypt it.
    std::vector<std::byte> contents;
    for (uint32_t i = 0; i < in_multiply; ++i) {
        contents.insert(contents.end(), in_contents.begin(), in_contents.end());
    }
    std::vector<std::byte> ciphertext(contents.size() + cipher.EXPANSION);
    cipher.Encrypt(contents, in_aad, in_ignore, ciphertext);

    // Verify ciphertext. Note that the test vectors specify either out_ciphertext (for short
    // messages) or out_ciphertext_endswith (for long messages), so only check the relevant one.
    if (!out_ciphertext.empty()) {
        BOOST_CHECK(out_ciphertext == ciphertext);
    } else {
        BOOST_CHECK(ciphertext.size() >= out_ciphertext_endswith.size());
        BOOST_CHECK(std::ranges::equal(out_ciphertext_endswith, std::span{ciphertext}.last(out_ciphertext_endswith.size())));
    }

    for (unsigned error = 0; error <= 12; ++error) {
        // error selects a type of error introduced:
        // - error=0: no errors, decryption should be successful
        // - error=1: wrong side
        // - error=2..9: bit error in ciphertext
        // - error=10: bit error in aad
        // - error=11: extra 0x00 at end of aad
        // - error=12: message index wrong

        // Instantiate self-decrypting BIP324 cipher.
        BIP324Cipher dec_cipher(key, ellswift_ours);
        BOOST_CHECK(!dec_cipher);
        BOOST_CHECK(dec_cipher.GetOurPubKey() == ellswift_ours);
        dec_cipher.Initialize(ellswift_theirs, (error == 1) ^ in_initiating, /*self_decrypt=*/true);
        BOOST_CHECK(dec_cipher);

        // Compare session variables.
        BOOST_CHECK(std::ranges::equal(out_session_id, dec_cipher.GetSessionID()) == (error != 1));
        BOOST_CHECK(std::ranges::equal(mid_send_garbage, dec_cipher.GetSendGarbageTerminator()) == (error != 1));
        BOOST_CHECK(std::ranges::equal(mid_recv_garbage, dec_cipher.GetReceiveGarbageTerminator()) == (error != 1));

        // Seek to the numbered packet.
        if (in_idx == 0 && error == 12) continue;
        uint32_t dec_idx = in_idx ^ (error == 12 ? (1U << m_rng.randrange(16)) : 0);
        for (uint32_t i = 0; i < dec_idx; ++i) {
            unsigned use_idx = i < in_idx ? i : 0;
            bool dec_ignore{false};
            dec_cipher.DecryptLength(std::span{dummies[use_idx]}.first(cipher.LENGTH_LEN));
            dec_cipher.Decrypt(std::span{dummies[use_idx]}.subspan(cipher.LENGTH_LEN), {}, dec_ignore, {});
        }

        // Construct copied (and possibly damaged) copy of ciphertext.
        // Decrypt length
        auto to_decrypt = ciphertext;
        if (error >= 2 && error <= 9) {
            to_decrypt[m_rng.randrange(to_decrypt.size())] ^= std::byte(1U << (error - 2));
        }

        // Decrypt length and resize ciphertext to accommodate.
        uint32_t dec_len = dec_cipher.DecryptLength(MakeByteSpan(to_decrypt).first(cipher.LENGTH_LEN));
        to_decrypt.resize(dec_len + cipher.EXPANSION);

        // Construct copied (and possibly damaged) copy of aad.
        auto dec_aad = in_aad;
        if (error == 10) {
            if (in_aad.size() == 0) continue;
            dec_aad[m_rng.randrange(dec_aad.size())] ^= std::byte(1U << m_rng.randrange(8));
        }
        if (error == 11) dec_aad.push_back({});

        // Decrypt contents.
        std::vector<std::byte> decrypted(dec_len);
        bool dec_ignore{false};
        bool dec_ok = dec_cipher.Decrypt(std::span{to_decrypt}.subspan(cipher.LENGTH_LEN), dec_aad, dec_ignore, decrypted);

        // Verify result.
        BOOST_CHECK(dec_ok == !error);
        if (dec_ok) {
            BOOST_CHECK(decrypted == contents);
            BOOST_CHECK(dec_ignore == in_ignore);
        }
    }
}
}; // struct BIP324Test

// XIP-4 (HX1) helpers. The HX1 record and application packet layouts are written out here from the XIP's text,
// independently of the node's transport code.

constexpr uint8_t HX1_KIND_OFFER{0x01};
constexpr uint8_t HX1_KIND_ACCEPT{0x02};

std::vector<std::byte> HexBytes(const UniValue& hex) { return ParseHex<std::byte>(hex.get_str()); }

std::string Sha256Hex(std::span<const std::byte> data)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(UCharCast(data.data()), data.size()).Finalize(hash.data());
    return HexStr(hash);
}

std::span<const std::byte> PubKeySpan(const EllSwiftPubKey& pubkey) { return {pubkey.data(), pubkey.size()}; }

/** The one record a mode 1 or 2 sender puts in its version packet: tag, version 01, kind, length, body. */
std::vector<std::byte> HX1Record(uint8_t kind, std::span<const std::byte> body)
{
    std::vector<std::byte> record;
    for (char c : std::string{"xcoin-pq"}) {
        record.push_back(std::byte(c));
    }
    record.push_back(std::byte{0x01});
    record.push_back(std::byte{kind});
    record.push_back(std::byte(body.size() & 0xff));
    record.push_back(std::byte(body.size() >> 8));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

/** Application packet i of the vectors: "I->R" or "R->I", then i as 4 bytes little-endian. */
std::vector<std::byte> AppContents(bool from_initiator, uint32_t i)
{
    std::vector<std::byte> contents;
    for (char c : std::string{from_initiator ? "I->R" : "R->I"}) {
        contents.push_back(std::byte(c));
    }
    for (int b = 0; b < 4; ++b) {
        contents.push_back(std::byte((i >> (8 * b)) & 0xff));
    }
    return contents;
}

std::vector<std::byte> EncryptPacket(BIP324Cipher& cipher, std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore)
{
    std::vector<std::byte> packet(contents.size() + BIP324Cipher::EXPANSION);
    cipher.Encrypt(contents, aad, ignore, packet);
    return packet;
}

/** Receive one packet the way V2Transport does, length first, and check what comes out. */
void CheckDecryptPacket(BIP324Cipher& cipher, std::span<const std::byte> packet, std::span<const std::byte> aad, bool ignore, std::span<const std::byte> contents)
{
    BOOST_REQUIRE_GE(packet.size(), BIP324Cipher::EXPANSION);
    const uint32_t len{cipher.DecryptLength(packet.first(BIP324Cipher::LENGTH_LEN))};
    BOOST_REQUIRE_EQUAL(len, contents.size());
    BOOST_REQUIRE_EQUAL(packet.size(), len + BIP324Cipher::EXPANSION);
    std::vector<std::byte> decrypted(len);
    bool dec_ignore{!ignore};
    BOOST_CHECK(cipher.Decrypt(packet.subspan(BIP324Cipher::LENGTH_LEN), aad, dec_ignore, decrypted));
    BOOST_CHECK_EQUAL(dec_ignore, ignore);
    BOOST_CHECK(std::ranges::equal(decrypted, contents));
}

/** Whether a packet authenticates under the receiver's current keys (its length is decrypted but not trusted). */
bool Authenticates(BIP324Cipher& cipher, std::span<const std::byte> packet)
{
    cipher.DecryptLength(packet.first(BIP324Cipher::LENGTH_LEN));
    std::vector<std::byte> decrypted(packet.size() - BIP324Cipher::EXPANSION);
    bool ignore{false};
    return cipher.Decrypt(packet.subspan(BIP324Cipher::LENGTH_LEN), {}, ignore, decrypted);
}

/** One output of the BIP324 (stage-1) HKDF, as src/bip324.cpp derives it, for the selected network. */
std::array<std::byte, 32> Stage1Output(std::span<const std::byte> ecdh_secret, const std::string& label)
{
    const auto& magic{Params().MessageStart()};
    const std::string salt{std::string{"bitcoin_v2_shared_secret"} + std::string(magic.begin(), magic.end())};
    CHKDF_HMAC_SHA256_L32 hkdf(UCharCast(ecdh_secret.data()), ecdh_secret.size(), salt);
    std::array<std::byte, 32> out;
    hkdf.Expand32(label, UCharCast(out.data()));
    return out;
}

const std::array<std::string, 4> STAGE1_KEY_LABELS{"initiator_L", "initiator_P", "responder_L", "responder_P"};
const std::array<std::string, 5> STAGE2_LABELS{"xcoin_hx1_initiator_L", "xcoin_hx1_initiator_P", "xcoin_hx1_responder_L", "xcoin_hx1_responder_P", "xcoin_hx1_session_id"};

std::array<std::span<const std::byte>, 5> Stage2Outputs(const BIP324Cipher::Stage2Keys& keys)
{
    return {keys.initiator_L, keys.initiator_P, keys.responder_L, keys.responder_P, keys.session_id};
}

/** XIP-4's stage-2 key schedule written out from its text with HMAC-SHA256, without DeriveStage2Keys(). */
void CheckStage2ScheduleText(const UniValue& expected, std::span<const std::byte> kem_secret, std::span<const std::byte> ecdh_secret,
                             std::span<const std::byte> ct, const EllSwiftPubKey& ell_initiator, std::span<const std::byte> ek,
                             const EllSwiftPubKey& ell_responder)
{
    std::vector<unsigned char> ikm2;
    for (const auto part : {kem_secret, ecdh_secret, ct, PubKeySpan(ell_initiator), ek, PubKeySpan(ell_responder)}) {
        ikm2.insert(ikm2.end(), UCharCast(part.data()), UCharCast(part.data()) + part.size());
    }
    BOOST_CHECK_EQUAL(ikm2.size(), expected["ikm2_len"].getInt<size_t>());
    BOOST_CHECK_EQUAL(Sha256Hex(MakeByteSpan(ikm2)), expected["ikm2_sha256"].get_str());

    const auto& magic{Params().MessageStart()};
    const std::string salt2{std::string{"xcoin_v2_hybrid_mlkem768"} + std::string(magic.begin(), magic.end())};
    BOOST_CHECK_EQUAL(salt2.size(), 28U);
    std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> prk2;
    CHMAC_SHA256(UCharCast(salt2.data()), salt2.size()).Write(ikm2.data(), ikm2.size()).Finalize(prk2.data());
    BOOST_CHECK_EQUAL(HexStr(prk2), expected["prk2"].get_str());
    for (const std::string& label : STAGE2_LABELS) {
        const unsigned char one{0x01};
        std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> okm;
        CHMAC_SHA256(prk2.data(), prk2.size()).Write(UCharCast(label.data()), label.size()).Write(&one, 1).Finalize(okm.data());
        BOOST_CHECK_EQUAL(HexStr(okm), expected[label].get_str());
    }
}

/** Send one side's handshake (ElligatorSwift key, garbage, garbage terminator, decoys, version packet) and
 *  compare it with the vector; the other side decrypts every packet. */
void CheckHandshakeFlight(BIP324Cipher& sender, BIP324Cipher& receiver, std::span<const std::byte> garbage,
                          const UniValue& decoys, std::span<const std::byte> version_contents,
                          const UniValue& expected_version_packet, const UniValue& expected_handshake)
{
    const EllSwiftPubKey& ellswift{sender.GetOurPubKey()};
    std::vector<std::byte> flight(ellswift.begin(), ellswift.end());
    flight.insert(flight.end(), garbage.begin(), garbage.end());
    const auto terminator{sender.GetSendGarbageTerminator()};
    flight.insert(flight.end(), terminator.begin(), terminator.end());
    std::span<const std::byte> aad{garbage};
    for (const UniValue& decoy : decoys.getValues()) {
        const auto contents{HexBytes(decoy)};
        const auto packet{EncryptPacket(sender, contents, aad, /*ignore=*/true)};
        CheckDecryptPacket(receiver, packet, aad, /*ignore=*/true, contents);
        flight.insert(flight.end(), packet.begin(), packet.end());
        aad = {};
    }
    const auto version_packet{EncryptPacket(sender, version_contents, aad, /*ignore=*/false)};
    CheckDecryptPacket(receiver, version_packet, aad, /*ignore=*/false, version_contents);
    flight.insert(flight.end(), version_packet.begin(), version_packet.end());

    BOOST_CHECK_EQUAL(expected_version_packet["stage1_index"].getInt<size_t>(), decoys.size());
    BOOST_CHECK_EQUAL(version_contents.size(), expected_version_packet["contents_len"].getInt<size_t>());
    BOOST_CHECK_EQUAL(Sha256Hex(version_contents), expected_version_packet["contents_sha256"].get_str());
    BOOST_CHECK_EQUAL(version_packet.size(), expected_version_packet["wire_len"].getInt<size_t>());
    BOOST_CHECK_EQUAL(Sha256Hex(version_packet), expected_version_packet["wire_sha256"].get_str());
    BOOST_CHECK_EQUAL(HexStr(version_packet), expected_version_packet["wire"].get_str());
    BOOST_CHECK_EQUAL(flight.size(), expected_handshake["len"].getInt<size_t>());
    BOOST_CHECK_EQUAL(Sha256Hex(flight), expected_handshake["sha256"].get_str());
    BOOST_CHECK_EQUAL(HexStr(flight), expected_handshake["bytes"].get_str());
}

/** Send what follows the version packet in one direction (decoys, then the application packets) and compare
 *  it with the vector: every pinned packet, and the length and hash of the whole stream. first_index is the
 *  sender's packet index, in its current stage, of the first of them. */
void CheckPacketsAfterVersion(BIP324Cipher& sender, BIP324Cipher& receiver, bool from_initiator,
                              const std::vector<std::vector<std::byte>>& decoys, uint32_t first_index,
                              const UniValue& expected)
{
    std::map<uint32_t, const UniValue*> pinned;
    for (const UniValue& entry : expected["entries"].getValues()) {
        pinned.emplace(entry["stage_index"].getInt<uint32_t>(), &entry);
    }
    const uint32_t count{expected["count"].getInt<uint32_t>()};
    BOOST_REQUIRE_GE(count, decoys.size());

    std::vector<std::byte> stream;
    uint32_t index{first_index};
    size_t matched{0};
    const auto send{[&](std::span<const std::byte> contents, bool decoy, uint32_t app_index) {
        const auto packet{EncryptPacket(sender, contents, {}, decoy)};
        CheckDecryptPacket(receiver, packet, {}, decoy, contents);
        if (const auto it{pinned.find(index)}; it != pinned.end()) {
            const UniValue& entry{*it->second};
            BOOST_CHECK_EQUAL(HexStr(packet), entry["wire"].get_str());
            BOOST_CHECK_EQUAL(HexStr(contents), entry["contents"].get_str());
            BOOST_CHECK_EQUAL(entry.exists("decoy") && entry["decoy"].get_bool(), decoy);
            if (!decoy) BOOST_CHECK_EQUAL(entry["app_index"].getInt<uint32_t>(), app_index);
            ++matched;
        }
        stream.insert(stream.end(), packet.begin(), packet.end());
        ++index;
    }};
    for (const auto& decoy : decoys) {
        send(decoy, /*decoy=*/true, 0);
    }
    for (uint32_t i = 0; i < count - decoys.size(); ++i) {
        send(AppContents(from_initiator, i), /*decoy=*/false, i);
    }

    BOOST_CHECK_EQUAL(matched, pinned.size());
    BOOST_CHECK_EQUAL(stream.size(), expected["all_len"].getInt<size_t>());
    BOOST_CHECK_EQUAL(Sha256Hex(stream), expected["all_sha256"].get_str());
}

void SelectVectorParams(const UniValue& handshake)
{
    const std::map<std::string, ChainType> chains{{"mainnet", ChainType::MAIN}, {"testnet", ChainType::TESTNET}, {"regtest", ChainType::REGTEST}};
    const auto chain{chains.find(handshake["network"].get_str())};
    BOOST_REQUIRE(chain != chains.end());
    SelectParams(chain->second);
    BOOST_REQUIRE_EQUAL(HexStr(Params().MessageStart()), handshake["magic"].get_str());
}

V2HybridMode VectorMode(const UniValue& mode)
{
    BOOST_REQUIRE(mode.getInt<int>() >= 0 && mode.getInt<int>() <= 2);
    return static_cast<V2HybridMode>(mode.getInt<int>());
}

CKey VectorKey(const UniValue& hex)
{
    const auto priv{ParseHex(hex.get_str())};
    CKey key;
    key.Set(priv.begin(), priv.end(), true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

/** Run one handshake of src/test/data/hx1_handshake_vectors.json through a pair of ciphers. */
void CheckHX1HandshakeVector(const UniValue& inputs, const UniValue& handshake)
{
    BOOST_TEST_INFO_SCOPE("handshake vector " << handshake["name"].get_str());
    SelectVectorParams(handshake);
    const V2HybridMode initiator_mode{VectorMode(handshake["initiator_mode"])};
    const V2HybridMode responder_mode{VectorMode(handshake["responder_mode"])};
    const bool hybrid{handshake.exists("stage2")};

    const CKey key_initiator{VectorKey(inputs["priv_initiator"])};
    const CKey key_responder{VectorKey(inputs["priv_responder"])};
    BIP324Cipher initiator(key_initiator, HexBytes(inputs["aux_initiator"]));
    BIP324Cipher responder(key_responder, HexBytes(inputs["aux_responder"]));
    const EllSwiftPubKey ell_initiator{initiator.GetOurPubKey()};
    const EllSwiftPubKey ell_responder{responder.GetOurPubKey()};
    BOOST_CHECK_EQUAL(HexStr(PubKeySpan(ell_initiator)), handshake["ell_initiator"].get_str());
    BOOST_CHECK_EQUAL(HexStr(PubKeySpan(ell_responder)), handshake["ell_responder"].get_str());
    const ECDHSecret ecdh_secret{key_initiator.ComputeBIP324ECDHSecret(ell_responder, ell_initiator, /*initiating=*/true)};
    BOOST_CHECK_EQUAL(HexStr(ecdh_secret), handshake["ecdh_secret"].get_str());
    BOOST_CHECK(key_responder.ComputeBIP324ECDHSecret(ell_initiator, ell_responder, /*initiating=*/false) == ecdh_secret);

    initiator.Initialize(ell_responder, /*initiator=*/true, /*self_decrypt=*/false, initiator_mode);
    responder.Initialize(ell_initiator, /*initiator=*/false, /*self_decrypt=*/false, responder_mode);
    BOOST_CHECK_EQUAL(initiator.HasStage2Secret(), initiator_mode != V2HybridMode::OFF);
    BOOST_CHECK_EQUAL(responder.HasStage2Secret(), responder_mode != V2HybridMode::OFF);

    // Stage 1 is BIP324, whatever the mode.
    const UniValue& stage1{handshake["stage1"]};
    for (size_t i = 0; i < STAGE1_KEY_LABELS.size(); ++i) {
        BOOST_CHECK_EQUAL(HexStr(Stage1Output(ecdh_secret, STAGE1_KEY_LABELS[i])), stage1[STAGE1_KEY_LABELS[i]].get_str());
    }
    BOOST_CHECK_EQUAL(HexStr(initiator.GetSessionID()), stage1["session_id"].get_str());
    BOOST_CHECK_EQUAL(HexStr(responder.GetSessionID()), stage1["session_id"].get_str());
    BOOST_CHECK_EQUAL(HexStr(initiator.GetSendGarbageTerminator()), stage1["garbage_terminator_initiator"].get_str());
    BOOST_CHECK_EQUAL(HexStr(initiator.GetReceiveGarbageTerminator()), stage1["garbage_terminator_responder"].get_str());
    BOOST_CHECK_EQUAL(HexStr(responder.GetSendGarbageTerminator()), stage1["garbage_terminator_responder"].get_str());
    BOOST_CHECK_EQUAL(HexStr(responder.GetReceiveGarbageTerminator()), stage1["garbage_terminator_initiator"].get_str());

    std::vector<std::byte> ek, ct, kem_secret;
    if (hybrid) {
        const UniValue& mlkem{handshake["mlkem"]};
        ek = HexBytes(mlkem["ek"]);
        ct = HexBytes(mlkem["ct"]);
        kem_secret = HexBytes(mlkem["shared_secret"]);
        BOOST_REQUIRE_EQUAL(ek.size(), BIP324Cipher::HX1_EK_LEN);
        BOOST_REQUIRE_EQUAL(ct.size(), BIP324Cipher::HX1_CT_LEN);
        BOOST_REQUIRE_EQUAL(kem_secret.size(), BIP324Cipher::HX1_SHARED_SECRET_LEN);
        BOOST_CHECK_EQUAL(Sha256Hex(ek), mlkem["ek_sha256"].get_str());
        BOOST_CHECK_EQUAL(Sha256Hex(ct), mlkem["ct_sha256"].get_str());
    }

    // VP_R carries the OFFER (mode 1 or 2 responder), VP_I the ACCEPT (hybrid only); both use stage-1 keys.
    const auto responder_version{responder_mode != V2HybridMode::OFF ? HX1Record(HX1_KIND_OFFER, ek) : std::vector<std::byte>{}};
    const auto initiator_version{hybrid ? HX1Record(HX1_KIND_ACCEPT, ct) : std::vector<std::byte>{}};
    CheckHandshakeFlight(responder, initiator, HexBytes(inputs["garbage_responder"]), handshake["responder_decoys_before_version"],
                         responder_version, handshake["responder_version_packet"], handshake["responder_handshake"]);
    CheckHandshakeFlight(initiator, responder, HexBytes(inputs["garbage_initiator"]), handshake["initiator_decoys_before_version"],
                         initiator_version, handshake["initiator_version_packet"], handshake["initiator_handshake"]);

    if (hybrid) {
        const UniValue& stage2{handshake["stage2"]};
        CheckStage2ScheduleText(stage2, kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder);
        BIP324Cipher::Stage2Keys keys;
        BIP324Cipher::DeriveStage2Keys(Params().MessageStart(), kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder, keys);
        const auto outputs{Stage2Outputs(keys)};
        for (size_t i = 0; i < STAGE2_LABELS.size(); ++i) {
            BOOST_CHECK_EQUAL(HexStr(outputs[i]), stage2[STAGE2_LABELS[i]].get_str());
        }

        // The initiator switches right after encrypting VP_I, the responder right after decrypting it.
        BOOST_CHECK(initiator.SwitchToStage2(kem_secret, ct, ek));
        BOOST_CHECK(responder.SwitchToStage2(kem_secret, ct, ek));
        for (BIP324Cipher* cipher : {&initiator, &responder}) {
            BOOST_CHECK(cipher->IsStage2());
            BOOST_CHECK(!cipher->HasStage2Secret());
            BOOST_CHECK(!cipher->SwitchToStage2(kem_secret, ct, ek));
            BOOST_CHECK_EQUAL(HexStr(cipher->GetSessionID()), stage2["xcoin_hx1_session_id"].get_str());
        }
    } else {
        // The classical decision: whichever side kept the ECDH secret drops it, and both stay on stage 1.
        initiator.DiscardStage2Secret();
        responder.DiscardStage2Secret();
        for (BIP324Cipher* cipher : {&initiator, &responder}) {
            BOOST_CHECK(!cipher->IsStage2());
            BOOST_CHECK(!cipher->HasStage2Secret());
            BOOST_CHECK_EQUAL(HexStr(cipher->GetSessionID()), stage1["session_id"].get_str());
        }
    }

    // In a hybrid session the responder's stage-2 stream starts with the confirmation packet, a decoy with
    // empty contents; the initiator may send decoys of its own first. Stage 1 continues after the version packet.
    std::vector<std::vector<std::byte>> initiator_decoys, responder_decoys;
    if (hybrid) {
        for (const UniValue& decoy : handshake["initiator_decoys_after_switch"].getValues()) {
            initiator_decoys.push_back(HexBytes(decoy));
        }
        responder_decoys.emplace_back();
    }
    const UniValue& after{handshake["packets_after_version"]};
    for (const char* direction : {"initiator_to_responder", "responder_to_initiator"}) {
        BOOST_CHECK_EQUAL(after[direction]["stage"].getInt<int>(), hybrid ? 2 : 1);
    }
    const uint32_t initiator_first{hybrid ? 0 : uint32_t(handshake["initiator_decoys_before_version"].size() + 1)};
    const uint32_t responder_first{hybrid ? 0 : uint32_t(handshake["responder_decoys_before_version"].size() + 1)};
    CheckPacketsAfterVersion(initiator, responder, /*from_initiator=*/true, initiator_decoys, initiator_first, after["initiator_to_responder"]);
    CheckPacketsAfterVersion(responder, initiator, /*from_initiator=*/false, responder_decoys, responder_first, after["responder_to_initiator"]);

    // What getpeerinfo reports once the other side's first stage-2 packet (or, classical, its version packet) has authenticated.
    const UniValue& reported{handshake["reported"]};
    BOOST_CHECK_EQUAL(HexStr(initiator.GetSessionID()), reported["initiator"]["session_id"].get_str());
    BOOST_CHECK_EQUAL(HexStr(responder.GetSessionID()), reported["responder"]["session_id"].get_str());
    BOOST_CHECK_EQUAL(initiator.IsStage2(), reported["initiator"]["transport_hybrid"].get_bool());
    BOOST_CHECK_EQUAL(responder.IsStage2(), reported["responder"]["transport_hybrid"].get_bool());
}

/** Stage-1 and stage-2 keys for the same connection: the eight packet keys are pairwise different, and so are
 *  the two session ids. */
void CheckStageKeysDistinct(std::span<const std::byte> kem_secret, std::span<const std::byte> ecdh_secret,
                            std::span<const std::byte> ct, const EllSwiftPubKey& ell_initiator,
                            std::span<const std::byte> ek, const EllSwiftPubKey& ell_responder)
{
    BIP324Cipher::Stage2Keys stage2;
    BIP324Cipher::DeriveStage2Keys(Params().MessageStart(), kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder, stage2);
    std::set<std::string> keys;
    for (const std::string& label : STAGE1_KEY_LABELS) {
        keys.insert(HexStr(Stage1Output(ecdh_secret, label)));
    }
    BOOST_CHECK_EQUAL(keys.size(), 4U);
    for (const auto key : {std::span<const std::byte>{stage2.initiator_L}, std::span<const std::byte>{stage2.initiator_P},
                           std::span<const std::byte>{stage2.responder_L}, std::span<const std::byte>{stage2.responder_P}}) {
        keys.insert(HexStr(key));
    }
    BOOST_CHECK_EQUAL(keys.size(), 8U);
    const std::string stage1_session_id{HexStr(Stage1Output(ecdh_secret, "session_id"))};
    BOOST_CHECK(HexStr(stage2.session_id) != stage1_session_id);
    BOOST_CHECK(!keys.contains(HexStr(stage2.session_id)));
    BOOST_CHECK(!keys.contains(stage1_session_id));
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(bip324_tests, BIP324Test)

BOOST_AUTO_TEST_CASE(packet_test_vectors) {
    // BIP324 key derivation mixes the network magic into the HKDF salt. The
    // upstream BIP test vectors are written for Bitcoin's mainnet magic; this
    // chain uses its own, so the mid_/out_ fields below were regenerated under
    // it (the in_ fields are unchanged from the BIP). Regenerated again in
    // stage B4, when the v2 mainnet magic became 'X','P','A',0x03
    // (contrib/regenesis/REGENESIS.md section 8 step 3): re-pinning the magic
    // to 0x02 reproduces the previous mid_/out_ values byte for byte, so the
    // transport itself is untouched.
    SelectParams(ChainType::MAIN);

    // The test vectors are converted using the following Python code in the BIP bip-0324/ directory:
    //
    // import sys
    // import csv
    // with open('packet_encoding_test_vectors.csv', newline='', encoding='utf-8') as csvfile:
    //     reader = csv.DictReader(csvfile)
    //     quote = lambda x: "\"" + x + "\""
    //     for row in reader:
    //         args = [
    //             row['in_idx'],
    //             quote(row['in_priv_ours']),
    //             quote(row['in_ellswift_ours']),
    //             quote(row['in_ellswift_theirs']),
    //             "true" if int(row['in_initiating']) else "false",
    //             quote(row['in_contents']),
    //             row['in_multiply'],
    //             quote(row['in_aad']),
    //             "true" if int(row['in_ignore']) else "false",
    //             quote(row['mid_send_garbage_terminator']),
    //             quote(row['mid_recv_garbage_terminator']),
    //             quote(row['out_session_id']),
    //             quote(row['out_ciphertext']),
    //             quote(row['out_ciphertext_endswith'])
    //         ]
    //         print("    TestBIP324PacketVector(\n        " + ",\n        ".join(args) + ");")
    TestBIP324PacketVector(
        1,
        "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7",
        "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b",
        "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5",
        true,
        "8e",
        1,
        "",
        false,
        "7ca06a9f880b607c19d01b13c9c55f3e",
        "7dc81f60fa23e6deb89bbb9fac494e71",
        "110e6eceea0811c010ec35890c0a392f002145d549a2f13d680729b08b7e057d",
        "ad1266464f621873c15d0026e6420d93c339f986d1",
        "");
    TestBIP324PacketVector(
        999,
        "6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246",
        "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000",
        false,
        "3eb1d4e98035cfd8eeb29bac969ed3824a",
        1,
        "",
        false,
        "0f5a7ae42ed79c1e2f678d8589a91772",
        "3d1d4bde458c07e04ae8e41c8697f2ae",
        "a425ba855fe9974e3ac2261bc9897c87e311ccf6be954733e6ed7eb3c3e8821b",
        "3c828d7168ae05a975e30a7f2d1026d362898f6d096c67ec7f6f159dab958f2b9d2ce337f4",
        "");
    TestBIP324PacketVector(
        0,
        "846a784f1a03dea59cc679754a60a7145542fa130e3efbd815c81e909ce32933",
        "480eacf1536b52257bf8ce78d8f4ce09395d744767c6c129e7838947ee625af3245592c111275e877d5baae22584cb5f1153e67c16bcd7da767726cd0d0c846a",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff22d5e441524d571a52b3def126189d3f416890a99d4da6ede2b0cde1760ce2c3f98457ae",
        true,
        "054290a6c6ba8d80478172e89d32bf690913ae9835de6dcf206ff1f4d652286fe0ddf74deba41d55de3edc77c42a32af79bbea2c00bae7492264c60866ae5a",
        1,
        "84932a55aac22b51e7b128d31d9f0550da28e6a3f394224707d878603386b2f9d0c6bcd8046679bfed7b68c517e7431e75d9dd34605727d2ef1c2babbf680ecc8d68d2c4886e9953a4034abde6da4189cd47c6bb3192242cf714d502ca6103ee84e08bc2ca4fd370d5ad4e7d06c7fbf496c6c7cc7eb19c40c61fb33df2a9ba48497a96c98d7b10c1f91098a6b7b16b4bab9687f27585ade1491ae0dba6a79e1e2d85dd9d9d45c5135ca5fca3f0f99a60ea39edbc9efc7923111c937913f225d67788d5f7e8852b697e26b92ec7bfcaa334a1665511c2b4c0a42d06f7ab98a9719516c8fd17f73804555ee84ab3b7d1762f6096b778d3cb9c799cbd49a9e4a325197b4e6cc4a5c4651f8b41ff88a92ec428354531f970263b467c77ed11312e2617d0d53fe9a8707f51f9f57a77bfb49afe3d89d85ec05ee17b9186f360c94ab8bb2926b65ca99dae1d6ee1af96cad09de70b6767e949023e4b380e66669914a741ed0fa420a48dbc7bfae5ef2019af36d1022283dd90655f25eec7151d471265d22a6d3f91dc700ba749bb67c0fe4bc0888593fbaf59d3c6fff1bf756a125910a63b9682b597c20f560ecb99c11a92c8c8c3f7fbfaa103146083a0ccaecf7a5f5e735a784a8820155914a289d57d8141870ffcaf588882332e0bcd8779efa931aa108dab6c3cce76691e345df4a91a03b71074d66333fd3591bff071ea099360f787bbe43b7b3dff2a59c41c7642eb79870222ad1c6f2e5a191ed5acea51134679587c9cf71c7d8ee290be6bf465c4ee47897a125708704ad610d8d00252d01959209d7cd04d5ecbbb1419a7e84037a55fefa13dee464b48a35c96bcb9a53e7ed461c3a1607ee00c3c302fd47cd73fda7493e947c9834a92d63dcfbd65aa7c38c3e3a2748bb5d9a58e7495d243d6b741078c8f7ee9c8813e473a323375702702b0afae1550c8341eedf5247627343a95240cb02e3e17d5dca16f8d8d3b2228e19c06399f8ec5c5e9dbe4caef6a0ea3ffb1d3c7eac03ae030e791fa12e537c80d56b55b764cadf27a8701052df1282ba8b5e3eb62b5dc7973ac40160e00722fa958d95102fc25c549d8c0e84bed95b7acb61ba65700c4de4feebf78d13b9682c52e937d23026fb4c6193e6644e2d3c99f91f4f39a8b9fc6d013f89c3793ef703987954dc0412b550652c01d922f525704d32d70d6d4079bc3551b563fb29577b3aecdc9505011701dddfd94830431e7a4918927ee44fb3831ce8c4513839e2deea1287f3fa1ab9b61a256c09637dbc7b4f0f8fbb783840f9c24526da883b0df0c473cf231656bd7bc1aaba7f321fec0971c8c2c3444bff2f55e1df7fea66ec3e440a612db9aa87bb505163a59e06b96d46f50d8120b92814ac5ab146bc78dbbf91065af26107815678ce6e33812e6bf3285d4ef3b7b04b076f21e7820dcbfdb4ad5218cf4ff6a65812d8fcb98ecc1e95e2fa58e3efe4ce26cd0bd400d6036ab2ad4f6c713082b5e3f1e04eb9e3b6c8f63f57953894b9e220e0130308e1fd91f72d398c1e7962ca2c31be83f31d6157633581a0a6910496de8d55d3d07090b6aa087159e388b7e7dec60f5d8a60d93ca2ae91296bd484d916bfaaa17c8f45ea4b1a91b37c82821199a2b7596672c37156d8701e7352aa48671d3b1bbbd2bd5f0a2268894a25b0cb2514af39c8743f8cce8ab4b523053739fd8a522222a09acf51ac704489cf17e4b7125455cb8f125b4d31af1eba1f8cf7f81a5a100a141a7ee72e8083e065616649c241f233645c5fc865d17f0285f5c52d9f45312c979bfb3ce5f2a1b951deddf280ffb3f370410cffd1583bfa90077835aa201a0712d1dcd1293ee177738b14e6b5e2a496d05220c3253bb6578d6aff774be91946a614dd7e879fb3dcf7451e0b9adb6a8c44f53c2c464bcc0019e9fad89cac7791a0a3f2974f759a9856351d4d2d7c5612c17cfc50f8479945df57716767b120a590f4bf656f4645029a525694d8a238446c5f5c2c1c995c09c1405b8b1eb9e0352ffdf766cc964f8dcf9f8f043dfab6d102cf4b298021abd78f1d9025fa1f8e1d710b38d9d1652f2d88d1305874ec41609b6617b65c5adb19b6295dc5c5da5fdf69f28144ea12f17c3c6fcce6b9b5157b3dfc969d6725fa5b098a4d9b1d31547ed4c9187452d281d0a5d456008caf1aa251fac8f950ca561982dc2dc908d3691ee3b6ad3ae3d22d002577264ca8e49c523bd51c4846be0d198ad9407bf6f7b82c79893eb2c05fe9981f687a97a4f01fe45ff8c8b7ecc551135cd960a0d6001ad35020be07ffb53cb9e731522ca8ae9364628914b9b8e8cc2f37f03393263603cc2b45295767eb0aac29b0930390eb89587ab2779d2e3decb8042acece725ba42eda650863f418f8d0d50d104e44fbbe5aa7389a4a144a8cecf00f45fb14c39112f9bfb56c0acbd44fa3ff261f5ce4acaa5134c2c1d0cca447040820c81ab1bcdc16aa075b7c68b10d06bbb7ce08b5b805e0238f24402cf24a4b4e00701935a0c68add3de090903f9b85b153cb179a582f57113bfc21c2093803f0cfa4d9d4672c2b05a24f7e4c34a8e9101b70303a7378b9c50b6cddd46814ef7fd73ef6923feceab8fc5aa8b0d185f2e83c7a99dcb1077c0ab5c1f5d5f01ba2f0420443f75c4417db9ebf1665efbb33dca224989920a64b44dc26f682cc77b4632c8454d49135e52503da855bc0f6ff8edc1145451a9772c06891f41064036b66c3119a0fc6e80dffeb65dc456108b7ca0296f4175fff3ed2b0f842cd46bd7e86f4c62dfaf1ddbf836263c00b34803de164983d0811cebfac86e7720c726d3048934c36c23189b02386a722ca9f0fe00233ab50db928d3bccea355cc681144b8b7edcaae4884d5a8f04425c0890ae2c74326e138066d8c05f4c82b29df99b034ea727afde590a1f2177ace3af99cfb1729d6539ce7f7f7314b046aab74497e63dd399e1f7d5f16517c23bd830d1fdee810f3c3b77573dd69c4b97d80d71fb5a632e00acdfa4f8e829faf3580d6a72c40b28a82172f8dcd4627663ebf6069736f21735fd84a226f427cd06bb055f94e7c92f31c48075a2955d82a5b9d2d0198ce0d4e131a112570a8ee40fb80462a81436a58e7db4e34b6e2c422e82f934ecda9949893da5730fc5c23c7c920f363f85ab28cc6a4206713c3152669b47efa8238fa826735f17b4e78750276162024ec85458cd5808e06f40dd9fd43775a456a3ff6cae90550d76d8b2899e0762ad9a371482b3e38083b1274708301d6346c22fea9bb4b73db490ff3ab05b2f7f9e187adef139a7794454b7300b8cc64d3ad76c0e4bc54e08833a4419251550655380d675bc91855aeb82585220bb97f03e976579c08f321b5f8f70988d3061f41465517d53ac571dbf1b24b94443d2e9a8e8a79b392b3d6a4ecdd7f626925c365ef6221305105ce9b5f5b6ecc5bed3d702bd4b7f5008aa8eb8c7aa3ade8ecf6251516fbefeea4e1082aa0e1848eddb31ffe44b04792d296054402826e4bd054e671f223e5557e4c94f89ca01c25c44f1a2ff2c05a70b43408250705e1b858bf0670679fdcd379203e36be3500dd981b1a6422c3cf15224f7fefdef0a5f225c5a09d15767598ecd9e262460bb33a4b5d09a64591efabc57c923d3be406979032ae0bc0997b65336a06dd75b253332ad6a8b63ef043f780a1b3fb6d0b6cad98b1ef4a02535eb39e14a866cfc5fc3a9c5deb2261300d71280ebe66a0776a151469551c3c5fa308757f956655278ec6330ae9e3625468c5f87e02cd9a6489910d4143c1f4ee13aa21a6859d907b788e28572fecee273d44e4a900fa0aa668dd861a60fb6b6b12c2c5ef3c8df1bd7ef5d4b0d1cdb8c15fffbb365b9784bd94abd001c6966216b9b67554ad7cb7f958b70092514f7800fc40244003e0fd1133a9b850fb17f4fcafde07fc87b07fb510670654a5d2d6fc9876ac74728ea41593beef003d6858786a52d3a40af7529596767c17000bfaf8dc52e871359f4ad8bf6e7b2853e5229bdf39657e213580294a5317c5df172865e1e17fe37093b585e04613f5f078f761b2b1752eb32983afda24b523af8851df9a02b37e77f543f18888a782a994a50563334282bf9cdfccc183fdf4fcd75ad86ee0d94f91ee2300a5befbccd14e03a77fc031a8cfe4f01e4c5290f5ac1da0d58ea054bd4837cfd93e5e34fc0eb16e48044ba76131f228d16cde9b0bb978ca7cdcd10653c358bdb26fdb723a530232c32ae0a4cecc06082f46e1c1d596bfe60621ad1e354e01e07b040cc7347c016653f44d926d13ca74e6cbc9d4ab4c99f4491c95c76fff5076b3936eb9d0a286b97c035ca88a3c6309f5febfd4cdaac869e4f58ed409b1e9eb4192fb2f9c2f12176d460fd98286c9d6df84598f260119fd29c63f800c07d8df83d5cc95f8c2fea2812e7890e8a0718bb1e031ecbebc0436dcf3e3b9a58bcc06b4c17f711f80fe1dffc3326a6eb6e00283055c6dabe20d311bfd5019591b7954f8163c9afad9ef8390a38f3582e0a79cdf0353de8eeb6b5f9f27b16ffdef7dd62869b4840ee226ccdce95e02c4545eb981b60571cd83f03dc5eaf8c97a0829a4318a9b3dc06c0e003db700b2260ff1fa8fee66890e637b109abb03ec901b05ca599775f48af50154c0e67d82bf0f558d7d3e0778dc38bea1eb5f74dc8d7f90abdf5511a424be66bf8b6a3cacb477d2e7ef4db68d2eba4d5289122d851f9501ba7e9c4957d8eba3be3fc8e785c4265a1d65c46f2809b70846c693864b169c9dcb78be26ea14b8613f145b01887222979a9e67aee5f800caa6f5c4229bdeefc901232ace6143c9865e4d9c07f51aa200afaf7e48a7d1d8faf366023beab12906ffcb3eaf72c0eb68075e4daf3c080e0c31911befc16f0cc4a09908bb7c1e26abab38bd7b788e1a09c0edf1a35a38d2ff1d3ed47fcdaae2f0934224694f5b56705b9409b6d3d64f3833b686f7576ec64bbdd6ff174e56c2d1edac0011f904681a73face26573fbba4e34652f7ae84acfb2fa5a5b3046f98178cd0831df7477de70e06a4c00e305f31aafc026ef064dd68fd3e4252b1b91d617b26c6d09b6891a00df68f105b5962e7f9d82da101dd595d286da721443b72b2aba2377f6e7772e33b3a5e3753da9c2578c5d1daab80187f55518c72a64ee150a7cb5649823c08c9f62cd7d020b45ec2cba8310db1a7785a46ab24785b4d54ff1660b5ca78e05a9a55edba9c60bf044737bc468101c4e8bd1480d749be5024adefca1d998abe33eaeb6b11fbb39da5d905fdd3f611b2e51517ccee4b8af72c2d948573505590d61a6783ab7278fc43fe55b1fcc0e7216444d3c8039bb8145ef1ce01c50e95a3f3feab0aee883fdb94cc13ee4d21c542aa795e18932228981690f4d4c57ca4db6eb5c092e29d8a05139d509a8aeb48baa1eb97a76e597a32b280b5e9d6c36859064c98ff96ef5126130264fa8d2f49213870d9fb036cff95da51f270311d9976208554e48ffd486470d0ecdb4e619ccbd8226147204baf8e235f54d8b1cba8fa34a9a4d055de515cdf180d2bb6739a175183c472e30b5c914d09eeb1b7dafd6872b38b48c6afc146101200e6e6a44fe5684e220adc11f5c403ddb15df8051e6bdef09117a3a5349938513776286473a3cf1d2788bb875052a2e6459fa7926da33380149c7f98d7700528a60c954e6f5ecb65842fde69d614be69eaa2040a4819ae6e756accf936e14c1e894489744a79c1f2c1eb295d13e2d767c09964b61f9cfe497649f712",
        false,
        "e8a75c58fb2257163a1f791778371d71",
        "9b3eedbebf85dfb5a8f672d32581a18d",
        "086011e78b079e231c5b5430457ec5344b8ec0c3d50da53157ec7297896327ca",
        "6bfaea35229fdcf4c56998a1225615ab4aa8b79bc1f27bdbf1029647bf97e21c5e340bcd5aee500decf33175eda9a8e621cda959c7bf40e720c2c00df06f4ae486f5eaf30da6c24448f4f1c58c579082592782",
        "");
    TestBIP324PacketVector(
        223,
        "c0f15820459f64d98e5c48681d13340572c574533dd9f7161b85fcc8224fdf30",
        "682871104d694baca8b9c7990ae6288f49e1ff4feb21dd5cffad67db7752fdfb6c3608d6996c54be04b35feef037da09ee4d9dca2363b343bc2d4f6d0ea609da",
        "56bd0c06f10352c3a1a9f4b4c92f6fa2b26df124b57878353c1fc691c51abea77c8817daeeb9fa546b77c8daf79d89b22b0e1b87574ece42371f00237aa9d83a",
        false,
        "7e0e78eb6990b059e6cf0ded66ea93ef82e72aa2f18ac24f2fc6ebab561ae557420729da103f64cecfa20527e15f9fb669a49bbbf274ef0389b3e43c8c44e5f60bf2ac38e2b55e7ec4273dba15ba41d21f8f5b3ee1688b3c29951218caf847a97fb50d75a86515d445699497d968164bf740012679b8962de573be941c62b7ef",
        1,
        "",
        true,
        "9d787b4c8e993f5b3de568d6db06e9c1",
        "aecaaf60c5bd25e6508e58cc13aefcf8",
        "0e2d4a0a3ebbf9edbd0a96e02b0c496268cf207ea8bb57ebab7d0172e52d7f25",
        "",
        "89cdd5430098198c6279a8f13557aaa913cf146c54754dd62b02fb87f8793c6852064bfcf33950a27347fc6dcd566dc1e1dda4bed18a5dcddd475b8cf4ea2f0a8c81c01c511bd543212a7af38312668df27cd49e3375412a2ad8f8a02de51a7555f70f7751d7bb15fdf5a9baa27b05763d9925012f508512aa78fd815aa752b4");
    TestBIP324PacketVector(
        448,
        "96cb391886681d1d3e23948e51987771a8ec3001b640c18fb994a855cea66b6e",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffdde3a077a6fd73711a27250c439ba78ef63d89cd0918c0a0a75f301ed96aa2a43ecf3f61",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7730be30000000000000000000000000000000000000000000000000000000000000000",
        true,
        "00cf68f8f7ac49ffaa02c4864fdf6dfe7bbf2c740b88d98c50ebafe32c92f3427f57601ffcb21a3435979287db8fee6c302926741f9d5e464c647eeb9b7acaeda46e00abd7506fc9a719847e9a7328215801e96198dac141a15c7c2f68e0690dd1176292a0dded04d1f548aad88f1aebdc0a8f87da4bb22df32dd7c160c225b843e83f6525d6d484f502f16d923124fc538794e21da2eb689d18d87406ecced5b9f92137239ed1d37bcfa7836641a83cf5e0a1cf63f51b06f158e499a459ede41c",
        1,
        "",
        false,
        "f22b37b12ee205ad2db81ad1fc1266d4",
        "7fa4b2e87e5b7673405e822abc112aa3",
        "1e54623ba774da4c2dfcfd1522eb4d23e3f6218337658392f75d93ac9ee82294",
        "",
        "76ee86043eb1ace6a91bdaa4a91048629bc51461755bc0b16973d391cbd2a6315ca7fcd6f7bb9a7aaeb9e870aed47825e4525fb77a77779ae350094f08ace4708816124b382ad7be96e1c74f7550cf44f7344b5bfaba6cdc8499cad33c7246e2361c61cb6eccee209941e5077a492c9c1928c1fb79563e32af7a2c6160b1f333");
    TestBIP324PacketVector(
        673,
        "4a7065c3ddbf84e29b8e20da0da3aaae1f708eae8ad1af4c4c00f46a7cda7b6b",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff450012ec3aeecf516f4b374af2e7fbb040e92dc3c0f12eafd00c729a137f4e892e5293c3",
        "9652d78baefc028cd37a6a92625b8b8f85fde1e4c944ad3f20e198bef8c02f19fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2e91870",
        false,
        "5c6272ee55da855bbbf7b1246d9885aa7aa601a715ab86fa46c50da533badf82b97597c968293ae04e",
        97561,
        "",
        false,
        "192f810a83e06c4aae3dc91ff6aa9f2e",
        "f2bef17a46c9a09ae4977e3ef5e71066",
        "97fa99756f042b62759ac6723a29436c1fe964192aa64b187aac6826bfe0f2cf",
        "",
        "63b9b80fd9490f9ea31e764e01b4875d85bbdb510e43c2cbe959212ff9b9e97af4fadfe79896451676ecb27cf6b0da015517c78ab4317a5b44a3f529ed108322859519598bc4e5a090fa759ecc50f2befc036a3f315527c3cb3eff72cfc77aae13f8bb8393b046e7902086722849afcb36dc3300f0156ef3d1ebcbe0791cf224");
    TestBIP324PacketVector(
        1024,
        "0f69aeffeff6172647ee5aa80bfb418ee742f4e9f1a51b463ac7c120d620e37d",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff04df0e67f9753e2cdb066b3b588a0069fde936a312e0d3f31acb335026b7072d8f2ad24c",
        "12a50f3fafea7c1eeada4cf8d33777704b77361453afc83bda91eef349ae044d20126c6200547ea5a6911776c05dee2a7f1a9ba7dfbabbbd273c3ef29ef46e46",
        true,
        "5f67d15d22ca9b2804eeab0a66f7f8e3a10fa5de5809a046084348cbc5304e843ef96f59a59c7d7fdfe5946489f3ea297d941bac326225df316a25fc90f0e65b0d31a9c497e960fdbf8c482516bc8a9c1c77b7f6d0e1143810c737f76f9224e6f2c9af5186b4f7259c7e8d165b6e4fe3d38a60bdbdd4d06ecdcaaf62086070dbb68686b802d53dfd7db14b18743832605f5461ad81e2af4b7e8ff0eff0867a25b93cec7becf15c43131895fed09a83bf1ee4a87d44dd0f02a837bf5a1232e201cb882734eb9643dc2dc4d4e8b5690840766212c7ac8f38ad8a9ec47c7a9b3e022ae3eb6a32522128b518bd0d0085dd81c5",
        69615,
        "",
        true,
        "acacaa13f62d37a7b55cf29fdb7631ec",
        "1bad0555a6087edeea674635850772c2",
        "69c6afbcea2ea172d621413ac1bd6b4c85277cd805adf1ef18a761a9f0c9a901",
        "",
        "828c423a832e5daeaf6a9fa0db17b933321a7ca0fba894b0a71c0a6b67b689a37ace89937858340572df61b8e7e36c9805434bac9833a0f9d40c4890020cd20434f78f162cc4854eef645edb0c028e3c4e2a99f8a17c32e1345d0ba3434c13a6d54fc7121c7eb0dd75b80828932791e117abbb165c11e11b57a3fb4afe7ffe78");
}

BOOST_AUTO_TEST_CASE(hx1_handshake_vectors)
{
    // XIP-4's pinned HX1 handshakes (src/test/data/hx1_handshake_vectors.json, from
    // contrib/testgen/gen_hx1_handshake_vectors.py) through pairs of ciphers: stage-1 and stage-2 keys, both
    // session ids, the version packets and 226 application packets each way after them, on mainnet, testnet A
    // and regtest, with and without decoys, and a prefer-mode initiator meeting a classical responder.
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::hx1_handshake_vectors)); // an object, so not read_json (which wants an array)
    BOOST_REQUIRE(vectors.isObject());
    const UniValue& handshakes{vectors["handshakes"]};
    BOOST_REQUIRE_EQUAL(handshakes.size(), 5U);
    std::set<std::string> hybrid_networks;
    for (const UniValue& handshake : handshakes.getValues()) {
        CheckHX1HandshakeVector(vectors["inputs"], handshake);
        if (handshake.exists("stage2")) hybrid_networks.insert(handshake["network"].get_str());
    }
    BOOST_CHECK((hybrid_networks == std::set<std::string>{"mainnet", "testnet", "regtest"}));
}

BOOST_AUTO_TEST_CASE(hx1_stage2_keys_distinct)
{
    // Both stages start their counters at 0, so they never reuse a key and nonce pair only because the eight
    // packet keys, four per stage, are pairwise different (XIP-4, "Stage-2 key schedule").
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::hx1_handshake_vectors));
    std::set<std::string> initiator_keys;
    for (const UniValue& handshake : vectors["handshakes"].getValues()) {
        if (!handshake.exists("stage2")) continue;
        SelectVectorParams(handshake);
        const UniValue& mlkem{handshake["mlkem"]};
        const EllSwiftPubKey ell_initiator{HexBytes(handshake["ell_initiator"])};
        const EllSwiftPubKey ell_responder{HexBytes(handshake["ell_responder"])};
        CheckStageKeysDistinct(HexBytes(mlkem["shared_secret"]), HexBytes(handshake["ecdh_secret"]), HexBytes(mlkem["ct"]),
                               ell_initiator, HexBytes(mlkem["ek"]), ell_responder);
        initiator_keys.insert(handshake["stage2"]["xcoin_hx1_initiator_L"].get_str());
    }
    // Every vector has the same ML-KEM and ECDH inputs; only MessageStart, in the salt, tells the networks apart.
    BOOST_CHECK_EQUAL(initiator_keys.size(), 3U);

    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        SelectParams(chain);
        for (int i = 0; i < 8; ++i) {
            const CKey key_initiator{GenerateRandomKey()};
            const CKey key_responder{GenerateRandomKey()};
            const EllSwiftPubKey ell_initiator{key_initiator.EllSwiftCreate(m_rng.randbytes<std::byte>(32))};
            const EllSwiftPubKey ell_responder{key_responder.EllSwiftCreate(m_rng.randbytes<std::byte>(32))};
            const ECDHSecret ecdh_secret{key_initiator.ComputeBIP324ECDHSecret(ell_responder, ell_initiator, /*initiating=*/true)};
            CheckStageKeysDistinct(m_rng.randbytes<std::byte>(BIP324Cipher::HX1_SHARED_SECRET_LEN), ecdh_secret,
                                   m_rng.randbytes<std::byte>(BIP324Cipher::HX1_CT_LEN), ell_initiator,
                                   m_rng.randbytes<std::byte>(BIP324Cipher::HX1_EK_LEN), ell_responder);
        }
    }
}

BOOST_AUTO_TEST_CASE(hx1_stage2_ciphers)
{
    // After SwitchToStage2() both directions start again at packet 0 under new keys: the same contents encrypt
    // differently in each direction and in each stage, and a stage-2 packet does not authenticate under the
    // stage-1 keys, with the stage-1 counters restarted or continued.
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::hx1_handshake_vectors));
    const UniValue& inputs{vectors["inputs"]};
    const UniValue& v1{vectors["handshakes"][0]};
    SelectVectorParams(v1);
    const auto ek{HexBytes(v1["mlkem"]["ek"])};
    const auto ct{HexBytes(v1["mlkem"]["ct"])};
    const auto kem_secret{HexBytes(v1["mlkem"]["shared_secret"])};
    const CKey key_initiator{VectorKey(inputs["priv_initiator"])};
    const CKey key_responder{VectorKey(inputs["priv_responder"])};
    const auto aux_initiator{HexBytes(inputs["aux_initiator"])};
    const auto aux_responder{HexBytes(inputs["aux_responder"])};

    BIP324Cipher initiator(key_initiator, aux_initiator);
    BIP324Cipher responder(key_responder, aux_responder);
    const EllSwiftPubKey ell_initiator{initiator.GetOurPubKey()};
    const EllSwiftPubKey ell_responder{responder.GetOurPubKey()};
    initiator.Initialize(ell_responder, /*initiator=*/true, /*self_decrypt=*/false, V2HybridMode::PREFER);
    responder.Initialize(ell_initiator, /*initiator=*/false, /*self_decrypt=*/false, V2HybridMode::REQUIRE);
    BOOST_REQUIRE(initiator.SwitchToStage2(kem_secret, ct, ek));
    BOOST_REQUIRE(responder.SwitchToStage2(kem_secret, ct, ek));
    BIP324Cipher stage1_initiator(key_initiator, aux_initiator);
    BIP324Cipher stage1_responder(key_responder, aux_responder);
    stage1_initiator.Initialize(ell_responder, /*initiator=*/true);
    stage1_responder.Initialize(ell_initiator, /*initiator=*/false);

    const auto contents{m_rng.randbytes<std::byte>(100)};
    const auto stage1_to_responder{EncryptPacket(stage1_initiator, contents, {}, /*ignore=*/false)};
    const auto stage1_to_initiator{EncryptPacket(stage1_responder, contents, {}, /*ignore=*/false)};
    const auto stage2_to_responder{EncryptPacket(initiator, contents, {}, /*ignore=*/false)};
    const auto stage2_to_initiator{EncryptPacket(responder, contents, {}, /*ignore=*/false)};
    const std::set<std::vector<std::byte>> packets{stage1_to_responder, stage1_to_initiator, stage2_to_responder, stage2_to_initiator};
    BOOST_CHECK_EQUAL(packets.size(), 4U);

    CheckDecryptPacket(responder, stage2_to_responder, {}, /*ignore=*/false, contents);
    CheckDecryptPacket(initiator, stage2_to_initiator, {}, /*ignore=*/false, contents);

    for (const bool to_responder : {true, false}) {
        const CKey& key{to_responder ? key_responder : key_initiator};
        const auto& aux{to_responder ? aux_responder : aux_initiator};
        const EllSwiftPubKey& their_pubkey{to_responder ? ell_initiator : ell_responder};
        const auto& stage2_packet{to_responder ? stage2_to_responder : stage2_to_initiator};
        BIP324Cipher restarted(key, aux);
        restarted.Initialize(their_pubkey, /*initiator=*/!to_responder);
        BOOST_CHECK(!Authenticates(restarted, stage2_packet));
        BIP324Cipher continued(key, aux);
        continued.Initialize(their_pubkey, /*initiator=*/!to_responder);
        BOOST_CHECK(Authenticates(continued, to_responder ? stage1_to_responder : stage1_to_initiator));
        BOOST_CHECK(!Authenticates(continued, stage2_packet));
    }

    // self_decrypt swaps the stage-2 ciphers the way it swaps the stage-1 ones.
    BIP324Cipher self_decrypt(key_initiator, aux_initiator);
    self_decrypt.Initialize(ell_responder, /*initiator=*/true, /*self_decrypt=*/true, V2HybridMode::PREFER);
    BOOST_REQUIRE(self_decrypt.SwitchToStage2(kem_secret, ct, ek));
    CheckDecryptPacket(self_decrypt, stage2_to_responder, {}, /*ignore=*/false, contents);
}

BOOST_AUTO_TEST_CASE(hx1_mode_off_keeps_nothing)
{
    // The XIP-4 kill switch at the cipher: with V2HybridMode::OFF, the default, Initialize() wipes the ECDH secret
    // where BIP324 always has and allocates no HX1 state, and SwitchToStage2() refuses. Stage 1 is the same in
    // every mode. A secret that is kept lives in the locked pool and leaves it on discard or destruction.
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::hx1_handshake_vectors));
    const UniValue& inputs{vectors["inputs"]};
    const UniValue& v1{vectors["handshakes"][0]};
    SelectVectorParams(v1);
    const auto ek{HexBytes(v1["mlkem"]["ek"])};
    const auto ct{HexBytes(v1["mlkem"]["ct"])};
    const auto kem_secret{HexBytes(v1["mlkem"]["shared_secret"])};
    const CKey key_initiator{VectorKey(inputs["priv_initiator"])};
    const auto aux_initiator{HexBytes(inputs["aux_initiator"])};
    const auto garbage_initiator{HexBytes(inputs["garbage_initiator"])};
    const EllSwiftPubKey ell_responder{HexBytes(v1["ell_responder"])};

    LockedPoolManager& pool{LockedPoolManager::Instance()};
    size_t key_alloc;
    {
        const size_t before{pool.stats().used};
        const CKey copy{key_initiator};
        key_alloc = pool.stats().used - before;
    }
    BOOST_REQUIRE_GT(key_alloc, 0U);

    const auto contents{m_rng.randbytes<std::byte>(50)};
    std::optional<std::vector<std::byte>> first_packet;
    for (const std::optional<V2HybridMode> mode : {std::optional<V2HybridMode>{}, std::optional{V2HybridMode::OFF},
                                                   std::optional{V2HybridMode::PREFER}, std::optional{V2HybridMode::REQUIRE}}) {
        BIP324Cipher cipher(key_initiator, aux_initiator);
        const size_t before{pool.stats().used};
        if (mode) {
            cipher.Initialize(ell_responder, /*initiator=*/true, /*self_decrypt=*/false, *mode);
        } else {
            cipher.Initialize(ell_responder, /*initiator=*/true);
        }
        if (!mode || *mode == V2HybridMode::OFF) {
            BOOST_CHECK(!cipher.HasStage2Secret());
            BOOST_CHECK_EQUAL(pool.stats().used + key_alloc, before);
            BOOST_CHECK(!cipher.SwitchToStage2(kem_secret, ct, ek));
        } else {
            BOOST_CHECK(cipher.HasStage2Secret());
            BOOST_CHECK_GT(pool.stats().used + key_alloc, before);
            BOOST_CHECK(!cipher.SwitchToStage2(std::span{kem_secret}.first(BIP324Cipher::HX1_SHARED_SECRET_LEN - 1), ct, ek));
            BOOST_CHECK(!cipher.SwitchToStage2(kem_secret, std::span{ct}.first(BIP324Cipher::HX1_CT_LEN - 1), ek));
            BOOST_CHECK(!cipher.SwitchToStage2(kem_secret, ct, std::span{ek}.first(BIP324Cipher::HX1_EK_LEN - 1)));
            BOOST_CHECK(cipher.HasStage2Secret());
            cipher.DiscardStage2Secret();
            BOOST_CHECK(!cipher.HasStage2Secret());
            BOOST_CHECK_EQUAL(pool.stats().used + key_alloc, before);
            BOOST_CHECK(!cipher.SwitchToStage2(kem_secret, ct, ek));
        }
        BOOST_CHECK(!cipher.IsStage2());
        BOOST_CHECK_EQUAL(HexStr(cipher.GetSessionID()), v1["stage1"]["session_id"].get_str());
        const auto packet{EncryptPacket(cipher, contents, garbage_initiator, /*ignore=*/false)};
        if (!first_packet) first_packet = packet;
        BOOST_CHECK(packet == *first_packet);
    }

    const size_t before{pool.stats().used};
    {
        BIP324Cipher cipher(key_initiator, aux_initiator);
        cipher.Initialize(ell_responder, /*initiator=*/true, /*self_decrypt=*/false, V2HybridMode::PREFER);
        BOOST_CHECK(cipher.HasStage2Secret());
        BOOST_CHECK_GT(pool.stats().used, before);
    }
    BOOST_CHECK_EQUAL(pool.stats().used, before);
}

BOOST_AUTO_TEST_SUITE_END()
