// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// HX1 (XIP-4): a V2Transport in either role against a scripted peer that sends what the fuzzer chooses (garbage,
// decoys, any version packet contents, stage-2 packets under the right or a wrong key, split however it likes), and
// the version packet record parser on its own. The expected reaction is worked out here from the XIP's tables,
// independently of the transport's parser.
//
// Input layout, for seed generators: integers are read from the end of the input and byte strings from the front,
// in the order the code consumes them (contrib/testgen/gen_hx1_fuzz_seeds.py mirrors it).

#include <bip324.h>
#include <chainparams.h>
#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <key.h>
#include <net.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <pubkey.h>
#include <random.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>
#include <util/expected.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr uint8_t KIND_OFFER{0x01};
constexpr uint8_t KIND_ACCEPT{0x02};
constexpr size_t HEADER_LEN{12};
constexpr size_t FIRST_PACKET_MAX{4095};
constexpr std::array<uint8_t, 8> TAG{'x', 'c', 'o', 'i', 'n', '-', 'p', 'q'};

enum class Class { NONE, MALFORMED, VALID };

/** XIP-4 "Version packet contents", row by row. */
Class Classify(std::span<const uint8_t> contents, uint8_t kind)
{
    if (contents.size() < 9 || !std::ranges::equal(contents.first(8), TAG)) return Class::NONE;
    if (contents[8] != 0x01) return Class::NONE;
    if (contents.size() < HEADER_LEN) return Class::MALFORMED;
    const size_t body_len{kind == KIND_OFFER ? mlkem768::ENCAPS_KEY_SIZE : mlkem768::CIPHERTEXT_SIZE};
    if (contents[9] != kind || static_cast<size_t>(contents[10] | (contents[11] << 8)) != body_len) return Class::MALFORMED;
    if (contents.size() < HEADER_LEN + body_len) return Class::MALFORMED;
    return Class::VALID;
}

Class FromTransport(V2Transport::HybridRecord record)
{
    switch (record) {
    case V2Transport::HybridRecord::NONE: return Class::NONE;
    case V2Transport::HybridRecord::MALFORMED: return Class::MALFORMED;
    case V2Transport::HybridRecord::VALID: return Class::VALID;
    }
    assert(false);
}

/** An HX1 record: tag, version, kind, body length (little-endian), body. */
std::vector<uint8_t> Record(uint8_t kind, std::span<const uint8_t> body, uint8_t version = 0x01)
{
    std::vector<uint8_t> ret(TAG.begin(), TAG.end());
    ret.push_back(version);
    ret.push_back(kind);
    ret.push_back(body.size() & 0xff);
    ret.push_back((body.size() >> 8) & 0xff);
    ret.insert(ret.end(), body.begin(), body.end());
    return ret;
}

std::vector<uint8_t> Bytes(std::span<const std::byte> data)
{
    return {UCharCast(data.data()), UCharCast(data.data()) + data.size()};
}

void Append(std::vector<uint8_t>& to, std::span<const uint8_t> more)
{
    to.insert(to.end(), more.begin(), more.end());
}

/** Packet contents of a message in the long type encoding: 0x00, 12 bytes of type, payload. */
std::vector<uint8_t> LongMessage(const std::string& type, std::span<const uint8_t> payload)
{
    std::vector<uint8_t> ret(1 + CMessageHeader::MESSAGE_TYPE_SIZE);
    std::ranges::copy(type, ret.begin() + 1);
    Append(ret, payload);
    return ret;
}

template <size_t N>
std::array<std::byte, N> ConsumeArray(FuzzedDataProvider& provider)
{
    std::array<std::byte, N> ret{};
    std::ranges::copy(provider.ConsumeBytes<std::byte>(N), ret.begin());
    return ret;
}

V2HybridMode ConsumeMode(FuzzedDataProvider& provider)
{
    return static_cast<V2HybridMode>(provider.ConsumeIntegralInRange<uint8_t>(0, 2));
}

/** The other end of the tested transport, driven through a BIP324Cipher of its own. It keeps its ECDH secret, so
 *  that it can switch to stage 2 with whatever ML-KEM secret the test likes. */
class Peer
{
    BIP324Cipher m_cipher;
    const bool m_initiator;
    std::vector<uint8_t> m_send_aad; //!< our garbage, the AAD of our first packet
    std::vector<uint8_t> m_recv_aad; //!< the transport's garbage, the AAD of its first packet

public:
    struct Packet {
        bool ignore;
        std::vector<uint8_t> contents;
    };

    Peer(const CKey& key, std::span<const std::byte> ent32, bool initiator) : m_cipher{key, ent32}, m_initiator{initiator} {}

    std::span<const std::byte> SessionID() const { return m_cipher.GetSessionID(); }

    /** Our key and garbage, the first bytes we send. */
    std::vector<uint8_t> Hello(std::vector<uint8_t> garbage)
    {
        m_send_aad = std::move(garbage);
        auto ret{Bytes(m_cipher.GetOurPubKey())};
        Append(ret, m_send_aad);
        return ret;
    }

    /** Derive the stage-1 keys from the transport's key, the first 64 bytes it sent. */
    void ReceiveKey(std::span<const uint8_t> key)
    {
        m_cipher.Initialize(EllSwiftPubKey{MakeByteSpan(key)}, m_initiator, /*self_decrypt=*/false, V2HybridMode::PREFER);
    }

    /** Take the transport's garbage and garbage terminator off the front of `in`; false if the terminator is not
     *  there. */
    bool ReceiveGarbage(std::vector<uint8_t>& in)
    {
        const auto terminator{Bytes(m_cipher.GetReceiveGarbageTerminator())};
        const auto found{std::ranges::search(in, terminator)};
        if (found.empty()) return false;
        m_recv_aad.assign(in.begin(), found.begin());
        in.erase(in.begin(), found.end());
        return true;
    }

    std::vector<uint8_t> Terminator() const { return Bytes(m_cipher.GetSendGarbageTerminator()); }

    /** An encrypted packet; the first one we send carries our garbage as AAD. */
    std::vector<uint8_t> Encrypt(std::span<const uint8_t> contents, bool ignore)
    {
        std::vector<uint8_t> ret(contents.size() + BIP324Cipher::EXPANSION);
        m_cipher.Encrypt(MakeByteSpan(contents), MakeByteSpan(m_send_aad), ignore, MakeWritableByteSpan(ret));
        m_send_aad.clear();
        return ret;
    }

    /** The packet at the front of `in`, removed from it; std::nullopt if it does not authenticate or `in` holds
     *  less than its length says, which only a wrong key does here. */
    std::optional<Packet> Decrypt(std::vector<uint8_t>& in)
    {
        if (in.size() < BIP324Cipher::LENGTH_LEN) return std::nullopt;
        const unsigned len{m_cipher.DecryptLength(MakeByteSpan(in).first(BIP324Cipher::LENGTH_LEN))};
        if (in.size() < len + BIP324Cipher::EXPANSION) return std::nullopt;
        Packet packet{.ignore = false, .contents = std::vector<uint8_t>(len)};
        if (!m_cipher.Decrypt(MakeByteSpan(in).subspan(BIP324Cipher::LENGTH_LEN, len + BIP324Cipher::EXPANSION - BIP324Cipher::LENGTH_LEN),
                              MakeByteSpan(m_recv_aad), packet.ignore, MakeWritableByteSpan(packet.contents))) {
            return std::nullopt;
        }
        m_recv_aad.clear();
        in.erase(in.begin(), in.begin() + len + BIP324Cipher::EXPANSION);
        return packet;
    }

    bool Switch(std::span<const std::byte> kem_secret, std::span<const std::byte> ct, std::span<const std::byte> ek)
    {
        return m_cipher.SwitchToStage2(kem_secret, ct, ek);
    }
};

/** Everything the transport has to send now. */
std::vector<uint8_t> TakeBytes(Transport& transport)
{
    std::vector<uint8_t> ret;
    while (true) {
        const auto& [bytes, more, type] = transport.GetBytesToSend(/*have_next_message=*/false);
        if (bytes.empty()) break;
        Append(ret, bytes);
        transport.MarkBytesSent(bytes.size());
    }
    return ret;
}

struct FeedResult {
    bool ok{true};                     //!< false: the transport refused, so the node disconnects
    size_t consumed{0};                //!< bytes the transport took, including the ones it refused on
    std::vector<CNetMessage> received; //!< messages it produced
    size_t rejected{0};                //!< packets that authenticated but carried no valid message type
};

/** Give `bytes` to the transport in pieces the fuzzer chooses, collecting the messages it produces. */
FeedResult Feed(Transport& transport, std::span<const uint8_t> bytes, FuzzedDataProvider& provider)
{
    FeedResult result;
    while (!bytes.empty()) {
        const size_t piece_len{provider.remaining_bytes() ? provider.ConsumeIntegralInRange<size_t>(1, bytes.size()) : bytes.size()};
        auto piece{bytes.first(piece_len)};
        bytes = bytes.subspan(piece_len);
        while (!piece.empty()) {
            const size_t before{piece.size()};
            const bool ok{transport.ReceivedBytes(piece)};
            result.consumed += before - piece.size();
            if (!ok) {
                result.ok = false;
                return result;
            }
            bool progress{piece.size() < before};
            if (transport.ReceivedMessageComplete()) {
                bool reject{false};
                CNetMessage msg{transport.GetReceivedMessage({}, reject)};
                if (reject) {
                    ++result.rejected;
                } else {
                    result.received.push_back(std::move(msg));
                }
                progress = true;
            }
            assert(progress);
        }
    }
    return result;
}

void ExpectCounts(const V2HybridCounters& counters, std::initializer_list<std::pair<V2HybridOutcome, uint64_t>> want)
{
    std::array<uint64_t, V2_HYBRID_OUTCOMES> expected{};
    for (const auto& [outcome, count] : want) {
        expected[static_cast<size_t>(outcome)] = count;
    }
    for (size_t i{0}; i < expected.size(); ++i) {
        assert(counters[i].load() == expected[i]);
    }
}

void ExpectInfo(const Transport& transport, TransportProtocolType type, std::optional<std::span<const std::byte>> session_id, bool hybrid)
{
    const auto info{transport.GetInfo()};
    assert(info.transport_type == type);
    assert(info.hybrid == hybrid);
    assert(info.session_id.has_value() == session_id.has_value());
    if (session_id) assert(std::ranges::equal(MakeByteSpan(*info.session_id), *session_id));
}

void ExpectDetecting(const Transport& transport)
{
    ExpectInfo(transport, TransportProtocolType::DETECTING, std::nullopt, /*hybrid=*/false);
}

/** A transport's or peer's key, entropy and garbage from the input. Long garbage comes from the RNG, and the entropy
 *  is hashed with the garbage so that the garbage cannot contain the terminator (as p2p_transport_serialization.cpp
 *  does). */
struct Side {
    CKey key;
    std::array<std::byte, 32> ent;
    std::vector<uint8_t> garbage;
};

std::optional<Side> ConsumeSide(FuzzedDataProvider& provider, InsecureRandomContext& rng)
{
    Side side;
    side.key = ConsumePrivateKey(provider, /*compressed=*/true);
    if (!side.key.IsValid()) return std::nullopt;
    const size_t garbage_len{provider.ConsumeIntegralInRange<size_t>(0, V2Transport::MAX_GARBAGE_LEN)};
    if (garbage_len <= 64) {
        side.garbage = provider.ConsumeBytes<uint8_t>(garbage_len);
        side.garbage.resize(garbage_len);
    } else {
        side.garbage = rng.randbytes<uint8_t>(garbage_len);
    }
    const auto ent{ConsumeFixedLengthByteVector<std::byte>(provider, 32)};
    CSHA256().Write(UCharCast(ent.data()), ent.size()).Write(side.garbage.data(), side.garbage.size()).Finalize(UCharCast(side.ent.data()));
    return side;
}

/** The ML-KEM seeds: d and z for the key pair, m for the encapsulation. */
struct Seeds {
    std::array<std::byte, 32> d, z, m;
};

Seeds ConsumeSeeds(FuzzedDataProvider& provider)
{
    Seeds seeds;
    seeds.d = ConsumeArray<32>(provider);
    seeds.z = ConsumeArray<32>(provider);
    seeds.m = ConsumeArray<32>(provider);
    return seeds;
}

/** ML-KEM with the seeds fixed, as the unit tests do; the node's own random path is theirs to test. */
V2HybridKem FixedKem(const Seeds& seeds)
{
    V2HybridKem kem;
    kem.keygen = [d = seeds.d, z = seeds.z] { return mlkem768::KeyGen(d, z); };
    kem.encaps = [m = seeds.m](std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE> ek) { return mlkem768::Encaps(ek, m); };
    return kem;
}

mlkem768::Error ConsumeError(FuzzedDataProvider& provider)
{
    return static_cast<mlkem768::Error>(provider.ConsumeIntegralInRange<uint8_t>(0, 3));
}

/** Version packet contents of a fuzzer-chosen kind: nothing, junk, the expected record with `body` or with a body from
 *  the input, a mutation of the expected record, or arbitrary bytes. */
std::vector<uint8_t> ConsumeContents(FuzzedDataProvider& provider, InsecureRandomContext& rng, uint8_t kind, std::span<const uint8_t> body)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 5)) {
    case 0:
        return {};
    case 1:
        return rng.randbytes<uint8_t>(rng.randrange(1300));
    case 2:
        return Record(kind, body);
    case 3:
        return Record(kind, ConsumeFixedLengthByteVector<uint8_t>(provider, body.size()));
    case 4: {
        auto record{Record(kind, body)};
        switch (provider.ConsumeIntegralInRange<uint8_t>(0, 7)) {
        case 0:
            record[8] = provider.ConsumeIntegral<uint8_t>(); // version
            break;
        case 1:
            record[9] = provider.ConsumeIntegral<uint8_t>(); // kind
            break;
        case 2: {
            const uint16_t len{provider.ConsumeIntegral<uint16_t>()};
            record[10] = len & 0xff;
            record[11] = len >> 8;
            break;
        }
        case 3:
            record.resize(provider.ConsumeIntegralInRange<size_t>(0, record.size()));
            break;
        case 4: {
            const auto bit{provider.ConsumeIntegralInRange<unsigned>(0, 63)}; // the tag
            record[bit / 8] ^= 1 << (bit % 8);
            break;
        }
        case 5: {
            auto first{Record(kind, body, provider.ConsumeIntegral<uint8_t>())}; // another version's record first
            Append(first, record);
            return first;
        }
        case 6:
            Append(record, ConsumeRandomLengthByteVector(provider, 64)); // trailing bytes
            break;
        default: {
            const auto pos{provider.ConsumeIntegralInRange<size_t>(0, record.size() - 1)};
            record[pos] = provider.ConsumeIntegral<uint8_t>();
            break;
        }
        }
        return record;
    }
    default:
        return ConsumeRandomLengthByteVector(provider, 1400);
    }
}

/** Up to three decoys from the peer, with contents from the RNG. */
std::vector<uint8_t> ConsumeDecoys(FuzzedDataProvider& provider, InsecureRandomContext& rng, Peer& peer)
{
    std::vector<uint8_t> ret;
    const auto count{provider.ConsumeIntegralInRange<unsigned>(0, 3)};
    for (unsigned i{0}; i < count; ++i) {
        Append(ret, peer.Encrypt(rng.randbytes<uint8_t>(provider.ConsumeIntegralInRange<size_t>(0, 200)), /*ignore=*/true));
    }
    return ret;
}

/** Queue messages on the transport and read them back through the peer. `first_limit`: the transport is an
 *  initiator whose next packet is its first under stage-2 keys, which has at most 4095 bytes of contents, so a larger
 *  message gets an empty decoy in front (XIP-4). `readable`: the peer has the transport's keys. */
void SendMessages(V2Transport& transport, Peer& peer, FuzzedDataProvider& provider, InsecureRandomContext& rng, bool& first_limit, bool readable)
{
    const auto count{provider.ConsumeIntegralInRange<unsigned>(0, 3)};
    for (unsigned i{0}; i < count; ++i) {
        // "ping" has a 1-byte short type id, "version" the 13-byte long form (BIP324).
        const bool ping{provider.ConsumeBool()};
        const size_t payload_len{provider.ConsumeBool() ? provider.ConsumeIntegralInRange<size_t>(FIRST_PACKET_MAX - 13, FIRST_PACKET_MAX + 100)
                                                        : provider.ConsumeIntegralInRange<size_t>(0, 300)};
        const auto payload{rng.randbytes<uint8_t>(payload_len)};
        CSerializedNetMsg msg;
        msg.m_type = ping ? "ping" : "version";
        msg.data = payload;
        const bool queued{transport.SetMessageToSend(msg)};
        assert(queued);
        auto bytes{TakeBytes(transport)};
        const bool limited{std::exchange(first_limit, false)};
        if (!readable) continue;
        const size_t contents_len{payload_len + (ping ? 1 : 13)};
        auto packet{peer.Decrypt(bytes)};
        assert(packet);
        if (limited && contents_len > FIRST_PACKET_MAX) {
            assert(packet->ignore && packet->contents.empty());
            packet = peer.Decrypt(bytes);
            assert(packet);
        }
        assert(!packet->ignore && packet->contents.size() == contents_len);
        assert(std::ranges::equal(std::span{packet->contents}.last(payload_len), payload));
        assert(bytes.empty());
    }
}

/** The peer sends packets of any size to a transport whose keys it has; the messages among them arrive intact. */
void PeerSends(V2Transport& transport, Peer& peer, FuzzedDataProvider& provider, InsecureRandomContext& rng)
{
    const auto count{provider.ConsumeIntegralInRange<unsigned>(0, 2)};
    for (unsigned i{0}; i < count; ++i) {
        const bool decoy{provider.ConsumeBool()};
        const auto payload{rng.randbytes<uint8_t>(provider.ConsumeIntegralInRange<size_t>(0, 20000))};
        const auto fed{Feed(transport, peer.Encrypt(decoy ? payload : LongMessage("version", payload), decoy), provider)};
        assert(fed.ok && fed.rejected == 0 && fed.received.size() == (decoy ? 0 : 1));
        if (!decoy) assert(fed.received[0].m_type == "version" && std::ranges::equal(fed.received[0].m_recv, MakeByteSpan(payload)));
    }
}

/** A classical session (stage-1 keys) or a confirmed hybrid one: messages both ways. */
void Exchange(V2Transport& transport, Peer& peer, FuzzedDataProvider& provider, InsecureRandomContext& rng, bool& first_limit)
{
    PeerSends(transport, peer, provider, rng);
    SendMessages(transport, peer, provider, rng, first_limit, /*readable=*/true);
    PeerSends(transport, peer, provider, rng);
}

/** After the tested side switched to stage 2, with the peer switched too, to the right key unless `wrong_key`. The
 *  peer's first stage-2 packet decides: under the right key at most 4095 bytes of contents is key confirmation and
 *  more fails as soon as its length is read; under a wrong key the length is random and the packet fails either
 *  way (XIP-4, "First stage-2 packet and key confirmation"). */
void Stage2(V2Transport& transport, Peer& peer, V2HybridCounters& counters, bool initiator, V2HybridMode mode, bool wrong_key,
            FuzzedDataProvider& provider, InsecureRandomContext& rng)
{
    bool first_limit{initiator};
    // The transport's own stage-2 packets may go out before the peer sends anything.
    if (provider.ConsumeBool()) SendMessages(transport, peer, provider, rng, first_limit, /*readable=*/!wrong_key);

    const bool over{provider.ConsumeBool()};
    const size_t len{over ? FIRST_PACKET_MAX + 1 + provider.ConsumeIntegralInRange<size_t>(0, FIRST_PACKET_MAX)
                          : provider.ConsumeIntegralInRange<size_t>(0, FIRST_PACKET_MAX)};
    const bool decoy{provider.ConsumeBool()};
    const bool message{!decoy && len >= 1 + CMessageHeader::MESSAGE_TYPE_SIZE};
    const auto payload{rng.randbytes<uint8_t>(message ? len - 1 - CMessageHeader::MESSAGE_TYPE_SIZE : len)};
    const auto fed{Feed(transport, peer.Encrypt(message ? LongMessage("version", payload) : payload, decoy), provider)};
    const bool retry{initiator && mode == V2HybridMode::PREFER};
    if (wrong_key || over) {
        if (over && !wrong_key) {
            assert(!fed.ok && fed.consumed == BIP324Cipher::LENGTH_LEN);
        } else if (fed.ok) {
            // The random length was within the limit: the packet fails once that many bytes are in.
            assert(fed.received.empty() && fed.rejected == 0);
            const auto filler{Feed(transport, rng.randbytes<uint8_t>(FIRST_PACKET_MAX + BIP324Cipher::EXPANSION), provider)};
            assert(!filler.ok);
        }
        ExpectCounts(counters, {{V2HybridOutcome::STAGE2_FAILED, 1}});
        const auto status{transport.GetHybridStatus()};
        assert(status.failure == V2HybridOutcome::STAGE2_FAILED && status.retry_classical == retry && !status.unconfirmed);
        ExpectDetecting(transport);
        return;
    }

    // Key confirmation, on a decoy or not.
    assert(fed.ok);
    if (message) {
        assert(fed.received.size() == 1 && fed.rejected == 0);
        assert(fed.received[0].m_type == "version" && std::ranges::equal(fed.received[0].m_recv, MakeByteSpan(payload)));
    } else if (decoy) {
        assert(fed.received.empty() && fed.rejected == 0);
    } else {
        assert(fed.received.size() + fed.rejected == 1);
    }
    ExpectInfo(transport, TransportProtocolType::V2, peer.SessionID(), /*hybrid=*/true);
    ExpectCounts(counters, {{V2HybridOutcome::HYBRID, 1}});
    const auto status{transport.GetHybridStatus()};
    assert(!status.unconfirmed && !status.retry_classical && !status.failure);
    // After key confirmation the usual size limit applies.
    Exchange(transport, peer, provider, rng, first_limit);
}

void Initialize()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
}

} // namespace

FUZZ_TARGET(p2p_transport_hx1_initiator, .init = Initialize)
{
    // An outbound transport in every mode; the fuzzer plays the responder (XIP-4, "Initiator, modes 1 and 2").
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    InsecureRandomContext rng{provider.ConsumeIntegral<uint64_t>()};
    const auto mode{ConsumeMode(provider)};
    const auto ours{ConsumeSide(provider, rng)};
    const auto theirs{ConsumeSide(provider, rng)};
    if (!ours || !theirs) return;
    const Seeds seeds{ConsumeSeeds(provider)};
    const bool encaps_fails{provider.ConsumeBool()};

    V2HybridCounters counters{};
    V2HybridKem kem{FixedKem(seeds)};
    if (encaps_fails) {
        kem.encaps = [error = ConsumeError(provider)](std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE>)
            -> util::Expected<mlkem768::Encapsulation, mlkem768::Error> { return util::Unexpected{error}; };
    }
    V2Transport transport{0, /*initiating=*/true, ours->key, ours->ent, ours->garbage, mode, std::move(kem), &counters};
    Peer peer{theirs->key, theirs->ent, /*initiator=*/false};

    // Our key and garbage go out at once. Nothing received yet: a v1 reconnect would be due, except in require mode.
    auto out{TakeBytes(transport)};
    assert(out.size() == EllSwiftPubKey::size() + ours->garbage.size());
    assert(transport.ShouldReconnectV1() == (mode != V2HybridMode::REQUIRE));
    assert(transport.GetHybridStatus().v1_refused == (mode == V2HybridMode::REQUIRE));
    peer.ReceiveKey(std::span{out}.first(EllSwiftPubKey::size()));
    out.erase(out.begin(), out.begin() + EllSwiftPubKey::size());

    // The peer's key, garbage, terminator and decoys. On the key we send our terminator, and in the HX1 modes
    // nothing else and no message until the peer's version packet is in; the kill switch sends the empty version
    // packet and is ready at once, as before HX1.
    auto flight{peer.Hello(theirs->garbage)};
    Append(flight, peer.Terminator());
    Append(flight, ConsumeDecoys(provider, rng, peer));
    const auto key_fed{Feed(transport, flight, provider)};
    assert(key_fed.ok && key_fed.received.empty() && key_fed.rejected == 0);
    assert(!transport.ShouldReconnectV1());
    Append(out, TakeBytes(transport));
    const bool garbage_ok{peer.ReceiveGarbage(out)};
    assert(garbage_ok);
    ExpectDetecting(transport);
    ExpectCounts(counters, {});
    bool first_limit{false};
    {
        CSerializedNetMsg msg;
        msg.m_type = "ping";
        const bool queued{transport.SetMessageToSend(msg)};
        assert(queued == (mode == V2HybridMode::OFF));
        if (mode == V2HybridMode::OFF) {
            Append(out, TakeBytes(transport));
            const auto vp_i{peer.Decrypt(out)};
            assert(vp_i && !vp_i->ignore && vp_i->contents.empty());
            const auto ping{peer.Decrypt(out)};
            assert(ping && !ping->ignore && ping->contents.size() == 1);
        }
    }
    assert(out.empty());

    // The peer's version packet.
    const auto key_pair{mlkem768::KeyGen(seeds.d, seeds.z)};
    assert(key_pair);
    const auto vp_r{ConsumeContents(provider, rng, KIND_OFFER, Bytes(key_pair->ek))};
    const auto fed{Feed(transport, peer.Encrypt(vp_r, /*ignore=*/false), provider)};
    assert(fed.received.empty() && fed.rejected == 0);
    Append(out, TakeBytes(transport));
    const auto status{transport.GetHybridStatus()};
    if (mode == V2HybridMode::OFF) {
        // The contents are ignored, whatever they are.
        assert(fed.ok && out.empty());
        ExpectCounts(counters, {});
        assert(!status.unconfirmed && !status.retry_classical && !status.failure && !status.v1_refused);
        ExpectInfo(transport, TransportProtocolType::V2, peer.SessionID(), /*hybrid=*/false);
        Exchange(transport, peer, provider, rng, first_limit);
        return;
    }
    const Class cls{Classify(vp_r, KIND_OFFER)};
    if (cls == Class::NONE) {
        if (mode == V2HybridMode::PREFER) {
            // Classical: our empty version packet, then stage-1 keys for good.
            assert(fed.ok);
            const auto vp_i{peer.Decrypt(out)};
            assert(vp_i && !vp_i->ignore && vp_i->contents.empty() && out.empty());
            ExpectInfo(transport, TransportProtocolType::V2, peer.SessionID(), /*hybrid=*/false);
            ExpectCounts(counters, {{V2HybridOutcome::CLASSICAL, 1}});
            assert(!status.unconfirmed && !status.retry_classical && !status.failure);
            Exchange(transport, peer, provider, rng, first_limit);
        } else {
            assert(!fed.ok && out.empty());
            ExpectCounts(counters, {{V2HybridOutcome::REFUSED, 1}});
            assert(status.failure == V2HybridOutcome::REFUSED && !status.retry_classical && !status.unconfirmed);
            ExpectDetecting(transport);
        }
        return;
    }
    const std::span<const uint8_t> ek{cls == Class::VALID ? std::span{vp_r}.subspan(HEADER_LEN, mlkem768::ENCAPS_KEY_SIZE) : std::span<const uint8_t>{}};
    if (cls == Class::MALFORMED || !mlkem768::CheckEncapsKey(MakeByteSpan(ek).first<mlkem768::ENCAPS_KEY_SIZE>())) {
        // Malformed, or a key that fails the section 7.2 check: no version packet; prefer mode retries classically.
        assert(!fed.ok && out.empty());
        ExpectCounts(counters, {{V2HybridOutcome::BAD_RECORD, 1}});
        assert(status.failure == V2HybridOutcome::BAD_RECORD && status.retry_classical == (mode == V2HybridMode::PREFER) && !status.unconfirmed);
        ExpectDetecting(transport);
        return;
    }
    if (encaps_fails) {
        // A local failure never downgrades, and is never retried.
        assert(!fed.ok && out.empty());
        ExpectCounts(counters, {{V2HybridOutcome::LOCAL_ERROR, 1}});
        assert(status.failure == V2HybridOutcome::LOCAL_ERROR && !status.retry_classical && !status.unconfirmed);
        ExpectDetecting(transport);
        return;
    }

    // HX1: our version packet is exactly one ACCEPT record with the ciphertext Encaps(ek, m) gives, under stage-1
    // keys; everything after it is stage 2, before the peer has confirmed anything.
    assert(fed.ok);
    const auto vp_i{peer.Decrypt(out)};
    assert(vp_i && !vp_i->ignore && out.empty());
    assert(Classify(vp_i->contents, KIND_ACCEPT) == Class::VALID && vp_i->contents.size() == HEADER_LEN + mlkem768::CIPHERTEXT_SIZE);
    const auto enc{mlkem768::Encaps(MakeByteSpan(ek).first<mlkem768::ENCAPS_KEY_SIZE>(), seeds.m)};
    assert(enc);
    assert(std::ranges::equal(std::span{vp_i->contents}.subspan(HEADER_LEN), Bytes(enc->ct)));
    ExpectDetecting(transport);
    ExpectCounts(counters, {});
    assert(status.unconfirmed && status.retry_classical == (mode == V2HybridMode::PREFER) && !status.failure);
    const bool wrong_key{provider.ConsumeBool()};
    auto kem_secret{*enc->shared_secret};
    if (wrong_key) kem_secret[0] ^= std::byte{1};
    const bool switched{peer.Switch(kem_secret, enc->ct, MakeByteSpan(ek))};
    assert(switched);
    Stage2(transport, peer, counters, /*initiator=*/true, mode, wrong_key, provider, rng);
}

FUZZ_TARGET(p2p_transport_hx1_responder, .init = Initialize)
{
    // An inbound transport in every mode; the fuzzer plays the initiator (XIP-4, "Responder, modes 1 and 2").
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    InsecureRandomContext rng{provider.ConsumeIntegral<uint64_t>()};
    const auto mode{ConsumeMode(provider)};
    const auto ours{ConsumeSide(provider, rng)};
    const auto theirs{ConsumeSide(provider, rng)};
    if (!ours || !theirs) return;
    const Seeds seeds{ConsumeSeeds(provider)};
    const uint8_t local_failure{provider.ConsumeIntegralInRange<uint8_t>(0, 2)}; // 1: key generation fails, 2: decapsulation fails
    const uint8_t opening{provider.ConsumeIntegralInRange<uint8_t>(0, 15)};      // 1: the v1 prefix, 2: v1 with another network's magic

    V2HybridCounters counters{};
    V2HybridKem kem{FixedKem(seeds)};
    if (local_failure == 1) {
        kem.keygen = [error = ConsumeError(provider)]() -> util::Expected<mlkem768::KeyPair, mlkem768::Error> { return util::Unexpected{error}; };
    } else if (local_failure == 2) {
        kem.decaps = [error = ConsumeError(provider)](std::span<const std::byte, mlkem768::DECAPS_KEY_SIZE>, std::span<const std::byte, mlkem768::CIPHERTEXT_SIZE>)
            -> util::Expected<mlkem768::SharedSecret, mlkem768::Error> { return util::Unexpected{error}; };
    }
    V2Transport transport{1, /*initiating=*/false, ours->key, ours->ent, ours->garbage, mode, std::move(kem), &counters};
    Peer peer{theirs->key, theirs->ent, /*initiator=*/true};

    // Nothing is sent before the peer's first bytes; v1 is detected from the first 16 (XIP-4, responder step 1).
    assert(TakeBytes(transport).empty());
    assert(!transport.ShouldReconnectV1());
    if (opening == 1 || opening == 2) {
        std::vector<uint8_t> prefix(Params().MessageStart().begin(), Params().MessageStart().end());
        if (opening == 2) prefix[0] ^= 1;
        const std::string version{"version"};
        Append(prefix, std::vector<uint8_t>(version.begin(), version.end()));
        prefix.resize(16, 0);
        if (opening == 2) Append(prefix, rng.randbytes<uint8_t>(EllSwiftPubKey::size() - 16));
        const auto fed{Feed(transport, prefix, provider)};
        if (opening == 2) {
            // A v1 peer of another network: dropped, and not an HX1 outcome.
            assert(!fed.ok);
            ExpectCounts(counters, {});
        } else if (mode == V2HybridMode::REQUIRE) {
            assert(!fed.ok && fed.consumed == 16);
            ExpectCounts(counters, {{V2HybridOutcome::REFUSED, 1}});
            assert(!transport.GetHybridStatus().retry_classical);
        } else {
            assert(fed.ok && fed.consumed == 16);
            ExpectInfo(transport, TransportProtocolType::V1, std::nullopt, /*hybrid=*/false);
            ExpectCounts(counters, {});
        }
        return;
    }

    // The peer's key and garbage. On the key we generate our ML-KEM key pair and send our key, garbage, terminator
    // and version packet, then nothing until the peer's version packet (XIP-4, responder steps 3 and 4).
    const auto key_fed{Feed(transport, peer.Hello(theirs->garbage), provider)};
    if (local_failure == 1 && mode != V2HybridMode::OFF) {
        assert(!key_fed.ok);
        ExpectCounts(counters, {{V2HybridOutcome::LOCAL_ERROR, 1}});
        assert(transport.GetHybridStatus().failure == V2HybridOutcome::LOCAL_ERROR);
        ExpectDetecting(transport);
        return;
    }
    assert(key_fed.ok && key_fed.received.empty() && key_fed.rejected == 0);
    auto out{TakeBytes(transport)};
    assert(out.size() >= EllSwiftPubKey::size());
    peer.ReceiveKey(std::span{out}.first(EllSwiftPubKey::size()));
    out.erase(out.begin(), out.begin() + EllSwiftPubKey::size());
    const bool garbage_ok{peer.ReceiveGarbage(out)};
    assert(garbage_ok);
    const auto vp_r{peer.Decrypt(out)};
    assert(vp_r && !vp_r->ignore && out.empty());
    const auto key_pair{mlkem768::KeyGen(seeds.d, seeds.z)};
    assert(key_pair);
    if (mode == V2HybridMode::OFF) {
        assert(vp_r->contents.empty());
    } else {
        assert(vp_r->contents == Record(KIND_OFFER, Bytes(key_pair->ek)));
    }
    ExpectDetecting(transport);
    ExpectCounts(counters, {});
    bool first_limit{false};
    {
        CSerializedNetMsg msg;
        msg.m_type = "ping";
        const bool queued{transport.SetMessageToSend(msg)};
        assert(queued == (mode == V2HybridMode::OFF));
        out = TakeBytes(transport);
        if (mode == V2HybridMode::OFF) {
            const auto ping{peer.Decrypt(out)};
            assert(ping && !ping->ignore && ping->contents.size() == 1);
        }
        assert(out.empty());
    }

    // The peer's terminator, decoys and version packet.
    const auto enc{mlkem768::Encaps(key_pair->ek, seeds.m)};
    assert(enc);
    const auto vp_i{ConsumeContents(provider, rng, KIND_ACCEPT, Bytes(enc->ct))};
    auto flight{peer.Terminator()};
    Append(flight, ConsumeDecoys(provider, rng, peer));
    Append(flight, peer.Encrypt(vp_i, /*ignore=*/false));
    const auto fed{Feed(transport, flight, provider)};
    assert(fed.received.empty() && fed.rejected == 0);
    out = TakeBytes(transport);
    const auto status{transport.GetHybridStatus()};
    assert(!status.retry_classical && !status.v1_refused); // responders never retry
    if (mode == V2HybridMode::OFF) {
        assert(fed.ok && out.empty());
        ExpectCounts(counters, {});
        assert(!status.unconfirmed && !status.failure);
        ExpectInfo(transport, TransportProtocolType::V2, peer.SessionID(), /*hybrid=*/false);
        Exchange(transport, peer, provider, rng, first_limit);
        return;
    }
    const Class cls{Classify(vp_i, KIND_ACCEPT)};
    if (cls == Class::NONE) {
        if (mode == V2HybridMode::PREFER) {
            // Classical: no confirmation packet, stage-1 keys for good.
            assert(fed.ok && out.empty());
            ExpectInfo(transport, TransportProtocolType::V2, peer.SessionID(), /*hybrid=*/false);
            ExpectCounts(counters, {{V2HybridOutcome::CLASSICAL, 1}});
            assert(!status.unconfirmed && !status.failure);
            Exchange(transport, peer, provider, rng, first_limit);
        } else {
            assert(!fed.ok && out.empty());
            ExpectCounts(counters, {{V2HybridOutcome::REFUSED, 1}});
            assert(status.failure == V2HybridOutcome::REFUSED && !status.unconfirmed);
            ExpectDetecting(transport);
        }
        return;
    }
    if (cls == Class::MALFORMED) {
        assert(!fed.ok && out.empty());
        ExpectCounts(counters, {{V2HybridOutcome::BAD_RECORD, 1}});
        assert(status.failure == V2HybridOutcome::BAD_RECORD && !status.unconfirmed);
        ExpectDetecting(transport);
        return;
    }
    if (local_failure == 2) {
        assert(!fed.ok && out.empty());
        ExpectCounts(counters, {{V2HybridOutcome::LOCAL_ERROR, 1}});
        assert(status.failure == V2HybridOutcome::LOCAL_ERROR && !status.unconfirmed);
        ExpectDetecting(transport);
        return;
    }

    // HX1: any ciphertext decapsulates (implicit rejection gives an unrelated K, never an error), and the
    // confirmation packet, exactly one empty 20-byte stage-2 decoy, goes out before anything else.
    assert(fed.ok);
    assert(out.size() == BIP324Cipher::EXPANSION);
    ExpectDetecting(transport);
    ExpectCounts(counters, {});
    assert(status.unconfirmed && !status.failure);
    const auto ct{MakeByteSpan(vp_i).subspan(HEADER_LEN).first<mlkem768::CIPHERTEXT_SIZE>()};
    const auto kem_secret{mlkem768::Decaps(*key_pair->dk, ct)};
    assert(kem_secret);
    assert((**kem_secret == *enc->shared_secret) == std::ranges::equal(ct, enc->ct));
    const bool wrong_key{provider.ConsumeBool()};
    auto secret{**kem_secret};
    if (wrong_key) secret[0] ^= std::byte{1};
    const bool switched{peer.Switch(secret, ct, key_pair->ek)};
    assert(switched);
    const auto confirmation{peer.Decrypt(out)};
    if (wrong_key) {
        assert(!confirmation);
    } else {
        assert(confirmation && confirmation->ignore && confirmation->contents.empty() && out.empty());
    }
    Stage2(transport, peer, counters, /*initiator=*/false, mode, wrong_key, provider, rng);
}

FUZZ_TARGET(p2p_transport_hx1_record)
{
    // ClassifyHybridRecord() against the XIP-4 table: exactly one row fits, only the first record is read, the body is
    // the record's body, and bytes after it are ignored.
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint8_t kind{provider.ConsumeBool() ? KIND_OFFER : KIND_ACCEPT};
    const auto contents{provider.ConsumeRemainingBytes<uint8_t>()};
    const Class expected{Classify(contents, kind)};
    std::span<const uint8_t> body;
    const Class got{FromTransport(V2Transport::ClassifyHybridRecord(contents, kind, body))};
    assert(got == expected);
    if (got != Class::VALID) {
        assert(body.empty());
        return;
    }
    const size_t body_len{kind == KIND_OFFER ? mlkem768::ENCAPS_KEY_SIZE : mlkem768::CIPHERTEXT_SIZE};
    assert(body.size() == body_len && body.data() == contents.data() + HEADER_LEN);
    // Trailing bytes are reserved and ignored; the body stays where it is.
    auto longer{contents};
    Append(longer, std::vector<uint8_t>{0xff, 0x00, 'x', 'c', 'o', 'i', 'n', '-', 'p', 'q', 0x01});
    std::span<const uint8_t> longer_body;
    assert(V2Transport::ClassifyHybridRecord(longer, kind, longer_body) == V2Transport::HybridRecord::VALID);
    assert(std::ranges::equal(longer_body, body));
    // Every prefix that keeps the tag and version is malformed; shorter ones are none.
    for (const size_t len : {size_t{0}, size_t{8}, size_t{9}, size_t{11}, HEADER_LEN, HEADER_LEN + body_len - 1}) {
        std::span<const uint8_t> prefix_body;
        const auto prefix{V2Transport::ClassifyHybridRecord(std::span{contents}.first(len), kind, prefix_body)};
        assert(prefix == (len < 9 ? V2Transport::HybridRecord::NONE : V2Transport::HybridRecord::MALFORMED));
        assert(prefix_body.empty());
    }
}
