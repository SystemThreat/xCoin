// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// HX1 (XIP-4) in V2Transport and CConnman. The record layout used here is written out from the XIP's text,
// independently of the node's parser.

#include <addrman.h>
#include <bip324.h>
#include <chainparams.h>
#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <key.h>
#include <net.h>
#include <netaddress.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <pubkey.h>
#include <span.h>
#include <support/lockedpool.h>
#include <test/data/hx1_handshake_vectors.json.h>
#include <test/data/ml_kem_768_fips203.json.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std::chrono_literals;

namespace {

constexpr uint8_t KIND_OFFER{0x01};
constexpr uint8_t KIND_ACCEPT{0x02};
constexpr size_t FIRST_PACKET_MAX{4095};

/** An HX1 record as XIP-4 lays it out: "xcoin-pq", version, kind, body length (2 bytes, little-endian), body. */
std::vector<uint8_t> Record(uint8_t kind, std::span<const uint8_t> body, uint8_t version = 0x01)
{
    std::vector<uint8_t> ret{'x', 'c', 'o', 'i', 'n', '-', 'p', 'q', version, kind,
                             uint8_t(body.size() & 0xff), uint8_t(body.size() >> 8)};
    ret.insert(ret.end(), body.begin(), body.end());
    return ret;
}

template <typename T>
std::vector<uint8_t> Bytes(const T& data)
{
    const auto span{MakeUCharSpan(data)};
    return {span.begin(), span.end()};
}

std::vector<uint8_t> Cat(std::initializer_list<std::span<const uint8_t>> parts)
{
    std::vector<uint8_t> ret;
    for (const auto part : parts) ret.insert(ret.end(), part.begin(), part.end());
    return ret;
}

std::string Sha256Hex(std::span<const uint8_t> data)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(data.data(), data.size()).Finalize(hash.data());
    return HexStr(hash);
}

CKey RandomKey(FastRandomContext& rng)
{
    CKey key;
    const uint256 data{rng.rand256()};
    key.Set(data.begin(), data.end(), true);
    return key;
}

CKey KeyFromHex(const UniValue& hex)
{
    const auto data{ParseHex(hex.get_str())};
    CKey key;
    key.Set(data.begin(), data.end(), true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

template <size_t N>
std::array<std::byte, N> ArrayFromHex(const UniValue& hex)
{
    const auto data{ParseHex<std::byte>(hex.get_str())};
    BOOST_REQUIRE_EQUAL(data.size(), N);
    std::array<std::byte, N> ret;
    std::ranges::copy(data, ret.begin());
    return ret;
}

uint64_t Count(const V2HybridCounters& counters, V2HybridOutcome outcome)
{
    return counters[static_cast<size_t>(outcome)].load();
}

/** The counters, as a map from outcome name to count, leaving out zeros. */
std::map<std::string, uint64_t> Counts(const V2HybridCounters& counters)
{
    std::map<std::string, uint64_t> ret;
    for (size_t i{0}; i < V2_HYBRID_OUTCOMES; ++i) {
        if (counters[i] != 0) ret.emplace(V2HybridOutcomeName(static_cast<V2HybridOutcome>(i)), counters[i].load());
    }
    return ret;
}

size_t LockedBytes() { return LockedPoolManager::Instance().stats().used; }

/** ML-KEM calls with the seeds fixed, as for the XIP-4 vectors. */
V2HybridKem FixedKem(const std::array<std::byte, 32>& d, const std::array<std::byte, 32>& z, const std::array<std::byte, 32>& m)
{
    V2HybridKem kem;
    kem.keygen = [d, z] { return mlkem768::KeyGen(d, z); };
    kem.encaps = [m](std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE> ek) { return mlkem768::Encaps(ek, m); };
    return kem;
}

/** Everything a transport has to send now. */
std::vector<uint8_t> TakeBytes(Transport& transport)
{
    std::vector<uint8_t> ret;
    while (true) {
        const auto& [bytes, more, type] = transport.GetBytesToSend(/*have_next_message=*/false);
        if (bytes.empty()) break;
        ret.insert(ret.end(), bytes.begin(), bytes.end());
        transport.MarkBytesSent(bytes.size());
    }
    return ret;
}

/** What a transport made of the bytes fed to it. */
struct FeedResult {
    bool ok{true}; //!< false: the transport failed, so the node disconnects
    std::vector<CNetMessage> messages;
    size_t rejected{0}; //!< packets that authenticated but carried no valid message type
};

FeedResult Feed(Transport& transport, std::span<const uint8_t> bytes)
{
    FeedResult result;
    while (true) {
        if (transport.ReceivedMessageComplete()) {
            bool reject{false};
            CNetMessage msg{transport.GetReceivedMessage({}, reject)};
            if (reject) {
                ++result.rejected;
            } else {
                result.messages.push_back(std::move(msg));
            }
            continue;
        }
        if (bytes.empty()) break;
        if (!transport.ReceivedBytes(bytes)) {
            result.ok = false;
            break;
        }
    }
    return result;
}

CSerializedNetMsg Message(std::string type, std::vector<uint8_t> payload)
{
    CSerializedNetMsg msg;
    msg.m_type = std::move(type);
    msg.data = std::move(payload);
    return msg;
}

/** Two transports back to back: side 0 the initiator, side 1 the responder. */
struct Link {
    std::array<Transport*, 2> side;
    std::array<bool, 2> ok{true, true};
    std::array<std::vector<uint8_t>, 2> wire;           //!< everything each side sent
    std::array<std::vector<CNetMessage>, 2> received;   //!< messages each side received
    std::array<std::deque<CSerializedNetMsg>, 2> queue; //!< messages each side still has to send

    Link(Transport& initiator, Transport& responder) : side{&initiator, &responder} {}

    /** Deliver bytes and messages both ways until nothing moves or a side fails. */
    void Pump()
    {
        bool progress{true};
        while (progress && ok[0] && ok[1]) {
            progress = false;
            for (const int s : {0, 1}) {
                if (!queue[s].empty() && side[s]->SetMessageToSend(queue[s].front())) {
                    queue[s].pop_front();
                    progress = true;
                }
                const auto bytes{TakeBytes(*side[s])};
                if (bytes.empty()) continue;
                progress = true;
                wire[s].insert(wire[s].end(), bytes.begin(), bytes.end());
                auto result{Feed(*side[1 - s], bytes)};
                ok[1 - s] = result.ok;
                std::ranges::move(result.messages, std::back_inserter(received[1 - s]));
                if (!ok[1 - s]) break;
            }
        }
    }
};

/** The other side of a tested V2Transport, made from a BIP324Cipher so that a test can send anything. It keeps its
 *  ECDH secret, so a test can switch it to stage 2 with whatever ML-KEM secret it likes. */
class Peer
{
    FastRandomContext& m_rng;
    BIP324Cipher m_cipher;
    const bool m_initiator;
    std::vector<uint8_t> m_send_aad;
    std::vector<uint8_t> m_recv_aad;

public:
    struct Packet {
        bool ignore;
        std::vector<uint8_t> contents;
    };

    Peer(FastRandomContext& rng, bool initiator)
        : m_rng{rng}, m_cipher{RandomKey(rng), MakeByteSpan(rng.rand256())}, m_initiator{initiator} {}

    BIP324Cipher& Cipher() { return m_cipher; }

    /** Our key and garbage, the first bytes we send. */
    std::vector<uint8_t> Hello(size_t garbage_len)
    {
        m_send_aad = m_rng.randbytes<uint8_t>(garbage_len);
        return Cat({Bytes(std::span<const std::byte>{m_cipher.GetOurPubKey()}), m_send_aad});
    }

    /** Take the tested transport's key off the front of `in` and derive the stage-1 keys. */
    void ReceiveKey(std::vector<uint8_t>& in)
    {
        BOOST_REQUIRE(in.size() >= EllSwiftPubKey::size());
        m_cipher.Initialize(EllSwiftPubKey{MakeByteSpan(in).first(EllSwiftPubKey::size())}, m_initiator,
                            /*self_decrypt=*/false, V2HybridMode::PREFER);
        in.erase(in.begin(), in.begin() + EllSwiftPubKey::size());
    }

    /** Take the tested transport's garbage and garbage terminator off the front of `in`. */
    void ReceiveGarbage(std::vector<uint8_t>& in)
    {
        const auto term{Bytes(m_cipher.GetReceiveGarbageTerminator())};
        const auto it{std::ranges::search(in, term).begin()};
        BOOST_REQUIRE(it != in.end());
        m_recv_aad.assign(in.begin(), it);
        in.erase(in.begin(), it + term.size());
    }

    std::vector<uint8_t> Terminator() { return Bytes(m_cipher.GetSendGarbageTerminator()); }

    /** An encrypted packet; the first one we send carries our garbage as AAD. */
    std::vector<uint8_t> Encrypt(std::span<const uint8_t> contents, bool ignore = false)
    {
        std::vector<uint8_t> ret(contents.size() + BIP324Cipher::EXPANSION);
        m_cipher.Encrypt(MakeByteSpan(contents), MakeByteSpan(m_send_aad), ignore, MakeWritableByteSpan(ret));
        m_send_aad.clear();
        return ret;
    }

    /** Decrypt the packet at the front of `in` and remove it. std::nullopt if it does not authenticate, or claims
     *  more bytes than `in` holds (which only a wrong key does here). */
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

    /** Switch to stage 2 with the given ML-KEM shared secret. */
    void Switch(std::span<const std::byte> kem_secret, std::span<const std::byte> ct, std::span<const std::byte> ek)
    {
        BOOST_REQUIRE(m_cipher.SwitchToStage2(kem_secret, ct, ek));
    }
};

/** A tested initiator facing a Peer as responder. */
struct InitiatorCase {
    V2HybridCounters counters{};
    V2Transport transport;
    Peer peer;
    std::vector<uint8_t> in; //!< bytes the transport sent that the peer has not processed

    InitiatorCase(FastRandomContext& rng, V2HybridMode mode, V2HybridKem kem = {})
        : transport{0, /*initiating=*/true, RandomKey(rng), MakeByteSpan(rng.rand256()),
                    rng.randbytes<uint8_t>(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1)), mode, std::move(kem), &counters},
          peer{rng, /*initiator=*/false}
    {
        in = TakeBytes(transport);
        peer.ReceiveKey(in);
    }

    /** Send the peer's key, garbage, terminator, `decoys` and a version packet with `contents`, and collect what the
     *  transport sends back. Returns whether the transport accepted it all. */
    bool SendHandshake(std::span<const uint8_t> contents, std::span<const std::vector<uint8_t>> decoys = {})
    {
        auto bytes{Cat({peer.Hello(peer_garbage_len), peer.Terminator()})};
        for (const auto& decoy : decoys) bytes = Cat({bytes, peer.Encrypt(decoy, /*ignore=*/true)});
        bytes = Cat({bytes, peer.Encrypt(contents)});
        const bool ok{Feed(transport, bytes).ok};
        in = Cat({in, TakeBytes(transport)});
        return ok;
    }

    size_t peer_garbage_len{7};
};

/** A tested responder facing a Peer as initiator. */
struct ResponderCase {
    V2HybridCounters counters{};
    V2Transport transport;
    Peer peer;
    std::vector<uint8_t> in;
    std::vector<uint8_t> offer; //!< the transport's version packet contents

    ResponderCase(FastRandomContext& rng, V2HybridMode mode, V2HybridKem kem = {})
        : transport{1, /*initiating=*/false, RandomKey(rng), MakeByteSpan(rng.rand256()),
                    rng.randbytes<uint8_t>(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1)), mode, std::move(kem), &counters},
          peer{rng, /*initiator=*/true} {}

    /** Send the peer's key and garbage; read the transport's handshake through its version packet. Returns whether
     *  the transport accepted the key. */
    bool Start()
    {
        if (!Feed(transport, peer.Hello(11)).ok) return false;
        in = TakeBytes(transport);
        peer.ReceiveKey(in);
        peer.ReceiveGarbage(in);
        auto packet{peer.Decrypt(in)};
        BOOST_REQUIRE(packet && !packet->ignore);
        offer = std::move(packet->contents);
        return true;
    }

    /** Send the peer's terminator, `decoys` and a version packet with `contents`. */
    bool SendVersion(std::span<const uint8_t> contents, std::span<const std::vector<uint8_t>> decoys = {})
    {
        auto bytes{peer.Terminator()};
        for (const auto& decoy : decoys) bytes = Cat({bytes, peer.Encrypt(decoy, /*ignore=*/true)});
        bytes = Cat({bytes, peer.Encrypt(contents)});
        const bool ok{Feed(transport, bytes).ok};
        in = Cat({in, TakeBytes(transport)});
        return ok;
    }

    /** The ek in the transport's offer. */
    std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE> OfferedKey() const
    {
        BOOST_REQUIRE_EQUAL(offer.size(), 12U + mlkem768::ENCAPS_KEY_SIZE);
        return MakeByteSpan(offer).subspan<12, mlkem768::ENCAPS_KEY_SIZE>();
    }
};

UniValue HandshakeVectors()
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::hx1_handshake_vectors));
    return vectors;
}

void SelectVectorParams(const UniValue& handshake)
{
    const std::map<std::string, ChainType> chains{{"mainnet", ChainType::MAIN}, {"testnet", ChainType::TESTNET}, {"regtest", ChainType::REGTEST}};
    SelectParams(chains.at(handshake["network"].get_str()));
    BOOST_REQUIRE_EQUAL(HexStr(Params().MessageStart()), handshake["magic"].get_str());
}

/** A transport with the XIP-4 vector inputs of one side. */
std::unique_ptr<V2Transport> VectorTransport(const UniValue& inputs, bool initiator, V2HybridMode mode, V2HybridCounters* counters)
{
    const std::string side{initiator ? "initiator" : "responder"};
    const auto aux{ArrayFromHex<32>(inputs["aux_" + side])};
    return std::make_unique<V2Transport>(initiator ? 0 : 1, initiator, KeyFromHex(inputs["priv_" + side]), aux,
                                         ParseHex(inputs["garbage_" + side].get_str()), mode,
                                         FixedKem(ArrayFromHex<32>(inputs["mlkem_d"]), ArrayFromHex<32>(inputs["mlkem_z"]),
                                                  ArrayFromHex<32>(inputs["mlkem_m"])),
                                         counters);
}

void CheckInfo(const Transport& transport, TransportProtocolType type, const std::string& session_id, bool hybrid)
{
    const auto info{transport.GetInfo()};
    BOOST_CHECK(info.transport_type == type);
    BOOST_CHECK_EQUAL(info.session_id ? HexStr(*info.session_id) : "", session_id);
    BOOST_CHECK_EQUAL(info.hybrid, hybrid);
}

void CheckDetecting(const Transport& transport) { CheckInfo(transport, TransportProtocolType::DETECTING, "", false); }

/** Message processing that does nothing: the CConnman tests drive the transport handshake only. */
class NoMessageProcessing final : public NetEventsInterface
{
public:
    void InitializeNode(const CNode&, ServiceFlags) override {}
    void FinalizeNode(const CNode&) override {}
    bool HasAllDesirableServiceFlags(ServiceFlags) const override { return true; }
    bool ProcessMessages(CNode&, std::atomic<bool>&) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
    bool SendMessages(CNode&) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
};

/** Everything the node wrote to a mocked socket so far. */
std::vector<uint8_t> Drain(DynSock::Pipe& pipe)
{
    std::vector<uint8_t> ret;
    std::array<uint8_t, 4096> buf;
    while (true) {
        const ssize_t n{pipe.GetBytes(buf.data(), buf.size())};
        if (n <= 0) break;
        ret.insert(ret.end(), buf.begin(), buf.begin() + n);
    }
    return ret;
}

/** A CConnman in prefer mode whose outbound connections get mocked sockets, one pair of pipes each. */
struct HX1ConnmanSetup : BasicTestingSetup {
    NetGroupManager m_netgroupman{NetGroupManager::NoAsmap()};
    AddrMan m_addrman{m_netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    NoMessageProcessing m_msgproc;
    std::vector<std::shared_ptr<DynSock::Pipes>> m_pipes;
    decltype(CreateSock) m_create_sock_orig{CreateSock};
    std::unique_ptr<ConnmanTestMsg> m_connman;
    const NodeSeconds m_start{1'800'000'000s};

    HX1ConnmanSetup() : BasicTestingSetup{ChainType::REGTEST}
    {
        SetMockTime(m_start);
        CreateSock = [this](int, int, int) -> std::unique_ptr<Sock> {
            m_pipes.push_back(std::make_shared<DynSock::Pipes>());
            return std::make_unique<DynSock>(m_pipes.back(), std::make_shared<DynSock::Queue>());
        };
        m_connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, m_addrman, m_netgroupman, Params());
        m_connman->SetMsgProc(&m_msgproc);
        m_connman->AddLocalServices(NODE_P2P_V2);
        m_connman->SetV2HybridMode(V2HybridMode::PREFER);
    }

    ~HX1ConnmanSetup()
    {
        m_connman.reset();
        CreateSock = m_create_sock_orig;
        SetMockTime(0s);
    }

    std::string Dest(int i) const { return strprintf("1.2.3.%d:%u", i, Params().GetDefaultPort()); }

    /** Open an outbound v2 connection; returns the node and its socket's pipes. */
    std::pair<CNode*, std::shared_ptr<DynSock::Pipes>> Open(const std::string& dest, ConnectionType type)
    {
        const size_t sockets{m_pipes.size()};
        const bool manual{type == ConnectionType::MANUAL};
        const CAddress addr{manual ? CAddress{} : CAddress{LookupNumeric(dest, Params().GetDefaultPort()), NODE_NONE}};
        BOOST_REQUIRE(m_connman->OpenNetworkConnection(addr, false, {}, manual ? dest.c_str() : nullptr, type, /*use_v2transport=*/true));
        BOOST_REQUIRE_EQUAL(m_pipes.size(), sockets + 1);
        return {m_connman->TestNodes().back(), m_pipes.back()};
    }

    /** One pass of the socket handler: the nodes send what they can and read what they were sent. */
    void Step() { m_connman->SocketHandlerPublic(); }

    /** Answer a node's handshake as a responder whose version packet has `contents`. Returns everything the node
     *  sent after its key. */
    std::vector<uint8_t> Respond(Peer& peer, DynSock::Pipes& pipes, std::span<const uint8_t> contents)
    {
        Step();
        auto in{Drain(pipes.send)};
        peer.ReceiveKey(in);
        const auto flight{Cat({peer.Hello(5), peer.Terminator(), peer.Encrypt(contents)})};
        pipes.recv.PushBytes(flight.data(), flight.size());
        Step();
        Step();
        return Cat({in, Drain(pipes.send)});
    }

    /** Whether a node runs mode 0: its empty version packet leaves at once, whatever the responder offers. */
    void CheckModeOff(DynSock::Pipes& pipes, FastRandomContext& rng)
    {
        Peer peer{rng, /*initiator=*/false};
        const auto key_pair{mlkem768::GenerateKeyPair()};
        BOOST_REQUIRE(key_pair);
        auto in{Respond(peer, pipes, Record(KIND_OFFER, Bytes(key_pair->ek)))};
        peer.ReceiveGarbage(in);
        const auto vp_i{peer.Decrypt(in)};
        BOOST_REQUIRE(vp_i);
        BOOST_CHECK(vp_i->contents.empty());
        BOOST_CHECK(in.empty());
    }

    uint64_t Count(V2HybridOutcome outcome) const { return m_connman->GetV2HybridCounts()[static_cast<size_t>(outcome)]; }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(hx1_transport_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(record_classification)
{
    // XIP-4 "Version packet contents": the rows do not overlap and only the first record is read.
    const auto ek{m_rng.randbytes<uint8_t>(mlkem768::ENCAPS_KEY_SIZE)};
    const auto ct{m_rng.randbytes<uint8_t>(mlkem768::CIPHERTEXT_SIZE)};
    const auto offer{Record(KIND_OFFER, ek)};
    const auto accept{Record(KIND_ACCEPT, ct)};
    using R = V2Transport::HybridRecord;
    const auto classify = [](std::span<const uint8_t> contents, uint8_t kind, std::span<const uint8_t>* body_out = nullptr) {
        std::span<const uint8_t> body;
        const R ret{V2Transport::ClassifyHybridRecord(contents, kind, body)};
        BOOST_CHECK_EQUAL(ret == R::VALID, !body.empty());
        if (body_out) *body_out = body;
        return ret;
    };

    for (const uint8_t kind : {KIND_OFFER, KIND_ACCEPT}) {
        const auto& valid{kind == KIND_OFFER ? offer : accept};
        const auto& body{kind == KIND_OFFER ? ek : ct};
        const uint8_t other{kind == KIND_OFFER ? KIND_ACCEPT : KIND_OFFER};
        // none: empty, fewer than 9 bytes, or not the tag; then a version other than 01.
        BOOST_CHECK(classify({}, kind) == R::NONE);
        for (size_t len{1}; len <= 8; ++len) BOOST_CHECK(classify(std::span{valid}.first(len), kind) == R::NONE);
        auto bad_tag{valid};
        bad_tag[m_rng.randrange(8)] ^= 1 << m_rng.randrange(8);
        BOOST_CHECK(classify(bad_tag, kind) == R::NONE);
        BOOST_CHECK(classify(Record(kind, body, /*version=*/0x02), kind) == R::NONE);
        BOOST_CHECK(classify(Record(kind, body, /*version=*/0x00), kind) == R::NONE);
        BOOST_CHECK(classify(m_rng.randbytes<uint8_t>(999), kind) == R::NONE);
        // A later version's record in front of the HX1 record: only the first record is read.
        BOOST_CHECK(classify(Cat({Record(kind, body, /*version=*/0x02), valid}), kind) == R::NONE);
        // malformed: the tag and version 01, then anything but exactly the expected record.
        for (size_t len{9}; len < 12; ++len) BOOST_CHECK(classify(std::span{valid}.first(len), kind) == R::MALFORMED);
        BOOST_CHECK(classify(Record(other, body), kind) == R::MALFORMED);
        BOOST_CHECK(classify(Record(other, other == KIND_OFFER ? ek : ct), kind) == R::MALFORMED);
        auto wrong_len{valid};
        wrong_len[10] ^= 1;
        BOOST_CHECK(classify(wrong_len, kind) == R::MALFORMED);
        BOOST_CHECK(classify(std::span{valid}.first(valid.size() - 1), kind) == R::MALFORMED);
        BOOST_CHECK(classify(std::span{valid}.first(12), kind) == R::MALFORMED);
        // HX1, with or without trailing bytes.
        std::span<const uint8_t> got;
        BOOST_CHECK(classify(valid, kind, &got) == R::VALID);
        BOOST_CHECK(std::ranges::equal(got, body));
        const auto trailing{Cat({valid, Record(kind, body, /*version=*/0x02), m_rng.randbytes<uint8_t>(10)})};
        BOOST_CHECK(classify(trailing, kind, &got) == R::VALID);
        BOOST_CHECK(std::ranges::equal(got, body));
    }
}

BOOST_AUTO_TEST_CASE(handshake_vectors)
{
    // XIP-4 vectors V1 (mainnet), V2 (testnet A) and V3 (regtest) through a pair of real transports: every byte either
    // side sends during the handshake, the confirmation packet, and pinned stage-2 packets from the other side.
    const UniValue vectors{HandshakeVectors()};
    const UniValue& inputs{vectors["inputs"]};
    for (const UniValue& hs : vectors["handshakes"].getValues()) {
        const std::string name{hs["name"].get_str()};
        if (name != "V1" && name != "V2" && name != "V3") continue;
        BOOST_TEST_CONTEXT(name)
        {
            SelectVectorParams(hs);
            V2HybridCounters counters_i{}, counters_r{};
            auto initiator{VectorTransport(inputs, true, V2HybridMode::PREFER, &counters_i)};
            auto responder{VectorTransport(inputs, false, V2HybridMode::PREFER, &counters_r)};
            const auto i_handshake{ParseHex(hs["initiator_handshake"]["bytes"].get_str())};
            const auto r_handshake{ParseHex(hs["responder_handshake"]["bytes"].get_str())};
            const std::string session_id2{hs["stage2"]["xcoin_hx1_session_id"].get_str()};

            // The initiator's key and garbage.
            const auto i_hello{TakeBytes(*initiator)};
            BOOST_CHECK_EQUAL(HexStr(i_hello), HexStr(std::span{i_handshake}.first(64 + 13)));
            BOOST_REQUIRE(Feed(*responder, i_hello).ok);

            // The responder's whole handshake leaves in one flight: key, garbage, terminator, VP_R with the offer.
            const auto r_flight{TakeBytes(*responder)};
            BOOST_CHECK_EQUAL(HexStr(r_flight), HexStr(r_handshake));
            BOOST_CHECK_EQUAL(Sha256Hex(r_flight), hs["responder_handshake"]["sha256"].get_str());
            CheckDetecting(*responder);
            // Nothing more until the responder has the initiator's version packet.
            auto ping{Message("ping", {1, 2, 3, 4, 5, 6, 7, 8})};
            BOOST_CHECK(!responder->SetMessageToSend(ping));
            BOOST_CHECK(TakeBytes(*responder).empty());

            // The initiator answers with its terminator and VP_I with the ciphertext, then uses stage 2.
            BOOST_REQUIRE(Feed(*initiator, r_flight).ok);
            const auto i_rest{TakeBytes(*initiator)};
            BOOST_CHECK_EQUAL(HexStr(Cat({i_hello, i_rest})), HexStr(i_handshake));
            BOOST_CHECK_EQUAL(Sha256Hex(Cat({i_hello, i_rest})), hs["initiator_handshake"]["sha256"].get_str());
            CheckDetecting(*initiator);
            BOOST_CHECK(initiator->GetHybridStatus().unconfirmed);

            // The responder switches and sends exactly its confirmation packet.
            BOOST_REQUIRE(Feed(*responder, i_rest).ok);
            const auto confirmation{TakeBytes(*responder)};
            const UniValue& r_packets{hs["packets_after_version"]["responder_to_initiator"]["entries"]};
            BOOST_CHECK_EQUAL(confirmation.size(), BIP324Cipher::EXPANSION);
            BOOST_CHECK_EQUAL(HexStr(confirmation), r_packets[0]["wire"].get_str());
            CheckDetecting(*responder);
            BOOST_CHECK(responder->GetHybridStatus().unconfirmed);

            // The confirmation packet confirms the initiator, before anything from the responder's node.
            BOOST_REQUIRE(Feed(*initiator, confirmation).ok);
            CheckInfo(*initiator, TransportProtocolType::V2, session_id2, true);
            BOOST_CHECK(!initiator->GetHybridStatus().unconfirmed);
            BOOST_CHECK(!initiator->GetHybridStatus().retry_classical);
            // The pinned R->I application packets 0 and 1 (stage-2 indices 1 and 2) authenticate. Their contents are
            // opaque test bytes, not messages.
            const auto r_app{Cat({ParseHex(r_packets[1]["wire"].get_str()), ParseHex(r_packets[2]["wire"].get_str())})};
            const auto r_result{Feed(*initiator, r_app)};
            BOOST_CHECK(r_result.ok);
            BOOST_CHECK_EQUAL(r_result.rejected, 2U);

            // The pinned I->R application packet 0 is the initiator's first stage-2 packet: key confirmation.
            const UniValue& i_packets{hs["packets_after_version"]["initiator_to_responder"]["entries"]};
            BOOST_REQUIRE_EQUAL(i_packets[0]["stage_index"].getInt<int>(), 0);
            const auto i_result{Feed(*responder, ParseHex(i_packets[0]["wire"].get_str()))};
            BOOST_CHECK(i_result.ok);
            BOOST_CHECK_EQUAL(i_result.rejected, 1U);
            CheckInfo(*responder, TransportProtocolType::V2, session_id2, true);
            BOOST_CHECK_EQUAL(hs["reported"]["initiator"]["session_id"].get_str(), session_id2);

            BOOST_CHECK((Counts(counters_i) == std::map<std::string, uint64_t>{{"hybrid", 1}}));
            BOOST_CHECK((Counts(counters_r) == std::map<std::string, uint64_t>{{"hybrid", 1}}));
        }
    }
}

BOOST_AUTO_TEST_CASE(handshake_vectors_with_decoys)
{
    // V4: decoys on both sides. The node's transport sends none, but accepts the other side's in both stages: a
    // responder decoy before VP_R, two initiator decoys before VP_I and one right after it (stage 2).
    const UniValue vectors{HandshakeVectors()};
    const UniValue& inputs{vectors["inputs"]};
    const UniValue* v1{nullptr};
    const UniValue* v4{nullptr};
    for (const UniValue& hs : vectors["handshakes"].getValues()) {
        if (hs["name"].get_str() == "V1") v1 = &hs;
        if (hs["name"].get_str() == "V4") v4 = &hs;
    }
    BOOST_REQUIRE(v1 && v4);
    SelectVectorParams(*v4);

    // Initiator: V4's responder flight; the transport answers as in V1, as it sends no decoys itself.
    {
        auto initiator{VectorTransport(inputs, true, V2HybridMode::PREFER, nullptr)};
        const auto hello{TakeBytes(*initiator)};
        BOOST_REQUIRE(Feed(*initiator, ParseHex((*v4)["responder_handshake"]["bytes"].get_str())).ok);
        BOOST_CHECK_EQUAL(HexStr(Cat({hello, TakeBytes(*initiator)})), (*v1)["initiator_handshake"]["bytes"].get_str());
        const UniValue& r_packets{(*v4)["packets_after_version"]["responder_to_initiator"]["entries"]};
        BOOST_REQUIRE(Feed(*initiator, ParseHex(r_packets[0]["wire"].get_str())).ok);
        CheckInfo(*initiator, TransportProtocolType::V2, (*v4)["reported"]["initiator"]["session_id"].get_str(), true);
    }
    // Responder: V4's initiator flight, then its stage-2 decoy, which is key confirmation, then app packet 0.
    {
        auto responder{VectorTransport(inputs, false, V2HybridMode::PREFER, nullptr)};
        const auto i_handshake{ParseHex((*v4)["initiator_handshake"]["bytes"].get_str())};
        BOOST_REQUIRE(Feed(*responder, std::span{i_handshake}.first(64 + 13)).ok);
        BOOST_CHECK_EQUAL(HexStr(TakeBytes(*responder)), (*v1)["responder_handshake"]["bytes"].get_str());
        BOOST_REQUIRE(Feed(*responder, std::span{i_handshake}.subspan(64 + 13)).ok);
        const UniValue& r_packets{(*v4)["packets_after_version"]["responder_to_initiator"]["entries"]};
        BOOST_CHECK_EQUAL(HexStr(TakeBytes(*responder)), r_packets[0]["wire"].get_str());
        CheckDetecting(*responder);
        const UniValue& i_packets{(*v4)["packets_after_version"]["initiator_to_responder"]["entries"]};
        BOOST_REQUIRE(i_packets[0]["decoy"].get_bool());
        BOOST_REQUIRE(Feed(*responder, ParseHex(i_packets[0]["wire"].get_str())).ok);
        CheckInfo(*responder, TransportProtocolType::V2, (*v4)["reported"]["responder"]["session_id"].get_str(), true);
        const auto result{Feed(*responder, ParseHex(i_packets[1]["wire"].get_str()))};
        BOOST_CHECK(result.ok);
        BOOST_CHECK_EQUAL(result.rejected, 1U);
    }
}

BOOST_AUTO_TEST_CASE(handshake_vectors_classical)
{
    // V5: a prefer-mode initiator meets a classical responder. It answers with the empty version packet BIP324
    // sends, byte for byte; only the moment moves. A mode-0 initiator sends the same bytes at once, and ignores an
    // offer (the kill switch).
    const UniValue vectors{HandshakeVectors()};
    const UniValue& inputs{vectors["inputs"]};
    const UniValue* v1{nullptr};
    const UniValue* v5{nullptr};
    for (const UniValue& hs : vectors["handshakes"].getValues()) {
        if (hs["name"].get_str() == "V1") v1 = &hs;
        if (hs["name"].get_str() == "V5") v5 = &hs;
    }
    BOOST_REQUIRE(v1 && v5);
    SelectVectorParams(*v5);
    const std::string stage1_session_id{(*v5)["reported"]["initiator"]["session_id"].get_str()};
    const auto i_handshake{ParseHex((*v5)["initiator_handshake"]["bytes"].get_str())};
    const auto r_handshake{ParseHex((*v5)["responder_handshake"]["bytes"].get_str())};
    const UniValue& i_packets{(*v5)["packets_after_version"]["initiator_to_responder"]["entries"]};
    const UniValue& r_packets{(*v5)["packets_after_version"]["responder_to_initiator"]["entries"]};

    {
        V2HybridCounters counters_i{};
        auto initiator{VectorTransport(inputs, true, V2HybridMode::PREFER, &counters_i)};
        auto responder{VectorTransport(inputs, false, V2HybridMode::OFF, nullptr)};
        const auto hello{TakeBytes(*initiator)};
        BOOST_REQUIRE(Feed(*responder, hello).ok);
        const auto r_flight{TakeBytes(*responder)};
        BOOST_CHECK_EQUAL(HexStr(r_flight), HexStr(r_handshake));
        BOOST_REQUIRE(Feed(*initiator, r_flight).ok);
        const auto i_rest{TakeBytes(*initiator)};
        BOOST_CHECK_EQUAL(HexStr(Cat({hello, i_rest})), HexStr(i_handshake));
        BOOST_REQUIRE(Feed(*responder, i_rest).ok);
        CheckInfo(*initiator, TransportProtocolType::V2, stage1_session_id, false);
        CheckInfo(*responder, TransportProtocolType::V2, stage1_session_id, false);
        BOOST_CHECK((Counts(counters_i) == std::map<std::string, uint64_t>{{"classical", 1}}));
        // The pinned stage-1 application packets (index 1, after the version packet) authenticate on both sides.
        BOOST_CHECK_EQUAL(Feed(*initiator, ParseHex(r_packets[0]["wire"].get_str())).rejected, 1U);
        BOOST_CHECK_EQUAL(Feed(*responder, ParseHex(i_packets[0]["wire"].get_str())).rejected, 1U);
        BOOST_CHECK(!initiator->GetHybridStatus().retry_classical);
    }

    // Mode 0: the initiator sends its empty version packet as soon as it has the responder's key, and ignores the
    // offer in V1's VP_R. The session is classical, on the stage-1 session id.
    SelectVectorParams(*v1);
    auto initiator{VectorTransport(inputs, true, V2HybridMode::OFF, nullptr)};
    const auto hello{TakeBytes(*initiator)};
    const auto v1_r_handshake{ParseHex((*v1)["responder_handshake"]["bytes"].get_str())};
    BOOST_REQUIRE(Feed(*initiator, std::span{v1_r_handshake}.first(64)).ok);
    BOOST_CHECK_EQUAL(HexStr(Cat({hello, TakeBytes(*initiator)})), HexStr(i_handshake));
    BOOST_REQUIRE(Feed(*initiator, std::span{v1_r_handshake}.subspan(64)).ok);
    CheckInfo(*initiator, TransportProtocolType::V2, stage1_session_id, false);
    BOOST_CHECK(TakeBytes(*initiator).empty());
    const auto status{initiator->GetHybridStatus()};
    BOOST_CHECK(!status.unconfirmed && !status.retry_classical && !status.failure && !status.v1_refused);
}

BOOST_AUTO_TEST_CASE(mode_matrix)
{
    // Two new transports in every pair of modes (the N0-N2 rows and columns of XIP-4's interop matrix), past the
    // rekey at 224 packets in each direction.
    using M = V2HybridMode;
    for (const M init_mode : {M::OFF, M::PREFER, M::REQUIRE}) {
        for (const M resp_mode : {M::OFF, M::PREFER, M::REQUIRE}) {
            BOOST_TEST_CONTEXT("initiator mode " << int(init_mode) << ", responder mode " << int(resp_mode))
            {
                V2HybridCounters counters_i{}, counters_r{};
                V2Transport initiator{0, true, init_mode, &counters_i};
                V2Transport responder{1, false, resp_mode, &counters_r};
                Link link{initiator, responder};
                for (int i{0}; i < 230; ++i) {
                    link.queue[0].push_back(Message("ping", m_rng.randbytes<uint8_t>(8)));
                    link.queue[1].push_back(Message(i % 2 ? "pong" : "hx1test", m_rng.randbytes<uint8_t>(m_rng.randrange(300))));
                }
                link.Pump();

                const bool hybrid{init_mode != M::OFF && resp_mode != M::OFF};
                if (init_mode == M::REQUIRE && resp_mode == M::OFF) {
                    // Dropped after VP_R: the initiator refuses and sends no version packet.
                    BOOST_CHECK(!link.ok[0] && link.ok[1]);
                    BOOST_CHECK((Counts(counters_i) == std::map<std::string, uint64_t>{{"refused", 1}}));
                    BOOST_CHECK(!initiator.GetHybridStatus().retry_classical);
                    continue;
                }
                if (init_mode == M::OFF && resp_mode == M::REQUIRE) {
                    // Dropped after VP_I.
                    BOOST_CHECK(link.ok[0] && !link.ok[1]);
                    BOOST_CHECK((Counts(counters_r) == std::map<std::string, uint64_t>{{"refused", 1}}));
                    continue;
                }
                BOOST_REQUIRE(link.ok[0] && link.ok[1]);
                BOOST_CHECK_EQUAL(link.received[1].size(), 230U);
                BOOST_CHECK_EQUAL(link.received[0].size(), 230U);
                const auto info_i{initiator.GetInfo()}, info_r{responder.GetInfo()};
                BOOST_CHECK(info_i.transport_type == TransportProtocolType::V2 && info_r.transport_type == TransportProtocolType::V2);
                BOOST_CHECK(info_i.session_id && info_i.session_id == info_r.session_id);
                BOOST_CHECK_EQUAL(info_i.hybrid, hybrid);
                BOOST_CHECK_EQUAL(info_r.hybrid, hybrid);
                const auto expect_counts = [&](M mode) -> std::map<std::string, uint64_t> {
                    if (mode == M::OFF) return {};
                    return {{hybrid ? "hybrid" : "classical", 1}};
                };
                BOOST_CHECK((Counts(counters_i) == expect_counts(init_mode)));
                BOOST_CHECK((Counts(counters_r) == expect_counts(resp_mode)));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(initiator_version_packet_classes)
{
    // A new initiator (prefer, then require) against responders that send every kind of version packet contents.
    const auto key_pair{mlkem768::GenerateKeyPair()};
    BOOST_REQUIRE(key_pair);
    const auto ek{Bytes(key_pair->ek)};
    const auto offer{Record(KIND_OFFER, ek)};

    struct Case {
        std::string name;
        std::vector<uint8_t> contents;
        enum { NONE, MALFORMED, HX1 } expect;
    };
    std::vector<Case> cases{
        {"empty", {}, Case::NONE},
        {"random", m_rng.randbytes<uint8_t>(1 + m_rng.randrange(999)), Case::NONE},
        {"bare tag", std::vector<uint8_t>(offer.begin(), offer.begin() + 8), Case::NONE},
        {"later version", Record(KIND_OFFER, ek, 0x02), Case::NONE},
        {"later version first", Cat({Record(KIND_OFFER, ek, 0x02), offer}), Case::NONE},
        {"9 bytes", std::vector<uint8_t>(offer.begin(), offer.begin() + 9), Case::MALFORMED},
        {"10 bytes", std::vector<uint8_t>(offer.begin(), offer.begin() + 10), Case::MALFORMED},
        {"11 bytes", std::vector<uint8_t>(offer.begin(), offer.begin() + 11), Case::MALFORMED},
        {"header only", std::vector<uint8_t>(offer.begin(), offer.begin() + 12), Case::MALFORMED},
        {"wrong kind", Record(KIND_ACCEPT, m_rng.randbytes<uint8_t>(mlkem768::CIPHERTEXT_SIZE)), Case::MALFORMED},
        {"wrong kind, offer length", Record(KIND_ACCEPT, ek), Case::MALFORMED},
        {"wrong length", Record(KIND_OFFER, std::span{ek}.first(1183)), Case::MALFORMED},
        {"truncated body", std::vector<uint8_t>(offer.begin(), offer.end() - 1), Case::MALFORMED},
        {"valid", offer, Case::HX1},
        {"trailing bytes", Cat({offer, m_rng.randbytes<uint8_t>(33)}), Case::HX1},
    };
    for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        for (const auto& c : cases) {
            for (const size_t decoys : {0, 2}) {
                BOOST_TEST_CONTEXT(c.name << ", mode " << int(mode) << ", " << decoys << " decoys")
                {
                    InitiatorCase t{m_rng, mode};
                    std::vector<std::vector<uint8_t>> decoy_contents;
                    for (size_t i{0}; i < decoys; ++i) decoy_contents.push_back(m_rng.randbytes<uint8_t>(m_rng.randrange(50)));
                    const bool ok{t.SendHandshake(c.contents, decoy_contents)};
                    t.peer.ReceiveGarbage(t.in);
                    const auto status{t.transport.GetHybridStatus()};
                    if (c.expect == Case::NONE && mode == V2HybridMode::PREFER) {
                        // Classical: the empty version packet, then application messages on stage-1 keys.
                        BOOST_REQUIRE(ok);
                        const auto vp_i{t.peer.Decrypt(t.in)};
                        BOOST_REQUIRE(vp_i);
                        BOOST_CHECK(!vp_i->ignore && vp_i->contents.empty());
                        BOOST_CHECK(t.in.empty());
                        CheckInfo(t.transport, TransportProtocolType::V2, HexStr(t.peer.Cipher().GetSessionID()), false);
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"classical", 1}}));
                        BOOST_CHECK(!status.retry_classical && !status.failure);
                        auto msg{Message("ping", {1, 2, 3, 4, 5, 6, 7, 8})};
                        BOOST_REQUIRE(t.transport.SetMessageToSend(msg));
                        auto packet_bytes{TakeBytes(t.transport)};
                        const auto packet{t.peer.Decrypt(packet_bytes)};
                        BOOST_CHECK(packet && !packet->ignore && packet->contents.size() == 9);
                    } else if (c.expect == Case::NONE) {
                        // Require mode: refused, nothing more sent, no retry.
                        BOOST_CHECK(!ok);
                        BOOST_CHECK(t.in.empty());
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"refused", 1}}));
                        BOOST_CHECK(!status.retry_classical);
                        BOOST_CHECK(status.failure == V2HybridOutcome::REFUSED);
                    } else if (c.expect == Case::MALFORMED) {
                        // Disconnect without a version packet; prefer mode retries once.
                        BOOST_CHECK(!ok);
                        BOOST_CHECK(t.in.empty());
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"bad_record", 1}}));
                        BOOST_CHECK_EQUAL(status.retry_classical, mode == V2HybridMode::PREFER);
                        BOOST_CHECK(status.failure == V2HybridOutcome::BAD_RECORD);
                        CheckDetecting(t.transport);
                    } else {
                        // HX1: VP_I carries a ciphertext for our ek, and everything after it uses stage 2.
                        BOOST_REQUIRE(ok);
                        const auto vp_i{t.peer.Decrypt(t.in)};
                        BOOST_REQUIRE(vp_i);
                        BOOST_REQUIRE_EQUAL(vp_i->contents.size(), 12 + mlkem768::CIPHERTEXT_SIZE);
                        BOOST_CHECK(std::ranges::equal(std::span{vp_i->contents}.first(12),
                                                       std::span<const uint8_t>{Record(KIND_ACCEPT, std::vector<uint8_t>(mlkem768::CIPHERTEXT_SIZE))}.first(12)));
                        BOOST_CHECK(t.in.empty());
                        CheckDetecting(t.transport);
                        BOOST_CHECK(status.unconfirmed && status.retry_classical == (mode == V2HybridMode::PREFER));
                        const auto ct{MakeByteSpan(vp_i->contents).subspan<12, mlkem768::CIPHERTEXT_SIZE>()};
                        const auto kem_secret{mlkem768::Decaps(*key_pair->dk, ct)};
                        BOOST_REQUIRE(kem_secret);
                        t.peer.Switch(**kem_secret, ct, key_pair->ek);
                        BOOST_REQUIRE(Feed(t.transport, t.peer.Encrypt({}, /*ignore=*/true)).ok);
                        CheckInfo(t.transport, TransportProtocolType::V2, HexStr(t.peer.Cipher().GetSessionID()), true);
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"hybrid", 1}}));
                        BOOST_CHECK(!t.transport.GetHybridStatus().retry_classical);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(responder_version_packet_classes)
{
    // A new responder (prefer, then require) against initiators that send every kind of version packet contents.
    for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        for (int c{0}; c < 9; ++c) {
            for (const size_t decoys : {0, 3}) {
                BOOST_TEST_CONTEXT("case " << c << ", mode " << int(mode) << ", " << decoys << " decoys")
                {
                    ResponderCase t{m_rng, mode};
                    BOOST_REQUIRE(t.Start());
                    // Its offer, in the first flight, and then nothing until our version packet.
                    const auto ek{t.OfferedKey()};
                    BOOST_CHECK(mlkem768::CheckEncapsKey(ek));
                    BOOST_CHECK(std::ranges::equal(std::span{t.offer}.first(12), std::span<const uint8_t>{Record(KIND_OFFER, Bytes(ek))}.first(12)));
                    BOOST_CHECK(t.in.empty());
                    auto enc{mlkem768::Encapsulate(ek)};
                    BOOST_REQUIRE(enc);
                    const auto accept{Record(KIND_ACCEPT, Bytes(enc->ct))};
                    std::vector<uint8_t> contents;
                    enum { NONE, MALFORMED, HX1 } expect{HX1};
                    switch (c) {
                    case 0: contents = {}; expect = NONE; break;
                    case 1: contents = m_rng.randbytes<uint8_t>(1 + m_rng.randrange(999)); expect = NONE; break;
                    case 2: contents = Record(KIND_ACCEPT, Bytes(enc->ct), 0x07); expect = NONE; break;
                    case 3: contents.assign(accept.begin(), accept.begin() + 10); expect = MALFORMED; break;
                    case 4: contents = Record(KIND_OFFER, Bytes(enc->ct)); expect = MALFORMED; break;
                    case 5: contents = Record(KIND_ACCEPT, std::span<const uint8_t>{Bytes(enc->ct)}.first(1000)); expect = MALFORMED; break;
                    case 6: contents.assign(accept.begin(), accept.end() - 5); expect = MALFORMED; break;
                    case 7: contents = accept; break;
                    case 8: contents = Cat({accept, m_rng.randbytes<uint8_t>(20)}); break;
                    }
                    std::vector<std::vector<uint8_t>> decoy_contents(decoys);
                    const size_t locked_before{LockedBytes()};
                    const bool ok{t.SendVersion(contents, decoy_contents)};
                    // Every exit releases the decapsulation key at once, not when the transport is destroyed.
                    BOOST_CHECK(LockedBytes() + mlkem768::DECAPS_KEY_SIZE <= locked_before);
                    const auto status{t.transport.GetHybridStatus()};
                    BOOST_CHECK(!status.retry_classical); // responders never retry
                    if (expect == NONE && mode == V2HybridMode::PREFER) {
                        BOOST_REQUIRE(ok);
                        BOOST_CHECK(t.in.empty()); // no confirmation packet in a classical session
                        CheckInfo(t.transport, TransportProtocolType::V2, HexStr(t.peer.Cipher().GetSessionID()), false);
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"classical", 1}}));
                        auto msg{Message("pong", {8, 7, 6, 5, 4, 3, 2, 1})};
                        BOOST_REQUIRE(t.transport.SetMessageToSend(msg));
                        auto bytes{TakeBytes(t.transport)};
                        const auto packet{t.peer.Decrypt(bytes)};
                        BOOST_CHECK(packet && !packet->ignore && packet->contents.size() == 9);
                    } else if (expect == NONE) {
                        BOOST_CHECK(!ok);
                        BOOST_CHECK(t.in.empty());
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"refused", 1}}));
                    } else if (expect == MALFORMED) {
                        BOOST_CHECK(!ok);
                        BOOST_CHECK(t.in.empty());
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"bad_record", 1}}));
                        CheckDetecting(t.transport);
                    } else {
                        // The confirmation packet: exactly one empty stage-2 decoy, 20 bytes, before anything else.
                        BOOST_REQUIRE(ok);
                        BOOST_CHECK_EQUAL(t.in.size(), BIP324Cipher::EXPANSION);
                        t.peer.Switch(*enc->shared_secret, enc->ct, ek);
                        const auto confirmation{t.peer.Decrypt(t.in)};
                        BOOST_REQUIRE(confirmation);
                        BOOST_CHECK(confirmation->ignore && confirmation->contents.empty());
                        CheckDetecting(t.transport);
                        BOOST_CHECK(status.unconfirmed);
                        // Our VERSION, the first stage-2 packet from the initiator, is key confirmation.
                        std::vector<uint8_t> version(1 + 12 + 100);
                        std::ranges::copy(std::string{"version"}, version.begin() + 1);
                        const auto result{Feed(t.transport, t.peer.Encrypt(version))};
                        BOOST_REQUIRE(result.ok);
                        BOOST_REQUIRE_EQUAL(result.messages.size(), 1U);
                        BOOST_CHECK_EQUAL(result.messages[0].m_type, "version");
                        CheckInfo(t.transport, TransportProtocolType::V2, HexStr(t.peer.Cipher().GetSessionID()), true);
                        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"hybrid", 1}}));
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(stage2_mismatch)
{
    // Wrong stage-2 keys are caught on the first stage-2 packet in each direction, at once and not at the handshake
    // timeout: the length decrypts to a random value, over the 4095-byte limit about 4095 times in 4096, and
    // otherwise the packet does not authenticate. The filler makes the second case fail at once too.
    for (int i{0}; i < 20; ++i) {
        // A responder that gets a random ciphertext: implicit rejection gives an unrelated K, not an error.
        ResponderCase r{m_rng, V2HybridMode::PREFER};
        BOOST_REQUIRE(r.Start());
        const auto ek{r.OfferedKey()};
        auto enc{mlkem768::Encapsulate(ek)};
        BOOST_REQUIRE(enc);
        const auto random_ct{m_rng.randbytes<uint8_t>(mlkem768::CIPHERTEXT_SIZE)};
        BOOST_REQUIRE(r.SendVersion(Record(KIND_ACCEPT, random_ct)));
        BOOST_REQUIRE_EQUAL(r.in.size(), BIP324Cipher::EXPANSION);
        // Our side derives its keys from the K it would have had; its view of the confirmation packet fails.
        r.peer.Switch(*enc->shared_secret, MakeByteSpan(random_ct), ek);
        auto confirmation{r.in};
        BOOST_CHECK(!r.peer.Decrypt(confirmation));
        std::vector<uint8_t> version(1 + 12 + 100);
        std::ranges::copy(std::string{"version"}, version.begin() + 1);
        BOOST_CHECK(!Feed(r.transport, Cat({r.peer.Encrypt(version), m_rng.randbytes<uint8_t>(FIRST_PACKET_MAX + 20)})).ok);
        BOOST_CHECK((Counts(r.counters) == std::map<std::string, uint64_t>{{"stage2_failed", 1}}));
        CheckDetecting(r.transport);
        BOOST_CHECK(!r.transport.GetHybridStatus().retry_classical);

        // An initiator whose responder derived other keys: its confirmation packet fails, and prefer mode retries.
        InitiatorCase t{m_rng, V2HybridMode::PREFER};
        const auto key_pair{mlkem768::GenerateKeyPair()};
        BOOST_REQUIRE(key_pair);
        BOOST_REQUIRE(t.SendHandshake(Record(KIND_OFFER, Bytes(key_pair->ek))));
        t.peer.ReceiveGarbage(t.in);
        const auto vp_i{t.peer.Decrypt(t.in)};
        BOOST_REQUIRE(vp_i);
        const auto wrong_secret{m_rng.randbytes<std::byte>(32)};
        t.peer.Switch(wrong_secret, MakeByteSpan(vp_i->contents).subspan(12), key_pair->ek);
        BOOST_CHECK(!Feed(t.transport, Cat({t.peer.Encrypt({}, /*ignore=*/true), m_rng.randbytes<uint8_t>(FIRST_PACKET_MAX + 20)})).ok);
        BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"stage2_failed", 1}}));
        const auto status{t.transport.GetHybridStatus()};
        BOOST_CHECK(status.retry_classical && status.failure == V2HybridOutcome::STAGE2_FAILED);
    }
}

BOOST_AUTO_TEST_CASE(stage2_auth_failure)
{
    // The right stage-2 keys, and a first stage-2 packet whose tag or ciphertext was changed: the length is valid,
    // so only the authentication check catches it.
    for (const bool flip_tag : {true, false}) {
        BOOST_TEST_CONTEXT((flip_tag ? "tag" : "ciphertext") << " byte flipped")
        {
            ResponderCase r{m_rng, V2HybridMode::PREFER};
            BOOST_REQUIRE(r.Start());
            auto enc{mlkem768::Encapsulate(r.OfferedKey())};
            BOOST_REQUIRE(enc);
            BOOST_REQUIRE(r.SendVersion(Record(KIND_ACCEPT, Bytes(enc->ct))));
            r.peer.Switch(*enc->shared_secret, enc->ct, r.OfferedKey());
            BOOST_REQUIRE(r.peer.Decrypt(r.in));
            std::vector<uint8_t> version(1 + 12 + 100);
            std::ranges::copy(std::string{"version"}, version.begin() + 1);
            auto packet{r.peer.Encrypt(version)};
            packet[flip_tag ? packet.size() - 1 : BIP324Cipher::LENGTH_LEN + 5] ^= 0x01;
            BOOST_CHECK(!Feed(r.transport, packet).ok);
            BOOST_CHECK((Counts(r.counters) == std::map<std::string, uint64_t>{{"stage2_failed", 1}}));
            const auto status_r{r.transport.GetHybridStatus()};
            BOOST_CHECK(status_r.failure == V2HybridOutcome::STAGE2_FAILED && !status_r.retry_classical);
            CheckDetecting(r.transport);

            InitiatorCase t{m_rng, V2HybridMode::PREFER};
            const auto key_pair{mlkem768::GenerateKeyPair()};
            BOOST_REQUIRE(key_pair);
            BOOST_REQUIRE(t.SendHandshake(Record(KIND_OFFER, Bytes(key_pair->ek))));
            t.peer.ReceiveGarbage(t.in);
            const auto vp_i{t.peer.Decrypt(t.in)};
            BOOST_REQUIRE(vp_i);
            const auto ct{MakeByteSpan(vp_i->contents).subspan<12, mlkem768::CIPHERTEXT_SIZE>()};
            const auto kem_secret{mlkem768::Decaps(*key_pair->dk, ct)};
            BOOST_REQUIRE(kem_secret);
            t.peer.Switch(**kem_secret, ct, key_pair->ek);
            auto confirmation{t.peer.Encrypt(std::vector<uint8_t>(8), /*ignore=*/true)};
            confirmation[flip_tag ? confirmation.size() - 1 : BIP324Cipher::LENGTH_LEN + 2] ^= 0x80;
            BOOST_CHECK(!Feed(t.transport, confirmation).ok);
            BOOST_CHECK((Counts(t.counters) == std::map<std::string, uint64_t>{{"stage2_failed", 1}}));
            const auto status_i{t.transport.GetHybridStatus()};
            BOOST_CHECK(status_i.retry_classical && status_i.failure == V2HybridOutcome::STAGE2_FAILED);
            CheckDetecting(t.transport);
        }
    }
}

BOOST_AUTO_TEST_CASE(first_packet_limit)
{
    // Before key confirmation the first stage-2 packet may have 4095 bytes of contents; 4096 fails as soon as the
    // length is read. After key confirmation larger packets pass.
    for (const size_t len : {FIRST_PACKET_MAX, FIRST_PACKET_MAX + 1}) {
        for (const bool test_initiator : {true, false}) {
            BOOST_TEST_CONTEXT(len << " bytes, " << (test_initiator ? "initiator" : "responder"))
            {
                std::unique_ptr<InitiatorCase> i;
                std::unique_ptr<ResponderCase> r;
                Peer* peer;
                V2Transport* transport;
                V2HybridCounters* counters;
                if (test_initiator) {
                    i = std::make_unique<InitiatorCase>(m_rng, V2HybridMode::PREFER);
                    const auto key_pair{mlkem768::GenerateKeyPair()};
                    BOOST_REQUIRE(key_pair);
                    BOOST_REQUIRE(i->SendHandshake(Record(KIND_OFFER, Bytes(key_pair->ek))));
                    i->peer.ReceiveGarbage(i->in);
                    const auto vp_i{i->peer.Decrypt(i->in)};
                    BOOST_REQUIRE(vp_i);
                    const auto ct{MakeByteSpan(vp_i->contents).subspan<12, mlkem768::CIPHERTEXT_SIZE>()};
                    const auto kem_secret{mlkem768::Decaps(*key_pair->dk, ct)};
                    BOOST_REQUIRE(kem_secret);
                    i->peer.Switch(**kem_secret, ct, key_pair->ek);
                    peer = &i->peer;
                    transport = &i->transport;
                    counters = &i->counters;
                } else {
                    r = std::make_unique<ResponderCase>(m_rng, V2HybridMode::PREFER);
                    BOOST_REQUIRE(r->Start());
                    auto enc{mlkem768::Encapsulate(r->OfferedKey())};
                    BOOST_REQUIRE(enc);
                    BOOST_REQUIRE(r->SendVersion(Record(KIND_ACCEPT, Bytes(enc->ct))));
                    r->peer.Switch(*enc->shared_secret, enc->ct, r->OfferedKey());
                    BOOST_REQUIRE(r->peer.Decrypt(r->in));
                    peer = &r->peer;
                    transport = &r->transport;
                    counters = &r->counters;
                }
                const auto packet{peer->Encrypt(std::vector<uint8_t>(len), /*ignore=*/true)};
                if (len > FIRST_PACKET_MAX) {
                    BOOST_CHECK(!Feed(*transport, std::span{packet}.first(BIP324Cipher::LENGTH_LEN)).ok);
                    BOOST_CHECK((Counts(*counters) == std::map<std::string, uint64_t>{{"stage2_failed", 1}}));
                } else {
                    BOOST_CHECK(Feed(*transport, packet).ok);
                    BOOST_CHECK((Counts(*counters) == std::map<std::string, uint64_t>{{"hybrid", 1}}));
                    BOOST_CHECK(transport->GetInfo().hybrid);
                    std::vector<uint8_t> big(1 + 12 + 100000);
                    std::ranges::copy(std::string{"block"}, big.begin() + 1);
                    const auto result{Feed(*transport, peer->Encrypt(big))};
                    BOOST_CHECK(result.ok && result.messages.size() == 1);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(first_send_limit)
{
    // A node never sends a first stage-2 packet over the limit: a larger first message gets an empty decoy in front.
    // A tx has a 1-byte short message type, so FIRST_PACKET_MAX - 1 and FIRST_PACKET_MAX are the two boundary sizes.
    for (const size_t payload : {size_t{100}, FIRST_PACKET_MAX - 1, FIRST_PACKET_MAX, FIRST_PACKET_MAX + 1, size_t{20000}}) {
        InitiatorCase t{m_rng, V2HybridMode::PREFER};
        const auto key_pair{mlkem768::GenerateKeyPair()};
        BOOST_REQUIRE(key_pair);
        BOOST_REQUIRE(t.SendHandshake(Record(KIND_OFFER, Bytes(key_pair->ek))));
        t.peer.ReceiveGarbage(t.in);
        const auto vp_i{t.peer.Decrypt(t.in)};
        BOOST_REQUIRE(vp_i);
        const auto ct{MakeByteSpan(vp_i->contents).subspan<12, mlkem768::CIPHERTEXT_SIZE>()};
        const auto kem_secret{mlkem768::Decaps(*key_pair->dk, ct)};
        BOOST_REQUIRE(kem_secret);
        t.peer.Switch(**kem_secret, ct, key_pair->ek);

        for (int n{0}; n < 2; ++n) {
            auto msg{Message("tx", std::vector<uint8_t>(payload))};
            BOOST_REQUIRE(t.transport.SetMessageToSend(msg));
            auto bytes{TakeBytes(t.transport)};
            auto packet{t.peer.Decrypt(bytes)};
            BOOST_REQUIRE(packet);
            if (n == 0 && payload + 1 > FIRST_PACKET_MAX) {
                BOOST_CHECK(packet->ignore && packet->contents.empty());
                packet = t.peer.Decrypt(bytes);
                BOOST_REQUIRE(packet);
            }
            BOOST_CHECK(!packet->ignore);
            BOOST_CHECK_EQUAL(packet->contents.size(), payload + 1);
            BOOST_CHECK(bytes.empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(responder_sends_between_version_packets)
{
    // A responder may send nothing between VP_R and VP_I: the initiator already reads stage 2 there.
    InitiatorCase t{m_rng, V2HybridMode::PREFER};
    const auto key_pair{mlkem768::GenerateKeyPair()};
    BOOST_REQUIRE(key_pair);
    BOOST_REQUIRE(t.SendHandshake(Record(KIND_OFFER, Bytes(key_pair->ek))));
    const auto decoy{t.peer.Encrypt(m_rng.randbytes<uint8_t>(10), /*ignore=*/true)};
    BOOST_CHECK(!Feed(t.transport, Cat({decoy, m_rng.randbytes<uint8_t>(FIRST_PACKET_MAX + 20)})).ok);
    BOOST_CHECK_EQUAL(Count(t.counters, V2HybridOutcome::STAGE2_FAILED), 1U);
}

BOOST_AUTO_TEST_CASE(local_failures)
{
    // A failure of this node's own ML-KEM call disconnects, never continues classically, and is never retried by
    // the node that failed. After a responder's decapsulation failure the initiator only sees the connection end
    // before key confirmation, which it retries.
    for (const auto error : {mlkem768::Error::RNG_FAILURE, mlkem768::Error::LIBRARY_FAILURE}) {
        for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
            {
                V2HybridKem kem;
                kem.keygen = [error]() -> util::Expected<mlkem768::KeyPair, mlkem768::Error> { return util::Unexpected{error}; };
                V2HybridCounters counters_i{}, counters_r{};
                V2Transport initiator{0, true, mode, &counters_i};
                V2Transport responder{1, false, RandomKey(m_rng), MakeByteSpan(m_rng.rand256()), {}, mode, kem, &counters_r};
                Link link{initiator, responder};
                link.Pump();
                BOOST_CHECK(link.ok[0] && !link.ok[1]);
                // The responder queued its key (on detecting v2), but no terminator and no version packet.
                BOOST_CHECK_EQUAL(TakeBytes(responder).size(), EllSwiftPubKey::size());
                BOOST_CHECK((Counts(counters_r) == std::map<std::string, uint64_t>{{"local_error", 1}}));
                BOOST_CHECK(responder.GetHybridStatus().failure == V2HybridOutcome::LOCAL_ERROR);
                BOOST_CHECK(!initiator.GetHybridStatus().retry_classical); // it never saw an offer
            }
            {
                V2HybridKem kem;
                kem.encaps = [error](std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE>) -> util::Expected<mlkem768::Encapsulation, mlkem768::Error> {
                    return util::Unexpected{error};
                };
                V2HybridCounters counters_i{}, counters_r{};
                V2Transport initiator{0, true, RandomKey(m_rng), MakeByteSpan(m_rng.rand256()), {}, mode, kem, &counters_i};
                V2Transport responder{1, false, mode, &counters_r};
                Link link{initiator, responder};
                link.Pump();
                BOOST_CHECK(!link.ok[0] && link.ok[1]);
                // No version packet: after its key, the initiator queued its terminator only.
                BOOST_CHECK_EQUAL(link.wire[0].size(), EllSwiftPubKey::size());
                BOOST_CHECK_EQUAL(TakeBytes(initiator).size(), BIP324Cipher::GARBAGE_TERMINATOR_LEN);
                BOOST_CHECK((Counts(counters_i) == std::map<std::string, uint64_t>{{"local_error", 1}}));
                const auto status{initiator.GetHybridStatus()};
                BOOST_CHECK(!status.retry_classical && status.failure == V2HybridOutcome::LOCAL_ERROR);
                CheckDetecting(initiator);
                CheckDetecting(responder);
            }
            {
                V2HybridKem kem;
                kem.decaps = [error](std::span<const std::byte, mlkem768::DECAPS_KEY_SIZE>, std::span<const std::byte, mlkem768::CIPHERTEXT_SIZE>)
                    -> util::Expected<mlkem768::SharedSecret, mlkem768::Error> { return util::Unexpected{error}; };
                V2HybridCounters counters_i{}, counters_r{};
                V2Transport initiator{0, true, mode, &counters_i};
                V2Transport responder{1, false, RandomKey(m_rng), MakeByteSpan(m_rng.rand256()), {}, mode, kem, &counters_r};
                Link link{initiator, responder};
                link.Pump();
                BOOST_CHECK(link.ok[0] && !link.ok[1]);
                BOOST_CHECK((Counts(counters_r) == std::map<std::string, uint64_t>{{"local_error", 1}}));
                BOOST_CHECK(!responder.GetHybridStatus().retry_classical);
                const auto status{initiator.GetHybridStatus()};
                BOOST_CHECK(status.unconfirmed && !status.failure);
                BOOST_CHECK_EQUAL(status.retry_classical, mode == V2HybridMode::PREFER);
                BOOST_CHECK(Counts(counters_i).empty());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(require_mode_v1)
{
    // Require mode refuses an inbound v1 peer after its 16-byte prefix, and never reconnects outbound with v1.
    SelectParams(ChainType::REGTEST);
    std::vector<uint8_t> v1_prefix(Params().MessageStart().begin(), Params().MessageStart().end());
    for (const char c : std::string{"version"}) v1_prefix.push_back(c);
    v1_prefix.resize(16, 0);
    for (const auto mode : {V2HybridMode::OFF, V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        V2HybridCounters counters{};
        V2Transport responder{1, false, mode, &counters};
        BOOST_CHECK(Feed(responder, std::span{v1_prefix}.first(15)).ok);
        const bool ok{Feed(responder, std::span{v1_prefix}.subspan(15)).ok};
        BOOST_CHECK_EQUAL(ok, mode != V2HybridMode::REQUIRE);
        BOOST_CHECK(responder.GetInfo().transport_type == (ok ? TransportProtocolType::V1 : TransportProtocolType::DETECTING));
        BOOST_CHECK_EQUAL(Count(counters, V2HybridOutcome::REFUSED), mode == V2HybridMode::REQUIRE ? 1U : 0U);
        BOOST_CHECK(TakeBytes(responder).empty());

        // An outbound connection that got nothing back after sending 24 bytes or more.
        V2HybridCounters counters_i{};
        V2Transport initiator{0, true, mode, &counters_i};
        BOOST_CHECK(!initiator.ShouldReconnectV1());
        TakeBytes(initiator);
        BOOST_CHECK_EQUAL(initiator.ShouldReconnectV1(), mode != V2HybridMode::REQUIRE);
        BOOST_CHECK_EQUAL(initiator.GetHybridStatus().v1_refused, mode == V2HybridMode::REQUIRE);
    }
}

BOOST_AUTO_TEST_CASE(secrets_and_kill_switch)
{
    // Mode 0 keeps no ECDH secret and allocates no HX1 state. In the HX1 modes the ECDH secret and the responder's
    // decapsulation key are held in locked memory during the handshake only, and released on every exit: key
    // confirmation, a classical peer, a failure, and destruction mid-handshake.
    const size_t base{LockedBytes()};
    const auto hello_peer = [&](Transport& transport, bool initiator) {
        // The other side's key: the transport initializes its ciphers.
        Peer peer{m_rng, !initiator};
        if (initiator) TakeBytes(transport);
        BOOST_REQUIRE(Feed(transport, peer.Hello(0)).ok);
    };

    for (const auto mode : {V2HybridMode::OFF, V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        BOOST_TEST_CONTEXT("mode " << int(mode))
        {
            // Just after the key: the cipher's private key is gone; HX1 keeps its secrets, mode 0 nothing.
            for (const bool initiator : {true, false}) {
                const size_t before{LockedBytes()};
                V2Transport transport{0, initiator, mode};
                const size_t with_key{LockedBytes()};
                BOOST_CHECK(with_key > before);
                hello_peer(transport, initiator);
                if (mode == V2HybridMode::OFF) {
                    BOOST_CHECK_EQUAL(LockedBytes(), before);
                } else {
                    // ECDH secret (and, for a responder, dk) in locked memory.
                    BOOST_CHECK(LockedBytes() > before);
                    if (!initiator) BOOST_CHECK(LockedBytes() >= before + mlkem768::DECAPS_KEY_SIZE);
                }
            }
            BOOST_CHECK_EQUAL(LockedBytes(), base); // destruction mid-handshake

            // Complete handshakes, hybrid or classical, against each mode.
            for (const auto other : {V2HybridMode::OFF, V2HybridMode::PREFER}) {
                V2Transport initiator{0, true, mode};
                V2Transport responder{1, false, other};
                Link link{initiator, responder};
                link.queue[0].push_back(Message("ping", {1, 2, 3, 4, 5, 6, 7, 8}));
                link.queue[1].push_back(Message("pong", {1, 2, 3, 4, 5, 6, 7, 8}));
                link.Pump();
                if (mode == V2HybridMode::REQUIRE && other == V2HybridMode::OFF) {
                    BOOST_CHECK(!link.ok[0]);
                } else {
                    BOOST_CHECK(link.ok[0] && link.ok[1]);
                    BOOST_CHECK(link.received[0].size() == 1 && link.received[1].size() == 1);
                }
                BOOST_CHECK_EQUAL(LockedBytes(), base);
            }
            // A failure mid-handshake (a malformed offer). The peer's own kept secret is released first.
            {
                InitiatorCase t{m_rng, mode};
                t.peer.Cipher().DiscardStage2Secret();
                const auto record{Record(KIND_OFFER, {})};
                BOOST_CHECK_EQUAL(t.SendHandshake(std::span{record}.first(10)), mode == V2HybridMode::OFF);
                BOOST_CHECK_EQUAL(LockedBytes(), base);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(real_random_path)
{
    // Key generation and encapsulation through GetStrongRandBytes, 32 bytes per call, and a fresh ML-KEM key for
    // every connection.
    for (int i{0}; i < 8; ++i) {
        V2Transport initiator{0, true, V2HybridMode::PREFER};
        V2Transport responder{1, false, V2HybridMode::PREFER};
        Link link{initiator, responder};
        link.queue[0].push_back(Message("ping", {1, 2, 3, 4, 5, 6, 7, 8}));
        link.Pump();
        BOOST_REQUIRE(link.ok[0] && link.ok[1]);
        BOOST_CHECK(responder.GetInfo().hybrid && initiator.GetInfo().hybrid);
        BOOST_CHECK_EQUAL(link.received[1].size(), 1U);
    }
    std::set<std::string> offered_keys;
    for (int i{0}; i < 8; ++i) {
        ResponderCase t{m_rng, V2HybridMode::PREFER};
        BOOST_REQUIRE(t.Start());
        offered_keys.insert(HexStr(t.OfferedKey()));
    }
    BOOST_CHECK_EQUAL(offered_keys.size(), 8U);
}

BOOST_FIXTURE_TEST_CASE(classical_retry_manual, HX1ConnmanSetup)
{
    // A MANUAL (addnode, -connect) destination whose HX1 handshake failed is marked for the classical retry. The
    // queued reconnection would be dropped if the addnode loop got there first, so the mark decides: whichever
    // attempt comes next runs in mode 0, and is counted when it opens.
    const std::string dest{Dest(4)};
    auto [node, pipes]{Open(dest, ConnectionType::MANUAL)};
    Peer peer{m_rng, /*initiator=*/false};
    {
        ASSERT_DEBUG_LOG("HX1: malformed HX1 record");
        Respond(peer, *pipes, Record(KIND_OFFER, std::vector<uint8_t>(100)));
    }
    BOOST_CHECK(node->fDisconnect);
    {
        ASSERT_DEBUG_LOG("HX1 handshake failed (bad_record), retrying once as classical v2");
        m_connman->DisconnectNodesPublic();
    }
    BOOST_CHECK(m_connman->HasV2HybridRetryMark(dest));
    auto queued{m_connman->QueuedReconnections()};
    BOOST_REQUIRE_EQUAL(queued.size(), 1U);
    BOOST_CHECK(queued[0].destination == dest && queued[0].use_v2transport && !queued[0].hybrid_classical_retry);
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::BAD_RECORD), 1U);
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 0U);

    // The addnode loop's fresh attempt comes first: it is the classical retry.
    auto [retry, retry_pipes]{Open(dest, ConnectionType::MANUAL)};
    BOOST_CHECK(!m_connman->HasV2HybridRetryMark(dest));
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 1U);
    // It runs mode 0 and ends classical.
    CheckModeOff(*retry_pipes, m_rng);
    CNodeStats stats;
    retry->CopyStats(stats);
    BOOST_CHECK(stats.m_transport_type == TransportProtocolType::V2);
    BOOST_CHECK(!stats.m_transport_hybrid);
    BOOST_CHECK_EQUAL(stats.m_session_id.size(), 64U);

    // The queued reconnection finds the destination connected and is dropped: one retry, not two.
    m_connman->PerformReconnectionsPublic();
    BOOST_CHECK(m_connman->QueuedReconnections().empty());
    BOOST_CHECK_EQUAL(m_pipes.size(), 2U);
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 1U);

    // A retried connection is never retried again for HX1.
    retry_pipes->recv.Eof();
    Step();
    m_connman->DisconnectNodesPublic();
    BOOST_CHECK(m_connman->QueuedReconnections().empty());
    BOOST_CHECK(!m_connman->HasV2HybridRetryMark(dest));
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 1U);
}

BOOST_FIXTURE_TEST_CASE(classical_retry_outbound, HX1ConnmanSetup)
{
    // An automatic outbound connection's retry is queued as a mode-0 reconnection, for each qualifying cause.
    const auto key_pair{mlkem768::GenerateKeyPair()};
    BOOST_REQUIRE(key_pair);
    const auto offer{Record(KIND_OFFER, Bytes(key_pair->ek))};

    // The peer closes after VP_I, before key confirmation.
    {
        auto [node, pipes]{Open(Dest(5), ConnectionType::OUTBOUND_FULL_RELAY)};
        Peer peer{m_rng, /*initiator=*/false};
        Respond(peer, *pipes, offer);
        BOOST_CHECK(node->m_transport->GetHybridStatus().unconfirmed);
        pipes->recv.Eof();
        Step();
        ASSERT_DEBUG_LOG("HX1 handshake failed (closed before key confirmation), retrying once as classical v2");
        m_connman->DisconnectNodesPublic();
    }
    // The handshake times out before key confirmation: counted as stage2_failed.
    {
        auto [node, pipes]{Open(Dest(6), ConnectionType::BLOCK_RELAY)};
        Peer peer{m_rng, /*initiator=*/false};
        Respond(peer, *pipes, offer);
        SetMockTime(m_start + 61s);
        {
            ASSERT_DEBUG_LOG("HX1: handshake timeout before key confirmation");
            Step();
        }
        BOOST_CHECK(node->fDisconnect);
        BOOST_CHECK_EQUAL(Count(V2HybridOutcome::STAGE2_FAILED), 1U);
        ASSERT_DEBUG_LOG("HX1 handshake failed (stage2_failed), retrying once as classical v2");
        m_connman->DisconnectNodesPublic();
        SetMockTime(m_start);
    }
    auto queued{m_connman->QueuedReconnections()};
    BOOST_REQUIRE_EQUAL(queued.size(), 2U);
    for (size_t i{0}; i < 2; ++i) {
        BOOST_CHECK_EQUAL(queued[i].destination, Dest(5 + i));
        BOOST_CHECK(queued[i].use_v2transport && queued[i].hybrid_classical_retry);
    }
    // Counted when the retry connections open, not when queued.
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 0U);
    m_connman->PerformReconnectionsPublic();
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 2U);
    const auto nodes{m_connman->TestNodes()};
    BOOST_REQUIRE_EQUAL(nodes.size(), 2U);
    BOOST_CHECK(nodes[0]->m_conn_type == ConnectionType::OUTBOUND_FULL_RELAY && nodes[1]->m_conn_type == ConnectionType::BLOCK_RELAY);
    BOOST_REQUIRE_EQUAL(m_pipes.size(), 4U);
    CheckModeOff(*m_pipes[2], m_rng);
    CheckModeOff(*m_pipes[3], m_rng);
}

BOOST_FIXTURE_TEST_CASE(no_retry_after_local_disconnect, HX1ConnmanSetup)
{
    // disconnectnode or a ban before key confirmation: this node chose to close, so there is no retry, even when
    // the peer's close follows.
    const auto key_pair{mlkem768::GenerateKeyPair()};
    BOOST_REQUIRE(key_pair);
    for (const bool ban : {false, true}) {
        const std::string dest{Dest(ban ? 8 : 7)};
        auto [node, pipes]{Open(dest, ConnectionType::MANUAL)};
        Peer peer{m_rng, /*initiator=*/false};
        Respond(peer, *pipes, Record(KIND_OFFER, Bytes(key_pair->ek)));
        BOOST_CHECK(node->m_transport->GetHybridStatus().retry_classical);
        BOOST_CHECK(ban ? m_connman->DisconnectNode(CSubNet{node->addr}) : m_connman->DisconnectNode(node->GetId()));
        pipes->recv.Eof();
        Step();
        m_connman->DisconnectNodesPublic();
        BOOST_CHECK(m_connman->QueuedReconnections().empty());
        BOOST_CHECK(!m_connman->HasV2HybridRetryMark(dest));
    }
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::STAGE2_FAILED), 0U);
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 0U);
}

BOOST_FIXTURE_TEST_CASE(require_mode_connman, HX1ConnmanSetup)
{
    // Require mode: no v1 reconnect for an outbound peer that closed without a byte (counted as refused), and no
    // classical retry. Prefer mode reconnects with v1 as today.
    for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        m_connman->SetV2HybridMode(mode);
        auto [node, pipes]{Open(Dest(mode == V2HybridMode::PREFER ? 9 : 10), ConnectionType::OUTBOUND_FULL_RELAY)};
        Step();
        pipes->recv.Eof();
        Step();
        if (mode == V2HybridMode::REQUIRE) {
            ASSERT_DEBUG_LOG("HX1: not retrying with v1 transport protocol (-v2hybrid=2)");
            m_connman->DisconnectNodesPublic();
            BOOST_CHECK(m_connman->QueuedReconnections().empty());
            BOOST_CHECK_EQUAL(Count(V2HybridOutcome::REFUSED), 1U);
        } else {
            m_connman->DisconnectNodesPublic();
            const auto queued{m_connman->QueuedReconnections()};
            BOOST_REQUIRE_EQUAL(queued.size(), 1U);
            BOOST_CHECK(!queued[0].use_v2transport && !queued[0].hybrid_classical_retry);
            BOOST_CHECK_EQUAL(Count(V2HybridOutcome::REFUSED), 0U);
            m_connman->PerformReconnectionsPublic();
            m_connman->ClearTestNodes();
        }
    }
    // A malformed offer in require mode: bad_record, no retry.
    auto [node, pipes]{Open(Dest(11), ConnectionType::MANUAL)};
    Peer peer{m_rng, /*initiator=*/false};
    Respond(peer, *pipes, Record(KIND_OFFER, std::vector<uint8_t>(3)));
    m_connman->DisconnectNodesPublic();
    BOOST_CHECK(m_connman->QueuedReconnections().empty());
    BOOST_CHECK(!m_connman->HasV2HybridRetryMark(Dest(11)));
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::BAD_RECORD), 1U);
}

BOOST_FIXTURE_TEST_CASE(require_mode_any_address, HX1ConnmanSetup)
{
    // Automatic outbound connections (addrman, private broadcast): require mode uses v2 for an address that does
    // not advertise NODE_P2P_V2; the other modes use v1 there, as today. Nobody uses v2 without the local flag.
    for (const auto mode : {V2HybridMode::OFF, V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
        m_connman->SetV2HybridMode(mode);
        BOOST_CHECK(m_connman->UseV2TransportTo(NODE_P2P_V2));
        BOOST_CHECK(m_connman->UseV2TransportTo(ServiceFlags{NODE_NETWORK | NODE_P2P_V2}));
        BOOST_CHECK_EQUAL(m_connman->UseV2TransportTo(NODE_NONE), mode == V2HybridMode::REQUIRE);
        BOOST_CHECK_EQUAL(m_connman->UseV2TransportTo(NODE_NETWORK), mode == V2HybridMode::REQUIRE);
        m_connman->RemoveLocalServices(NODE_P2P_V2);
        BOOST_CHECK(!m_connman->UseV2TransportTo(NODE_P2P_V2));
        BOOST_CHECK(!m_connman->UseV2TransportTo(NODE_NONE));
        m_connman->AddLocalServices(NODE_P2P_V2);
    }
}

BOOST_FIXTURE_TEST_CASE(removenode_clears_retry_mark, HX1ConnmanSetup)
{
    // A MANUAL destination removed with removenode forgets its classical retry: a later addnode tries HX1 again.
    const std::string dest{Dest(12)};
    BOOST_REQUIRE(m_connman->AddNode({dest, /*m_use_v2transport=*/true}));
    auto [node, pipes]{Open(dest, ConnectionType::MANUAL)};
    Peer peer{m_rng, /*initiator=*/false};
    Respond(peer, *pipes, Record(KIND_OFFER, std::vector<uint8_t>(100)));
    m_connman->DisconnectNodesPublic();
    BOOST_REQUIRE(m_connman->HasV2HybridRetryMark(dest));
    BOOST_CHECK(m_connman->RemoveAddedNode(dest));
    BOOST_CHECK(!m_connman->HasV2HybridRetryMark(dest));
    m_connman->PerformReconnectionsPublic();
    m_connman->ClearTestNodes();

    BOOST_REQUIRE(m_connman->AddNode({dest, /*m_use_v2transport=*/true}));
    auto [again, again_pipes]{Open(dest, ConnectionType::MANUAL)};
    BOOST_CHECK_EQUAL(Count(V2HybridOutcome::CLASSICAL_RETRY), 0U);
    // The new connection runs HX1: it answers an offer with an ACCEPT record.
    Peer peer2{m_rng, /*initiator=*/false};
    const auto key_pair{mlkem768::GenerateKeyPair()};
    BOOST_REQUIRE(key_pair);
    auto in{Respond(peer2, *again_pipes, Record(KIND_OFFER, Bytes(key_pair->ek)))};
    peer2.ReceiveGarbage(in);
    const auto vp_i{peer2.Decrypt(in)};
    BOOST_REQUIRE(vp_i);
    BOOST_CHECK_EQUAL(vp_i->contents.size(), 12U + mlkem768::CIPHERTEXT_SIZE);
}

BOOST_FIXTURE_TEST_CASE(removenode_before_disconnect_then_addnode, HX1ConnmanSetup)
{
    // removenode runs before the disconnect loop sees the failed handshake, so the loop marks the destination again;
    // the next addnode of it must still try HX1.
    const std::string dest{Dest(13)};
    BOOST_REQUIRE(m_connman->AddNode({dest, /*m_use_v2transport=*/true}));
    auto [node, pipes]{Open(dest, ConnectionType::MANUAL)};
    Peer peer{m_rng, /*initiator=*/false};
    Respond(peer, *pipes, Record(KIND_OFFER, std::vector<uint8_t>(100)));
    BOOST_CHECK(m_connman->RemoveAddedNode(dest));
    m_connman->DisconnectNodesPublic();
    BOOST_REQUIRE(m_connman->HasV2HybridRetryMark(dest));
    BOOST_REQUIRE(m_connman->AddNode({dest, /*m_use_v2transport=*/true}));
    BOOST_CHECK(!m_connman->HasV2HybridRetryMark(dest));
    m_connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(bad_encapsulation_keys)
{
    // V6's two keys and every C2SP CCTV modulus key: an otherwise valid offer is refused without a version packet,
    // counted as bad_record, and a prefer-mode initiator retries once.
    std::vector<std::vector<uint8_t>> bad_keys;
    const UniValue vectors{HandshakeVectors()};
    for (const UniValue& key : vectors["bad_encapsulation_keys"]["keys"].getValues()) {
        bad_keys.push_back(ParseHex(key["ek"].get_str()));
        BOOST_CHECK_EQUAL(Sha256Hex(bad_keys.back()), key["sha256"].get_str());
    }
    UniValue fips203;
    BOOST_REQUIRE(fips203.read(json_tests::ml_kem_768_fips203));
    const auto valid_ek{ParseHex(fips203["cctv_modulus"]["ek"].get_str())};
    for (const UniValue& change : fips203["cctv_modulus"]["changes"].getValues()) {
        // Set 12-bit coefficient `index` to `value` (ByteEncode12, FIPS 203 Algorithm 5).
        const auto index{change[0].getInt<size_t>()};
        const auto value{change[1].getInt<unsigned>()};
        auto ek{valid_ek};
        const size_t pos{384 * (index / 256) + 3 * ((index % 256) / 2)};
        if (index % 2 == 0) {
            ek[pos] = value & 0xff;
            ek[pos + 1] = (ek[pos + 1] & 0xf0) | (value >> 8);
        } else {
            ek[pos + 1] = (ek[pos + 1] & 0x0f) | ((value & 0x0f) << 4);
            ek[pos + 2] = value >> 4;
        }
        bad_keys.push_back(std::move(ek));
    }
    BOOST_REQUIRE_EQUAL(bad_keys.size(), 2U + 780U);
    // Each case costs an ECDH; a sample of the CCTV keys also runs in require mode.
    for (size_t i{0}; i < bad_keys.size(); ++i) {
        for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::REQUIRE}) {
            if (mode == V2HybridMode::REQUIRE && i >= 2 && i % 50 != 0) continue;
            InitiatorCase t{m_rng, mode};
            BOOST_CHECK(!t.SendHandshake(Record(KIND_OFFER, bad_keys[i])));
            t.peer.ReceiveGarbage(t.in);
            BOOST_CHECK(t.in.empty());
            BOOST_CHECK_EQUAL(Count(t.counters, V2HybridOutcome::BAD_RECORD), 1U);
            BOOST_CHECK_EQUAL(t.transport.GetHybridStatus().retry_classical, mode == V2HybridMode::PREFER);
        }
    }
}

BOOST_AUTO_TEST_CASE(byte_at_a_time)
{
    // One byte per ReceivedBytes call crosses every state-machine boundary with a partial buffer: a whole
    // handshake and 230 application messages each way, past the 224-packet rekey, hybrid and then mode 0.
    for (const auto mode : {V2HybridMode::PREFER, V2HybridMode::OFF}) {
        BOOST_TEST_CONTEXT("mode " << int(mode))
        {
            V2Transport initiator{0, true, mode};
            V2Transport responder{1, false, mode};
            const std::array<Transport*, 2> side{&initiator, &responder};
            std::array<std::deque<CSerializedNetMsg>, 2> queue;
            std::array<size_t, 2> got{0, 0};
            for (int i{0}; i < 230; ++i) {
                queue[0].push_back(Message("ping", m_rng.randbytes<uint8_t>(m_rng.randrange(40))));
                queue[1].push_back(Message("pong", m_rng.randbytes<uint8_t>(m_rng.randrange(40))));
            }
            bool progress{true};
            while (progress) {
                progress = false;
                for (const int s : {0, 1}) {
                    if (!queue[s].empty() && side[s]->SetMessageToSend(queue[s].front())) {
                        queue[s].pop_front();
                        progress = true;
                    }
                    const auto& [bytes, _more, _type] = side[s]->GetBytesToSend(false);
                    if (!bytes.empty()) {
                        std::span<const uint8_t> one{bytes.first(1)};
                        BOOST_REQUIRE(side[1 - s]->ReceivedBytes(one));
                        const size_t consumed{1 - one.size()};
                        side[s]->MarkBytesSent(consumed);
                        if (consumed) progress = true;
                    }
                    while (side[1 - s]->ReceivedMessageComplete()) {
                        bool reject{false};
                        side[1 - s]->GetReceivedMessage({}, reject);
                        if (!reject) ++got[1 - s];
                        progress = true;
                    }
                }
            }
            BOOST_CHECK_EQUAL(got[0], 230U);
            BOOST_CHECK_EQUAL(got[1], 230U);
            const bool hybrid{mode != V2HybridMode::OFF};
            BOOST_CHECK_EQUAL(initiator.GetInfo().hybrid, hybrid);
            BOOST_CHECK_EQUAL(responder.GetInfo().hybrid, hybrid);
            BOOST_CHECK(initiator.GetInfo().session_id && initiator.GetInfo().session_id == responder.GetInfo().session_id);
        }
    }
}

BOOST_AUTO_TEST_CASE(quantum_adversary)
{
    // The property HX1 exists for, on real C++ streams (XIP-4, "The quantum-adversary test"): an attacker who
    // breaks ECDH holds both ElligatorSwift private keys, derives the stage-1 keys and reads the version packets,
    // but every packet after them fails to authenticate under the stage-1 keys, both with the stage-1 counters
    // continued past the version packet and with them restarted at 0.
    SelectParams(ChainType::REGTEST);
    for (const bool read_initiator_stream : {true, false}) {
        const CKey key_i{RandomKey(m_rng)}, key_r{RandomKey(m_rng)};
        const uint256 ent_i{m_rng.rand256()}, ent_r{m_rng.rand256()};
        V2Transport initiator{0, true, key_i, MakeByteSpan(ent_i),
                              m_rng.randbytes<uint8_t>(m_rng.randrange(20)), V2HybridMode::PREFER};
        V2Transport responder{1, false, key_r, MakeByteSpan(ent_r),
                              m_rng.randbytes<uint8_t>(m_rng.randrange(20)), V2HybridMode::PREFER};
        Link link{initiator, responder};
        for (int i{0}; i < 230; ++i) {
            link.queue[0].push_back(Message("ping", m_rng.randbytes<uint8_t>(m_rng.randrange(60))));
            link.queue[1].push_back(Message("pong", m_rng.randbytes<uint8_t>(m_rng.randrange(60))));
        }
        link.Pump();
        BOOST_REQUIRE(link.ok[0] && link.ok[1]);
        BOOST_REQUIRE(initiator.GetInfo().hybrid && responder.GetInfo().hybrid);
        BOOST_REQUIRE_EQUAL(link.received[0].size(), 230U);
        BOOST_REQUIRE_EQUAL(link.received[1].size(), 230U);

        // The ElligatorSwift public keys, as sent. The adversary plays the side that received `stream`.
        const EllSwiftPubKey ell_i{MakeByteSpan(link.wire[0]).first(EllSwiftPubKey::size())};
        const EllSwiftPubKey ell_r{MakeByteSpan(link.wire[1]).first(EllSwiftPubKey::size())};
        const std::vector<uint8_t>& stream{read_initiator_stream ? link.wire[0] : link.wire[1]};
        const CKey& adv_key{read_initiator_stream ? key_r : key_i};
        const uint256& adv_ent{read_initiator_stream ? ent_r : ent_i};
        const EllSwiftPubKey& their_ell{read_initiator_stream ? ell_i : ell_r};
        const bool adv_initiator{!read_initiator_stream};

        const auto make_cipher = [&] {
            auto c{std::make_unique<BIP324Cipher>(adv_key, MakeByteSpan(adv_ent))};
            c->Initialize(their_ell, adv_initiator, /*self_decrypt=*/false, V2HybridMode::OFF);
            return c;
        };
        auto cipher{make_cipher()};

        std::vector<uint8_t> in{stream};
        in.erase(in.begin(), in.begin() + EllSwiftPubKey::size());
        const auto term{Bytes(cipher->GetReceiveGarbageTerminator())};
        const auto term_it{std::ranges::search(in, term).begin()};
        BOOST_REQUIRE(term_it != in.end());
        std::vector<uint8_t> aad(in.begin(), term_it);
        in.erase(in.begin(), term_it + term.size());
        // Read stage-1 packets up to and including the version packet (ignore bit clear); decoys are skipped.
        const auto read_stage1 = [&] {
            BOOST_REQUIRE(in.size() >= BIP324Cipher::LENGTH_LEN);
            const unsigned len{cipher->DecryptLength(MakeByteSpan(in).first(BIP324Cipher::LENGTH_LEN))};
            BOOST_REQUIRE(in.size() >= len + BIP324Cipher::EXPANSION);
            std::vector<uint8_t> contents(len);
            bool ignore{false};
            BOOST_REQUIRE(cipher->Decrypt(MakeByteSpan(in).subspan(BIP324Cipher::LENGTH_LEN, len + BIP324Cipher::EXPANSION - BIP324Cipher::LENGTH_LEN),
                                          MakeByteSpan(aad), ignore, MakeWritableByteSpan(contents)));
            aad.clear();
            in.erase(in.begin(), in.begin() + len + BIP324Cipher::EXPANSION);
            return ignore;
        };
        while (read_stage1()) {}

        // `in` now begins with the first packet after the version packet (a stage-2 packet). It must not
        // authenticate under the stage-1 keys, with the length cipher continued or restarted at 0.
        const auto fails_under = [&](BIP324Cipher& c) {
            if (in.size() < BIP324Cipher::LENGTH_LEN) return true;
            const unsigned len{c.DecryptLength(MakeByteSpan(in).first(BIP324Cipher::LENGTH_LEN))};
            if (size_t{len} + BIP324Cipher::EXPANSION > in.size()) return true; // a random length: not a stage-1 packet
            std::vector<uint8_t> contents(len);
            bool ignore{false};
            return !c.Decrypt(MakeByteSpan(in).subspan(BIP324Cipher::LENGTH_LEN, len + BIP324Cipher::EXPANSION - BIP324Cipher::LENGTH_LEN),
                              {}, ignore, MakeWritableByteSpan(contents));
        };
        BOOST_CHECK(fails_under(*cipher)); // stage-1 counters continued past the version packet
        auto fresh{make_cipher()};
        BOOST_CHECK(fails_under(*fresh));  // stage-1 counters restarted at 0
    }
}

BOOST_AUTO_TEST_SUITE_END()
