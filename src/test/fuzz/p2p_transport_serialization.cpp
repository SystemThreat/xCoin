// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>
#include <chainparams.h>
#include <crypto/mlkem768.h>
#include <hash.h>
#include <net.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace {

auto g_all_messages = ALL_NET_MESSAGE_TYPES;

void initialize_p2p_transport_serialization()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
    std::sort(g_all_messages.begin(), g_all_messages.end());
}

} // namespace

FUZZ_TARGET(p2p_transport_serialization, .init = initialize_p2p_transport_serialization)
{
    // Construct transports for both sides, with dummy NodeIds.
    V1Transport recv_transport{NodeId{0}};
    V1Transport send_transport{NodeId{1}};

    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto checksum_assist = fuzzed_data_provider.ConsumeBool();
    auto magic_bytes_assist = fuzzed_data_provider.ConsumeBool();
    std::vector<uint8_t> mutable_msg_bytes;

    auto header_bytes_remaining = CMessageHeader::HEADER_SIZE;
    if (magic_bytes_assist) {
        auto msg_start = Params().MessageStart();
        for (size_t i = 0; i < CMessageHeader::MESSAGE_SIZE_SIZE; ++i) {
            mutable_msg_bytes.push_back(msg_start[i]);
        }
        header_bytes_remaining -= CMessageHeader::MESSAGE_SIZE_SIZE;
    }

    if (checksum_assist) {
        header_bytes_remaining -= CMessageHeader::CHECKSUM_SIZE;
    }

    auto header_random_bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(header_bytes_remaining);
    mutable_msg_bytes.insert(mutable_msg_bytes.end(), header_random_bytes.begin(), header_random_bytes.end());
    auto payload_bytes = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    if (checksum_assist && mutable_msg_bytes.size() == CMessageHeader::CHECKSUM_OFFSET) {
        CHash256 hasher;
        unsigned char hsh[32];
        hasher.Write(payload_bytes);
        hasher.Finalize(hsh);
        for (size_t i = 0; i < CMessageHeader::CHECKSUM_SIZE; ++i) {
           mutable_msg_bytes.push_back(hsh[i]);
        }
    }

    mutable_msg_bytes.insert(mutable_msg_bytes.end(), payload_bytes.begin(), payload_bytes.end());
    std::span<const uint8_t> msg_bytes{mutable_msg_bytes};
    while (msg_bytes.size() > 0) {
        if (!recv_transport.ReceivedBytes(msg_bytes)) {
            break;
        }
        if (recv_transport.ReceivedMessageComplete()) {
            const std::chrono::microseconds m_time{std::numeric_limits<int64_t>::max()};
            bool reject_message{false};
            CNetMessage msg = recv_transport.GetReceivedMessage(m_time, reject_message);
            assert(msg.m_type.size() <= CMessageHeader::MESSAGE_TYPE_SIZE);
            assert(msg.m_raw_message_size <= mutable_msg_bytes.size());
            assert(msg.m_raw_message_size == CMessageHeader::HEADER_SIZE + msg.m_message_size);
            assert(msg.m_time == m_time);

            std::vector<unsigned char> header;
            auto msg2 = NetMsg::Make(msg.m_type, std::span{msg.m_recv});
            bool queued = send_transport.SetMessageToSend(msg2);
            assert(queued);
            std::optional<bool> known_more;
            while (true) {
                const auto& [to_send, more, _msg_type] = send_transport.GetBytesToSend(false);
                if (known_more) assert(!to_send.empty() == *known_more);
                if (to_send.empty()) break;
                send_transport.MarkBytesSent(to_send.size());
                known_more = more;
            }
        }
    }
}

namespace {

/** How the handshake between the two transports is expected to end (XIP-4). */
struct Expectation {
    /** The side (0 initiator, 1 responder) whose ReceivedBytes() must return false, which ends the simulation. */
    std::optional<int> fail_side;
    /** Both sides end in a confirmed HX1 session. */
    bool hybrid{false};
};

template<RandomNumberGenerator R>
void SimulationTest(Transport& initiator, Transport& responder, R& rng, FuzzedDataProvider& provider, const Expectation& expect = {})
{
    // Simulation test with two Transport objects, which send messages to each other, with
    // sending and receiving fragmented into multiple pieces that may be interleaved. It primarily
    // verifies that the sending and receiving side are compatible with each other, plus a few
    // sanity checks. It does not attempt to introduce errors in the communicated data.

    // Put the transports in an array for by-index access.
    const std::array<Transport*, 2> transports = {&initiator, &responder};

    // Two vectors representing in-flight bytes. inflight[i] is from transport[i] to transport[!i].
    std::array<std::vector<uint8_t>, 2> in_flight;

    // Two queues with expected messages. expected[i] is expected to arrive in transport[!i].
    std::array<std::deque<CSerializedNetMsg>, 2> expected;

    // Vectors with bytes last returned by GetBytesToSend() on transport[i].
    std::array<std::vector<uint8_t>, 2> to_send;

    // Last returned 'more' values (if still relevant) by transport[i]->GetBytesToSend(), for
    // both have_next_message false and true.
    std::array<std::optional<bool>, 2> last_more, last_more_next;

    // Whether more bytes to be sent are expected on transport[i], before and after
    // SetMessageToSend().
    std::array<std::optional<bool>, 2> expect_more, expect_more_next;

    // Whether the side expected to refuse the handshake has done so, which ends the simulation.
    bool failed{false};

    // How many messages each side has queued so far.
    std::array<unsigned, 2> queued_count{0, 0};

    // Function to consume a message type.
    auto msg_type_fn = [&]() {
        uint8_t v = provider.ConsumeIntegral<uint8_t>();
        if (v == 0xFF) {
            // If v is 0xFF, construct a valid (but possibly unknown) message type from the fuzz
            // data.
            std::string ret;
            while (ret.size() < CMessageHeader::MESSAGE_TYPE_SIZE) {
                char c = provider.ConsumeIntegral<char>();
                // Match the allowed characters in CMessageHeader::IsMessageTypeValid(). Any other
                // character is interpreted as end.
                if (c < ' ' || c > 0x7E) break;
                ret += c;
            }
            return ret;
        } else {
            // Otherwise, use it as index into the list of known messages.
            return g_all_messages[v % g_all_messages.size()];
        }
    };

    // Function to construct a CSerializedNetMsg to send.
    auto make_msg_fn = [&](bool first) {
        CSerializedNetMsg msg;
        if (first) {
            // Always send a "version" message as first one.
            msg.m_type = "version";
        } else {
            msg.m_type = msg_type_fn();
        }
        // Determine size of message to send (limited to 75 kB for performance reasons).
        size_t size = provider.ConsumeIntegralInRange<uint32_t>(0, 75000);
        // Get payload of message from RNG.
        msg.data = rng.randbytes(size);
        // Return.
        return msg;
    };

    // The next message to be sent (initially version messages, but will be replaced once sent).
    std::array<CSerializedNetMsg, 2> next_msg = {
        make_msg_fn(/*first=*/true),
        make_msg_fn(/*first=*/true)
    };

    // Wrapper around transport[i]->GetBytesToSend() that performs sanity checks.
    auto bytes_to_send_fn = [&](int side) -> Transport::BytesToSend {
        // Invoke GetBytesToSend twice (for have_next_message = {false, true}). This function does
        // not modify state (it's const), and only the "more" return value should differ between
        // the calls.
        const auto& [bytes, more_nonext, msg_type] = transports[side]->GetBytesToSend(false);
        const auto& [bytes_next, more_next, msg_type_next] = transports[side]->GetBytesToSend(true);
        // Compare with expected more.
        if (expect_more[side].has_value()) assert(!bytes.empty() == *expect_more[side]);
        // Verify consistency between the two results.
        assert(std::ranges::equal(bytes, bytes_next));
        assert(msg_type == msg_type_next);
        if (more_nonext) assert(more_next);
        // Compare with previously reported output.
        assert(to_send[side].size() <= bytes.size());
        assert(std::ranges::equal(to_send[side], std::span{bytes}.first(to_send[side].size())));
        to_send[side].resize(bytes.size());
        std::copy(bytes.begin(), bytes.end(), to_send[side].begin());
        // Remember 'more' results.
        last_more[side] = {more_nonext};
        last_more_next[side] = {more_next};
        // Return.
        return {bytes, more_nonext, msg_type};
    };

    // Function to make side send a new message.
    auto new_msg_fn = [&](int side) {
        // Don't do anything if there are too many unreceived messages already.
        if (expected[side].size() >= 16) return;
        // Try to send (a copy of) the message in next_msg[side].
        CSerializedNetMsg msg = next_msg[side].Copy();
        bool queued = transports[side]->SetMessageToSend(msg);
        // Update expected more data.
        expect_more[side] = expect_more_next[side];
        expect_more_next[side] = std::nullopt;
        // Verify consistency of GetBytesToSend after SetMessageToSend
        bytes_to_send_fn(/*side=*/side);
        if (queued) {
            // Remember that this message is now expected by the receiver.
            expected[side].emplace_back(std::move(next_msg[side]));
            ++queued_count[side];
            // Construct a new next message to send.
            next_msg[side] = make_msg_fn(/*first=*/false);
        }
    };

    // Function to make side send out bytes (if any).
    auto send_fn = [&](int side, bool everything = false) {
        const auto& [bytes, more, msg_type] = bytes_to_send_fn(/*side=*/side);
        // Don't do anything if no bytes to send.
        if (bytes.empty()) return false;
        size_t send_now = everything ? bytes.size() : provider.ConsumeIntegralInRange<size_t>(0, bytes.size());
        if (send_now == 0) return false;
        // Add bytes to the in-flight queue, and mark those bytes as consumed.
        in_flight[side].insert(in_flight[side].end(), bytes.begin(), bytes.begin() + send_now);
        transports[side]->MarkBytesSent(send_now);
        // If all to-be-sent bytes were sent, move last_more data to expect_more data.
        if (send_now == bytes.size()) {
            expect_more[side] = last_more[side];
            expect_more_next[side] = last_more_next[side];
        }
        // Remove the bytes from the last reported to-be-sent vector.
        assert(to_send[side].size() >= send_now);
        to_send[side].erase(to_send[side].begin(), to_send[side].begin() + send_now);
        // Verify that GetBytesToSend gives a result consistent with earlier.
        bytes_to_send_fn(/*side=*/side);
        // Return whether anything was sent.
        return send_now > 0;
    };

    // Function to make !side receive bytes (if any).
    auto recv_fn = [&](int side, bool everything = false) {
        // Don't do anything if no bytes in flight.
        if (in_flight[side].empty()) return false;
        // Decide span to receive
        size_t to_recv_len = in_flight[side].size();
        if (!everything) to_recv_len = provider.ConsumeIntegralInRange<size_t>(0, to_recv_len);
        std::span<const uint8_t> to_recv = std::span{in_flight[side]}.first(to_recv_len);
        // Process those bytes
        while (!to_recv.empty()) {
            size_t old_len = to_recv.size();
            bool ret = transports[!side]->ReceivedBytes(to_recv);
            // Bytes must always be accepted, as this test does not introduce any errors in
            // communication, except by the side expected to refuse the handshake (XIP-4). The node
            // closes the connection there, so nothing is processed after it.
            if (!ret) {
                assert(expect.fail_side == (side == 0 ? 1 : 0));
                failed = true;
                return true;
            }
            // Clear cached expected 'more' information: if certainly no more data was to be sent
            // before, receiving bytes makes this uncertain.
            if (expect_more[!side] == false) expect_more[!side] = std::nullopt;
            if (expect_more_next[!side] == false) expect_more_next[!side] = std::nullopt;
            // Verify consistency of GetBytesToSend after ReceivedBytes
            bytes_to_send_fn(/*side=*/!side);
            bool progress = to_recv.size() < old_len;
            if (transports[!side]->ReceivedMessageComplete()) {
                bool reject{false};
                auto received = transports[!side]->GetReceivedMessage({}, reject);
                // Receiving must succeed.
                assert(!reject);
                // There must be a corresponding expected message.
                assert(!expected[side].empty());
                // The m_message_size field must be correct.
                assert(received.m_message_size == received.m_recv.size());
                // The m_type must match what is expected.
                assert(received.m_type == expected[side].front().m_type);
                // The data must match what is expected.
                assert(std::ranges::equal(received.m_recv, MakeByteSpan(expected[side].front().data)));
                expected[side].pop_front();
                progress = true;
            }
            // Progress must be made (by processing incoming bytes and/or returning complete
            // messages) until all received bytes are processed.
            assert(progress);
        }
        // Remove the processed bytes from the in_flight buffer.
        in_flight[side].erase(in_flight[side].begin(), in_flight[side].begin() + to_recv_len);
        // Return whether anything was received.
        return to_recv_len > 0;
    };

    // Main loop, interleaving new messages, sends, and receives.
    LIMITED_WHILE(provider.remaining_bytes() && !failed, 1000) {
        CallOneOf(provider,
            // (Try to) give the next message to the transport.
            [&] { new_msg_fn(/*side=*/0); },
            [&] { new_msg_fn(/*side=*/1); },
            // (Try to) send some bytes from the transport to the network.
            [&] { send_fn(/*side=*/0); },
            [&] { send_fn(/*side=*/1); },
            // (Try to) receive bytes from the network, converting to messages.
            [&] { recv_fn(/*side=*/0); },
            [&] { recv_fn(/*side=*/1); }
        );
    }

    // When we're done, perform sends and receives of existing messages to flush anything already
    // in flight.
    auto flush_fn = [&] {
        while (!failed) {
            bool any = false;
            if (send_fn(/*side=*/0, /*everything=*/true)) any = true;
            if (send_fn(/*side=*/1, /*everything=*/true)) any = true;
            if (recv_fn(/*side=*/0, /*everything=*/true)) any = true;
            if (recv_fn(/*side=*/1, /*everything=*/true)) any = true;
            if (!any) break;
        }
    };
    flush_fn();

    // A hybrid responder confirms its keys on the initiator's first stage-2 packet, a require-mode
    // responder refuses v1 on the initiator's first bytes (XIP-4), and a v2 responder only detects a v1
    // initiator from its first 16 bytes: have the initiator send a message if the fuzzer did not.
    if (!failed && (expect.hybrid || expect.fail_side || transports[1]->GetInfo().transport_type == TransportProtocolType::DETECTING) &&
        queued_count[0] == 0) {
        new_msg_fn(/*side=*/0);
        flush_fn();
    }

    if (expect.fail_side) {
        assert(failed);
        return;
    }

    // Make sure nothing is left in flight.
    assert(in_flight[0].empty());
    assert(in_flight[1].empty());

    // Make sure all expected messages were received.
    assert(expected[0].empty());
    assert(expected[1].empty());

    // Compare session IDs and transport types, and check the HX1 state (XIP-4).
    const auto info0{transports[0]->GetInfo()};
    const auto info1{transports[1]->GetInfo()};
    assert(info0.session_id == info1.session_id);
    assert(info0.transport_type == info1.transport_type);
    assert(info0.hybrid == expect.hybrid);
    assert(info1.hybrid == expect.hybrid);
}

std::unique_ptr<Transport> MakeV1Transport(NodeId nodeid) noexcept
{
    return std::make_unique<V1Transport>(nodeid);
}

/** ML-KEM calls with seeds from the RNG, so that a run is reproducible; the node's own random path is for the
 *  unit tests. */
template<RandomNumberGenerator RNG>
V2HybridKem FixedSeedKem(RNG& rng)
{
    std::array<std::byte, 32> d, z, m;
    for (auto* seed : {&d, &z, &m}) std::ranges::copy(rng.template randbytes<std::byte>(32), seed->begin());
    V2HybridKem kem;
    kem.keygen = [d, z] { return mlkem768::KeyGen(d, z); };
    kem.encaps = [m](std::span<const std::byte, mlkem768::ENCAPS_KEY_SIZE> ek) { return mlkem768::Encaps(ek, m); };
    return kem;
}

template<RandomNumberGenerator RNG>
std::unique_ptr<Transport> MakeV2Transport(NodeId nodeid, bool initiator, RNG& rng, FuzzedDataProvider& provider, V2HybridMode mode, V2HybridCounters* counters)
{
    // Retrieve key
    auto key = ConsumePrivateKey(provider);
    if (!key.IsValid()) return {};
    // Construct garbage
    size_t garb_len = provider.ConsumeIntegralInRange<size_t>(0, V2Transport::MAX_GARBAGE_LEN);
    std::vector<uint8_t> garb;
    if (garb_len <= 64) {
        // When the garbage length is up to 64 bytes, read it directly from the fuzzer input.
        garb = provider.ConsumeBytes<uint8_t>(garb_len);
        garb.resize(garb_len);
    } else {
        // If it's longer, generate it from the RNG. This avoids having large amounts of
        // (hopefully) irrelevant data needing to be stored in the fuzzer data.
        garb = rng.randbytes(garb_len);
    }
    // Retrieve entropy
    auto ent = provider.ConsumeBytes<std::byte>(32);
    ent.resize(32);
    // Use as entropy SHA256(ent || garbage). This prevents a situation where the fuzzer manages to
    // include the garbage terminator (which is a function of both ellswift keys) in the garbage.
    // This is extremely unlikely (~2^-116) with random keys/garbage, but the fuzzer can choose
    // both non-randomly and dependently. Since the entropy is hashed anyway inside the ellswift
    // computation, no coverage should be lost by using a hash as entropy, and it removes the
    // possibility of garbage that happens to contain what is effectively a hash of the keys.
    CSHA256().Write(UCharCast(ent.data()), ent.size())
             .Write(garb.data(), garb.size())
             .Finalize(UCharCast(ent.data()));

    return std::make_unique<V2Transport>(nodeid, initiator, key, ent, std::move(garb), mode, FixedSeedKem(rng), counters);
}

/** Both sides' -v2hybrid modes and how the handshake between them ends (XIP-4, "Interop matrix"). */
struct ModePair {
    V2HybridMode initiator;
    V2HybridMode responder;
    Expectation expect;
};

ModePair ConsumeModePair(FuzzedDataProvider& provider)
{
    const uint8_t v{provider.ConsumeIntegral<uint8_t>()};
    ModePair modes{static_cast<V2HybridMode>(v % 3), static_cast<V2HybridMode>((v / 3) % 3), {}};
    const bool off_initiator{modes.initiator == V2HybridMode::OFF};
    const bool off_responder{modes.responder == V2HybridMode::OFF};
    if (off_initiator && modes.responder == V2HybridMode::REQUIRE) {
        modes.expect.fail_side = 1;
    } else if (modes.initiator == V2HybridMode::REQUIRE && off_responder) {
        modes.expect.fail_side = 0;
    } else {
        modes.expect.hybrid = !off_initiator && !off_responder;
    }
    return modes;
}

/** What a side in `mode` has counted once the simulation ends (XIP-4, "What a node reports"). */
void CheckCounters(const V2HybridCounters& counters, V2HybridMode mode, const Expectation& expect, int side)
{
    std::array<uint64_t, V2_HYBRID_OUTCOMES> want{};
    if (mode != V2HybridMode::OFF) {
        if (expect.fail_side == side) {
            want[static_cast<size_t>(V2HybridOutcome::REFUSED)] = 1;
        } else if (expect.hybrid) {
            want[static_cast<size_t>(V2HybridOutcome::HYBRID)] = 1;
        } else {
            want[static_cast<size_t>(V2HybridOutcome::CLASSICAL)] = 1;
        }
    }
    for (size_t i{0}; i < want.size(); ++i) assert(counters[i].load() == want[i]);
}

} // namespace

FUZZ_TARGET(p2p_transport_bidirectional, .init = initialize_p2p_transport_serialization)
{
    // Test with two V1 transports talking to each other.
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>());
    auto t1 = MakeV1Transport(NodeId{0});
    auto t2 = MakeV1Transport(NodeId{1});
    if (!t1 || !t2) return;
    SimulationTest(*t1, *t2, rng, provider);
}

FUZZ_TARGET(p2p_transport_bidirectional_v2, .init = initialize_p2p_transport_serialization)
{
    // Test with two V2 transports talking to each other, in every pair of -v2hybrid modes (XIP-4).
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>());
    const ModePair modes{ConsumeModePair(provider)};
    std::array<V2HybridCounters, 2> counters{};
    auto t1 = MakeV2Transport(NodeId{0}, true, rng, provider, modes.initiator, &counters[0]);
    auto t2 = MakeV2Transport(NodeId{1}, false, rng, provider, modes.responder, &counters[1]);
    if (!t1 || !t2) return;
    SimulationTest(*t1, *t2, rng, provider, modes.expect);
    CheckCounters(counters[0], modes.initiator, modes.expect, /*side=*/0);
    CheckCounters(counters[1], modes.responder, modes.expect, /*side=*/1);
}

FUZZ_TARGET(p2p_transport_bidirectional_v1v2, .init = initialize_p2p_transport_serialization)
{
    // Test with a V1 initiator talking to a V2 responder, in every -v2hybrid mode: require refuses v1 (XIP-4).
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>());
    const auto mode{static_cast<V2HybridMode>(provider.ConsumeIntegral<uint8_t>() % 3)};
    Expectation expect;
    if (mode == V2HybridMode::REQUIRE) expect.fail_side = 1;
    V2HybridCounters counters{};
    auto t1 = MakeV1Transport(NodeId{0});
    auto t2 = MakeV2Transport(NodeId{1}, false, rng, provider, mode, &counters);
    if (!t1 || !t2) return;
    SimulationTest(*t1, *t2, rng, provider, expect);
    // A v1 session counts nothing; a refusal counts once.
    for (size_t i{0}; i < counters.size(); ++i) {
        assert(counters[i].load() == (i == static_cast<size_t>(V2HybridOutcome::REFUSED) && expect.fail_side ? 1U : 0U));
    }
}
