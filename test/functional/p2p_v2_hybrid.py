#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the HX1 hybrid post-quantum v2 transport (XIP-4).

Three nodes, one per -v2hybrid mode (0 off, 1 prefer, 2 require), and framework peers in every mode and both
roles. The framework peer in its default mode 0 is an old node: classical BIP324 that ignores version packet
contents. Covers the interop matrix between nodes and against the framework peer, the getpeerinfo and
getnetworkinfo fields and counters, the kill switch, require mode refusing v1 and classical peers and the v1
reconnect, inbound failures, the one classical retry after each failure XIP-4 lists, and the startup errors.
"""
import re
import time

from test_framework.crypto import mlkem
from test_framework.messages import NODE_P2P_V2
from test_framework.p2p import P2PInterface, P2P_SERVICES, logger
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)
from test_framework.v2_p2p import (
    EncryptedP2PState,
    HX1_FIRST_STAGE2_MAX_CONTENTS,
    HX1_MODE_OFF,
    HX1_MODE_PREFER,
    HX1_MODE_REQUIRE,
    HX1_OUTCOMES,
)

MODES = (HX1_MODE_OFF, HX1_MODE_PREFER, HX1_MODE_REQUIRE)
MODE_NAMES = {HX1_MODE_OFF: "off", HX1_MODE_PREFER: "prefer", HX1_MODE_REQUIRE: "require"}
# getnetworkinfo's v2hybrid_counts: the outcomes the framework knows, plus the retry connections a node opens.
COUNTERS = HX1_OUTCOMES + ("classical_retry",)
NO_HX1_RECORD = "sent no HX1 record, disconnecting (-v2hybrid=2)"
CLASSICAL_RETRY = "retrying once as classical v2"
V1_RETRY = "retrying with v1 transport protocol for peer"
# A version packet's 20 bytes of expansion (3 length, 1 header, 16 tag), and an OFFER record (12-byte header, ek).
PACKET_EXPANSION = 20
OFFER_RECORD_LEN = 12 + mlkem.EK_SIZE


class HybridPeer(P2PInterface):
    """A framework peer that builds its EncryptedP2PState with `make_state` on every connection, so a test can
    change one side's HX1 behaviour, and so that a reconnection by the node (its classical retry) starts from a
    fresh state. Counts connections and disconnections, which can come and go between two polls."""
    def __init__(self, make_state=EncryptedP2PState):
        super().__init__()
        self.make_state = make_state
        self.connections = 0
        self.disconnections = 0

    def connection_made(self, transport):
        if self.v2_state is not None:
            self.v2_state = self.make_state(initiating=self.v2_state.initiating, net=self.v2_state.net,
                                            hybrid_mode=self.v2_state.hybrid_mode)
        self.connections += 1
        super().connection_made(transport)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.disconnections += 1

    def data_received(self, t):
        # A refused or failed handshake is an expected outcome here. Close the connection as asyncio would, but
        # without its fatal-error report on stderr, which test_runner.py counts as a failed test.
        try:
            super().data_received(t)
        except ValueError as e:
            logger.debug(f"closing the connection after an expected handshake failure: {e}")
            self._transport.abort()

    def wait_for_hx1_disconnect(self, n=1):
        self.wait_until(lambda: self.disconnections == n, check_connected=False)


class WrongSecretState(EncryptedP2PState):
    """Derives its stage-2 keys from the wrong ML-KEM secret: as a responder from a wrong decapsulation, as an
    initiator from a wrong encapsulation result with the right ciphertext. The filler after the switch makes the
    node's first stage-2 packet fail at once whether or not its length happens to pass the limit."""
    def hx1_decaps(self, dk, ct):
        return bytes(32)

    def hx1_encaps(self, ek):
        _, ct = super().hx1_encaps(ek)
        return bytes(32), ct

    def hx1_decoys_after_switch(self):
        return [b"", b"\x00" * (HX1_FIRST_STAGE2_MAX_CONTENTS + 100)]


class WrongSecretResponderState(WrongSecretState):
    """As a responder, sends its (wrongly keyed) confirmation packet and then reads nothing more. Both sides fail
    on the other's first stage-2 packet; making this side never close lets the node's detection happen first, so
    the classical-retry test sees the node count stage2_failed rather than race the peer's close (XIP-4 shrinks
    that window but does not remove it)."""
    def v2_receive_packet(self, response, aad=b''):
        if self.hybrid:
            return 0, None  # hold the node's stage-2 packets unread; never raise, never close
        return super().v2_receive_packet(response, aad)


class MalformedRecordState(EncryptedP2PState):
    """Sends the HX1 tag and version, then stops inside the 12-byte record header: malformed (XIP-4)."""
    def hx1_version_contents(self, record):
        return record[:11]


class BadKeyState(EncryptedP2PState):
    """Offers an encapsulation key whose first coefficient is 3329, which fails the FIPS 203 section 7.2 check."""
    def hx1_keygen(self):
        ek, dk = super().hx1_keygen()
        return mlkem.set_ek_coefficient(bytes(ek), 0, 3329), dk


class OversizeFirstPacketState(EncryptedP2PState):
    """An initiator whose first stage-2 packet has one byte of contents over the limit."""
    def _hx1_check_first_send(self, contents):
        pass

    def hx1_decoys_after_switch(self):
        return [b"\x00" * (HX1_FIRST_STAGE2_MAX_CONTENTS + 1)]


class DecoyState(EncryptedP2PState):
    """Sends decoys in both stages: three before its version packet and three right after its switch, the last
    one as large as the first stage-2 packet may be."""
    def decoys_before_version(self):
        return [b"", b"\x01" * 50, b"\x02" * 1000]

    def hx1_decoys_after_switch(self):
        return [b"", b"\x03" * 500, b"\x04" * HX1_FIRST_STAGE2_MAX_CONTENTS]


class SilentResponderState(EncryptedP2PState):
    """A responder that finishes HX1 but never sends its confirmation packet."""
    def take_pending_handshake_bytes(self):
        super().take_pending_handshake_bytes()
        return b""


class SilentResponderPeer(HybridPeer):
    """On its first connection, sends nothing at all after its version packet: the node's session stays
    unconfirmed until its handshake timeout. The node's classical retry, its second connection, runs normally."""
    def __init__(self):
        super().__init__(SilentResponderState)

    def on_version(self, message):
        if self.connections == 1:
            return
        super().on_version(message)


class HoldVersionState(EncryptedP2PState):
    """A responder that sends its garbage terminator at once but holds its version packet back until released,
    to see what the node sends before it has VP_R."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.held_version_packet = None

    def decoys_before_version(self):
        return []

    def complete_handshake(self, response):
        length, out = super().complete_handshake(response)
        if out:
            # The version packet is the last packet in `out`: empty in mode 0, the OFFER in the HX1 modes.
            vp_len = PACKET_EXPANSION + (0 if self.hybrid_mode == HX1_MODE_OFF else OFFER_RECORD_LEN)
            self.held_version_packet, out = out[-vp_len:], out[:-vp_len]
        return length, out


class HoldVersionPeer(HybridPeer):
    def __init__(self):
        super().__init__(HoldVersionState)
        self.deferred_version = None

    def on_version(self, message):
        if self.v2_state.held_version_packet is not None:
            # Answer only once our version packet has left, so that the node's stream stays in order.
            self.deferred_version = message
            return
        super().on_version(message)

    def release_version_packet(self):
        packet, self.v2_state.held_version_packet = self.v2_state.held_version_packet, None
        self.send_raw_message(packet)
        if self.deferred_version is not None:
            message, self.deferred_version = self.deferred_version, None
            super().on_version(message)


class V2HybridTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        # Node 1 runs the default mode, which XIP-4 sets to prefer on every network.
        self.extra_args = [["-v2transport=1", "-v2hybrid=0"], ["-v2transport=1"], ["-v2transport=1", "-v2hybrid=2"]]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.expected = [{name: 0 for name in COUNTERS} for _ in self.nodes]
        # The framework peer for p2p_idx listens on p2p_port(MAX_NODES - (p2p_idx + 1)), so p2p_idx must stay in
        # 0..8 to keep clear of the three running nodes' ports (p2p_port(0..2)). Reconnected-to peers each need a
        # port used only once (the listener holds a reconnect peer's protocol for the node's second attempt), so
        # they get their own five indices; the rest cycle through a shared pool, since a peer that is not
        # reconnected to clears its port when it disconnects.
        self.reconnect_pool = iter(range(5))       # 0..4  -> ports p2p_port(11..7)
        self.share_pool = [5, 6, 7, 8]             # ports p2p_port(6..3)
        self.share_i = 0
        self.test_getnetworkinfo()
        self.test_node_pairs()
        self.test_framework_peers()
        self.test_decoys()
        self.test_kill_switch()
        self.test_require_mode()
        self.test_inbound_failures()
        self.test_classical_retry()
        self.test_startup_errors()

    # Helpers

    def next_idx(self):
        """A p2p_idx from the shared pool, for a peer the node is not reconnected to."""
        idx = self.share_pool[self.share_i % len(self.share_pool)]
        self.share_i += 1
        return idx

    def reconnect_idx(self):
        """A fresh p2p_idx for a peer the node reconnects to: the framework's listener keeps that port's protocol
        for the node's second attempt, so the port cannot be shared."""
        return next(self.reconnect_pool)

    def expect(self, i, counter, n=1):
        self.expected[i][counter] += n

    def check_counts(self):
        for node, expected in zip(self.nodes, self.expected):
            self.wait_until(lambda: node.getnetworkinfo()["v2hybrid_counts"] == expected)

    def wait_peerless(self, node):
        self.wait_until(lambda: not node.getpeerinfo())

    def open_outbound(self, node, peer, *, v2hybrid=HX1_MODE_OFF, supports_v2_p2p=True, reconnect=False,
                      connection_type="outbound-full-relay"):
        """Have `node` connect out to `peer`, advertised as v2, without waiting for the handshake: for connections
        that are expected to fail, and for the classical retry (`reconnect` keeps the peer listening for it)."""
        def callback(address, port):
            node.addconnection(f"{address}:{port}", connection_type, True)
        p2p_idx = self.reconnect_idx() if reconnect else self.next_idx()
        peer.peer_accept_connection(connect_cb=callback, connect_id=p2p_idx + 1, net=node.chain,
                                    timeout_factor=node.timeout_factor, supports_v2_p2p=supports_v2_p2p,
                                    reconnect=reconnect, v2hybrid=v2hybrid, services=P2P_SERVICES | NODE_P2P_V2)()
        peer.wait_until(lambda: peer.connections >= 1, check_connected=False)
        return peer

    def check_session(self, node, peer, hybrid):
        """The node's one peer reports v2, a 64-hex session id and `hybrid`, and the same as the framework peer."""
        infos = node.getpeerinfo()
        assert_equal(len(infos), 1)
        info = infos[0]
        assert_equal(info["transport_protocol_type"], "v2")
        assert_equal(info["transport_hybrid"], hybrid)
        assert_equal(len(info["session_id"]), 64)
        expected = peer.v2_state.transport_info()
        assert_equal({key: info[key] for key in expected}, expected)

    # Tests

    def test_getnetworkinfo(self):
        self.log.info("getnetworkinfo reports the mode and zero counters at startup")
        for i, node in enumerate(self.nodes):
            info = node.getnetworkinfo()
            assert_equal(info["v2hybrid"], MODE_NAMES[i])
            assert_equal(sorted(info["v2hybrid_counts"]), sorted(COUNTERS))
        self.check_counts()

    def test_node_pairs(self):
        self.log.info("Every pair of modes between two nodes, in both roles (XIP-4 interop matrix, N0 to N2)")
        for a in range(3):
            for b in range(3):
                if a == b:
                    continue
                node_a, node_b = self.nodes[a], self.nodes[b]
                if {a, b} == {HX1_MODE_OFF, HX1_MODE_REQUIRE}:
                    # Dropped: after VP_R when the require node initiates, after VP_I when it responds. Neither
                    # side falls back to v1 or retries.
                    self.log.info(f"node {a} (mode {a}) connects to node {b} (mode {b}): dropped")
                    with self.nodes[2].assert_debug_log([NO_HX1_RECORD], unexpected_msgs=[V1_RETRY, CLASSICAL_RETRY], timeout=5):
                        node_a.addnode(f"127.0.0.1:{p2p_port(b)}", "onetry")
                        self.expect(2, "refused")
                        self.check_counts()
                        self.wait_peerless(node_a)
                        self.wait_peerless(node_b)
                    continue
                hybrid = a != HX1_MODE_OFF and b != HX1_MODE_OFF
                kind = "hybrid" if hybrid else "classical"
                self.log.info(f"node {a} (mode {a}) connects to node {b} (mode {b}): {kind}")
                with node_a.assert_debug_log([f"New manual peer connected: transport: v2 ({kind})"], timeout=5), \
                     node_b.assert_debug_log([f"New inbound peer connected: transport: v2 ({kind})"], timeout=5):
                    self.connect_nodes(a, b)
                info_a, info_b = node_a.getpeerinfo(), node_b.getpeerinfo()
                assert_equal(len(info_a), 1)
                assert_equal(len(info_b), 1)
                for info in (info_a[0], info_b[0]):
                    assert_equal(info["transport_protocol_type"], "v2")
                    assert_equal(info["transport_hybrid"], hybrid)
                    assert_equal(len(info["session_id"]), 64)
                assert_equal(info_a[0]["session_id"], info_b[0]["session_id"])
                for i in (a, b):
                    if i != HX1_MODE_OFF:
                        self.expect(i, kind)
                self.check_counts()
                self.disconnect_nodes(a, b)
                self.wait_peerless(node_a)
                self.wait_peerless(node_b)

    def test_framework_peers(self):
        for i, node in enumerate(self.nodes):
            for mode in MODES:
                hybrid = i != HX1_MODE_OFF and mode != HX1_MODE_OFF
                kind = "hybrid" if hybrid else "classical"
                self.log.info(f"framework peer in mode {mode} connects in to node {i} (mode {i})")
                if (mode, i) == (HX1_MODE_OFF, HX1_MODE_REQUIRE):
                    # An old node: dropped after VP_I.
                    with node.assert_debug_log([NO_HX1_RECORD], timeout=5):
                        peer = node.add_p2p_connection(HybridPeer(), supports_v2_p2p=True, v2hybrid=mode, expect_success=False)
                        peer.wait_for_hx1_disconnect()
                    self.expect(i, "refused")
                elif (mode, i) == (HX1_MODE_REQUIRE, HX1_MODE_OFF):
                    # The peer refuses the node's empty VP_R; the node counts nothing in mode 0.
                    peer = node.add_p2p_connection(HybridPeer(), supports_v2_p2p=True, v2hybrid=mode, expect_success=False)
                    peer.wait_for_hx1_disconnect()
                    assert_equal(peer.v2_state.hx1_outcome, "refused")
                else:
                    peer = node.add_p2p_connection(HybridPeer(), supports_v2_p2p=True, v2hybrid=mode)
                    self.check_session(node, peer, hybrid)
                    if mode != HX1_MODE_OFF:
                        assert_equal(peer.v2_state.hx1_outcome, kind)
                    if i != HX1_MODE_OFF:
                        self.expect(i, kind)
                self.check_counts()
                node.disconnect_p2ps()
                self.wait_peerless(node)

                self.log.info(f"node {i} (mode {i}) connects out to a framework peer in mode {mode}")
                if (i, mode) == (HX1_MODE_REQUIRE, HX1_MODE_OFF):
                    # Dropped after VP_R, without a v1 reconnect or a classical retry.
                    peer = HybridPeer()
                    with node.assert_debug_log([NO_HX1_RECORD], unexpected_msgs=[V1_RETRY, CLASSICAL_RETRY], timeout=5):
                        self.open_outbound(node, peer, v2hybrid=mode)
                        peer.wait_for_hx1_disconnect()
                        self.wait_peerless(node)
                    self.expect(i, "refused")
                elif (i, mode) == (HX1_MODE_OFF, HX1_MODE_REQUIRE):
                    peer = HybridPeer()
                    self.open_outbound(node, peer, v2hybrid=mode)
                    peer.wait_for_hx1_disconnect()
                    assert_equal(peer.v2_state.hx1_outcome, "refused")
                    self.wait_peerless(node)
                else:
                    peer = node.add_outbound_p2p_connection(HybridPeer(), p2p_idx=self.next_idx(), supports_v2_p2p=True,
                                                            advertise_v2_p2p=True, v2hybrid=mode)
                    self.check_session(node, peer, hybrid)
                    if mode != HX1_MODE_OFF:
                        assert_equal(peer.v2_state.hx1_outcome, kind)
                    if i != HX1_MODE_OFF:
                        self.expect(i, kind)
                    node.disconnect_p2ps()
                    self.wait_peerless(node)
                self.check_counts()

    def test_decoys(self):
        node = self.nodes[1]
        self.log.info("Decoys in both stages, from a framework initiator and from a framework responder")
        peer = node.add_p2p_connection(HybridPeer(DecoyState), supports_v2_p2p=True, v2hybrid=HX1_MODE_PREFER)
        self.check_session(node, peer, hybrid=True)
        node.disconnect_p2ps()
        self.wait_peerless(node)
        peer = node.add_outbound_p2p_connection(HybridPeer(DecoyState), p2p_idx=self.next_idx(), supports_v2_p2p=True,
                                                advertise_v2_p2p=True, v2hybrid=HX1_MODE_PREFER)
        self.check_session(node, peer, hybrid=True)
        node.disconnect_p2ps()
        self.wait_peerless(node)
        self.expect(1, "hybrid", 2)
        self.check_counts()

    def test_kill_switch(self):
        node0 = self.nodes[0]
        for mode in (HX1_MODE_OFF, HX1_MODE_PREFER):
            self.log.info(f"Kill switch: the mode-0 node sends its empty version packet before it has the responder's (framework mode {mode})")
            peer = HoldVersionPeer()
            self.open_outbound(node0, peer, v2hybrid=mode)
            peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
            assert_equal(peer.v2_state.received_version_contents, b"")
            assert peer.v2_state.held_version_packet is not None
            peer.release_version_packet()
            peer.wait_for_verack()
            peer.sync_with_ping()
            self.check_session(node0, peer, hybrid=False)
            if mode != HX1_MODE_OFF:
                assert_equal(peer.v2_state.hx1_outcome, "classical")
            peer.peer_disconnect()
            self.wait_peerless(node0)
        assert_equal(node0.getnetworkinfo()["v2hybrid"], "off")
        self.check_counts()

        for i in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
            node = self.nodes[i]
            self.log.info(f"A node in mode {i} sends its garbage terminator, then waits for the responder's version packet")
            peer = HoldVersionPeer()
            self.open_outbound(node, peer, v2hybrid=HX1_MODE_PREFER)
            peer.wait_until(lambda: peer.v2_state.found_garbage_terminator)
            handshake_sent = 64 + len(peer.v2_state.received_garbage) + 16
            self.wait_until(lambda: node.getpeerinfo()[-1]["bytessent"] >= handshake_sent)
            assert_equal(node.getpeerinfo()[-1]["bytessent"], handshake_sent)
            assert not peer.v2_state.tried_v2_handshake
            assert_equal(node.getpeerinfo()[-1]["transport_protocol_type"], "detecting")
            assert_equal(node.getpeerinfo()[-1]["transport_hybrid"], False)
            peer.release_version_packet()
            peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
            peer.wait_for_verack()
            peer.sync_with_ping()
            self.check_session(node, peer, hybrid=True)
            self.expect(i, "hybrid")
            peer.peer_disconnect()
            self.wait_peerless(node)
        self.check_counts()

    def test_require_mode(self):
        node1, node2 = self.nodes[1], self.nodes[2]
        self.log.info("Require mode refuses an inbound plaintext v1 peer after its 16-byte prefix; prefer mode accepts it")
        with node2.assert_debug_log(["HX1: refusing inbound v1 connection (-v2hybrid=2)"], timeout=5):
            peer = node2.add_p2p_connection(HybridPeer(), supports_v2_p2p=False, expect_success=False)
            peer.wait_for_hx1_disconnect()
        self.expect(2, "refused")
        self.check_counts()
        node2.disconnect_p2ps()
        self.wait_peerless(node2)
        node1.add_p2p_connection(HybridPeer(), supports_v2_p2p=False)
        info = node1.getpeerinfo()
        assert_equal(len(info), 1)
        assert_equal(info[0]["transport_protocol_type"], "v1")
        assert_equal(info[0]["transport_hybrid"], False)
        assert_equal(info[0]["session_id"], "")
        node1.disconnect_p2ps()
        self.wait_peerless(node1)

        self.log.info("Require mode never reconnects with v1 to a peer that sent nothing; prefer mode does, as today")
        peer = HybridPeer()
        with node2.assert_debug_log(["HX1: not retrying with v1 transport protocol (-v2hybrid=2)"], unexpected_msgs=[V1_RETRY], timeout=5):
            self.open_outbound(node2, peer, supports_v2_p2p=False)
            peer.wait_for_hx1_disconnect()
            self.wait_peerless(node2)
            self.expect(2, "refused")
            self.check_counts()
        assert_equal(peer.connections, 1)
        with node1.assert_debug_log([V1_RETRY], timeout=5):
            peer = node1.add_outbound_p2p_connection(HybridPeer(), p2p_idx=self.reconnect_idx(), supports_v2_p2p=False, advertise_v2_p2p=True)
        assert_equal(peer.connections, 2)
        info = node1.getpeerinfo()
        assert_equal(len(info), 1)
        assert_equal(info[0]["transport_protocol_type"], "v1")
        assert_equal(info[0]["transport_hybrid"], False)
        node1.disconnect_p2ps()
        self.wait_peerless(node1)
        self.check_counts()

        self.log.info("Require mode rejects addnode and addconnection with v2transport=false")
        ip_port = f"127.0.0.1:{p2p_port(1)}"
        error = "Error: v2transport=false is not allowed with -v2hybrid=2"
        assert_raises_rpc_error(-8, error, node2.addnode, node=ip_port, command="onetry", v2transport=False)
        assert_raises_rpc_error(-8, error, node2.addnode, node=ip_port, command="add", v2transport=False)
        assert_raises_rpc_error(-8, error, node2.addconnection, ip_port, "outbound-full-relay", False)
        assert_equal(node2.getaddednodeinfo(), [])
        self.wait_peerless(node2)

    def test_inbound_failures(self):
        node = self.nodes[1]
        for what, make_state, counter, log_line in (
            ("a malformed record", MalformedRecordState, "bad_record",
             "HX1: malformed HX1 record (11 bytes of version packet contents), disconnecting"),
            ("a first stage-2 packet over the limit", OversizeFirstPacketState, "stage2_failed",
             f"HX1: the first stage-2 packet claims {HX1_FIRST_STAGE2_MAX_CONTENTS + 1} bytes of contents, "
             f"over the {HX1_FIRST_STAGE2_MAX_CONTENTS}-byte limit before key confirmation"),
            ("wrong stage-2 keys", WrongSecretState, "stage2_failed", "HX1: the first stage-2 packet"),
        ):
            self.log.info(f"A framework initiator with {what}: {counter}, no retry by a responder")
            with node.assert_debug_log([log_line], unexpected_msgs=[CLASSICAL_RETRY], timeout=5):
                peer = node.add_p2p_connection(HybridPeer(make_state), supports_v2_p2p=True, v2hybrid=HX1_MODE_PREFER,
                                               expect_success=False)
                peer.wait_for_hx1_disconnect()
                self.wait_peerless(node)
            self.expect(1, counter)
            self.check_counts()
            node.disconnect_p2ps()

    def classical_retry(self, node, peer, cause, log_lines):
        """Open an outbound HX1 connection to `peer` that fails with `cause`, and check the one classical retry."""
        with node.assert_debug_log(log_lines + [f"HX1 handshake failed ({cause}), retrying once as classical v2",
                                                "HX1: classical retry connection opened"]):
            self.open_outbound(node, peer, v2hybrid=HX1_MODE_PREFER, reconnect=True)
            peer.wait_for_hx1_disconnect()
            # The retry: the node reconnects to the same address with the same connection type, in mode 0, so it
            # ignores the offer and the session ends classical.
            peer.wait_until(lambda: peer.connections == 2, check_connected=False)
            peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
            peer.wait_for_verack()
            peer.sync_with_ping()
        self.check_session(node, peer, hybrid=False)
        assert_equal(node.getpeerinfo()[0]["connection_type"], "outbound-full-relay")
        assert_equal(peer.v2_state.hx1_outcome, "classical")
        assert_equal(peer.v2_state.received_version_contents, b"")
        self.expect(1, cause)
        self.expect(1, "classical_retry")
        self.check_counts()
        # A retried connection is never retried again.
        with node.assert_debug_log([], unexpected_msgs=[CLASSICAL_RETRY, V1_RETRY]):
            peer.peer_disconnect()
            peer.wait_for_hx1_disconnect(2)
            self.wait_peerless(node)
        assert_equal(peer.connections, 2)
        self.check_counts()

    def test_classical_retry(self):
        node = self.nodes[1]
        self.log.info("The peer's stage-2 keys differ: stage2_failed, then one classical retry")
        self.classical_retry(node, HybridPeer(WrongSecretResponderState), "stage2_failed", ["HX1: the first stage-2 packet"])
        self.log.info("The peer's record is malformed: bad_record, then one classical retry")
        self.classical_retry(node, HybridPeer(MalformedRecordState), "bad_record",
                             ["HX1: malformed HX1 record (11 bytes of version packet contents), disconnecting"])
        self.log.info("The peer's encapsulation key fails the FIPS 203 check: bad_record, then one classical retry")
        self.classical_retry(node, HybridPeer(BadKeyState), "bad_record",
                             ["HX1: the ML-KEM encapsulation key failed the FIPS 203 section 7.2 check, disconnecting"])

        self.log.info("The handshake times out before key confirmation: stage2_failed, then one classical retry")
        self.restart_node(1, ["-v2transport=1", "-peertimeout=3"])
        self.expected[1] = {name: 0 for name in COUNTERS}
        node.setmocktime(int(time.time()))
        peer = SilentResponderPeer()
        with node.assert_debug_log(["HX1: handshake timeout before key confirmation",
                                    "HX1 handshake failed (stage2_failed), retrying once as classical v2",
                                    "HX1: classical retry connection opened"], timeout=5):
            self.open_outbound(node, peer, v2hybrid=HX1_MODE_PREFER, reconnect=True)
            # The responder has switched and read the node's VERSION under stage-2 keys, but the node has had no
            # stage-2 packet back: it reports the session as detecting.
            peer.wait_until(lambda: peer.message_count["version"] == 1)
            assert peer.v2_state.hybrid
            info = node.getpeerinfo()
            assert_equal(len(info), 1)
            assert_equal(info[0]["transport_protocol_type"], "detecting")
            assert_equal(info[0]["transport_hybrid"], False)
            assert_equal(info[0]["session_id"], "")
            node.bumpmocktime(4)  # InactivityCheck() triggers now
            peer.wait_for_hx1_disconnect()
            peer.wait_until(lambda: peer.connections == 2, check_connected=False)
            peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
            peer.wait_for_verack()
            peer.sync_with_ping()
        self.check_session(node, peer, hybrid=False)
        assert_equal(peer.v2_state.hx1_outcome, "classical")
        self.expect(1, "stage2_failed")
        self.expect(1, "classical_retry")
        self.check_counts()
        peer.peer_disconnect()
        self.wait_peerless(node)

    def test_startup_errors(self):
        self.log.info("Invalid -v2hybrid values, and require mode without v2, are startup errors")
        self.stop_node(0)
        for args, message in (
            (["-v2hybrid=3"], "Invalid -v2hybrid value '3' (must be 0, 1 or 2)."),
            (["-v2hybrid="], "Invalid -v2hybrid value '' (must be 0, 1 or 2)."),
            (["-v2hybrid=2", "-v2transport=0"], "Cannot set -v2hybrid=2 without -v2transport."),
        ):
            self.nodes[0].assert_start_raises_init_error(args, re.escape("Error: " + message), match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, ["-v2transport=1", "-v2hybrid=0"])
        assert_equal(self.nodes[0].getnetworkinfo()["v2hybrid"], "off")


if __name__ == '__main__':
    V2HybridTest(__file__).main()
