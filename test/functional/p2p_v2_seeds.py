#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a new node's first connection to a seed is v2 (HX1 under the default -v2hybrid=1).

Addresses from the DNS seeds and the fixed seeds are stored as NODE_P2P_V2 (SeedAddressServiceFlags()), so the
first automatic connection to one is v2 rather than plaintext v1. A seed that does not speak v2 is still reached:
the node reconnects with v1, as Bitcoin Core does. -v2transport=0 still connects over v1.

Regtest has no fixed seeds, so the nodes here run mainnet with -fixedseeds=1. Every outbound connection goes
through a local SOCKS5 proxy that sends it to another test node on 127.0.0.1: nothing leaves this machine.

The test works with any number of IPv4 fixed seeds spread over up to 8 distinct /16s (31.99.1 has five, in four
/16s). A fresh node connects to one seed per /16, all of which the proxy sends to the same stand-in node, so attempts
and proxy requests are matched by address and the two ends of each connection by session id. With more /16s than the
8 outbound full-relay slots, the node would also open block-relay-only connections to seeds, which the first two
cases do not expect; outbound_count() stops the test with a message then instead of letting it time out. The v1-only
case runs with -maxconnections=1, so exactly one seed is tried, however many /16s there are.
"""
import re

from test_framework.netutil import format_addr_port
from test_framework.socks5 import (
    Socks5Configuration,
    Socks5Server,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

V1_RETRY = "retrying with v1 transport protocol for peer"
MAX_OUTBOUND_FULL_RELAY = 8  # MAX_OUTBOUND_FULL_RELAY_CONNECTIONS


class P2PV2SeedsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = ""  # main: the only chain with fixed seeds
        self.setup_clean_chain = True
        self.num_nodes = 3
        # Node 0 is the new node and connects out on its own. Nodes 1 (v2, prefer) and 2 (v1 only) stand in for
        # the seed and make no outbound connections.
        self.disable_autoconnect = False
        self.extra_args = [[], ["-v2transport=1", "-connect=0"], ["-v2transport=0", "-connect=0"]]

    def setup_network(self):
        self.setup_nodes()

    def setup_nodes(self):
        # Nodes listen on p2p_port(0..2), so the proxy takes p2p_port(3).
        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        conf.unauth = True
        conf.auth = True
        self.requests = []
        self.target = None

        def destinations_factory(requested_to_addr, requested_to_port):
            # Always a local test node: the seed's real address is never contacted.
            self.requests.append(format_addr_port(requested_to_addr, requested_to_port))
            return {"actual_to_addr": "127.0.0.1", "actual_to_port": p2p_port(self.target)}

        conf.destinations_factory = destinations_factory
        self.proxy_arg = f"-proxy={conf.addr[0]}:{conf.addr[1]}"
        self.socks5_server = Socks5Server(conf)
        self.socks5_server.start()
        # Node 0 starts in each test case, from an empty peers.dat, and never without the proxy.
        self.extra_args[0] = [self.proxy_arg]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(1)
        self.start_node(2)

    def start_fresh(self, target, extra_args):
        """Start node 0 with no peers.dat, so it takes its first peer from the fixed seeds, and have the proxy send
        its connections to node `target`. Returns the debug log offset at startup."""
        node = self.nodes[0]
        for name in ("peers.dat", "anchors.dat"):
            (node.chain_path / name).unlink(missing_ok=True)
        self.target = target
        self.requests.clear()
        offset = node.debug_log_size(encoding="utf-8") if node.debug_log_path.exists() else 0
        self.start_node(0, extra_args=[self.proxy_arg, "-fixedseeds=1"] + extra_args)
        return offset

    def log_since(self, offset):
        with open(self.nodes[0].debug_log_path, encoding="utf-8") as log:
            log.seek(offset)
            return log.read()

    def fixed_seeds(self, offset):
        """Wait until node 0 has added its fixed seeds to addrman and return them ("ip:port")."""
        loaded = re.compile(r"Added (\d+) fixed seeds from reachable networks")
        self.wait_until(lambda: loaded.search(self.log_since(offset)))
        text = self.log_since(offset)
        seeds = re.findall(r"Added hardcoded seed: (\S+)", text)
        assert seeds, "no fixed seeds loaded"
        assert_equal(int(loaded.search(text).group(1)), len(seeds))
        return seeds

    def attempts(self, offset):
        """Node 0's connection attempts since `offset`, by address, in order: {address: [(transport, type), ...]}."""
        tries = {}
        for transport, conn_type, address in re.findall(r"trying (v1|v2|classical v2) connection \(([^)]+)\) to (\S+),",
                                                        self.log_since(offset)):
            tries.setdefault(address, []).append((transport, conn_type))
        return tries

    @staticmethod
    def outbound_count(seeds):
        """How many of `seeds` a fresh node with the default -maxconnections connects to: one per IPv4 /16 (outbound
        peers must be in distinct network groups). Only up to MAX_OUTBOUND_FULL_RELAY /16s: with more, the node fills
        its full-relay slots and then opens block-relay-only connections to seeds in the other /16s, which
        check_first_contact() and wait_peers() do not model."""
        groups = set()
        for seed in seeds:
            host = seed.rsplit(":", 1)[0]
            assert re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host), f"{seed}: this test groups IPv4 seeds only"
            groups.add(tuple(host.split(".")[:2]))
        assert len(groups) <= MAX_OUTBOUND_FULL_RELAY, \
            f"fixed seeds span {len(groups)} IPv4 /16s; this test handles up to {MAX_OUTBOUND_FULL_RELAY}"
        return len(groups)

    def wait_peers(self, node, count, transport):
        """Wait until `node` has `count` peers whose version messages it has received, check that each is on
        `transport`, and return them."""
        def ready():
            infos = node.getpeerinfo()
            return len(infos) == count and all(info["version"] > 0 for info in infos)
        self.wait_until(ready)
        infos = node.getpeerinfo()
        assert_equal(len(infos), count)
        for info in infos:
            assert_equal(info["transport_protocol_type"], transport)
        return infos

    def check_first_contact(self, offset, seeds, peers, transport):
        """Every address node 0 tried is a fixed seed it is now connected to, tried once, over `transport`, and the
        proxy was asked for each exactly once."""
        tries = self.attempts(offset)
        assert_equal(sorted(tries), sorted(peer["addr"] for peer in peers))
        for address, sequence in tries.items():
            assert address in seeds, address
            assert_equal(sequence, [(transport, "outbound-full-relay")])
        assert_equal(sorted(self.requests), sorted(tries))
        for peer in peers:
            assert_equal(peer["connection_type"], "outbound-full-relay")

    def stop_fresh(self):
        self.stop_node(0)
        for node in self.nodes[1:]:
            self.wait_until(lambda: not node.getpeerinfo())

    def run_test(self):
        node, seed_v2, seed_v1 = self.nodes

        self.log.info("A new node's first connection to each fixed seed is v2, and HX1 under the default prefer mode")
        offset = self.start_fresh(1, ["-v2transport=1"])
        seeds = self.fixed_seeds(offset)
        count = self.outbound_count(seeds)
        peers = self.wait_peers(node, count, "v2")
        self.check_first_contact(offset, seeds, peers, "v2")
        inbound = self.wait_peers(seed_v2, count, "v2")
        for info in peers + inbound:
            assert_equal(info["transport_hybrid"], True)
        for info in inbound:
            assert_equal(info["inbound"], True)
        # Both ends of every connection agree on the session: the stand-in seed holds exactly node 0's connections.
        assert_equal(sorted(info["session_id"] for info in inbound), sorted(info["session_id"] for info in peers))
        self.stop_fresh()

        self.log.info("With -v2transport=0 the first connection to each fixed seed is v1, as before")
        offset = self.start_fresh(1, ["-v2transport=0"])
        seeds = self.fixed_seeds(offset)
        count = self.outbound_count(seeds)
        peers = self.wait_peers(node, count, "v1")
        self.check_first_contact(offset, seeds, peers, "v1")
        self.wait_peers(seed_v2, count, "v1")
        self.stop_fresh()

        self.log.info("A seed that does not speak v2 drops the v2 attempt; the node reconnects with v1")
        # One outbound slot: the v1 retry inherits the slot the dropped v2 attempt held, so no other seed is tried
        # in between and the attempts are exactly [v2, v1] to one address, however many fixed seeds there are.
        offset = self.start_fresh(2, ["-v2transport=1", "-maxconnections=1"])
        seeds = self.fixed_seeds(offset)
        [info] = self.wait_peers(node, 1, "v1")
        address = info["addr"]
        assert address in seeds, address
        assert_equal(self.attempts(offset), {address: [("v2", "outbound-full-relay"), ("v1", "outbound-full-relay")]})
        assert V1_RETRY in self.log_since(offset)
        assert_equal(self.requests, [address, address])
        assert_equal(info["connection_type"], "outbound-full-relay")
        assert_equal(info["transport_hybrid"], False)
        self.wait_peers(seed_v1, 1, "v1")
        self.stop_fresh()

        self.socks5_server.stop()


if __name__ == '__main__':
    P2PV2SeedsTest(__file__).main()
