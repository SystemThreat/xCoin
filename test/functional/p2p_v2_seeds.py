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

    def attempts(self, offset):
        """The fixed seeds node 0 loaded and its connection attempts as (transport, connection type, address),
        from its debug log since `offset`."""
        with open(self.nodes[0].debug_log_path, encoding="utf-8") as log:
            log.seek(offset)
            text = log.read()
        seeds = re.findall(r"Added hardcoded seed: (\S+)", text)
        tries = re.findall(r"trying (v1|v2|classical v2) connection \(([^)]+)\) to (\S+),", text)
        return seeds, tries

    def peer(self, node):
        infos = node.getpeerinfo()
        assert_equal(len(infos), 1)
        return infos[0]

    def wait_peer(self, node, transport):
        """Wait until `node` has one peer whose version message it has received, check that the peer is on
        `transport`, and return it."""
        def ready():
            infos = node.getpeerinfo()
            return len(infos) == 1 and infos[0]["version"] > 0
        self.wait_until(ready)
        info = self.peer(node)
        assert_equal(info["transport_protocol_type"], transport)
        return info

    def stop_fresh(self):
        self.stop_node(0)
        for node in self.nodes[1:]:
            self.wait_until(lambda: not node.getpeerinfo())

    def run_test(self):
        node, seed_v2, seed_v1 = self.nodes

        self.log.info("A new node's first connection to its fixed seed is v2, and HX1 under the default prefer mode")
        offset = self.start_fresh(1, ["-v2transport=1"])
        info = self.wait_peer(node, "v2")
        seeds, tries = self.attempts(offset)
        assert seeds, "no fixed seeds loaded"
        assert_equal(tries, [("v2", "outbound-full-relay", info["addr"])])
        assert info["addr"] in seeds
        assert_equal(self.requests, [info["addr"]])
        assert_equal(info["connection_type"], "outbound-full-relay")
        assert_equal(info["transport_hybrid"], True)
        inbound = self.wait_peer(seed_v2, "v2")
        assert_equal(inbound["inbound"], True)
        assert_equal(inbound["transport_hybrid"], True)
        assert_equal(inbound["session_id"], info["session_id"])
        self.stop_fresh()

        self.log.info("With -v2transport=0 the first connection to the fixed seed is v1, as before")
        offset = self.start_fresh(1, ["-v2transport=0"])
        info = self.wait_peer(node, "v1")
        seeds, tries = self.attempts(offset)
        assert_equal(tries, [("v1", "outbound-full-relay", info["addr"])])
        assert info["addr"] in seeds
        assert_equal(self.requests, [info["addr"]])
        self.wait_peer(seed_v2, "v1")
        self.stop_fresh()

        self.log.info("A seed that does not speak v2 drops the v2 attempt; the node reconnects with v1")
        offset = self.start_fresh(2, ["-v2transport=1"])
        info = self.wait_peer(node, "v1")
        seeds, tries = self.attempts(offset)
        address = info["addr"]
        assert address in seeds
        assert_equal(tries, [("v2", "outbound-full-relay", address), ("v1", "outbound-full-relay", address)])
        with open(node.debug_log_path, encoding="utf-8") as log:
            log.seek(offset)
            assert V1_RETRY in log.read()
        assert_equal(self.requests, [address, address])
        assert_equal(info["transport_hybrid"], False)
        self.wait_peer(seed_v1, "v1")
        self.stop_fresh()

        self.socks5_server.stop()


if __name__ == '__main__':
    P2PV2SeedsTest(__file__).main()
