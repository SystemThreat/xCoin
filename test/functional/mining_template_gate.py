#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getblocktemplate gate and the -allowsolomining option.

On a non-test chain getblocktemplate refuses to serve a template while the node
has no peers (RPC_CLIENT_NOT_CONNECTED, -9) or is in initial block download
(RPC_CLIENT_IN_INITIAL_DOWNLOAD, -10), exactly as upstream. The node option
-allowsolomining lifts both refusals for a single-node launch or an isolated
rehearsal and is announced by a startup warning. Test chains (regtest and the
rehearsal chain) are exempt as upstream, so this test runs a mainnet node.
"""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

TEMPLATE_REQUEST = {"rules": ["segwit"]}


class MiningTemplateGateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = ""  # main: the only chain the gate applies to
        # While GENESIS_IS_FINAL is false the v1 genesis stands in and mainnet
        # refuses to start without this override; it has no effect once the
        # genesis is final.
        self.extra_args = [["-allowunfinalgenesis=1"]]

    def clear_stderr(self, node):
        # A mainnet node reports its startup warnings on stderr (the placeholder
        # genesis, low disk space, -allowsolomining); stop_node expects it empty.
        node.stderr.seek(0)
        node.stderr.truncate()

    def connect_mainnet_peer(self, node):
        # add_p2p_connection picks the magic from node.chain, which is "" for
        # mainnet here, so connect with the mainnet magic directly.
        peer = P2PInterface()
        peer.peer_connect(dstaddr="127.0.0.1", dstport=p2p_port(node.index), net="mainnet",
                          timeout_factor=node.timeout_factor, supports_v2_p2p=False, send_version=True)()
        node.p2ps.append(peer)
        peer.wait_until(lambda: peer.is_connected, check_connected=False)
        peer.wait_for_verack()
        self.wait_until(lambda: node.getconnectioncount() == 1)
        return peer

    def run_test(self):
        node = self.nodes[0]
        self.clear_stderr(node)

        self.log.info("Without peers a mainnet node refuses to serve a template")
        assert_equal(node.getconnectioncount(), 0)
        assert_raises_rpc_error(-9, "is not connected!", node.getblocktemplate, TEMPLATE_REQUEST)

        self.log.info("With a peer but in initial block download it still refuses")
        self.connect_mainnet_peer(node)
        assert_equal(node.getblockchaininfo()["initialblockdownload"], True)
        assert_raises_rpc_error(-10, "is in initial sync", node.getblocktemplate, TEMPLATE_REQUEST)
        node.disconnect_p2ps()
        self.wait_until(lambda: node.getconnectioncount() == 0)

        self.log.info("-allowsolomining lifts the gate and warns at startup")
        with node.assert_debug_log(["-allowsolomining is set"]):
            self.restart_node(0, extra_args=self.extra_args[0] + ["-allowsolomining=1"])
        self.clear_stderr(node)
        assert_equal(node.getconnectioncount(), 0)
        assert_equal(node.getblockchaininfo()["initialblockdownload"], True)
        template = node.getblocktemplate(TEMPLATE_REQUEST)
        assert_equal(template["height"], 1)
        assert_equal(template["previousblockhash"], node.getbestblockhash())

        self.log.info("Without the option the gate is back")
        self.restart_node(0, extra_args=self.extra_args[0])
        self.clear_stderr(node)
        assert_raises_rpc_error(-9, "is not connected!", node.getblocktemplate, TEMPLATE_REQUEST)


if __name__ == '__main__':
    MiningTemplateGateTest(__file__).main()
