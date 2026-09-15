#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""-reindex must never reject the chain's own genesis block.

Audit finding 1 (2026-09-14): with BIP34 active from height 0, ContextualCheckBlock
demanded a height push in the genesis coinbase, InvalidChainFound asserted on a null
tip, and the persisted reindex flag turned the crash into a boot loop. Mainnet and
testnet A now activate BIP34 at height 1 and the check skips the genesis block
outright; this test forces the worst case (BIP34 at height 0) on regtest and
reindexes twice."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ReindexGenesisTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-testactivationheight=bip34@0"]]

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getblockhash(0)
        self.generate(node, 3)
        tip = node.getbestblockhash()

        self.log.info("Reindex with BIP34 active from height 0: the genesis block must be accepted")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        self.wait_until(lambda: node.getblockcount() == 3)
        assert_equal(node.getblockhash(0), genesis)
        assert_equal(node.getbestblockhash(), tip)

        self.log.info("A second reindex, chain state already rebuilt")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex-chainstate"])
        self.wait_until(lambda: node.getblockcount() == 3)
        assert_equal(node.getbestblockhash(), tip)


if __name__ == "__main__":
    ReindexGenesisTest(__file__).main()
