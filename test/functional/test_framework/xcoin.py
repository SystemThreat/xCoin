#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""xCoin witness v3, in Python (contrib/regenesis/REGENESIS.md section 4).

This is the functional-test counterpart of src/script/xcoin_v3.h and the C++
test helpers in src/test/util/pq.{h,cpp}: the tagged leaf and branch hashes,
the Merkle root that IS the witness program, and the Taproot-shaped control
block whose internal-key slot carries the fixed XCOIN_V3_NOKEY marker.

It exists because the PQ-only output rule (bad-txout-not-pq) makes every
Bitcoin output type consensus-invalid on every chain of this fork: an output
may only be witness v3, OP_RETURN, or - where the chain still permits it -
witness v2. So the test framework cannot mine or relay a P2PKH, P2WPKH, P2SH
or P2TR output at all, and its mining helper and MiniWallet pay a witness v3
output instead.

Signing an ML-DSA-65 or SLH-DSA leaf needs the node's own crypto and is not
reimplemented here. What is reimplemented is the ANYONE-CAN-SPEND leaf: leaf
version 0xc0 over the script OP_TRUE, spent with the witness stack
[leaf script, control block] and no signature at all. That is the exact
analogue of the framework's Bitcoin p2tr-OP_TRUE address, and it is the
building block the inherited tests use.
"""

import unittest

from .key import TaggedHash
from .messages import (
    hash256,
    sha256,
    ser_string,
)
from .script import (
    CScript,
    OP_CHECKSIG,
    OP_DROP,
    OP_TRUE,
)
from .script_util import program_to_witness_script
from .segwit_addr import encode_segwit_address

# Consensus tags are scoped to the PROJECT name, never to the ticker.
XCOIN_V3_LEAF_TAG = "XCoinLeaf"
XCOIN_V3_BRANCH_TAG = "XCoinBranch"

# The 32 bytes that fill the internal-key slot of every v3 control block:
# a PLAIN SHA-256 of "xcoin/v3/nokey" (not a tagged hash). Any other value
# makes the control block invalid; there is no key path.
XCOIN_V3_NOKEY = sha256(b"xcoin/v3/nokey")
assert XCOIN_V3_NOKEY.hex() == "54b62806c9e55d19448216fc3426a3a04466fbc59c18238795cbbc9003330a65"

# Leaf versions (control block byte 0; bit 0 is the parity bit and must be 0).
XCOIN_LEAF_PQ = 0xc0               # ML-DSA-65 tapscript
XCOIN_LEAF_SLH = 0xc2              # SLH-DSA-SHA2-128s tapscript (fallback)
XCOIN_LEAF_RESERVED_PROOF = 0xc4
XCOIN_LEAF_RESERVED_LEDGER = 0xc6

XCOIN_V3_CONTROL_BASE_SIZE = 33
XCOIN_V3_CONTROL_MAX_NODE_COUNT = 128

# Address HRPs (see test_framework.address).
XCOIN_HRP_MAIN = "xpa"
XCOIN_HRP_REGTEST = "nxrt"
XCOIN_HRP_REHEARSAL = "txa"


def xcoin_leaf_hash(script, version=XCOIN_LEAF_PQ):
    """tagged_hash("XCoinLeaf", version || compact_size(script) || script)."""
    assert version & 1 == 0
    return TaggedHash(XCOIN_V3_LEAF_TAG, bytes([version]) + ser_string(bytes(script)))


def xcoin_branch_hash(a, b):
    """tagged_hash("XCoinBranch", sorted(a, b))."""
    return TaggedHash(XCOIN_V3_BRANCH_TAG, min(a, b) + max(a, b))


class XcoinV3Info:
    """A witness v3 script tree: its leaves, its root (the witness program) and
    the output script. Only the shapes the tests need are built here - a single
    leaf, or a balanced tree over a list of leaves - which is all
    src/test/util/pq.cpp builds too."""

    def __init__(self, leaves):
        """leaves: a list of (version, CScript) pairs, at least one."""
        assert len(leaves) >= 1
        self.leaves = [(version, CScript(script)) for version, script in leaves]
        self.leaf_hashes = [xcoin_leaf_hash(script, version) for version, script in self.leaves]
        # The path from each leaf to the root, as a list of sibling hashes.
        self.paths = _merkle_paths(self.leaf_hashes)
        self.root = _merkle_root(self.leaf_hashes)
        self.scriptPubKey = program_to_witness_script(3, self.root)

    def control_block(self, index=0):
        """leaf version || XCOIN_V3_NOKEY || path."""
        assert index < len(self.leaves)
        assert len(self.paths[index]) <= XCOIN_V3_CONTROL_MAX_NODE_COUNT
        return bytes([self.leaves[index][0]]) + XCOIN_V3_NOKEY + b"".join(self.paths[index])

    def leaf_script(self, index=0):
        return bytes(self.leaves[index][1])

    def witness_stack(self, index=0, stack_items=()):
        """The full witness stack spending leaf `index`: the leaf's own stack
        items, then the leaf script, then the control block."""
        return [*stack_items, self.leaf_script(index), self.control_block(index)]

    def address(self, main=False, hrp=None):
        return encode_segwit_address(hrp or (XCOIN_HRP_MAIN if main else XCOIN_HRP_REGTEST), 3, self.root)


def _merkle_root(hashes):
    if len(hashes) == 1:
        return hashes[0]
    mid = len(hashes) // 2
    return xcoin_branch_hash(_merkle_root(hashes[:mid]), _merkle_root(hashes[mid:]))


def _merkle_paths(hashes):
    """For each leaf, the list of sibling hashes from the leaf up to the root."""
    if len(hashes) == 1:
        return [[]]
    mid = len(hashes) // 2
    left, right = hashes[:mid], hashes[mid:]
    left_root, right_root = _merkle_root(left), _merkle_root(right)
    return [p + [right_root] for p in _merkle_paths(left)] + [p + [left_root] for p in _merkle_paths(right)]


def xcoin_v3_op_true(tag_name=None):
    """The deterministic anyone-can-spend witness v3 tree: one 0xc0 leaf whose
    script leaves true on the stack and takes no signature. With a tag name the
    leaf drops a tag first, which changes the root and therefore the address, so
    two tagged wallets never share UTXOs."""
    if tag_name is None:
        script = CScript([OP_TRUE])
    else:
        script = CScript([hash256(tag_name.encode()), OP_DROP, OP_TRUE])
    return XcoinV3Info([(XCOIN_LEAF_PQ, script)])


def create_deterministic_address_xcoin_v3_op_true(tag_name=None, main=False):
    """(address, XcoinV3Info) of the anyone-can-spend witness v3 output above."""
    info = xcoin_v3_op_true(tag_name)
    address = info.address(main=main)
    if tag_name is None and not main:
        assert address == ANYONECANSPEND_V3_ADDRESS_REGTEST, address
    return (address, info)


# The untagged anyone-can-spend v3 address, pinned so a change to the tagged
# hashing is loud. This is MiniWallet's default address and the address blocks
# 76-100 of the framework's cached chain pay.
ANYONECANSPEND_V3_ADDRESS_REGTEST = "nxrt1rydw50gpwa6yfknz6kkqu2jtvtlxkpmf8fltuv67tgk02mw38wysspgwx6w"


class TestFrameworkXcoinV3(unittest.TestCase):
    def test_pinned_hashes(self):
        """The vectors REGENESIS.md section 4 pins, recomputed here. They are the
        same four the C++ unit test xcoin_v3_tests checks, so this Python
        implementation and the consensus one cannot drift apart silently."""
        pq_leaf = CScript([bytes(range(1, 33)), OP_CHECKSIG])
        self.assertEqual(xcoin_leaf_hash(pq_leaf, XCOIN_LEAF_PQ).hex(),
                         "50371c2936f8bfda05c69228affb83119c687ad8a477b1a18bd01c0a468902d6")
        self.assertEqual(xcoin_leaf_hash(CScript(b""), XCOIN_LEAF_PQ).hex(),
                         "e3bb8e8060cd8ae48c5e91228aa5c257cd5bb80ae1cf853f4dec66a042b1c2f9")
        self.assertEqual(xcoin_leaf_hash(CScript([OP_TRUE]), XCOIN_LEAF_SLH).hex(),
                         "cb25e1b1ec8b174d327f1e6466c018383dd0e23860f6805cab1738dd65922adf")
        self.assertEqual(xcoin_branch_hash(xcoin_leaf_hash(pq_leaf, XCOIN_LEAF_PQ),
                                           xcoin_leaf_hash(CScript(b""), XCOIN_LEAF_PQ)).hex(),
                         "2339dd5ab68ae3ec676b327297e620ce7f2f7e7eb594be396a12ce600df76845")

    def test_single_leaf_tree(self):
        """A one-leaf tree's root IS its leaf hash, and its control block carries
        no path at all."""
        info = xcoin_v3_op_true()
        self.assertEqual(info.root, xcoin_leaf_hash(CScript([OP_TRUE]), XCOIN_LEAF_PQ))
        self.assertEqual(len(info.control_block()), XCOIN_V3_CONTROL_BASE_SIZE)
        self.assertEqual(info.control_block()[0], XCOIN_LEAF_PQ)
        self.assertEqual(info.control_block()[1:], XCOIN_V3_NOKEY)
        self.assertEqual(info.scriptPubKey.hex(), "5320" + info.root.hex())
        self.assertEqual(info.address(), ANYONECANSPEND_V3_ADDRESS_REGTEST)

    def test_two_leaf_tree(self):
        """Each leaf of a two-leaf tree proves itself with the other's hash."""
        a = (XCOIN_LEAF_PQ, CScript([OP_TRUE]))
        b = (XCOIN_LEAF_SLH, CScript([OP_TRUE]))
        info = XcoinV3Info([a, b])
        ha, hb = xcoin_leaf_hash(a[1], a[0]), xcoin_leaf_hash(b[1], b[0])
        self.assertEqual(info.root, xcoin_branch_hash(ha, hb))
        self.assertEqual(info.control_block(0), bytes([a[0]]) + XCOIN_V3_NOKEY + hb)
        self.assertEqual(info.control_block(1), bytes([b[0]]) + XCOIN_V3_NOKEY + ha)

    def test_tagged_addresses_differ(self):
        seen = {xcoin_v3_op_true().address()}
        for tag in ["cache-0", "cache-1", "cache-2", "node-0", "node-1"]:
            address = xcoin_v3_op_true(tag).address()
            self.assertNotIn(address, seen)
            seen.add(address)
