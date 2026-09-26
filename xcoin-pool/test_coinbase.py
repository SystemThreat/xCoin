#!/usr/bin/env python3
"""Launch-critical regression tests for xcoin-pool coinbase construction.

The pool serves the v2 chain (contrib/regenesis/REGENESIS.md): witness v3 only,
block 1 pays the genesis distribution verbatim, and every non-coinbase
transaction owes the settlement levy. Run with:

    python3 xcoin-pool/test_coinbase.py -v
"""

import asyncio
import hashlib
import importlib.util
import json
import logging
import struct
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("xcoin-pool.py")
SPEC = importlib.util.spec_from_file_location("xcoin_pool", MODULE_PATH)
POOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POOL)
POOL.log.setLevel(logging.CRITICAL)   # the refusal path logs a warning by design

REPO = Path(__file__).resolve().parent.parent

COIN = 100_000_000
MAX_MONEY = 100_000_000 * COIN         # src/consensus/amount.h: the 100,000,000 XID cap, 10^16 sat (test_the_cap_mirrors_consensus)
STUB_COINBASE_VALUE = 14 * COIN        # a stub template value, not any chain's subsidy (the pool never assumes one)
WITNESS_COMMITMENT = "6a24aa21a9ed" + "7c" * 32   # BIP-141 shape, 38 bytes

# A pinned key hash and its addresses on each chain (the same key, three prefixes).
FOUNDER_KEY_HASH = "a158ac5047845bfdedad6e2e3e074b2bac33cefa7440b6b3aba668b40bd8bce9"
FOUNDER_V2_MAIN = "xpa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5sdnc0av"
FOUNDER_V3_MAIN = "xpa1rt682c5qx4vqdjed0jvws2q2fjtjuxhs3r2fm9k9dp9ezlwv5m68s5w4dn0"
FOUNDER_V2_REHEARSAL = "txa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5s03pnlk"
FOUNDER_V3_REHEARSAL = "txa1rt682c5qx4vqdjed0jvws2q2fjtjuxhs3r2fm9k9dp9ezlwv5m68skvv334"
FOUNDER_V3_PROGRAM = "5e8eac5006ab00d965af931d05014992e5c35e111a93b2d8ad09722fb994de8f"
FOUNDER_V3_SCRIPT = "5320" + FOUNDER_V3_PROGRAM

# NerdMiner's own first-chain mining key, the address a rehearsal worker uses.
MINER_V3_REHEARSAL = "txa1rk0shs7zn527v0wh2gah4h598fhpxv9csgvzqymrj29jd3frmvvaq4jlady"
MINER_V3_SCRIPT = "5320b3e1787853a2bcc7baea476f5bd0a74dc26617104304026c725164d8a47b633a"


def read_varint(data, offset):
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    if first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def parse_coinbase(tx):
    """(scriptSig, [(value, script), ...]) of a non-witness coinbase serialization."""
    offset = 4
    vin_count, offset = read_varint(tx, offset)
    assert vin_count == 1
    offset += 32 + 4
    script_len, offset = read_varint(tx, offset)
    script_sig = tx[offset:offset + script_len]
    offset += script_len + 4
    output_count, offset = read_varint(tx, offset)
    outputs = []
    for _ in range(output_count):
        amount = struct.unpack_from("<Q", tx, offset)[0]
        offset += 8
        script_len, offset = read_varint(tx, offset)
        script = tx[offset:offset + script_len]
        offset += script_len
        outputs.append((amount, script))
    assert offset + 4 == len(tx), "trailing bytes after the outputs"
    return script_sig, outputs


def parse_outputs(tx):
    return parse_coinbase(tx)[1]


def serialize_txout(value_sat, script):
    """CTxOut: nValue int64 LE || compact_size(script) || script."""
    return struct.pack("<q", value_sat) + POOL.varint(len(script)) + script


def build(height, coinbasevalue, payout, en_size=8, wc=WITNESS_COMMITMENT):
    part1, part2 = POOL.build_coinbase(height, coinbasevalue, en_size, wc, payout)
    return part1 + bytes(en_size) + part2


class AddressTests(unittest.TestCase):
    """decode_address / payout_script: witness v3 in, OP_3 <root> out."""

    def setUp(self):
        self.saved_hrp = POOL.CFG["hrp"]

    def tearDown(self):
        POOL.CFG["hrp"] = self.saved_hrp

    def test_v3_rehearsal_worker_is_authorized(self):
        POOL.CFG["hrp"] = "txa"
        self.assertEqual(POOL.decode_address(MINER_V3_REHEARSAL),
                         (3, bytes.fromhex(MINER_V3_SCRIPT[4:])))
        self.assertEqual(POOL.payout_script(MINER_V3_REHEARSAL).hex(), MINER_V3_SCRIPT)

    def test_v3_mainnet_worker_is_authorized(self):
        POOL.CFG["hrp"] = "xpa"
        self.assertEqual(POOL.payout_script(FOUNDER_V3_MAIN).hex(), FOUNDER_V3_SCRIPT)

    def test_worker_address_with_worker_name_suffix(self):
        # mining.authorize splits on the first dot before parsing.
        POOL.CFG["hrp"] = "txa"
        user = MINER_V3_REHEARSAL + ".rig1"
        self.assertEqual(POOL.payout_script(user.split(".")[0]).hex(), MINER_V3_SCRIPT)

    def test_uppercase_and_whitespace_are_accepted(self):
        POOL.CFG["hrp"] = "txa"
        self.assertEqual(POOL.payout_script("  " + MINER_V3_REHEARSAL.upper() + "  ").hex(),
                         MINER_V3_SCRIPT)

    def test_a_v2_address_is_refused_on_mainnet(self):
        POOL.CFG["hrp"] = "xpa"
        with self.assertRaises(POOL.AddressError) as caught:
            POOL.payout_script(FOUNDER_V2_MAIN)
        message = str(caught.exception)
        self.assertIn("witness v2", message)
        self.assertIn("witness v3", message)
        self.assertIsNone(POOL.decode_address(FOUNDER_V2_MAIN))

    def test_a_v2_address_is_refused_on_the_rehearsal_chain(self):
        POOL.CFG["hrp"] = "txa"
        with self.assertRaises(POOL.AddressError) as caught:
            POOL.payout_script(FOUNDER_V2_REHEARSAL)
        self.assertIn("witness v3", str(caught.exception))

    def test_wrong_chain_address_is_refused(self):
        POOL.CFG["hrp"] = "txa"
        with self.assertRaises(POOL.AddressError) as caught:
            POOL.payout_script(FOUNDER_V3_MAIN)
        self.assertIn("'xpa'", str(caught.exception))

    def test_regtest_still_accepts_witness_v2(self):
        """Regtest keeps v2 outputs valid (permitV2Outputs), so the pool may be
        pointed at a regtest node with either address form."""
        POOL.CFG["hrp"] = POOL.REGTEST_HRP
        key = bytes.fromhex(FOUNDER_KEY_HASH)
        v2 = POOL.bech32m_encode(POOL.REGTEST_HRP, 2, key)
        v3 = POOL.bech32m_encode(POOL.REGTEST_HRP, 3, POOL.single_leaf_program(key))
        self.assertEqual(POOL.payout_script(v2).hex(), "5220" + FOUNDER_KEY_HASH)
        self.assertEqual(POOL.payout_script(v3).hex(), FOUNDER_V3_SCRIPT)

    def test_malformed_addresses_are_refused(self):
        POOL.CFG["hrp"] = "txa"
        bad = [
            "",
            "txa1",
            "not-an-address",
            MINER_V3_REHEARSAL[:-1] + "q",                      # broken checksum
            MINER_V3_REHEARSAL[:20].upper() + MINER_V3_REHEARSAL[20:],  # mixed case
            POOL.bech32m_encode("txa", 3, b"\x11" * 20),         # 20-byte program
            POOL.bech32m_encode("txa", 1, b"\x11" * 32),         # witness v1
        ]
        for addr in bad:
            with self.subTest(addr=addr):
                self.assertIsNone(POOL.decode_address(addr))
                with self.assertRaises(POOL.AddressError):
                    POOL.payout_script(addr)


class CoinbaseTests(unittest.TestCase):
    """From height 2 the coinbase pays OP_3 <root> and nothing else."""

    def setUp(self):
        self.saved_hrp = POOL.CFG["hrp"]
        POOL.CFG["hrp"] = "txa"

    def tearDown(self):
        POOL.CFG["hrp"] = self.saved_hrp

    def test_pays_op3_root_to_the_v3_worker(self):
        spk = POOL.payout_script(MINER_V3_REHEARSAL)
        outputs = parse_outputs(build(2, STUB_COINBASE_VALUE, spk))
        self.assertEqual(outputs, [
            (STUB_COINBASE_VALUE, bytes.fromhex(MINER_V3_SCRIPT)),
            (0, bytes.fromhex(WITNESS_COMMITMENT)),
        ])
        payout_script = outputs[0][1]
        self.assertEqual(payout_script[0], 0x53)   # OP_3
        self.assertEqual(payout_script[1], 0x20)   # 32-byte push
        self.assertEqual(len(payout_script), 34)

    def test_height_1_is_an_ordinary_block(self):
        """Block 1 pays the miner like any other block: nothing is carried in."""
        POOL.CFG["hrp"] = "txa"
        outputs = parse_outputs(build(1, STUB_COINBASE_VALUE, POOL.payout_script(MINER_V3_REHEARSAL)))
        self.assertEqual(len(outputs), 2)
        self.assertEqual(outputs[0], (STUB_COINBASE_VALUE, bytes.fromhex(MINER_V3_SCRIPT)))
        self.assertEqual(outputs[1][1].hex(), WITNESS_COMMITMENT)

    def test_pays_the_founder_address(self):
        POOL.CFG["hrp"] = "xpa"
        spk = POOL.payout_script(FOUNDER_V3_MAIN)
        outputs = parse_outputs(build(2, 50 * COIN, spk))
        self.assertEqual(outputs[0], (50 * COIN, bytes.fromhex(FOUNDER_V3_SCRIPT)))

    def test_fees_ride_on_the_payout_output(self):
        """coinbasevalue = subsidy + fees (which include every levy the block
        collected); the pool pays all of it, it keeps nothing."""
        spk = POOL.payout_script(MINER_V3_REHEARSAL)
        value = STUB_COINBASE_VALUE + 123_456
        outputs = parse_outputs(build(2, value, spk))
        self.assertEqual(sum(amount for amount, _ in outputs), value)

    def test_a_witness_v2_payout_is_refused_on_this_chain(self):
        v2_spk = bytes.fromhex("5220" + FOUNDER_KEY_HASH)
        for hrp in ("txa", "xpa"):
            POOL.CFG["hrp"] = hrp
            with self.assertRaises(ValueError) as caught:
                build(2, STUB_COINBASE_VALUE, v2_spk)
            self.assertIn("bad-txout-not-pq", str(caught.exception))

    def test_a_bare_program_is_refused(self):
        """The pre-v3 caller passed a bare 32-byte key hash; that must not
        silently become a malformed script."""
        with self.assertRaises(ValueError):
            build(2, STUB_COINBASE_VALUE, bytes.fromhex(FOUNDER_KEY_HASH))

    def test_regtest_v2_payout_is_allowed(self):
        POOL.CFG["hrp"] = POOL.REGTEST_HRP
        v2_spk = bytes.fromhex("5220" + FOUNDER_KEY_HASH)
        outputs = parse_outputs(build(2, 50 * COIN, v2_spk))
        self.assertEqual(outputs[0], (50 * COIN, v2_spk))

    def test_coinbase_without_witness_commitment(self):
        spk = POOL.payout_script(MINER_V3_REHEARSAL)
        outputs = parse_outputs(build(2, STUB_COINBASE_VALUE, spk, wc=None))
        self.assertEqual(outputs, [(STUB_COINBASE_VALUE, bytes.fromhex(MINER_V3_SCRIPT))])

    def test_future_epoch_is_rejected_before_pow_rpc(self):
        session = POOL.Session.__new__(POOL.Session)
        session.jobs = {"1": {"mintime": int(time.time()) - 1}}
        old_rpc = POOL.rpc
        try:
            POOL.rpc = lambda *_a, **_k: self.fail("PoW RPC must not be called")
            result = asyncio.run(session.validate(
                "1", "00" * 4, f"{int(time.time()) + 3 * 60 * 60:08x}", "00000000", None
            ))
            self.assertEqual(result, (False, False, None, None))
        finally:
            POOL.rpc = old_rpc


class ScriptSigAndDataCarrierTests(unittest.TestCase):
    """Consensus shape rules the pool must not violate."""

    def setUp(self):
        self.saved_hrp = POOL.CFG["hrp"]
        POOL.CFG["hrp"] = "txa"
        self.spk = POOL.payout_script(MINER_V3_REHEARSAL)

    def tearDown(self):
        POOL.CFG["hrp"] = self.saved_hrp

    def test_scriptsig_stays_inside_the_100_byte_limit(self):
        for height in (1, 2, 16, 17, 127, 128, 255, 256, 65_535, 65_536,
                       1_000_000, 16_777_215, 16_777_216, 2_000_000_000):
            for en_size in (4, 8, 12, 16):
                with self.subTest(height=height, extranonce=en_size):
                    tx = build(height, STUB_COINBASE_VALUE, self.spk, en_size=en_size)
                    script_sig, _ = parse_coinbase(tx)
                    self.assertLessEqual(len(script_sig), POOL.MAX_COINBASE_SCRIPTSIG)
                    self.assertGreaterEqual(len(script_sig), POOL.MIN_COINBASE_SCRIPTSIG)
                    # the tail is the miner's extranonce slot, the head the
                    # BIP-34 height push followed by the /xcoin/ tag
                    self.assertEqual(script_sig[-en_size:], bytes(en_size))
                    self.assertIn(b"/xcoin/", script_sig)

    def test_an_oversized_extranonce_is_refused_not_mined(self):
        with self.assertRaises(ValueError) as caught:
            build(2, STUB_COINBASE_VALUE, self.spk, en_size=120)
        self.assertIn("bad-cb-length", str(caught.exception))

    def test_the_only_op_return_is_the_witness_commitment(self):
        outputs = parse_outputs(build(2, STUB_COINBASE_VALUE, self.spk))
        data = [script for _, script in outputs if script[:1] == b"\x6a"]
        self.assertEqual(data, [bytes.fromhex(WITNESS_COMMITMENT)])
        self.assertLessEqual(len(data[0]), POOL.MAX_OP_RETURN_RELAY)
        self.assertLess(sum(len(s) for s in data), POOL.MAX_BLOCK_DATACARRIER_BYTES)

    def test_an_oversized_witness_commitment_is_refused(self):
        with self.assertRaises(ValueError):
            build(2, STUB_COINBASE_VALUE, self.spk, wc="6a" + "00" * 100)


class FakeWriter:
    def __init__(self):
        self.sent = []

    def get_extra_info(self, _what):
        return ("127.0.0.1", 54321)

    def write(self, data):
        self.sent.append(json.loads(data.decode()))

    async def drain(self):
        return None


class StratumAuthorizeTests(unittest.TestCase):
    """mining.authorize end to end: what a NerdMiner actually gets back."""

    def setUp(self):
        self.saved_hrp = POOL.CFG["hrp"]
        POOL.CFG["hrp"] = "txa"
        self.saved_rpc = POOL.rpc
        POOL.JOBS.tmpl = None

    def tearDown(self):
        POOL.CFG["hrp"] = self.saved_hrp
        POOL.rpc = self.saved_rpc
        POOL.JOBS.tmpl = None

    def authorize(self, user, template):
        POOL.rpc = lambda method, params=None: template if method == "getblocktemplate" else None
        session = POOL.Session(None, FakeWriter())
        asyncio.run(session.dispatch({"id": 2, "method": "mining.authorize",
                                      "params": [user, "x"]}))
        return session, session.w.sent

    def template(self, height, coinbasevalue):
        t = {"height": height, "coinbasevalue": coinbasevalue, "version": 0x20000000,
             "bits": "1f00ffff", "curtime": int(time.time()), "mintime": int(time.time()) - 60,
             "previousblockhash": "00" * 32, "transactions": [],
             "default_witness_commitment": WITNESS_COMMITMENT}
        return t

    def test_a_v3_worker_is_authorized_and_gets_an_op3_job(self):
        session, sent = self.authorize(MINER_V3_REHEARSAL + ".rig1",
                                       self.template(2, STUB_COINBASE_VALUE))
        self.assertTrue(sent[0]["result"], sent[0])
        self.assertIsNone(sent[0]["error"])
        self.assertEqual(session.worker, "rig1")
        self.assertEqual(session.spk.hex(), MINER_V3_SCRIPT)
        notify = [m for m in sent if m.get("method") == "mining.notify"]
        self.assertEqual(len(notify), 1)
        p1, p2 = notify[0]["params"][2], notify[0]["params"][3]
        cb = bytes.fromhex(p1) + bytes(session.en2_size + len(session.en1)) + bytes.fromhex(p2)
        outputs = parse_outputs(cb)
        self.assertEqual(outputs[0], (STUB_COINBASE_VALUE, bytes.fromhex(MINER_V3_SCRIPT)))

    def test_a_v2_worker_is_refused(self):
        session, sent = self.authorize(FOUNDER_V2_REHEARSAL + ".rig1",
                                       self.template(2, STUB_COINBASE_VALUE))
        self.assertFalse(sent[0]["result"])
        self.assertIn("witness v3", sent[0]["error"][1])
        self.assertIsNone(session.spk)
        self.assertFalse([m for m in sent if m.get("method") == "mining.notify"])


class JobSnapshotTests(unittest.TestCase):
    """Audit finding 4: the header's merkle root and the block body must come from
    the same job. The pool used to build the body from the LIVE template, so any
    mempool change between job and solution produced bad-txnmrklroot."""

    def setUp(self):
        self.saved_rpc, self.saved_hrp, self.saved_jobs = POOL.rpc, POOL.CFG["hrp"], POOL.JOBS
        POOL.CFG["hrp"] = "txa"
        POOL.JOBS = POOL.Jobs()

    def tearDown(self):
        POOL.rpc, POOL.CFG["hrp"], POOL.JOBS = self.saved_rpc, self.saved_hrp, self.saved_jobs

    @staticmethod
    def template(prev, txs, height=5):
        now = int(time.time())
        return {"height": height, "coinbasevalue": STUB_COINBASE_VALUE, "version": 0x20000000,
                "bits": "207fffff", "curtime": now, "mintime": now - 60,
                "previousblockhash": prev, "transactions": txs,
                "default_witness_commitment": WITNESS_COMMITMENT}

    @staticmethod
    def tx(seed):
        data = ("02000000" + seed * 20 + "00000000")
        return {"data": data, "txid": hashlib.sha256(data.encode()).hexdigest(), "fee": 1000}

    def test_refresh_reports_tip_moves_and_same_count_tx_changes(self):
        a, b = self.tx("aa"), self.tx("bb")
        tmpl = {"t": self.template("11" * 32, [a])}
        POOL.rpc = lambda method, params=None: tmpl["t"] if method == "getblocktemplate" else None
        self.assertEqual(POOL.JOBS.refresh(), "tip")
        self.assertIsNone(POOL.JOBS.refresh())                       # identical template
        tmpl["t"] = self.template("11" * 32, [b])                    # same tip, same count, different tx
        self.assertEqual(POOL.JOBS.refresh(), "txs")
        tmpl["t"] = self.template("22" * 32, [b])                    # new tip
        self.assertEqual(POOL.JOBS.refresh(), "tip")

    def test_solved_block_uses_the_job_snapshot_not_the_live_template(self):
        a, b = self.tx("aa"), self.tx("bb")
        tmpl = {"t": self.template("11" * 32, [a])}
        def rpc(method, params=None):
            if method == "getblocktemplate": return tmpl["t"]
            if method == "getmetaldagpowhash": return "00" * 32    # every share is a block
            return None
        POOL.rpc = rpc
        self.assertEqual(POOL.JOBS.refresh(), "tip")
        session = POOL.Session(None, FakeWriter())
        session.spk = POOL.payout_script(MINER_V3_REHEARSAL)
        asyncio.run(session.notify(clean=True))
        jid = list(session.jobs)[-1]
        job = session.jobs[jid]
        self.assertEqual(job["txs"], [a["data"]])
        # The mempool churns: same tip, same transaction count, a different transaction.
        tmpl["t"] = self.template("11" * 32, [b])
        self.assertEqual(POOL.JOBS.refresh(), "txs")
        ok, is_block, block_hex, _ = asyncio.run(session.validate(jid, "00000000", f"{tmpl['t']['curtime']:08x}", "00000000", None))
        self.assertTrue(ok and is_block)
        block = bytes.fromhex(block_hex)
        self.assertIn(bytes.fromhex(a["data"]), block)             # the job's transaction
        self.assertNotIn(bytes.fromhex(b["data"]), block)          # never the live template's
        # ...and the header's merkle root is exactly merkle(coinbase, A).
        header = block[:80]
        cb = job["p1"] + session.en1 + bytes(4) + job["p2"]
        root = POOL.dsha256(cb)
        for sib in job["branch_le"]: root = POOL.dsha256(root + sib)
        self.assertEqual(header[36:68], root)
        self.assertEqual(root, POOL.dsha256(POOL.dsha256(cb) + bytes.fromhex(a["txid"])[::-1]))

    def test_share_on_a_stale_tip_is_rejected(self):
        a = self.tx("aa")
        tmpl = {"t": self.template("11" * 32, [a])}
        POOL.rpc = lambda method, params=None: tmpl["t"] if method == "getblocktemplate" else "00" * 32
        POOL.JOBS.refresh()
        session = POOL.Session(None, FakeWriter())
        session.spk = POOL.payout_script(MINER_V3_REHEARSAL)
        asyncio.run(session.notify(clean=True))
        jid = list(session.jobs)[-1]
        tmpl["t"] = self.template("22" * 32, [a], height=6)        # the tip moved
        POOL.JOBS.refresh()
        ok, is_block, _, _ = asyncio.run(session.validate(jid, "00000000", f"{tmpl['t']['curtime']:08x}", "00000000", None))
        self.assertFalse(ok)
        self.assertFalse(is_block)


class SubmitRateLimitTests(unittest.TestCase):
    """Audit finding 14: a flooding client is rationed and eventually dropped, and the
    node is never consulted for submits beyond the budget."""

    def setUp(self):
        self.saved_rpc, self.saved_hrp, self.saved_jobs = POOL.rpc, POOL.CFG["hrp"], POOL.JOBS
        POOL.CFG["hrp"] = "txa"; POOL.JOBS = POOL.Jobs()

    def tearDown(self):
        POOL.rpc, POOL.CFG["hrp"], POOL.JOBS = self.saved_rpc, self.saved_hrp, self.saved_jobs

    def test_submits_beyond_the_budget_are_refused_without_the_node(self):
        calls = []
        def rpc(method, params=None):
            calls.append(method)
            if method == "getblocktemplate":
                now = int(time.time())
                return {"height": 5, "coinbasevalue": STUB_COINBASE_VALUE, "version": 0x20000000, "bits": "207fffff",
                        "curtime": now, "mintime": now - 60, "previousblockhash": "11" * 32, "transactions": [],
                        "default_witness_commitment": WITNESS_COMMITMENT}
            return "ff" * 32   # never a share, never a block
        POOL.rpc = rpc
        POOL.JOBS.refresh()
        session = POOL.Session(None, FakeWriter())
        session.spk = POOL.payout_script(MINER_V3_REHEARSAL)
        asyncio.run(session.notify(clean=True))
        jid = list(session.jobs)[-1]
        ntime = f"{session.jobs[jid]['mintime'] + 1:08x}"
        async def flood(n):
            for i in range(n):
                await session.dispatch({"id": i, "method": "mining.submit", "params": ["w", jid, "00000000", ntime, f"{i:08x}"]})
        asyncio.run(flood(POOL.SUBMIT_RATE_PER_SEC + 10))
        pow_calls = calls.count("getmetaldagpowhash")
        self.assertEqual(pow_calls, POOL.SUBMIT_RATE_PER_SEC)                 # the budget, and not one more
        replies = [m for m in session.w.sent if "result" in m]
        self.assertEqual(sum(1 for m in replies if m.get("error") and m["error"][1] == "rate limited"), 10)


class VardiffFastRampTests(unittest.TestCase):
    """A miner whose shares arrive faster than FAST_RAMP_SHARES_PER_SEC has its
    difficulty doubled at once (bounded 2x per step), so it never reaches the flood
    limit before the first scheduled retune. A slow miner is untouched until then."""

    def setUp(self):
        self.saved = POOL.CFG["start_diff"], POOL.CFG["vardiff_interval"]

    def tearDown(self):
        POOL.CFG["start_diff"], POOL.CFG["vardiff_interval"] = self.saved

    def _session(self):
        session = POOL.Session(None, FakeWriter())
        session.diff = POOL.CFG["start_diff"]
        return session

    def test_start_difficulty_is_sized_for_a_gpu(self):
        self.assertGreaterEqual(POOL.CFG["start_diff"], 0.05)   # not the 0.001 that flooded a GPU in the e2e run

    def test_fast_shares_double_the_difficulty_immediately(self):
        session = self._session()
        start = session.diff
        async def burst(n):
            for _ in range(n):
                await session.observe_share()    # back-to-back: far faster than 5 shares/s
        asyncio.run(burst(6))
        # first share sets the clock, second and on double every time: >= 2^4 after six
        self.assertGreaterEqual(session.diff, start * 16)
        self.assertLessEqual(session.diff, POOL.CFG["vardiff_max"])

    def test_slow_shares_do_not_ramp_before_the_interval(self):
        session = self._session()
        start = session.diff
        async def slow():
            await session.observe_share()
            session.last_share_at -= 2.0      # pretend the next share is two seconds later
            await session.observe_share()
        asyncio.run(slow())
        self.assertEqual(session.diff, start)


class CreditedDifficultyTests(unittest.TestCase):
    """An accepted share is credited at the threshold the miner actually met:
    min(share difficulty, network difficulty). On a chain easier than the share
    difficulty every accepted share is a block and the work behind it is the
    network's, so crediting the share difficulty inflated the measured hashrate
    (the rehearsal reported 4.7e14 H/s for a 9 MH/s rig) and vardiff ramped to
    its cap on that phantom figure."""

    EASY_BITS = "207fffff"                       # regtest / young-chain powLimit

    def test_credit_is_the_smaller_of_share_and_network_difficulty(self):
        easy = POOL.bits_to_target(self.EASY_BITS)
        net = POOL.target_to_diff(easy)
        self.assertLess(net, 1e-6)
        self.assertEqual(POOL.credited_diff(1e6, easy), net)            # share diff far above the chain
        self.assertEqual(POOL.credited_diff(net / 4, easy), net / 4)    # share diff below the chain
        hard = POOL.diff_to_target(1000.0)
        self.assertAlmostEqual(POOL.credited_diff(0.05, hard), 0.05)    # normal case: share diff rules

    def test_vardiff_never_sets_a_share_difficulty_above_the_network(self):
        saved = POOL.JOBS
        POOL.JOBS = POOL.Jobs()
        POOL.JOBS.tmpl = {"bits": self.EASY_BITS}
        try:
            session = POOL.Session(None, FakeWriter())
            session.diff = POOL.CFG["start_diff"]
            net = POOL.target_to_diff(POOL.bits_to_target(self.EASY_BITS))
            async def retune(n):
                for _ in range(n):               # each step moves at most 2x, so walk it down
                    await session.apply_diff(1e6)
            asyncio.run(retune(1))
            self.assertEqual(session.diff, POOL.CFG["start_diff"] / 2)   # never up, even when asked for 1e6
            asyncio.run(retune(40))
            self.assertLessEqual(session.diff, max(net, POOL.CFG["vardiff_min"]))
        finally:
            POOL.JOBS = saved

    def test_block_on_an_easy_chain_is_recorded_at_network_difficulty(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        saved = {k: getattr(POOL, k) for k in ("MINERS_FILE", "RIGS_FILE", "STATS_FILE", "MINERS", "RIGS", "rpc", "JOBS")}
        saved_hrp = POOL.CFG["hrp"]
        for k in ("MINERS_FILE", "RIGS_FILE", "STATS_FILE"):
            setattr(POOL, k, str(Path(tmp.name) / k.lower()))
        POOL.MINERS, POOL.RIGS = {}, {}
        POOL.CFG["hrp"] = "txa"; POOL.JOBS = POOL.Jobs()
        submitted = []
        def rpc(method, params=None):
            if method == "getblocktemplate":
                now = int(time.time())
                return {"height": 5, "coinbasevalue": STUB_COINBASE_VALUE, "version": 0x20000000, "bits": self.EASY_BITS,
                        "curtime": now, "mintime": now - 60, "previousblockhash": "11" * 32, "transactions": [],
                        "default_witness_commitment": WITNESS_COMMITMENT}
            if method == "getmetaldagpowhash":
                return "00" * 32                 # a block, and a share at any difficulty
            if method == "submitblock":
                submitted.append(params); return None
            if method == "getbestblockhash":
                return "not-our-hash"
            return None
        POOL.rpc = rpc
        try:
            POOL.JOBS.refresh()
            session = POOL.Session(None, FakeWriter())
            session.spk = POOL.payout_script(MINER_V3_REHEARSAL)
            session.address, session.worker = MINER_V3_REHEARSAL, "rig1"
            session.diff = 1e6                   # vardiff already pushed far above the chain
            asyncio.run(session.notify(clean=True))
            jid = list(session.jobs)[-1]
            ntime = f"{session.jobs[jid]['mintime'] + 1:08x}"
            asyncio.run(session.dispatch({"id": 7, "method": "mining.submit",
                                          "params": ["w", jid, "00000000", ntime, "00000000"]}))
            rig = POOL.RIGS[f"{MINER_V3_REHEARSAL}|rig1"]
            net = POOL.target_to_diff(POOL.bits_to_target(self.EASY_BITS))
            self.assertEqual(rig["shares"], 1)
            self.assertEqual(rig["recent"][-1]["d"], net)                # not 1e6
            self.assertEqual(POOL.MINERS[MINER_V3_REHEARSAL]["recent"][-1]["d"], net)
            self.assertLess(POOL.measured_hps(rig, int(time.time())), 1.0)   # a fraction of a hash/s, not 4e14
        finally:
            for k, v in saved.items():
                setattr(POOL, k, v)
            POOL.CFG["hrp"] = saved_hrp
            tmp.cleanup()


class WebSessionNamingTests(unittest.TestCase):
    """Founder request 2026-09-15: every browser session is its own rig,
    web-solo-00001, web-solo-00002, ... from a counter that survives restarts;
    a miner's own worker name is untouched; the pool tells the session its name."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {k: getattr(POOL, k) for k in ("SESSION_SEQ_FILE", "MINERS_FILE", "RIGS_FILE", "STATS_FILE", "MINERS", "RIGS", "rpc", "JOBS")}
        self.saved_hrp = POOL.CFG["hrp"]
        for k in ("SESSION_SEQ_FILE", "MINERS_FILE", "RIGS_FILE", "STATS_FILE"):
            setattr(POOL, k, str(Path(self.tmp.name) / k.lower()))
        POOL.MINERS, POOL.RIGS = {}, {}
        POOL.CFG["hrp"] = "txa"; POOL.JOBS = POOL.Jobs()
        def rpc(method, params=None):
            if method == "getblocktemplate":
                now = int(time.time())
                return {"height": 5, "coinbasevalue": STUB_COINBASE_VALUE, "version": 0x20000000, "bits": "207fffff",
                        "curtime": now, "mintime": now - 60, "previousblockhash": "11" * 32, "transactions": [],
                        "default_witness_commitment": WITNESS_COMMITMENT}
            return None
        POOL.rpc = rpc
        POOL.JOBS.refresh()

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(POOL, k, v)
        POOL.CFG["hrp"] = self.saved_hrp
        self.tmp.cleanup()

    def _authorize(self, worker):
        session = POOL.Session(None, FakeWriter())
        asyncio.run(session.dispatch({"id": 2, "method": "mining.authorize", "params": [f"{MINER_V3_REHEARSAL}.{worker}"]}))
        return session

    def test_browser_sessions_are_numbered_in_order_and_told_their_name(self):
        a = self._authorize("web-solo")
        b = self._authorize("web-solo")
        c = self._authorize("web")
        self.assertEqual((a.worker, b.worker, c.worker), ("web-solo-00001", "web-solo-00002", "web-00003"))
        self.assertEqual(sorted(k.split("|")[1] for k in POOL.RIGS), ["web-00003", "web-solo-00001", "web-solo-00002"])
        notice = [m for m in a.w.sent if m.get("method") == "client.show_message"]
        self.assertEqual(notice[0]["params"], ["registered as web-solo-00001"])
        # the reply to authorize itself is unchanged
        self.assertTrue(any(m.get("id") == 2 and m.get("result") is True for m in a.w.sent))

    def test_counter_survives_a_restart_and_own_names_are_kept(self):
        self._authorize("web-solo")
        self._authorize("web-solo")
        self.assertEqual(Path(POOL.SESSION_SEQ_FILE).read_text(), "2")
        POOL.MINERS, POOL.RIGS = {}, {}                    # a restart reloads nothing but the file
        self.assertEqual(self._authorize("web-solo").worker, "web-solo-00003")
        for own in ("wayne", "rehearsal1", "rig1", "webby", "web_1", "default"):
            self.assertEqual(self._authorize(own).worker, own)
        self.assertEqual(Path(POOL.SESSION_SEQ_FILE).read_text(), "3")   # own names do not consume numbers


class SubmitInputValidationTests(unittest.TestCase):
    """Audit findings L1 and L2: every mining.submit field is miner-supplied. A
    malformed or wrong-length one is a rejected share with a stratum error; the
    session lives on and the node is never asked for a PoW hash."""

    def setUp(self):
        self.saved_rpc, self.saved_hrp, self.saved_jobs = POOL.rpc, POOL.CFG["hrp"], POOL.JOBS
        POOL.CFG["hrp"] = "txa"; POOL.JOBS = POOL.Jobs()
        self.calls = []
        def rpc(method, params=None):
            self.calls.append(method)
            if method == "getblocktemplate":
                now = int(time.time())
                return {"height": 5, "coinbasevalue": STUB_COINBASE_VALUE, "version": 0x20000000, "bits": "207fffff",
                        "curtime": now, "mintime": now - 60, "previousblockhash": "11" * 32, "transactions": [],
                        "default_witness_commitment": WITNESS_COMMITMENT}
            if method == "getmetaldagpowhash":
                return "00" * 32   # every well-formed share is a block
            return None
        POOL.rpc = rpc
        POOL.JOBS.refresh()
        self.session = POOL.Session(None, FakeWriter())
        self.session.spk = POOL.payout_script(MINER_V3_REHEARSAL)
        self.session.address = MINER_V3_REHEARSAL
        self.session.worker = "rig1"
        asyncio.run(self.session.notify(clean=True))
        self.jid = list(self.session.jobs)[-1]
        self.ntime = f"{self.session.jobs[self.jid]['mintime'] + 1:08x}"

    def tearDown(self):
        POOL.rpc, POOL.CFG["hrp"], POOL.JOBS = self.saved_rpc, self.saved_hrp, self.saved_jobs

    def submit(self, mid, en2="00000000", ntime=None, nonce="00000000", vbits=None):
        params = ["w", self.jid, en2, ntime or self.ntime, nonce]
        if vbits is not None:
            params.append(vbits)
        asyncio.run(self.session.dispatch({"id": mid, "method": "mining.submit", "params": params}))
        return [m for m in self.session.w.sent if m.get("id") == mid][-1]

    def test_a_well_formed_share_is_accepted(self):
        reply = self.submit(1)
        self.assertTrue(reply["result"], reply)
        self.assertIn("getmetaldagpowhash", self.calls)

    def test_malformed_hex_is_a_clean_reject_not_an_exception(self):
        cases = {
            "en2": dict(en2="zz"),
            "en2 odd length": dict(en2="0000000"),
            "en2 not a string": dict(en2=[0, 0, 0, 0]),
            "nonce": dict(nonce="zzzzzzzz"),
            "nonce over 32 bits": dict(nonce="100000000"),
            "nonce negative": dict(nonce="-1"),
            "nonce not a string": dict(nonce=12345),
            "ntime": dict(ntime="nope"),
            "ntime not a string": dict(ntime={"t": 1}),
            "vbits": dict(vbits="zzzzzzzz"),
            "vbits over 32 bits": dict(vbits="1ffffffff"),
            "vbits not a string": dict(vbits=[1]),
        }
        for label, kw in cases.items():
            with self.subTest(case=label):
                self.calls.clear()
                mid = 100 + len(self.session.w.sent)
                reply = self.submit(mid, **kw)
                self.assertFalse(reply["result"], reply)
                self.assertIsNotNone(reply["error"], reply)
                self.assertNotIn("getmetaldagpowhash", self.calls)   # nothing reached the node
        # ...and the session is still serving: the next good share is accepted.
        self.assertTrue(self.submit(999)["result"])

    def test_a_non_dict_or_exploding_request_does_not_kill_the_session(self):
        """handle() answers a request that raises with a stratum error and keeps reading."""
        class Reader:
            def __init__(self, lines): self.lines = list(lines)
            async def readline(self):
                return self.lines.pop(0) if self.lines else b""
        good = json.dumps({"id": 7, "method": "mining.submit",
                           "params": ["w", self.jid, "00000000", self.ntime, "00000000"]}) + "\n"
        self.session.r = Reader([
            b"[1, 2, 3]\n",                                                   # not an object
            b'{"id": 5, "method": "mining.submit", "params": 5}\n',           # len() of an int
            b'{"id": 6, "method": "mining.submit", "params": ["w", [], "00", "00", "00"]}\n',  # unhashable jid
            good.encode(),
        ])
        self.session.w.close = lambda: None
        asyncio.run(self.session.handle())
        replies = {m.get("id"): m for m in self.session.w.sent if "result" in m}
        self.assertFalse(replies[5]["result"]); self.assertIsNotNone(replies[5]["error"])
        self.assertFalse(replies[6]["result"]); self.assertIsNotNone(replies[6]["error"])
        self.assertTrue(replies[7]["result"], replies[7])

    def test_extranonce2_must_be_exactly_en2_size(self):
        """Audit finding L2: build_coinbase baked len(en1) + en2_size into the
        scriptSig length varint; any other en2 length is a block the node would
        reject as malformed, so it must never be accepted as a share."""
        self.assertEqual(self.session.en2_size, 4)
        for en2 in ("", "00", "000000", "0000000000", "00" * 40):
            with self.subTest(en2=en2):
                self.calls.clear()
                reply = self.submit(200 + len(en2), en2=en2)
                self.assertFalse(reply["result"], reply)
                self.assertIn("extranonce2", reply["error"][1])
                self.assertNotIn("getmetaldagpowhash", self.calls)
        # the exact size is a share (and here, a block whose scriptSig parses)
        reply = self.submit(300, en2="0a0b0c0d")
        self.assertTrue(reply["result"], reply)
        ok, is_block, block_hex, _ = asyncio.run(self.session.validate(self.jid, "0a0b0c0d", self.ntime, "00000000", None))
        self.assertTrue(ok and is_block)
        blk = bytes.fromhex(block_hex)
        seg_cb = blk[80 + 1:]                   # header, varint(1) tx count, then the segwit coinbase
        # strip marker+flag after the version and the 34-byte witness before the locktime
        cb = seg_cb[:4] + seg_cb[6:-38] + seg_cb[-4:]
        job = self.session.jobs[self.jid]
        self.assertEqual(cb, job["p1"] + self.session.en1 + bytes.fromhex("0a0b0c0d") + job["p2"])
        script_sig, _ = parse_coinbase(cb)
        self.assertEqual(script_sig[-8:], self.session.en1 + bytes.fromhex("0a0b0c0d"))
        self.assertLessEqual(len(script_sig), POOL.MAX_COINBASE_SCRIPTSIG)

    def test_parse_submit_params_accepts_exactly_what_the_header_needs(self):
        en2, ntime, nonce, vbits = POOL.parse_submit_params("0a0b0c0d", "5f000000", "ffffffff", "20000000", 4)
        self.assertEqual((en2, ntime, nonce, vbits), (bytes.fromhex("0a0b0c0d"), 0x5f000000, 0xffffffff, 0x20000000))
        self.assertIsNone(POOL.parse_submit_params("0a0b0c0d", "5f000000", "ffffffff", None, 4)[3])
        for bad in [("0a0b0c", "5f000000", "ffffffff", None), ("0a0b0c0d", "5f000000", "ffffffff", "-1"),
                    ("0a0b0c0d", "5f000000", "100000000", None), ("0a0b0c0d", "xx", "ffffffff", None)]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    POOL.parse_submit_params(*bad, 4)


class AgentSanitizationTests(unittest.TestCase):
    """Audit finding L3: the mining.subscribe user-agent is untrusted text that is
    shown in the Discord leaderboard. It is filtered like the worker name."""

    def test_a_normal_agent_survives(self):
        self.assertEqual(POOL.sanitize_agent("MMM-CLI/1.0.0 (Apple M3 Pro; Mac15,6)"),
                         "MMM-CLI/1.0.0 (Apple M3 Pro; Mac15,6)")
        self.assertEqual(POOL.sanitize_agent("cpuminer-opt/3.21.0"), "cpuminer-opt/3.21.0")

    def test_control_characters_and_markdown_are_stripped(self):
        evil = "Miner (M3\n**FAKE ADMIN**: withdraw at xpa1qevil\n)"
        clean = POOL.sanitize_agent(evil)
        for ch in "\n\r\t*_`~|<>@#[]\\":
            self.assertNotIn(ch, clean)
        self.assertEqual(clean, "Miner (M3FAKE ADMIN: withdraw at xpa1qevil)")
        self.assertEqual(POOL.sanitize_agent("@everyone <#123> [x](http://y) `code` ~~s~~ __u__"),
                         "everyone 123 x(http://y) code s u")
        self.assertEqual(POOL.sanitize_agent(""), "?")
        self.assertEqual(POOL.sanitize_agent(None), "None")
        self.assertEqual(len(POOL.sanitize_agent("A" * 500)), POOL.MAX_AGENT_LEN)

    def test_subscribe_stores_the_sanitized_agent_and_the_embed_has_no_injected_row(self):
        session = POOL.Session(None, FakeWriter())
        asyncio.run(session.dispatch({"id": 1, "method": "mining.subscribe",
                                      "params": ["Miner (M3\n**FAKE ADMIN**: withdraw at xpa1qevil\n)"]}))
        self.assertEqual(session.agent, "Miner (M3FAKE ADMIN: withdraw at xpa1qevil)")
        session.address = MINER_V3_REHEARSAL; session.worker = "rig1"
        POOL.SESSIONS.add(session)
        try:
            desc = POOL.build_leaderboard_embed()["embeds"][0]["description"]
        finally:
            POOL.SESSIONS.discard(session)
        rows = desc.split("\n")
        self.assertEqual(len(rows), 2, rows)                 # one rig: name line + stats line
        self.assertTrue(rows[0].startswith("**rig1** · "))
        self.assertNotIn("**FAKE", desc)
        self.assertIn("M3FAKE ADMIN: withdraw at xpa1qevil", rows[0])


class ReportedHashrateTests(unittest.TestCase):
    """Audit finding L4: a mining.hashrate self-report is display-only. The pool's
    own figures (hashrate_hps, hashrate_mhs, the leaderboard total) come from
    accepted shares and never include it."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {k: getattr(POOL, k) for k in ("MINERS_FILE", "RIGS_FILE", "STATS_FILE", "MINERS", "RIGS")}
        for k in ("MINERS_FILE", "RIGS_FILE", "STATS_FILE"):
            setattr(POOL, k, str(Path(self.tmp.name) / k.lower()))
        POOL.MINERS, POOL.RIGS = {}, {}

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(POOL, k, v)
        self.tmp.cleanup()

    def test_self_reported_hashrate_never_enters_the_measured_figures(self):
        session = POOL.Session(None, FakeWriter())
        session.address, session.worker = MINER_V3_REHEARSAL, "rig1"
        now = int(time.time())
        POOL.record_share(session.address, 1.0)                 # 2^32 hashes of verified work in 600 s
        POOL.record_rig_share(session.address, "rig1", 1.0)
        asyncio.run(session.dispatch({"id": 9, "method": "mining.hashrate", "params": [1e15]}))
        rig = POOL.RIGS[f"{session.address}|rig1"]
        self.assertEqual(rig["reported_hps"], 1e15)
        measured = (2 ** 32) / 600.0
        self.assertAlmostEqual(POOL.measured_hps(rig, now), measured, delta=1.0)
        self.assertEqual(POOL.reported_hps(rig, now), 1e15)
        self.assertIsNone(POOL.reported_hps(rig, now + 60))     # stale after REPORTED_HPS_TTL
        POOL.save_stats()
        stats = json.loads(Path(POOL.STATS_FILE).read_text())
        self.assertAlmostEqual(stats["hashrate_hps"], measured, delta=1.0)          # measured only
        self.assertEqual(stats["reported_hashrate_hps"], 1e15)                       # labelled separately
        row = stats["leaderboard"][0]
        self.assertAlmostEqual(row["hashrate_mhs"], round(measured / 1e6, 2), places=2)
        self.assertEqual(row["reported_hashrate_mhs"], 1e9)
        POOL.SESSIONS.add(session)
        try:
            embed = POOL.build_leaderboard_embed()["embeds"][0]
        finally:
            POOL.SESSIONS.discard(session)
        self.assertIn(f"pool {POOL._fmt_rate(POOL.measured_hps(POOL.MINERS[session.address], now))}", embed["footer"]["text"])
        self.assertNotIn(POOL._fmt_rate(1e15), embed["footer"]["text"])
        self.assertIn("miner reports", embed["description"])


class LevyTests(unittest.TestCase):
    """The settlement levy the pool must never assume it can undercut."""

    def test_genesis_rule_charges_nothing(self):
        # src/consensus/params.h SETTLEMENT_LEVY_GENESIS_RULE: zero rate, zero cap.
        self.assertEqual(POOL.SETTLEMENT_LEVY_BP, 0)
        self.assertEqual(POOL.SETTLEMENT_LEVY_CAP_SAT, 0)
        for sats in (0, 1, 2_001, 10_000, 50 * COIN, MAX_MONEY):
            self.assertEqual(POOL.settlement_levy(sats), 0)
            self.assertEqual(POOL.levy_from_inputs(sats), 0)
        # 1,480 sat: a typical 1,480-vB 1-in-2-out ML-DSA payment at the 1 sat/vB relay floor (src/policy/policy.h)
        self.assertEqual(POOL.payout_fee_floor_sats(50 * COIN, byte_fee_sats=1480), 1480)

    def test_matches_the_consensus_static_asserts(self):
        # src/consensus/levy.h, the REFERENCE rule: SETTLEMENT_LEVY_BP = 5, cap 10,000.
        bp, cap = POOL.SETTLEMENT_LEVY_REFERENCE_BP, POOL.SETTLEMENT_LEVY_REFERENCE_CAP_SAT
        self.assertEqual((bp, cap), (5, 10_000))
        self.assertEqual(POOL.settlement_levy(10_000, bp, cap), 5)
        self.assertEqual(POOL.settlement_levy(1, bp, cap), 1)          # rounds up
        self.assertEqual(POOL.settlement_levy(2_000, bp, cap), 1)
        self.assertEqual(POOL.settlement_levy(2_001, bp, cap), 2)
        self.assertEqual(POOL.settlement_levy(0, bp, cap), 0)
        self.assertEqual(POOL.settlement_levy(10_000, 0, cap), 0)
        # The raw arithmetic before the cap (Consensus::SettlementLevyUncapped).
        # levy.h: SettlementLevyUncapped(MAX_MONEY, SETTLEMENT_LEVY_BP) == 5'000'000'000'000 (50,000 XID)
        self.assertEqual(POOL.settlement_levy_uncapped(MAX_MONEY, bp), 5_000_000_000_000)
        self.assertEqual(POOL.settlement_levy_uncapped(MAX_MONEY, 10_000), MAX_MONEY)     # 100% of the cap: no overflow
        self.assertEqual(POOL.levy_from_inputs(10_005, bp, cap), 5)
        self.assertEqual(POOL.settlement_levy(10_005 - 5, bp, cap), 5)
        # 50 XID in: 2,498,751 sat would be the uncapped answer; the cap makes it 10,000.
        self.assertEqual(POOL.levy_from_inputs(50 * COIN, bp, cap_sat=MAX_MONEY), 2_498_751)
        self.assertEqual(POOL.levy_from_inputs(50 * COIN, bp, cap), cap)
        self.assertLessEqual(POOL.settlement_levy(50 * COIN - 10_000, bp, cap), 10_000)

    def test_the_reference_cap_matches_the_consensus_static_asserts(self):
        """Audit finding L5: src/consensus/levy.h caps the reference levy at
        SETTLEMENT_LEVY_CAP_SAT (10,000 sat); the pool's helpers must agree
        whenever a test (or a future activation) runs them at that rule."""
        bp, cap = POOL.SETTLEMENT_LEVY_REFERENCE_BP, POOL.SETTLEMENT_LEVY_REFERENCE_CAP_SAT
        self.assertEqual(cap, 10_000)                                          # consensus/params.h
        self.assertEqual(POOL.settlement_levy(20_000_000, bp, cap), 10_000)     # 0.2 XID out: exactly at the cap
        self.assertEqual(POOL.settlement_levy(20_000_001, bp, cap), 10_000)     # one sat past the crossover
        self.assertEqual(POOL.settlement_levy(19_999_999, bp, cap), 10_000)     # ceil(9,999.9995) = 10,000
        self.assertEqual(POOL.settlement_levy(19_998_000, bp, cap), 9_999)      # just under the cap
        self.assertEqual(POOL.settlement_levy(1_000_000_000_000, bp, cap), 10_000)  # 10,000 XID out owes the cap
        self.assertEqual(POOL.settlement_levy(MAX_MONEY, bp, cap), 10_000)   # the whole supply (levy.h)
        self.assertEqual(POOL.levy_from_inputs(MAX_MONEY, bp, cap), 10_000)  # wallet-side helper too
        # A raised cap is proportional again above the old crossover (the soft-fork lever).
        self.assertEqual(POOL.settlement_levy(COIN, bp, cap_sat=100_000), 50_000)
        # A whole block reward, swept: never more than the cap.
        for total in (STUB_COINBASE_VALUE, 50 * COIN, 76_650 * COIN, MAX_MONEY):
            self.assertLessEqual(POOL.levy_from_inputs(total, bp, cap), cap)
        # And under the genesis rule the floor is the byte fee alone.
        self.assertEqual(POOL.payout_fee_floor_sats(MAX_MONEY), 0)
        self.assertEqual(POOL.payout_fee_floor_sats(MAX_MONEY, 12_345), 12_345)

    def test_the_cap_mirrors_consensus(self):
        """MAX_MONEY above is the consensus cap, so the levy mirror tests the real boundary."""
        amount = (REPO / "src" / "consensus" / "amount.h").read_text()
        self.assertIn("static constexpr CAmount MAX_MONEY = 100000000 * COIN;", amount)
        levy = (REPO / "src" / "consensus" / "levy.h").read_text()
        self.assertIn("SettlementLevyUncapped(MAX_MONEY, SETTLEMENT_LEVY_BP) == 5'000'000'000'000LL", levy)
        self.assertEqual(MAX_MONEY, 10_000_000_000_000_000)

    def test_the_default_rpc_port_is_mainnets(self):
        """src/chainparamsbase.cpp: mainnet RPC is 8332 (the rehearsal chain's is 19432)."""
        base = (REPO / "src" / "chainparamsbase.cpp").read_text()
        self.assertRegex(base, r'ChainType::MAIN:\s*return std::make_unique<CBaseChainParams>\("", 8332\)')
        self.assertIn('CBaseChainParams>("testneta", 19432)', base)
        source = MODULE_PATH.read_text()
        self.assertIn('os.environ.get("XCOIN_RPC_PORT", "8332")', source)
        self.assertNotRegex(source, r"(?<!\d)9[34]32(?!\d)")        # the old, no-chain defaults
        readme = MODULE_PATH.with_name("README.md").read_text()
        self.assertNotRegex(readme, r"(?<!\d)9[34]32(?!\d)")
        self.assertIn("XID", readme.splitlines()[2])
        self.assertNotIn("XAT", readme)
        self.assertNotIn("XCF", readme)                              # retired 2026-09-25
        self.assertNotIn("XCF", source)

    def test_the_floor_is_never_below_the_levy(self):
        for total in (1, 999, 10_000, 50 * COIN, 76_650 * COIN):
            for byte_fee in (0, 1, 500, 10_000_000):
                with self.subTest(total=total, byte_fee=byte_fee):
                    fee = POOL.payout_fee_floor_sats(total, byte_fee)
                    self.assertGreaterEqual(fee, byte_fee)
                    self.assertGreaterEqual(fee, POOL.settlement_levy(total - fee))

    def test_the_pool_builds_no_payout_transaction(self):
        """The accounting assumption behind the levy: this pool is SOLO. It pays
        the miner in the coinbase (exempt from the levy) and never constructs a
        spending transaction, so it has no fee to keep and none to underpay. If
        that ever changes, the new path must fee-floor at payout_fee_floor_sats."""
        source = MODULE_PATH.read_text()
        for rpc_name in ("createrawtransaction", "signrawtransactionwithwallet",
                         "sendrawtransaction", "sendtoaddress", "sendmany",
                         "fundrawtransaction", "walletcreatefundedpsbt"):
            self.assertNotIn(rpc_name, source, f"pool calls {rpc_name}: it now builds "
                                               "transactions and owes the settlement levy")

    def test_the_coinbase_keeps_nothing_back(self):
        POOL.CFG["hrp"], saved = "txa", POOL.CFG["hrp"]
        try:
            spk = POOL.payout_script(MINER_V3_REHEARSAL)
            value = STUB_COINBASE_VALUE + POOL.settlement_levy(76_650 * COIN)
            outputs = parse_outputs(build(2, value, spk))
            paid = sum(amount for amount, script in outputs if script[:1] != b"\x6a")
            self.assertEqual(paid, value)      # no pool cut, no rounding loss
        finally:
            POOL.CFG["hrp"] = saved


class RpcCredentialTests(unittest.TestCase):
    """The node's cookie file is the credential. The environment is a fallback that warns."""
    def setUp(self):
        self.saved = {k: POOL.CFG[k] for k in ("rpc_cookie", "rpc_user", "rpc_pass")}
    def tearDown(self):
        POOL.CFG.update(self.saved)

    def test_cookie_file_is_read_on_every_call(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".cookie")
            with open(path, "w") as f:
                f.write("__cookie__:abc123\n")
            POOL.CFG.update(rpc_cookie=path, rpc_user="ignored", rpc_pass="ignored")
            self.assertEqual(POOL._rpc_credentials(), "__cookie__:abc123")
            with open(path, "w") as f:          # nexd restarted: new cookie, no pool restart
                f.write("__cookie__:restarted\n")
            self.assertEqual(POOL._rpc_credentials(), "__cookie__:restarted")

    def test_missing_cookie_is_an_error_not_a_fallback(self):
        POOL.CFG.update(rpc_cookie="/nonexistent/testneta/.cookie", rpc_user="u", rpc_pass="p")
        with self.assertRaises(OSError):
            POOL._rpc_credentials()
        self.assertIsNone(POOL.rpc("getblockchaininfo"))   # logged, not raised, not the env password

    def test_malformed_cookie_is_refused(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".cookie")
            with open(path, "w") as f:
                f.write("not a cookie\n")
            POOL.CFG.update(rpc_cookie=path)
            with self.assertRaises(RuntimeError):
                POOL._rpc_credentials()

    def test_environment_fallback_when_no_cookie_is_configured(self):
        POOL.CFG.update(rpc_cookie="", rpc_user="u", rpc_pass="p")
        self.assertEqual(POOL._rpc_credentials(), "u:p")


if __name__ == "__main__":
    unittest.main()
