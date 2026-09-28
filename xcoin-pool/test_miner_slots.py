#!/usr/bin/env python3
"""Miner slots: XCOIN_POOL_MAX_MINERS caps the authorized sessions a pool serves at
once, a full pool refuses the next miner and points it at the pool directory, and
pool_stats.json publishes the slot figures the explorer and xcoinpool.com show.

    python3 xcoin-pool/test_miner_slots.py -v
"""

import asyncio
import importlib.util
import json
import logging
import os
import tempfile
import time
import unittest
from pathlib import Path

STATS_TMP = tempfile.mkdtemp(prefix="xcoin-pool-slots-")
os.environ["XCOIN_STATS_DIR"] = STATS_TMP          # keep the registry out of ~/.xcoin

MODULE_PATH = Path(__file__).with_name("xcoin-pool.py")
SPEC = importlib.util.spec_from_file_location("xcoin_pool_slots", MODULE_PATH)
POOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POOL)
POOL.log.setLevel(logging.CRITICAL)                  # refusals log a warning by design

MINER = "txa1rk0shs7zn527v0wh2gah4h598fhpxv9csgvzqymrj29jd3frmvvaq4jlady"


class FakeWriter:
    def __init__(self):
        self.sent = []
        self.closed = False

    def get_extra_info(self, _what):
        return ("127.0.0.1", 54321)

    def write(self, data):
        self.sent.append(json.loads(data.decode()))

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class MinerSlotTests(unittest.TestCase):
    def setUp(self):
        self.saved = {k: POOL.CFG[k] for k in ("hrp", "max_miners", "region", "public_stratum")}
        self.saved_rpc = POOL.rpc
        POOL.CFG["hrp"] = "txa"
        POOL.rpc = lambda method, params=None: None    # no template: authorize only
        POOL.JOBS.tmpl = None
        POOL.SESSIONS.clear()

    def tearDown(self):
        POOL.CFG.update(self.saved)
        POOL.rpc = self.saved_rpc
        POOL.SESSIONS.clear()

    def connect_and_authorize(self, worker):
        s = POOL.Session(None, FakeWriter())
        POOL.SESSIONS.add(s)                           # handle() does this on connect
        asyncio.run(s.dispatch({"id": 2, "method": "mining.authorize", "params": [f"{MINER}.{worker}", "x"]}))
        return s

    def test_a_full_pool_refuses_the_next_miner_and_names_the_directory(self):
        POOL.CFG["max_miners"] = 2
        a, b = self.connect_and_authorize("rig1"), self.connect_and_authorize("rig2")
        self.assertTrue(a.w.sent[0]["result"] and b.w.sent[0]["result"])
        c = self.connect_and_authorize("rig3")
        self.assertFalse(c.w.sent[0]["result"])
        self.assertEqual(c.w.sent[0]["error"][0], 24)
        self.assertIn("pool full", c.w.sent[0]["error"][1])
        self.assertIn("xcoinpool.com", c.w.sent[0]["error"][1])
        self.assertEqual(c.w.sent[1]["method"], "client.show_message")
        self.assertIsNone(c.spk)                       # never counted, never paid
        self.assertTrue(c.w.closed)
        self.assertEqual(POOL.connected_miners(), 2)
        self.assertTrue(POOL.pool_full())

    def test_a_refused_browser_session_does_not_burn_a_session_number(self):
        POOL.CFG["max_miners"] = 1
        self.connect_and_authorize("rig1")
        seq = Path(STATS_TMP, "web_session_seq.txt")
        before = seq.read_text() if seq.exists() else None
        self.connect_and_authorize("web-solo")
        self.assertEqual(seq.read_text() if seq.exists() else None, before)

    def test_a_connected_miner_may_authorize_again_when_full(self):
        POOL.CFG["max_miners"] = 1
        a = self.connect_and_authorize("rig1")
        asyncio.run(a.dispatch({"id": 3, "method": "mining.authorize", "params": [f"{MINER}.rig1", "x"]}))
        self.assertTrue([m for m in a.w.sent if m.get("id") == 3][0]["result"])
        self.assertFalse(a.w.closed)

    def test_a_disconnect_frees_a_slot(self):
        POOL.CFG["max_miners"] = 1
        a = self.connect_and_authorize("rig1")
        POOL.SESSIONS.discard(a)                       # handle()'s finally on disconnect
        b = self.connect_and_authorize("rig2")
        self.assertTrue(b.w.sent[0]["result"])

    def test_no_cap_by_default(self):
        POOL.CFG["max_miners"] = 0
        sessions = [self.connect_and_authorize(f"rig{i}") for i in range(5)]
        self.assertTrue(all(s.w.sent[0]["result"] for s in sessions))
        self.assertFalse(POOL.pool_full())

    def test_refused_and_unauthorized_sessions_hold_no_slot(self):
        POOL.CFG["max_miners"] = 1
        POOL.SESSIONS.add(POOL.Session(None, FakeWriter()))   # connected, never authorized
        a = self.connect_and_authorize("rig1")
        self.assertTrue(a.w.sent[0]["result"])

    def test_stats_publish_slots_and_directory_facts(self):
        POOL.CFG.update(max_miners=2, region="Hong Kong", public_stratum="stratum+tcp://198.252.107.13:3336")
        self.connect_and_authorize("rig1"); self.connect_and_authorize("rig2")
        POOL.save_stats()
        stats = json.loads(Path(STATS_TMP, "pool_stats.json").read_text())
        self.assertEqual((stats["connected_miners"], stats["max_miners"], stats["full"]), (2, 2, True))
        self.assertEqual(stats["region"], "Hong Kong")
        self.assertEqual(stats["stratum"], "stratum+tcp://198.252.107.13:3336")
        self.assertLessEqual(abs(stats["updated"] - time.time()), 5)

    def test_stats_without_a_cap_say_null(self):
        POOL.CFG.update(max_miners=0, region="", public_stratum="")
        POOL.save_stats()
        stats = json.loads(Path(STATS_TMP, "pool_stats.json").read_text())
        self.assertIsNone(stats["max_miners"])
        self.assertFalse(stats["full"])
        self.assertIsNone(stats["region"])


class SlotsMatchPayouts(unittest.TestCase):
    """Why a PPLNS pool's slots and XCOIN_PPLNS_MAX_OUTPUTS are set to the same number:
    a block pays only the max_outputs largest miners, so every connected miner can be
    in a block only when the payout list is at least as long as the slot count."""
    FEE = bytes([0x53, 0x20]) + b"\xfe" * 32

    def spks(self, n):
        return [bytes([0x53, 0x20]) + i.to_bytes(32, "big") for i in range(1, n + 1)]

    def setUp(self):
        self.saved_hrp = POOL.CFG["hrp"]; POOL.CFG["hrp"] = "xpa"

    def tearDown(self):
        POOL.CFG["hrp"] = self.saved_hrp

    def test_fifty_slots_fifty_outputs_pays_everyone(self):
        miners = self.spks(50)
        outs = POOL.pplns_split(50 * 10**8, {s: 1.0 for s in miners}, 299, self.FEE, 10_000, 50, miners[0])
        paid = {spk for spk, _ in outs if spk != self.FEE}
        self.assertEqual(paid, set(miners))
        self.assertEqual(sum(a for _, a in outs), 50 * 10**8)
        p1, p2 = POOL.build_coinbase(900, 50 * 10**8, 8, None, outs)   # 51 outputs serialize
        self.assertTrue(p1 and p2)

    def test_fifty_miners_on_a_forty_output_list_leave_ten_unpaid(self):
        miners = self.spks(50)
        outs = POOL.pplns_split(50 * 10**8, {s: 1.0 + i for i, s in enumerate(miners)}, 299, self.FEE, 10_000, 40, miners[0])
        self.assertEqual(len([s for s, _ in outs if s != self.FEE]), 40)   # the 10 smallest get nothing


if __name__ == "__main__":
    unittest.main()
