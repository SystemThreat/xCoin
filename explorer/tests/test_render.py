#!/usr/bin/env python3
"""Renders every page against a stub rehearsal chain.

No node is needed: `rpc` is replaced with a small in-memory chain shaped like the
testnet A rehearsal — a genesis block, three coinbases of 50 XID (the Annual Tenth's blocks 60,001-220,000) to witness v3 [EMISSION-SHAPE]
addresses, one spend with a 0.1 XID fee, and one pending transaction. The tests then
assert what each page says: XID everywhere and never an old ticker, witness v3
everywhere, the fee shown, the charter in the network panel, the front page naming
the testnet A rehearsal, and — with the chain's levy rule of 0 bp — no levy text on
any page. A second class raises LEVY_BP to 5 (a test chain) and checks that the levy
rows, column and verdicts come back, so that machinery stays covered.

Run:  python3 -m unittest discover -s tests -v        (from the explorer directory)
"""
import importlib.util, io, json, os, unittest
from decimal import Decimal
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("xcoin_explorer_render", os.path.join(ROOT, "xcoin-explorer.py"))
X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(X)
REAL_RPC = X.rpc                              # the classes below swap in stubs; the exactness tests need the real one

SAT = 100_000_000
HRP = "txa"                                   # the rehearsal chain
SUBSIDY = 50.0                                # a stub value: the Annual Tenth pays 50 XID for blocks 60,001-220,000 [EMISSION-SHAPE]
KH_A = "a158ac5047845bfdedad6e2e3e074b2bac33cefa7440b6b3aba668b40bd8bce9"
KH_B = "6fa9" + "00" * 30
KH_C = "11" * 32


def v3(kh):
    prog = X.carried_program(bytes.fromhex(kh))
    return X.bech32m_encode(HRP, 3, prog), X.script_for_program(3, prog).hex()


ADDR_A, SPK_A = v3(KH_A)
ADDR_B, SPK_B = v3(KH_B)
ADDR_C, SPK_C = v3(KH_C)
V2_A = X.bech32m_encode(HRP, 2, bytes.fromhex(KH_A))


def out(value, spk, addr, typ="witness_v3_pq", n=0):
    o = {"value": value, "n": n, "scriptPubKey": {"hex": spk, "type": typ}}
    if addr: o["scriptPubKey"]["address"] = addr
    return o


def coinbase(txid, vouts):
    return {"txid": txid, "size": 200, "vsize": 200,
            "vin": [{"coinbase": "01", "sequence": 0}], "vout": vouts}


SPEND_OUT_A, SPEND_OUT_B = 49.5, 0.4          # 49.9 XID out of a 50 XID input -> 0.1 XID fee [EMISSION-SHAPE]
SPEND_FEE_SAT = int(0.1 * SAT)
MEM_FEE, MEM_OUT = 0.0001, 1.0                # the pending transaction

GENESIS = coinbase("t0", [out(0.0, "6a4f" + "00" * 79, None, "nulldata", n=0)])
TX1 = coinbase("t1", [out(SUBSIDY, SPK_A, ADDR_A)])
TX2 = coinbase("t2", [out(SUBSIDY, SPK_B, ADDR_B)])
TX3 = coinbase("t3", [out(SUBSIDY, SPK_B, ADDR_B)])
SPEND = {"txid": "s1", "size": 5600, "vsize": 1450,
         "vin": [{"txid": "t1", "vout": 0, "sequence": 0,
                  "txinwitness": ["aa" * 1952, "bb" * 3309,
                                  X.key32_checksig_script(bytes.fromhex(KH_A)).hex(),
                                  (bytes([0xc0]) + X.XCOIN_V3_NOKEY).hex()]}],
         "vout": [out(SPEND_OUT_A, SPK_C, ADDR_C, n=0), out(SPEND_OUT_B, SPK_A, ADDR_A, n=1)]}
MEM = {"txid": "m1", "size": 2800, "vsize": 700,
       "vin": [{"txid": "t2", "vout": 0, "sequence": 0}],
       "vout": [out(MEM_OUT, SPK_C, ADDR_C, n=0)]}

BLOCKS = [
    {"height": 0, "hash": "00" * 31 + "01", "time": 1_780_000_000, "nTx": 1, "size": 400,
     "weight": 1600, "difficulty": 1.0, "bits": "1e0fffff", "nonce": 1,
     "merkleroot": "aa" * 32, "confirmations": 4, "tx": [GENESIS]},
    {"height": 1, "hash": "00" * 31 + "02", "time": 1_780_000_300, "nTx": 1, "size": 400,
     "weight": 1600, "difficulty": 1.0, "bits": "1e0fffff", "nonce": 2,
     "merkleroot": "bb" * 32, "confirmations": 3, "tx": [TX1]},
    {"height": 2, "hash": "00" * 31 + "03", "time": 1_780_000_600, "nTx": 1, "size": 400,
     "weight": 1600, "difficulty": 1.0, "bits": "1e0fffff", "nonce": 3,
     "merkleroot": "cc" * 32, "confirmations": 2, "tx": [TX2]},
    {"height": 3, "hash": "00" * 31 + "04", "time": 1_780_000_900, "nTx": 2, "size": 6000,
     "weight": 24000, "difficulty": 1.0, "bits": "1e0fffff", "nonce": 4,
     "merkleroot": "dd" * 32, "confirmations": 1, "tx": [TX3, SPEND]},
]
BY_HASH = {b["hash"]: b for b in BLOCKS}
TXS = {t["txid"]: t for b in BLOCKS for t in b["tx"]}
TXS["m1"] = MEM
SPK_BY_ADDR = {ADDR_A: SPK_A, ADDR_B: SPK_B, ADDR_C: SPK_C}
CHARTER = {"charter_hash": "ecc7ca06" + "00" * 28, "currency_id": "33e67832" + "11" * 28,
           "genesis_hash": BLOCKS[0]["hash"], "genesis_is_final": True}


def stub_rpc(method, params=None):
    p = params or []
    if method == "getblockcount": return len(BLOCKS) - 1
    if method == "getblockhash": return BLOCKS[p[0]]["hash"] if 0 <= p[0] < len(BLOCKS) else None
    if method == "getblock": return BY_HASH.get(p[0])
    if method == "getblockheader": return BY_HASH.get(p[0])
    if method == "getblockchaininfo":
        return {"chain": "test", "blocks": len(BLOCKS) - 1, "difficulty": 1.0}
    if method == "gettxoutsetinfo": return {"total_amount": 3 * SUBSIDY - 0.1}
    if method == "getmempoolinfo": return {"size": 1}
    if method == "getrawmempool": return ["m1"]
    if method == "getmempoolentry": return {"vsize": MEM["vsize"], "fees": {"base": MEM_FEE}}
    if method == "getnetworkhashps": return 1234567.0
    if method == "getcharter": return dict(CHARTER)
    if method == "getblockstats": return {"subsidy": int(SUBSIDY * SAT)}
    if method == "getrawtransaction": return TXS.get(p[0])
    if method == "validateaddress":
        a = p[0]
        if a in SPK_BY_ADDR: return {"isvalid": True, "scriptPubKey": SPK_BY_ADDR[a], "type": "witness_v3_pq"}
        return {"isvalid": False, "error": "not an address on this chain"}
    if method == "scantxoutset":
        spk = p[1][0]["desc"][4:-1]
        ups = []
        for b in BLOCKS:
            for t in b["tx"]:
                for n, o in enumerate(t["vout"]):
                    if o["scriptPubKey"]["hex"] == spk and o["value"] > 0:
                        if t["txid"] == "t1" and n == 0: continue      # spent by SPEND
                        ups.append({"txid": t["txid"], "vout": n, "amount": o["value"], "height": b["height"]})
        return {"unspents": ups, "total_amount": sum(u["amount"] for u in ups)}
    return None


def reindex():
    """Rebuild the explorer's own index from block 0 (TXMETA stores the levy at index time)."""
    with X.IDX_LOCK:
        X.LAST_IDX = -1
        for d in (X.TXIDX, X.ADDRIDX, X.UTXO, X.BAL, X.TXMETA, X.MINERS): d.clear()
        del X.SERIES[:]
    X.refresh_index()


def every_page():
    """(name, html) for every page the explorer renders."""
    return [("overview", X.view_overview()),
            ("block 1", X.view_block("1")), ("block 3", X.view_block("3")),
            ("tx s1", X.view_tx("s1")), ("tx t2", X.view_tx("t2")),
            ("address A", X.view_address(ADDR_A)), ("address C", X.view_address(ADDR_C)),
            ("address C from v2", X.view_address(ADDR_C, came_from=V2_A)),
            ("v2 string", X.view_address(V2_A)),
            ("rich list", X.view_richlist()), ("mempool", X.view_mempool()),
            ("404", X.page("Not found", X.error_panel("404", f"Try a {HRP}1r address.")))]


# Words that must never reach a reader. XATInstance is the cross-site tab script's
# global (a code name), so it is stripped before the ticker check. XCF (retired
# 2026-09-25) and XAT are both old tickers.
BANNED = ("Sept", "live since", "carried", "carry", "first chain", "first-chain",
          "previous chain", "launch", "re-genesis", "chain history")


def assert_clean(tc, name, h, levy_allowed=False):
    tc.assertIn("XID", h, f"{name}: the unit is XID")
    tc.assertNotIn("XAT", h.replace("XATInstance", ""), f"{name}: never the old ticker")
    tc.assertNotIn("XCF", h, f"{name}: never the retired ticker")
    tc.assertNotIn("21,000,000", h, f"{name}: never the old cap")
    for w in BANNED:
        tc.assertNotIn(w, h, f"{name}: {w!r} must not render")
    if not levy_allowed:
        tc.assertNotIn("levy", h.lower(), f"{name}: no levy text when the rule is 0 bp")


class Rendering(unittest.TestCase):
    """The chain's rule: LEVY_BP is 0, nothing about a levy renders."""

    @classmethod
    def setUpClass(cls):
        X.rpc = stub_rpc
        X.web_pool_stats = lambda: {}
        X.CFG["hrp"] = HRP
        X.CFG["chain"], X.CFG["chain_label"] = "rehearsal", "Rehearsal chain"
        X.LEVY_BP = 0
        reindex()

    def test_the_default_levy_is_the_chains_rule(self):
        self.assertEqual(X.LEVY_BP, 0)
        self.assertEqual(X.settlement_levy(10_000), 0)

    def test_the_index_owns_the_utxo_set(self):
        # A: paid 50 in block 1, spent it, got 0.4 back; B: two coinbases; C: paid once
        self.assertEqual(X.BAL[ADDR_A], int(SPEND_OUT_B * SAT))
        self.assertEqual(X.BAL[ADDR_B], int(2 * SUBSIDY * SAT))
        self.assertEqual(X.BAL[ADDR_C], int(SPEND_OUT_A * SAT))
        self.assertEqual(X.TXMETA["s1"]["fee"], SPEND_FEE_SAT)
        self.assertEqual(X.TXMETA["s1"]["levy"], 0)
        self.assertEqual(X.MINERS[ADDR_B], 2)

    def test_every_page_is_clean(self):
        for name, h in every_page():
            assert_clean(self, name, h)

    def test_overview_names_the_rehearsal_and_the_charter(self):
        h = X.view_overview()
        self.assertIn("testnet A rehearsal", h)
        self.assertIn("Mainnet genesis is not mined", h)
        self.assertIn(CHARTER["charter_hash"], h)
        self.assertIn(CHARTER["currency_id"], h)
        self.assertIn("Currency id", h)
        self.assertIn("no premine", h)
        self.assertIn("witness v3 only", h)
        self.assertIn("MetalDAG", h)
        self.assertIn("of 100,000,000 XID", h)
        self.assertIn("XID · era subsidy at the tip", h)
        self.assertIn("100,000,000 XID cap", h)
        self.assertIn(X.EMISSION_NOTE, h, "the network panel states the schedule from one constant")
        self.assertIn('<span data-s="supply">', h)
        self.assertIn("Testnet", h, "the Testnet badge follows the rehearsal chain")
        self.assertIn("distributedledgertechnologies.com", h, "the DLT backlink stays")
        self.assertIn("--accent:#c7ff2e", h, "the acid-lime design stays")
        self.assertIn("19432", h, "the rehearsal chain's RPC port is in the network panel")
        self.assertNotIn(":9432", h)
        self.assertNotIn(":9333", h)

    def test_block_reward_is_read_from_the_chain(self):
        h = X.view_overview()
        self.assertIn(">50<", h, "the era-0 subsidy comes from getblockstats")  # [EMISSION-SHAPE]

    def test_block_one_is_an_ordinary_block(self):
        h = X.view_block("1")
        self.assertIn("50 XID", h)  # [EMISSION-SHAPE]
        self.assertIn("witness v3", h)
        self.assertIn(ADDR_A[:20], h)
        self.assertNotIn("Block 1 is", h)

    def test_block_with_a_spend_shows_the_fee_only(self):
        h = X.view_block("3")
        self.assertIn("<th>Fees</th>", h)
        self.assertIn("0.1 XID paid", h)
        self.assertNotIn("Fees / levy", h)
        self.assertNotIn("below", h)

    def test_transaction_shows_the_fee_paid(self):
        h = X.view_tx("s1")
        self.assertIn("Fee paid", h)
        self.assertIn("<strong>0.1 XID</strong>", h)
        self.assertIn("fee 0.1 XID", h)
        self.assertIn("49.9 XID out", h)
        self.assertIn("ML-DSA-65 (0xc0)", h, "the spent leaf is decoded from the control block")
        self.assertIn("single leaf", h)
        self.assertNotIn("Levy required", h)
        self.assertNotIn("pill", h.split("Fee paid")[1][:120], "no verdict pill without a levy")

    def test_coinbase_pays_no_fee(self):
        h = X.view_tx("t2")
        self.assertIn("pays no fee", h)
        self.assertIn("witness v3", h)
        self.assertNotIn("Levy required", h)

    def test_address_page(self):
        h = X.view_address(ADDR_C)
        self.assertIn("witness v3", h)
        self.assertIn("Merkle root", h)
        self.assertIn(X.v3_program_of(ADDR_C).hex(), h)
        self.assertIn("49.5 XID", h)
        self.assertIn('<div class=summary-note>XID</div>', h)

    def test_a_witness_v2_string_maps_to_the_same_key(self):
        h = X.view_address(V2_A)
        self.assertIn("Witness v2 string", h)
        self.assertIn("not payable on this chain", h)
        self.assertIn("Witness v3 only", h)
        self.assertIn(ADDR_A, h, "the v3 address of the SAME key is named")
        h2 = X.view_address(ADDR_A, came_from=V2_A)
        self.assertIn("Witness v2 string", h2)
        self.assertIn("witness v3 address of the same key", h2)

    def test_a_mainnet_v2_string_names_this_chain_too(self):
        h = X.view_address(X.bech32m_encode("xpa", 2, bytes.fromhex(KH_A)))
        self.assertIn("Different chain", h)
        self.assertIn(ADDR_A, h)

    def test_rich_list(self):
        h = X.view_richlist()
        self.assertIn("Rich list", h)
        self.assertIn(ADDR_B[:20], h)
        self.assertIn("100 XID", h)
        self.assertIn(f"{HRP}1r", h)

    def test_mempool_has_no_levy_column(self):
        h = X.view_mempool()
        self.assertIn("1 pending", h)
        self.assertIn("0.0001 XID", h)
        self.assertNotIn("Levy required", h)
        self.assertNotIn("below", h)
        self.assertIn("showing 1 of 1</span>", h)

    def test_amounts_are_exact_up_to_the_cap(self):
        # The renderer works in integer sats, so the last satoshi survives up to the
        # 10^16-sat cap (a float in XID units is exact only below 2^26 XID).
        self.assertEqual(X.sats_xat(10_000_000_000_000_000), "100,000,000")
        self.assertEqual(X.sats_xat(9_999_999_999_999_999), "99,999,999.99999999")
        self.assertEqual(X.sats_xat(9_007_199_254_740_993), "90,071,992.54740993")
        self.assertEqual(X.sats_xat(11_000_000), "0.11")
        self.assertEqual(X.sats_xat(1), "0.00000001")
        self.assertEqual(X.sats_xat(0), "0")
        self.assertEqual(X.CFG["max_supply"], 100_000_000)

    def test_404_renders(self):
        self.assertIn(f"{HRP}1r address", X.page("Not found", X.error_panel("404", f"Try a {HRP}1r address.")))

    def test_api_stats(self):
        d = X.api_stats()
        self.assertEqual(d["charter"]["currency_id"], CHARTER["currency_id"])
        self.assertEqual(d["levy_bp"], 0)
        self.assertEqual(d["hrp"], HRP)
        self.assertEqual(d["chain"], "rehearsal")

    def test_mainnet_profile_copy(self):
        X.CFG["chain"], X.CFG["chain_label"], X.CFG["hrp"] = "mainnet", "Mainnet", "xpa"
        try:
            h = X.view_overview()
        finally:
            X.CFG["chain"], X.CFG["chain_label"], X.CFG["hrp"] = "rehearsal", "Rehearsal chain", HRP
        self.assertIn("xCoin · mainnet", h)
        self.assertIn('class="network-status">Mainnet<', h)
        self.assertNotIn("rehearsal", h.split("<main")[1])
        assert_clean(self, "mainnet overview", h)


class LevyOverride(unittest.TestCase):
    """A test chain with XCOIN_LEVY_BP=5: the levy rows, column and verdicts render."""

    @classmethod
    def setUpClass(cls):
        X.rpc = stub_rpc
        X.web_pool_stats = lambda: {}
        X.CFG["hrp"] = HRP
        X.CFG["chain"], X.CFG["chain_label"] = "rehearsal", "Rehearsal chain"
        X.LEVY_BP = 5
        reindex()

    @classmethod
    def tearDownClass(cls):
        X.LEVY_BP = 0
        reindex()

    LEVY_S1 = "0.02495"       # ceil(5 × 4,990,000,000 / 10,000) = 2,495,000 sat on 49.9 XID out
    LEVY_M1 = "0.0005"        # 50,000 sat on 1 XID out; the pending fee of 0.0001 is below it

    def test_settlement_levy_follows_the_override(self):
        self.assertEqual(X.settlement_levy(10_000), 5)
        self.assertEqual(X.TXMETA["s1"]["levy"], 2_495_000)

    def test_every_page_still_says_xid(self):
        for name, h in every_page():
            assert_clean(self, name, h, levy_allowed=True)

    def test_network_panel_shows_the_rule(self):
        h = X.view_overview()
        self.assertIn("Settlement levy", h)
        self.assertIn("5 bp of every transaction", h)

    def test_block_totals_fee_and_levy(self):
        h = X.view_block("3")
        self.assertIn("Fees / levy", h)
        self.assertIn("0.1 XID paid", h)
        self.assertIn(f"{self.LEVY_S1} XID required by the 5 bp settlement levy", h)

    def test_transaction_shows_levy_required_and_the_verdict(self):
        h = X.view_tx("s1")
        self.assertIn("Fee paid", h)
        self.assertIn("Levy required", h)
        self.assertIn("levy met", h)
        self.assertIn(f"{self.LEVY_S1} XID", h)
        self.assertIn(f"levy {self.LEVY_S1} XID", h)
        self.assertIn("5 bp of the outputs", h)

    def test_coinbase_names_the_levy_exemption(self):
        h = X.view_tx("t2")
        self.assertIn("pays no fee", h)
        self.assertIn("Levy required", h)
        self.assertIn("applies to non-coinbase", h)

    def test_mempool_has_the_levy_column_and_the_pill(self):
        h = X.view_mempool()
        self.assertIn("Levy required", h)
        self.assertIn("levy = 5 bp of the outputs", h)
        self.assertIn(f"{self.LEVY_M1} XID", h)
        self.assertIn("below levy", h)

    def test_api_stats_reports_the_override(self):
        self.assertEqual(X.api_stats()["levy_bp"], 5)


def as_node_json(v):
    """What rpc() hands back for a stub answer: its floats as the Decimals parse_float gives."""
    return json.loads(json.dumps(v), parse_float=Decimal)


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *exc): return False


class ExactAmounts(unittest.TestCase):
    """Node JSON carries amounts in XID. A float holds them exactly only below 2^26 XID
    (67,108,864): from there one float step is more than a sat. rpc() parses them as
    Decimal, and to_sats, sats_xat and xat stay in integers."""

    def test_to_sats_on_parsed_node_json(self):
        self.assertEqual(X.to_sats(json.loads("67108865.00000001", parse_float=Decimal)), 6710886500000001)
        self.assertEqual(X.to_sats(json.loads("67108865.00000002", parse_float=Decimal)), 6710886500000002)
        self.assertEqual(X.to_sats(json.loads("99999999.99999999", parse_float=Decimal)), 9_999_999_999_999_999)
        self.assertEqual(X.to_sats(json.loads("100000000.00000000", parse_float=Decimal)), 10_000_000_000_000_000)
        # The hazard itself: the same text parsed as a float loses the sat.
        self.assertNotEqual(X.to_sats(json.loads("67108865.00000002")), 6710886500000002)
        # Below 2^26 XID a float is still exact.
        self.assertEqual(X.to_sats(json.loads("67108863.99999999")), 6710886399999999)

    def test_rpc_parses_amounts_as_decimal(self):
        body = (b'{"result": {"total_amount": 67108865.00000002, "value": 99999999.99999999, "height": 7},'
                b' "error": null, "id": "exp"}')
        with mock.patch("urllib.request.urlopen", lambda req, timeout=15: _Resp(body)):
            r = REAL_RPC("gettxoutsetinfo")
        self.assertIsInstance(r["total_amount"], Decimal)
        self.assertEqual(X.to_sats(r["total_amount"]), 6710886500000002)
        self.assertEqual(X.to_sats(r["value"]), 9_999_999_999_999_999)
        self.assertEqual(r["height"], 7)

    def test_xat_formats_through_whole_sats(self):
        self.assertEqual(X.xat(Decimal("67108865.00000002")), "67,108,865.00000002")
        self.assertEqual(X.xat(Decimal("99999999.99999999")), "99,999,999.99999999")
        self.assertEqual(X.xat(Decimal("100000000.00000000")), "100,000,000")
        self.assertEqual(X.xat(Decimal("0.11000000")), "0.11")
        self.assertEqual(X.xat(0), "0")
        self.assertEqual(X.xat("12.5"), "12.5")
        self.assertEqual(X.xat(49.9), "49.9")
        self.assertEqual(X.xat("not a number"), "not a number")

    def test_api_json_carries_decimals_as_numbers(self):
        d = json.loads(X.jdump({"supply": Decimal("12.5"), "difficulty": Decimal("1.0"), "n": 3}))
        self.assertEqual(d, {"supply": 12.5, "difficulty": 1.0, "n": 3})
        with self.assertRaises(TypeError):
            X.jdump({"x": object()})


class NodeJsonTypes(unittest.TestCase):
    """The rendering tests again, with every stub answer typed as rpc() types it (Decimal
    amounts), plus a transaction whose outputs sum past 2^26 XID."""

    BIG = {"txid": "big1", "size": 300, "vsize": 300,
           "vin": [{"txid": "t2", "vout": 0, "sequence": 0}],
           "vout": [out(67_108_864.5, SPK_C, ADDR_C, n=0), out(0.50000002, SPK_A, ADDR_A, n=1)]}

    @classmethod
    def setUpClass(cls):
        TXS["big1"] = cls.BIG
        X.rpc = lambda method, params=None: as_node_json(stub_rpc(method, params))
        X.web_pool_stats = lambda: {}
        X.CFG["hrp"] = HRP
        X.CFG["chain"], X.CFG["chain_label"] = "rehearsal", "Rehearsal chain"
        X.LEVY_BP = 0
        reindex()

    @classmethod
    def tearDownClass(cls):
        TXS.pop("big1", None)
        X.rpc = stub_rpc
        reindex()

    def test_every_page_renders(self):
        for name, h in every_page():
            assert_clean(self, name, h)

    def test_a_total_past_2_26_xid_keeps_its_last_sat(self):
        h = X.view_tx("big1")
        self.assertIn("67,108,865.00000002 XID out", h)
        self.assertIn("67,108,864.5 XID", h)
        self.assertIn("0.50000002 XID", h)

    def test_the_api_encodes(self):
        self.assertEqual(json.loads(X.jdump(X.api_stats()))["chain"], "rehearsal")
        self.assertEqual(json.loads(X.jdump(X.api_block("3")))["height"], 3)
        self.assertEqual(json.loads(X.jdump(X.api_network()))["height"], len(BLOCKS) - 1)

    def test_the_block_reward_is_exact(self):
        self.assertEqual(X.tip_subsidy(len(BLOCKS) - 1), Decimal(50))
        self.assertIn(">50<", X.view_overview())


if __name__ == "__main__":
    unittest.main(verbosity=2)
