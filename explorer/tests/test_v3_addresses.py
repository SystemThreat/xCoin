#!/usr/bin/env python3
"""Pins the explorer's witness v3 helpers to the chain's own vectors.

Every expected value here comes from a source of truth outside this file:

  - xcoin-regenesis/src/test/xcoin_v3_tests.cpp        leaf and branch hashes
  - xcoin-regenesis/contrib/regenesis/REGENESIS.md     sections 3, 4 and 6
  - xcoin-regenesis/contrib/regenesis/carry_v3_vector.json  the carry conversion
  - x-Coin/wallet-cli-regenesis/wallet_cli.py          the same Python arithmetic
  - x-Coin/nerdminer-regenesis/Tests/.../XcoinAddressTests.swift  the same in Swift

The founder's payout key is the pinned end-to-end case: the witness v2
string xpa1z59v2c5z... must map to the witness v3 string xpa1rt682c5q... on mainnet
and txa1rt682c5q... on the rehearsal chain, through the single-leaf 0xc0 conversion.

Run:  python3 -m unittest discover -s tests -v        (from the explorer directory)
"""
import importlib.util, json, os, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("xcoin_explorer", os.path.join(ROOT, "xcoin-explorer.py"))
X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(X)

# The shared vector file in the node worktree, when it is there (read-only).
CARRY_VECTOR = os.path.join(os.path.dirname(ROOT), "xcoin-regenesis",
                            "contrib", "regenesis", "carry_v3_vector.json")

FOUNDER_V2_MAIN = "xpa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5sdnc0av"
FOUNDER_V3_MAIN = "xpa1rt682c5qx4vqdjed0jvws2q2fjtjuxhs3r2fm9k9dp9ezlwv5m68s5w4dn0"
FOUNDER_V2_REHEARSAL = "txa1z59v2c5z8s3dlmmdddchrup6t9wkr8nh6w3qtdvat5e5tgz7chn5s03pnlk"
FOUNDER_V3_REHEARSAL = "txa1rt682c5qx4vqdjed0jvws2q2fjtjuxhs3r2fm9k9dp9ezlwv5m68skvv334"
FOUNDER_KEY_HASH = "a158ac5047845bfdedad6e2e3e074b2bac33cefa7440b6b3aba668b40bd8bce9"
FOUNDER_V3_ROOT = "5e8eac5006ab00d965af931d05014992e5c35e111a93b2d8ad09722fb994de8f"
FOUNDER_V2_SCRIPT = "5220" + FOUNDER_KEY_HASH
FOUNDER_V3_SCRIPT = "5320" + FOUNDER_V3_ROOT

VECTOR_KEY_HASH = bytes(range(1, 33))
VECTOR_V2_MAIN = "xpa1zqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqaww8gc"
VECTOR_V3_MAIN = "xpa1r2qm3c2fklzla5pwxjg52l7urzxwxs7kc53mmrgvt6qwq535fqttqmrh23s"
VECTOR_V3_REHEARSAL = "txa1r2qm3c2fklzla5pwxjg52l7urzxwxs7kc53mmrgvt6qwq535fqttqepwkn2"


class TaggedHashing(unittest.TestCase):
    def test_nokey_marker_is_plain_sha256_of_the_tag(self):
        self.assertEqual(X.XCOIN_V3_NOKEY.hex(),
                         "54b62806c9e55d19448216fc3426a3a04466fbc59c18238795cbbc9003330a65")

    def test_leaf_and_branch_vectors(self):
        s1 = X.key32_checksig_script(VECTOR_KEY_HASH)
        self.assertEqual(s1.hex(), "200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20ac")
        l1 = X.leaf_hash(X.XCOIN_LEAF_PQ, s1)
        self.assertEqual(l1.hex(), "50371c2936f8bfda05c69228affb83119c687ad8a477b1a18bd01c0a468902d6")
        l2 = X.leaf_hash(X.XCOIN_LEAF_PQ, b"")
        self.assertEqual(l2.hex(), "e3bb8e8060cd8ae48c5e91228aa5c257cd5bb80ae1cf853f4dec66a042b1c2f9")
        l3 = X.leaf_hash(X.XCOIN_LEAF_SLH, b"\x51")
        self.assertEqual(l3.hex(), "cb25e1b1ec8b174d327f1e6466c018383dd0e23860f6805cab1738dd65922adf")
        b12 = X.branch_hash(l1, l2)
        self.assertEqual(b12.hex(), "2339dd5ab68ae3ec676b327297e620ce7f2f7e7eb594be396a12ce600df76845")
        self.assertEqual(X.branch_hash(l2, l1), b12, "branch hashing sorts its inputs")
        self.assertEqual(X.branch_hash(b12, l3).hex(),
                         "44546098ecf80a10fbf7441c650152021a8f099a8eb816d80a04e0f01df60687")
        # A one-leaf tree's root IS the leaf hash: that is the whole carry conversion.
        self.assertEqual(X.carried_program(VECTOR_KEY_HASH), l1)

    def test_compact_size(self):
        self.assertEqual(X.compact_size(34), b"\x22")
        self.assertEqual(X.compact_size(252), b"\xfc")
        self.assertEqual(X.compact_size(253), b"\xfd\xfd\x00")
        self.assertEqual(X.compact_size(0x1234), b"\xfd\x34\x12")
        self.assertEqual(X.compact_size(0x10000), b"\xfe\x00\x00\x01\x00")


class FounderConversionVector(unittest.TestCase):
    """The pinned end-to-end case (REGENESIS.md section 3, 'carry as v3')."""

    def test_v2_address_decodes_to_the_key_hash(self):
        hrp, ver, prog = X.bech32m_decode(FOUNDER_V2_MAIN)
        self.assertEqual((hrp, ver, prog.hex()), ("xpa", 2, FOUNDER_KEY_HASH))

    def test_single_leaf_root(self):
        self.assertEqual(X.carried_program(bytes.fromhex(FOUNDER_KEY_HASH)).hex(), FOUNDER_V3_ROOT)

    def test_mainnet_conversion(self):
        conv = X.convert_v1_address(FOUNDER_V2_MAIN)
        self.assertEqual(conv["v3"], FOUNDER_V3_MAIN)
        self.assertEqual(conv["key_hash"], FOUNDER_KEY_HASH)
        self.assertEqual(conv["program"], FOUNDER_V3_ROOT)
        self.assertEqual(conv["v1_script"], FOUNDER_V2_SCRIPT)
        self.assertEqual(conv["v3_script"], FOUNDER_V3_SCRIPT)

    def test_rehearsal_conversion(self):
        self.assertEqual(X.convert_v1_address(FOUNDER_V2_REHEARSAL)["v3"], FOUNDER_V3_REHEARSAL)
        self.assertEqual(X.convert_v1_address(FOUNDER_V2_MAIN, hrp="txa")["v3"], FOUNDER_V3_REHEARSAL)

    def test_a_v3_address_is_not_convertible(self):
        self.assertIsNone(X.convert_v1_address(FOUNDER_V3_MAIN))
        self.assertIsNone(X.convert_v1_address("not an address"))
        self.assertTrue(X.is_v1_address(FOUNDER_V2_MAIN))
        self.assertFalse(X.is_v1_address(FOUNDER_V3_MAIN))
        self.assertTrue(X.is_v3_address(FOUNDER_V3_MAIN))
        self.assertTrue(X.is_v3_address(FOUNDER_V3_REHEARSAL))

    def test_node_vector_key_hash(self):
        self.assertEqual(X.bech32m_encode("xpa", 2, VECTOR_KEY_HASH), VECTOR_V2_MAIN)
        self.assertEqual(X.convert_v1_address(VECTOR_V2_MAIN)["v3"], VECTOR_V3_MAIN)
        self.assertEqual(X.convert_v1_address(VECTOR_V2_MAIN, hrp="txa")["v3"], VECTOR_V3_REHEARSAL)

    @unittest.skipUnless(os.path.exists(CARRY_VECTOR), "carry_v3_vector.json not present")
    def test_recomputes_the_shared_carry_vector(self):
        """Recompute every case in the node's own shared vector file."""
        with open(CARRY_VECTOR, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["leaf_tag"], X.XCOIN_V3_LEAF_TAG.decode())
        self.assertEqual(data["branch_tag"], X.XCOIN_V3_BRANCH_TAG.decode())
        self.assertEqual(data["nokey_marker"], X.XCOIN_V3_NOKEY.hex())
        self.assertTrue(data["cases"])
        for case in data["cases"]:
            kh = bytes.fromhex(case["key_hash"])
            self.assertEqual(case["leaf_version"], X.XCOIN_LEAF_PQ)
            self.assertEqual(X.key32_checksig_script(kh).hex(), case["leaf_script_hex"])
            self.assertEqual(X.script_for_program(2, kh).hex(), case["v2_script_hex"])
            prog = X.carried_program(kh)
            self.assertEqual(prog.hex(), case["v3_program"])
            self.assertEqual(X.script_for_program(3, prog).hex(), case["v3_script_hex"])
            self.assertEqual(X.bech32m_encode(data["hrp_main"], 2, kh), case["v2_address_main"])
            self.assertEqual(X.bech32m_encode(data["hrp_main"], 3, prog), case["v3_address_main"])
            self.assertEqual(X.bech32m_encode(data["hrp_rehearsal"], 2, kh), case["v2_address_rehearsal"])
            self.assertEqual(X.bech32m_encode(data["hrp_rehearsal"], 3, prog), case["v3_address_rehearsal"])
            self.assertEqual(X.convert_v1_address(case["v2_address_main"])["v3"], case["v3_address_main"])


class Bech32m(unittest.TestCase):
    def test_round_trip_and_case(self):
        self.assertEqual(X.bech32m_decode(FOUNDER_V3_MAIN.upper()), X.bech32m_decode(FOUNDER_V3_MAIN))
        self.assertIsNone(X.bech32m_decode("Xpa1r" + FOUNDER_V3_MAIN[5:]), "mixed case is not an address")

    def test_rejects_damage(self):
        bad = list(FOUNDER_V3_MAIN)
        bad[10] = "p" if bad[10] == "q" else "q"
        self.assertIsNone(X.bech32m_decode("".join(bad)))
        self.assertIsNone(X.bech32m_decode(""))
        self.assertIsNone(X.bech32m_decode("xpa1rb" + FOUNDER_V3_MAIN[6:]), "'b' is not a bech32 character")
        # witness v0 is bech32, not bech32m
        self.assertIsNone(X.bech32m_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))


class ScriptDecoding(unittest.TestCase):
    def test_script_for_program(self):
        self.assertEqual(X.script_for_program(3, bytes.fromhex(FOUNDER_V3_ROOT)).hex(), FOUNDER_V3_SCRIPT)
        self.assertEqual(X.script_for_program(2, bytes.fromhex(FOUNDER_KEY_HASH)).hex(), FOUNDER_V2_SCRIPT)

    def test_address_from_script_hex(self):
        self.assertEqual(X.address_from_spk_hex(FOUNDER_V3_SCRIPT, "xpa"), FOUNDER_V3_MAIN)
        self.assertEqual(X.address_from_spk_hex(FOUNDER_V3_SCRIPT, "txa"), FOUNDER_V3_REHEARSAL)
        self.assertEqual(X.address_from_spk_hex(FOUNDER_V2_SCRIPT, "xpa"), FOUNDER_V2_MAIN)
        self.assertIsNone(X.address_from_spk_hex("6a4c0568656c6c6f", "xpa"), "OP_RETURN is not an address")
        self.assertIsNone(X.address_from_spk_hex("zz", "xpa"))

    def test_v3_program_of(self):
        self.assertEqual(X.v3_program_of(FOUNDER_V3_MAIN).hex(), FOUNDER_V3_ROOT)
        self.assertIsNone(X.v3_program_of(FOUNDER_V2_MAIN))

    def test_decode_a_single_leaf_spend(self):
        """The carried spend path: [pubkey, sig, leaf script, control block] with an empty path."""
        script = X.key32_checksig_script(bytes.fromhex(FOUNDER_KEY_HASH))
        control = bytes([X.XCOIN_LEAF_PQ]) + X.XCOIN_V3_NOKEY
        w = X.decode_v3_witness(["aa" * 1952, "bb" * 3309, script.hex(), control.hex()])
        self.assertEqual(w["leaf_version"], 0xc0)
        self.assertTrue(w["single_leaf"])
        self.assertEqual(w["depth"], 0)
        self.assertEqual(w["root"], FOUNDER_V3_ROOT, "a one-leaf tree's root is its leaf hash")

    def test_decode_a_two_leaf_spend(self):
        pq = X.key32_checksig_script(bytes.fromhex(FOUNDER_KEY_HASH))
        slh_leaf = X.leaf_hash(X.XCOIN_LEAF_SLH, X.key32_checksig_script(bytes(32)))
        control = bytes([X.XCOIN_LEAF_PQ]) + X.XCOIN_V3_NOKEY + slh_leaf
        w = X.decode_v3_witness(["aa" * 1952, "bb" * 3309, pq.hex(), control.hex()])
        self.assertFalse(w["single_leaf"])
        self.assertEqual(w["depth"], 1)
        self.assertEqual(w["root"], X.branch_hash(X.leaf_hash(X.XCOIN_LEAF_PQ, pq), slh_leaf).hex())

    def test_refuses_a_control_block_without_the_marker(self):
        script = X.key32_checksig_script(bytes.fromhex(FOUNDER_KEY_HASH))
        self.assertIsNone(X.decode_v3_witness([script.hex(), (bytes([0xc0]) + bytes(32)).hex()]))
        self.assertIsNone(X.decode_v3_witness([]))


class SettlementLevy(unittest.TestCase):
    """ceil(bp × outputs / 10,000) satoshis, integer arithmetic. The chain's rule is 0 bp
    (the module default), so the arithmetic is pinned at an explicit 5 bp."""

    def test_the_default_is_the_chains_rule(self):
        self.assertEqual(X.LEVY_BP, int(os.environ.get("XCOIN_LEVY_BP", "0") or 0))
        self.assertEqual(X.settlement_levy(10_000, bp=0), 0)
        self.assertEqual(X.settlement_levy(10_000), X.settlement_levy(10_000, bp=X.LEVY_BP))

    def test_zero_and_negative(self):
        self.assertEqual(X.settlement_levy(0, bp=5), 0)
        self.assertEqual(X.settlement_levy(-1, bp=5), 0)

    def test_rounds_up(self):
        self.assertEqual(X.settlement_levy(1, bp=5), 1)          # ceil(5 / 10,000)
        self.assertEqual(X.settlement_levy(1999, bp=5), 1)       # ceil(9,995 / 10,000)
        self.assertEqual(X.settlement_levy(2000, bp=5), 1)       # exactly 1
        self.assertEqual(X.settlement_levy(2001, bp=5), 2)
        self.assertEqual(X.settlement_levy(10_000, bp=5), 5)
        self.assertEqual(X.settlement_levy(100_000_000, bp=5), 50_000)   # 1 XCF -> 0.0005 XCF

    def test_matches_the_definition_on_a_wide_range(self):
        for bp in (1, 5, 250):
            for out in (1, 7, 999, 1234567, 10**8, 76_650 * 10**8, 21_000_000 * 10**8):
                self.assertEqual(X.settlement_levy(out, bp=bp), -(-out * bp // X.LEVY_DENOMINATOR))


class SearchRouting(unittest.TestCase):
    """The search box: a witness v2 string never 404s, it maps."""

    def test_v1_string_maps_to_its_v3_address(self):
        dest, _ = X.route_search(FOUNDER_V2_MAIN)
        self.assertEqual(dest, f"/address/{FOUNDER_V3_MAIN}?from={FOUNDER_V2_MAIN}")

    def test_v3_string_goes_straight_through(self):
        self.assertEqual(X.route_search(FOUNDER_V3_REHEARSAL)[0], f"/address/{FOUNDER_V3_REHEARSAL}")

    def test_height(self):
        self.assertEqual(X.route_search("1")[0], "/block/1")
        self.assertEqual(X.route_search("  ")[0], "/")


if __name__ == "__main__":
    unittest.main(verbosity=2)
