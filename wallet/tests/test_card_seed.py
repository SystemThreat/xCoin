#!/usr/bin/env python3
"""Card-bound wallet tests — all against the simulated NTAG 424 DNA, no hardware.

Covers the .mmm v2 format, the full provision -> read_seed -> decrypt loop, the
two-factor property (disk alone / card alone are useless), wrong-card rejection,
duplicate-card backup, and the invariant that a card wallet never reveals its seed.
"""

import io, json, os, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import card_seed as cs
import wallet_cli as w

class FakeReaderTransport(cs.SimTransport):
    """SimTransport but with the wait/close interface the wallet drives."""
    def wait_for_card(self, timeout=30, prompt=False): pass

def fresh_factory_card():
    return cs.SimNTAG424()

class CardHarness(unittest.TestCase):
    """Routes card_seed's PCSCTransport to an in-memory factory card, and pins
    ~/.xcoin auth dir to a temp dir."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        os.environ.pop("XCOIN_WALLET_PASSPHRASE", None)
        self.card = fresh_factory_card()
        self._real_pcsc = cs.PCSCTransport
        self._real_authdir = cs.AUTH_DIR
        cs.AUTH_DIR = Path(self.tmp.name)
        harness = self
        def make_transport(): return FakeReaderTransport(harness.card)
        cs.PCSCTransport = make_transport
        self.addCleanup(self._restore)
    def _restore(self):
        cs.PCSCTransport = self._real_pcsc
        cs.AUTH_DIR = self._real_authdir
    def use_card(self, card): self.card = card

class TestMmm2Format(unittest.TestCase):
    def test_roundtrip(self):
        seed = "ab" * 32
        factor = os.urandom(32); fam = cs.family_of(factor)
        blob = w.mmm2_encode(seed, factor, fam)
        self.assertTrue(blob.startswith(w.MMM2_MAGIC))
        self.assertEqual(w.mmm2_family(blob), fam)
        self.assertNotIn(bytes.fromhex(seed), blob)
        self.assertEqual(w.mmm2_decode(blob, factor), seed)
    def test_wrong_card_factor_fails(self):
        blob = w.mmm2_encode("cd" * 32, os.urandom(32), "0" * 16)
        with self.assertRaisesRegex(w.WalletError, "wrong card"):
            w.mmm2_decode(blob, os.urandom(32))
    def test_passphrase_second_factor(self):
        seed, factor = "ef" * 32, os.urandom(32)
        blob = w.mmm2_encode(seed, factor, cs.family_of(factor), "pw")
        self.assertEqual(w.mmm2_decode(blob, factor, "pw"), seed)
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(blob, factor, "wrong")
    def test_tamper_detected(self):
        factor = os.urandom(32)
        blob = bytearray(w.mmm2_encode("ab" * 32, factor, cs.family_of(factor)))
        blob[60] ^= 1
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(bytes(blob), factor)

class TestCardProvisioning(CardHarness):
    def test_provision_read_roundtrip(self):
        factor = cs.SecureBuffer(os.urandom(32))
        fam = cs.family_of(factor.bytes())
        t = cs.PCSCTransport()
        rec = cs.provision_card(t, factor, fam, label="primary")  # saves auth itself
        # factory keys are gone now; a fresh factory card would NOT read
        t2 = cs.PCSCTransport()
        got, auth = cs.read_factor(t2)
        try:
            self.assertEqual(got.bytes(), factor.bytes())
            self.assertEqual(auth["uid"], rec["uid"])
        finally:
            got.close(); factor.close()
    def test_unprovisioned_card_has_no_auth(self):
        t = cs.PCSCTransport()
        with self.assertRaisesRegex(cs.CardError, "not provisioned"):
            cs.read_factor(t)
    def test_factory_reset_wipes(self):
        factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), factor, cs.family_of(factor.bytes()))
        uid = cs.factory_reset_card(cs.PCSCTransport())
        self.assertEqual(uid, rec["uid"])
        # factor field on the card is zeroed
        self.assertEqual(self.card.files[cs.CARD_FILE][:32], bytearray(32))
        factor.close()

class TestCardWalletCLI(CardHarness):
    def run_cli(self, wallet, *argv, card=None):
        if card is not None: self.use_card(card)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

    def test_new_card_then_unlock(self):
        wallet = Path(self.tmp.name) / "wallet001.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline")
        self.assertEqual(rc, 0)
        self.assertTrue(w.is_card_wallet(wallet))
        # seed was never printed
        blob = wallet.read_bytes()
        self.assertTrue(blob.startswith(w.MMM2_MAGIC))
        # unlock: read_seed must tap the (same) provisioned card and return a valid seed
        seed = w.read_seed(wallet)
        self.assertTrue(w._valid_seed(seed))
        # and it must be stable (same card -> same seed)
        self.assertEqual(seed, w.read_seed(wallet))

    def test_disk_alone_is_useless(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        blob = wallet.read_bytes()
        # a random factor (attacker without the card) cannot decrypt
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(blob, os.urandom(32))

    def test_wrong_card_rejected(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        # provision a DIFFERENT card (different factor/family) and try to unlock
        other = fresh_factory_card()
        self.use_card(other)
        other_factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), other_factor, cs.family_of(other_factor.bytes()))
        other_factor.close()
        with self.assertRaisesRegex(w.WalletError, "family mismatch"):
            w.read_seed(wallet)

    def test_seed_reveal_refused(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "seed", "--yes")
        self.assertEqual(rc, 1)
        self.assertNotIn("Seed:", out)
        rc, out = self.run_cli(wallet, "--json", "seed", "--yes")
        self.assertEqual(rc, 1)

    def test_encrypt_refused_on_card_wallet(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "encrypt")
        self.assertEqual(rc, 1)

    def test_backup_card_duplicate_unlocks(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        primary_seed = w.read_seed(wallet)
        # card-backup taps the primary (read factor), then a factory card.
        # Simulate the two taps by swapping the active card at the input() point.
        backup_card = fresh_factory_card()
        import builtins
        real_input = builtins.input
        def fake_input(prompt=""):
            self.use_card(backup_card)   # step 2: place the factory card
            return ""
        builtins.input = fake_input
        try:
            rc, out = self.run_cli(wallet, "card-backup")
        finally:
            builtins.input = real_input
        self.assertEqual(rc, 0)
        # the backup card must now unlock the SAME wallet to the SAME seed
        self.use_card(backup_card)
        self.assertEqual(w.read_seed(wallet), primary_seed)

    def test_card_list_and_test(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "--json", "card-list")
        rows = json.loads(out)
        self.assertEqual(len(rows), 1)
        rc, out = self.run_cli(wallet, "--json", "card-test")
        self.assertTrue(json.loads(out)["ok"])

class TestPermanentCards(CardHarness):
    def run_cli(self, wallet, *argv, card=None):
        if card is not None: self.use_card(card)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

    def test_default_is_permanent(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline")
        self.assertEqual(rc, 0)
        rec = json.loads(list(Path(self.tmp.name).glob("card-*.auth"))[0].read_text())
        self.assertTrue(rec["permanent"])
        self.assertNotIn("master_key", rec)   # master discarded (no reset/re-key)
        self.assertNotIn("write_key", rec)    # write key discarded (factor immutable)
        self.assertIn("read_key", rec)        # read-only key kept (needed to unlock)
        # still unlocks
        self.assertTrue(w._valid_seed(w.read_seed(wallet)))

    def test_permanent_card_cannot_be_reset(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "card-reset", "--yes")
        self.assertEqual(rc, 1)
        with self.assertRaisesRegex(cs.CardError, "PERMANENTLY"):
            cs.factory_reset_card(cs.PCSCTransport())

    def test_resettable_opt_out_keeps_keys(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline", "--resettable")
        self.assertEqual(rc, 0)
        rec = json.loads(list(Path(self.tmp.name).glob("card-*.auth"))[0].read_text())
        self.assertFalse(rec["permanent"])
        self.assertIn("master_key", rec); self.assertIn("write_key", rec); self.assertIn("read_key", rec)
        # and CAN be reset
        uid = cs.factory_reset_card(cs.PCSCTransport())
        self.assertEqual(uid, rec["uid"])

    def test_make_permanent_helper(self):
        factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), factor, cs.family_of(factor.bytes()))
        factor.close()
        self.assertIn("master_key", json.loads(cs.auth_path(rec["uid"]).read_text()))
        cs.make_permanent(rec["uid"])
        sealed = json.loads(cs.auth_path(rec["uid"]).read_text())
        self.assertTrue(sealed["permanent"])
        self.assertNotIn("master_key", sealed); self.assertNotIn("write_key", sealed)
        self.assertIn("read_key", sealed)

class TestSecureBuffer(unittest.TestCase):
    def test_zeroized_on_close(self):
        b = cs.SecureBuffer(b"secretseed")
        self.assertEqual(b.bytes(), b"secretseed")
        b.close()
        self.assertEqual(b.bytes(), b"")
    def test_context_manager(self):
        with cs.SecureBuffer(b"x" * 32) as b:
            self.assertEqual(len(b.bytes()), 32)

if __name__ == "__main__":
    unittest.main(verbosity=2)
