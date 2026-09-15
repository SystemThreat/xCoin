#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""xCoin witness v3 wallet (contrib/regenesis/REGENESIS.md section 4, stage B3).

On a fresh regtest chain with the re-genesis rules:
- the wallet hands out witness v3 (pqtr) addresses by default (nxrt1r... on
  regtest, xpa1r... on mainnet) and never the same one twice; the legacy
  witness v2 type (nxrt1z...) is handed out, and paid, only on a node started
  with -permitv2outputs=1 (audit finding T9), and stays spendable regardless;
- getaddressinfo / validateaddress / decodescript understand the addresses;
- coins mined to a v3 address are spent through the ML-DSA-65 leaf;
- a legacy v2 coin is spent with `send` into a fresh v3 address;
- the SLH-DSA-SHA2-128s fallback leaf is spent with descriptorprocesspsbt and
  an explicit pqtr() descriptor that carries only the SLH key;
- the mempool accepts an 80-byte OP_RETURN scriptPubKey and rejects 81 bytes;
- listdescriptors exports the derived post-quantum public keys so a wallet
  without private keys imports them and watches the same addresses;
- an import that carries a literal post-quantum private key is refused;
- a locked encrypted wallet says so when its pre-derived addresses run out,
  and refills on unlock.
"""

from decimal import Decimal
import re

from test_framework.address import xcoin_bech32_to_bytes
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

MLDSA_PUBKEY_SIZE = 1952
MLDSA_SIGNATURE_SIZE = 3309
SLH_SIGNATURE_SIZE = 7856
LEAF_SCRIPT_SIZE = 34          # <key32> OP_CHECKSIG
CONTROL_BLOCK_SIZE_2_LEAVES = 65  # version || nokey marker || one sibling hash
SETTLEMENT_LEVY_BP = 5         # REGENESIS.md section 6


def settlement_levy(amount):
    """The levy a transaction paying `amount` out owes: ceil(amount * 5 / 10000)."""
    sats = int(amount * COIN)
    return Decimal(-(-sats * SETTLEMENT_LEVY_BP // 10000)) / COIN


def witness_sizes(node, txid):
    tx = node.getrawtransaction(txid, True)
    return [[len(w) // 2 for w in vin["txinwitness"]] for vin in tx["vin"]]


class XcoinV3WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # The framework's cached chain mines to P2PKH, which the PQ-only output
        # rule rejects; start from the genesis block instead.
        self.setup_clean_chain = True
        # This test mines block 1 itself (below), so the framework must not.
        # -levybp=5: the chain ships without a levy (REGENESIS.md section 6); this
        # test enables the dormant machinery at the reference rate so the wallet's
        # levy path is exercised and measured. The inherited suite runs without it.
        # -permitv2outputs=1: the node relays and mines new witness v2 outputs, so the
        # wallet hands out and pays v2 addresses; the last section restarts without it.
        self.extra_args = [["-fallbackfee=0.0001", "-txindex=1", "-levybp=5", "-permitv2outputs=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getmempoolinfo()["permitv2outputs"], True)
        node.createwallet(wallet_name="w", load_on_startup=True)
        w = node.get_wallet_rpc("w")
        node.createwallet(wallet_name="miner")
        miner = node.get_wallet_rpc("miner")
        mine_to = miner.getnewaddress()
        assert mine_to.startswith("nxrt1r")

        self.log.info("Addresses: v3 by default, v2 on request, decoded by the node")
        a3 = w.getnewaddress()
        assert a3.startswith("nxrt1r"), a3
        version, program = xcoin_bech32_to_bytes(a3)
        assert_equal(version, 3)
        assert_equal(len(program), 32)
        info = w.getaddressinfo(a3)
        assert_equal(info["ismine"], True)
        assert_equal(info["solvable"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 3)
        assert_equal(info["witness_program"], program.hex())
        assert_equal(info["ispq"], True)
        assert info["desc"].startswith("pqtr({"), info["desc"]
        assert "pq(" in info["desc"] and "slh(" in info["desc"], info["desc"]
        assert info["parent_desc"].startswith("pqtr({pq("), info["parent_desc"]
        # Siblings are listed in leaf-hash order (a control block has no left/right), so sort.
        leaves = sorted(info["xcoin_v3_leaves"], key=lambda leaf: leaf["leaf_version"])
        assert_equal([leaf["leaf_version"] for leaf in leaves], [0xc0, 0xc2])
        assert_equal([leaf["algorithm"] for leaf in leaves], ["ml-dsa-65", "slh-dsa-sha2-128s"])
        assert_equal([leaf["depth"] for leaf in leaves], [1, 1])
        assert_equal(len(leaves[0]["pubkey"]), 2 * MLDSA_PUBKEY_SIZE)
        assert_equal(len(leaves[1]["pubkey"]), 64)
        assert_equal(info["scriptPubKey"], "5320" + program.hex())
        va = node.validateaddress(a3)
        assert_equal(va["isvalid"], True)
        assert_equal(va["witness_version"], 3)
        assert_equal(va["ispq"], True)
        ds = node.decodescript(info["scriptPubKey"])
        assert_equal(ds["type"], "witness_v3_pq")
        assert_equal(ds["address"], a3)
        assert "segwit" not in ds  # a witness program is never wrapped again

        a2 = w.getnewaddress("", "xcoin-v2")
        assert a2.startswith("nxrt1z"), a2
        info2 = w.getaddressinfo(a2)
        assert_equal(info2["witness_version"], 2)
        assert_equal(info2["ismine"], True)
        assert_equal(info2["pubkey_algorithm"], "ml-dsa-65")
        assert_equal(len(info2["pubkey"]), 2 * MLDSA_PUBKEY_SIZE)
        assert info2["desc"].startswith("pq("), info2["desc"]
        assert_raises_rpc_error(-5, "Unknown address type", w.getnewaddress, "", "bech32x")

        self.log.info("Address reuse: the wallet never hands out the same v3 address twice")
        fresh = [w.getnewaddress() for _ in range(30)]
        assert all(a.startswith("nxrt1r") for a in fresh)
        assert_equal(len(set(fresh)), 30)
        assert a3 not in fresh
        change = [w.getrawchangeaddress() for _ in range(5)]
        assert all(a.startswith("nxrt1r") for a in change)
        assert_equal(len(set(change) | set(fresh) | {a3}), 36)

        self.log.info("Mine: block 1 pays the regtest distribution; then one block to v3, one to v2, then maturity")
        self.generatetoaddress(node, 1, mine_to)
        self.generatetoaddress(node, 1, a3)
        self.generatetoaddress(node, 1, a2)
        self.generatetoaddress(node, 100, mine_to)
        assert_equal(node.getblockcount(), 103)
        balances = w.getbalances()["mine"]
        assert_equal(balances["trusted"], Decimal(100))
        unspent = w.listunspent()
        assert_equal({u["address"] for u in unspent}, {a3, a2})
        utxo3 = next(u for u in unspent if u["address"] == a3)
        utxo2 = next(u for u in unspent if u["address"] == a2)
        assert_equal(utxo3["amount"], Decimal(50))

        self.log.info("Spend the v3 coin through the ML-DSA-65 leaf")
        payee = w.getnewaddress()
        res = w.send(outputs=[{payee: 10}], options={"inputs": [{"txid": utxo3["txid"], "vout": utxo3["vout"]}], "add_inputs": False})
        assert_equal(res["complete"], True)
        txid3 = res["txid"]
        assert txid3 in node.getrawmempool()
        assert_equal(witness_sizes(node, txid3), [[MLDSA_PUBKEY_SIZE, MLDSA_SIGNATURE_SIZE, LEAF_SCRIPT_SIZE, CONTROL_BLOCK_SIZE_2_LEAVES]])
        tx3 = node.getrawtransaction(txid3, True)
        assert_equal({o["scriptPubKey"]["type"] for o in tx3["vout"]}, {"witness_v3_pq"})
        self.generatetoaddress(node, 1, mine_to)
        assert_equal(w.gettransaction(txid3)["confirmations"], 1)

        self.log.info("Spend the legacy v2 coin into a fresh v3 address")
        v2_dest = w.getnewaddress()
        assert v2_dest.startswith("nxrt1r"), v2_dest
        res2 = w.send(outputs=[{v2_dest: utxo2["amount"]}],
                      options={"inputs": [{"txid": utxo2["txid"], "vout": utxo2["vout"]}], "add_inputs": False,
                               "subtract_fee_from_outputs": [0]})
        assert_equal(res2["complete"], True)
        assert_equal(witness_sizes(node, res2["txid"]), [[MLDSA_SIGNATURE_SIZE + 1, MLDSA_PUBKEY_SIZE]])
        tx2 = node.getrawtransaction(res2["txid"], True)
        assert_equal(len(tx2["vout"]), 1)
        assert_equal(tx2["vout"][0]["scriptPubKey"]["address"], v2_dest)
        assert_greater_than(utxo2["amount"], tx2["vout"][0]["value"])
        self.generatetoaddress(node, 1, mine_to)
        assert not any(u["address"].startswith("nxrt1z") for u in w.listunspent(0))
        # Paying a v2 address is allowed on this node ...
        v2_paid = w.sendtoaddress(a2, 1)
        self.generatetoaddress(node, 1, mine_to)
        assert_equal(w.gettransaction(v2_paid)["confirmations"], 1)
        assert_equal([u["address"] for u in w.listunspent() if u["address"].startswith("nxrt1z")], [a2])

        self.log.info("Spend the SLH-DSA-SHA2-128s fallback leaf with descriptorprocesspsbt")
        seed_pq = "11" * 32
        seed_slh = "22" * 48
        priv_desc = descsum_create(f"pqtr({{pq({seed_pq}),slh({seed_slh})}})")
        desc_info = node.getdescriptorinfo(priv_desc)
        assert_equal(desc_info["hasprivatekeys"], True)
        assert_equal(desc_info["isrange"], False)
        pub_desc = desc_info["descriptor"]
        pub_pq = re.search(r"pq\(([0-9a-f]+)\)", pub_desc).group(1)
        assert_equal(len(pub_pq), 2 * MLDSA_PUBKEY_SIZE)
        assert_equal(len(re.search(r"slh\(([0-9a-f]+)\)", pub_desc).group(1)), 64)
        tree_addr = node.deriveaddresses(pub_desc)[0]
        assert tree_addr.startswith("nxrt1r"), tree_addr
        fund_txid = w.sendtoaddress(tree_addr, 5)
        self.generatetoaddress(node, 1, mine_to)
        scan = node.scantxoutset("start", [f"addr({tree_addr})"])
        assert_equal(len(scan["unspents"]), 1)
        tree_utxo = scan["unspents"][0]
        assert_equal(tree_utxo["txid"], fund_txid)
        dest = w.getnewaddress()
        psbt = node.createpsbt([{"txid": tree_utxo["txid"], "vout": tree_utxo["vout"]}], [{dest: Decimal("4.99")}])
        psbt = node.utxoupdatepsbt(psbt)
        # Only the SLH-DSA private key: the signer must take the fallback leaf.
        slh_only_desc = descsum_create(f"pqtr({{pq({pub_pq}),slh({seed_slh})}})")
        signed = node.descriptorprocesspsbt(psbt, [slh_only_desc])
        assert_equal(signed["complete"], True)
        fallback_txid = node.sendrawtransaction(signed["hex"])
        assert_equal(witness_sizes(node, fallback_txid), [[SLH_SIGNATURE_SIZE, LEAF_SCRIPT_SIZE, CONTROL_BLOCK_SIZE_2_LEAVES]])
        self.generatetoaddress(node, 1, mine_to)
        assert_equal(w.gettransaction(fallback_txid)["confirmations"], 1)
        # With every key the same tree is spent through the (smaller) ML-DSA leaf.
        fund2 = w.sendtoaddress(tree_addr, 3)
        self.generatetoaddress(node, 1, mine_to)
        tree_utxo2 = next(u for u in node.scantxoutset("start", [f"addr({tree_addr})"])["unspents"] if u["txid"] == fund2)
        psbt2 = node.utxoupdatepsbt(node.createpsbt([{"txid": tree_utxo2["txid"], "vout": tree_utxo2["vout"]}], [{dest: Decimal("2.99")}]))
        signed2 = node.descriptorprocesspsbt(psbt2, [priv_desc])
        assert_equal(signed2["complete"], True)
        mldsa_txid = node.sendrawtransaction(signed2["hex"])
        assert_equal(witness_sizes(node, mldsa_txid), [[MLDSA_PUBKEY_SIZE, MLDSA_SIGNATURE_SIZE, LEAF_SCRIPT_SIZE, CONTROL_BLOCK_SIZE_2_LEAVES]])
        self.generatetoaddress(node, 1, mine_to)

        self.log.info("OP_RETURN policy: an 80-byte data-carrier scriptPubKey relays, 81 bytes do not")
        assert_equal(node.getmempoolinfo()["maxdatacarriersize"], 80)
        utxo = next(u for u in w.listunspent() if u["amount"] >= 10)
        # The fee is derived, not fixed: the settlement levy (REGENESIS.md
        # section 6) is ceil(outputs * 5 / 10000), so a flat 0.01 stops
        # clearing it as soon as the coin is worth more than 20 XCF and the
        # transaction is rejected as "bad-txns-levy" before policy is reached.
        fee = max(Decimal("0.01"), settlement_levy(utxo["amount"] - Decimal("0.01")))
        change_amount = utxo["amount"] - fee
        assert_greater_than_or_equal(fee, settlement_levy(change_amount))
        for data_bytes, script_bytes, allowed in ((77, 80, True), (78, 81, False)):
            change_addr = w.getrawchangeaddress()
            raw = node.createrawtransaction(
                [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                [{"data": "cc" * data_bytes}, {change_addr: change_amount}])
            decoded = node.decoderawtransaction(raw)
            assert_equal(len(decoded["vout"][0]["scriptPubKey"]["hex"]) // 2, script_bytes)
            signed = w.signrawtransactionwithwallet(raw)
            assert_equal(signed["complete"], True)
            result = node.testmempoolaccept([signed["hex"]])[0]
            assert_equal(result["allowed"], allowed)
            if not allowed:
                assert_equal(result["reject-reason"], "datacarrier")

        self.log.info("Watch-only: the public descriptors re-import into a wallet without private keys")
        # pq()/slh() keys have no public derivation, so the public form lists the
        # derived public keys explicitly (audit finding W3); the private form is
        # the ranged xprv descriptor, unchanged.
        # The export carries the look-ahead the signer has derived (keypool=1 in this harness);
        # derive ten unused keys per descriptor so the watch-only wallet has that many to give out.
        w.keypoolrefill(10)
        exported = w.listdescriptors()["descriptors"]
        private = w.listdescriptors(True)["descriptors"]
        assert_equal(len(exported), len(private))
        for entry in private:
            assert "tprv" in entry["desc"] and "/*" in entry["desc"], entry["desc"]
        for entry in exported:
            assert "tpub" not in entry["desc"] and "*" not in entry["desc"], entry["desc"][:80]
            assert entry["desc"].startswith(("pqtr({pq(keys(", "pq(keys(")), entry["desc"][:80]
            assert "range" in entry and "next_index" in entry
            # One public key per cached position, for every key in the tree.
            for key in re.findall(r"keys\(([0-9a-f,]+)\)", entry["desc"]):
                assert_equal(len(key.split(",")), entry["range"][1] + 1)
        node.createwallet(wallet_name="watch", disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc("watch")
        res = watch.importdescriptors(exported)
        assert all(r["success"] for r in res), res
        assert_equal(watch.listdescriptors()["descriptors"], exported)
        for addr in [a3, a2, payee] + fresh + change:
            assert_equal(watch.getaddressinfo(addr)["ismine"], True)
        assert_equal(watch.getaddressinfo(mine_to)["ismine"], False)
        assert_equal(watch.getbalances()["mine"]["trusted"], w.getbalances()["mine"]["trusted"])
        assert_equal(len(watch.listunspent()), len(w.listunspent()))
        # The same next addresses, receive and change, in the same order.
        for _ in range(3):
            assert_equal(watch.getnewaddress(), w.getnewaddress())
            assert_equal(watch.getrawchangeaddress(), w.getrawchangeaddress())
            assert_equal(watch.getnewaddress("", "xcoin-v2"), w.getnewaddress("", "xcoin-v2"))
        # Past the exported keys the watch-only wallet has no addresses left; the signer keeps deriving.
        for _ in range(7):
            assert_equal(watch.getnewaddress(), w.getnewaddress())
        assert_raises_rpc_error(-12, "No addresses available", watch.getnewaddress)
        assert w.getnewaddress().startswith("nxrt1r")
        # The key lists survive a reload of the watch-only wallet.
        node.unloadwallet("watch")
        node.loadwallet("watch")
        assert_equal(watch.getaddressinfo(a3)["ismine"], True)
        v3_ext = lambda descs: next(e for e in descs if e["desc"].startswith("pqtr(") and not e["internal"])
        assert_equal(v3_ext(watch.listdescriptors()["descriptors"])["next_index"], v3_ext(exported)["next_index"] + 10)
        # A range beyond the exported keys is refused; the key list is never a private form.
        v3_export = next(e for e in exported if e["desc"].startswith("pqtr(") and not e["internal"])
        too_far = dict(v3_export, range=[0, v3_export["range"][1] + 1])
        res = watch.importdescriptors([too_far])
        assert_equal(res[0]["success"], False)
        assert "beyond the" in res[0]["error"]["message"], res[0]
        assert_equal(node.getdescriptorinfo(v3_export["desc"])["hasprivatekeys"], False)
        assert_equal(node.getdescriptorinfo(v3_export["desc"])["isrange"], True)
        assert_equal(node.deriveaddresses(v3_export["desc"], [0, 0]), [a3])
        assert_raises_rpc_error(-5, "Cannot derive script", node.deriveaddresses, v3_export["desc"], [0, v3_export["range"][1] + 1])

        self.log.info("Import: a literal post-quantum private key is refused, alone and next to a BIP32 key")
        # DescriptorScriptPubKeyMan persists only secp256k1 keys; a literal seed would be dropped
        # silently and the coins spent only through the other leaf (audit finding W2).
        xprv = re.search(r"pq\((tprv[0-9A-Za-z]+)", private[0]["desc"]).group(1)
        for desc in (f"pqtr({{pq({seed_pq}),slh({xprv}/9h/0/*)}})",
                     f"pqtr({{pq({xprv}/9h/0/*),slh({seed_slh})}})",
                     f"pqtr({{pq({seed_pq}),slh({seed_slh})}})",
                     f"pq({seed_pq})"):
            res = w.importdescriptors([{"desc": descsum_create(desc), "timestamp": "now"}])
            assert_equal(res[0]["success"], False)
            assert "literal post-quantum private key" in res[0]["error"]["message"], res[0]
        # Whitespace around a key is refused without echoing the key (audit finding W1).
        res = w.importdescriptors([{"desc": descsum_create(f"pq({seed_pq} )"), "timestamp": "now"}])
        assert_equal(res[0]["success"], False)
        assert_equal(res[0]["error"]["message"], "pq(): key contains leading or trailing whitespace")
        assert_raises_rpc_error(-5, "pq(): key contains leading or trailing whitespace", node.getdescriptorinfo, f"pq( {seed_pq})")

        self.log.info("Encrypted wallet: a locked wallet says so when its pre-derived addresses run out")
        # A post-quantum key is derived from the private key only, so the look-ahead
        # (keypool=1 in this harness) cannot be refilled while locked (audit finding Q4).
        node.createwallet(wallet_name="enc", passphrase="pass")
        enc = node.get_wallet_rpc("enc")
        assert_equal(enc.getwalletinfo()["unlocked_until"], 0)
        first = enc.getnewaddress()
        assert first.startswith("nxrt1r")
        assert_raises_rpc_error(-12, "Keypool ran out and the wallet is locked: unlock it with walletpassphrase", enc.getnewaddress)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", enc.keypoolrefill)
        enc.walletpassphrase("pass", 100)  # refills on unlock
        enc.walletlock()
        second = enc.getnewaddress()
        assert second != first
        assert_raises_rpc_error(-12, "Keypool ran out and the wallet is locked", enc.getnewaddress)
        enc.walletpassphrase("pass", 100)
        unlocked = [enc.getnewaddress() for _ in range(5)]
        assert_equal(len(set(unlocked) | {first, second}), 7)

        self.log.info("Without -permitv2outputs=1 the wallet neither hands out nor pays a v2 address")
        # Audit finding T9: the node would not relay or mine the transaction, so the wallet
        # refuses up front and names the flag. The v2 coin it already holds stays spendable.
        self.restart_node(0, extra_args=[a for a in self.extra_args[0] if a != "-permitv2outputs=1"])
        assert_equal(node.getmempoolinfo()["permitv2outputs"], False)
        w = node.get_wallet_rpc("w")
        flag_error = "requires a regtest node started with -permitv2outputs=1"
        assert_raises_rpc_error(-12, flag_error, w.getnewaddress, "", "xcoin-v2")
        assert_raises_rpc_error(-12, flag_error, w.getrawchangeaddress, "xcoin-v2")
        assert_raises_rpc_error(-6, flag_error, w.sendtoaddress, a2, 1)
        assert_raises_rpc_error(-4, flag_error, w.send, [{a2: 1}])
        assert_raises_rpc_error(-5, flag_error, w.sendall, [a2])
        assert_raises_rpc_error(-4, flag_error, w.walletcreatefundedpsbt, [], [{a2: 1}])
        assert w.getnewaddress().startswith("nxrt1r")
        assert_equal(w.getaddressinfo(a2)["ismine"], True)
        v2_utxo = next(u for u in w.listunspent() if u["address"] == a2)
        v3_dest = w.getnewaddress()
        res = w.send(outputs=[{v3_dest: v2_utxo["amount"]}],
                     options={"inputs": [{"txid": v2_utxo["txid"], "vout": v2_utxo["vout"]}], "add_inputs": False,
                              "subtract_fee_from_outputs": [0]})
        assert_equal(res["complete"], True)
        assert res["txid"] in node.getrawmempool()
        assert_equal(witness_sizes(node, res["txid"]), [[MLDSA_SIGNATURE_SIZE + 1, MLDSA_PUBKEY_SIZE]])
        self.generatetoaddress(node, 1, mine_to)
        assert_equal(w.gettransaction(res["txid"])["confirmations"], 1)
        assert not any(u["address"].startswith("nxrt1z") for u in w.listunspent(0))
        # -changetype=xcoin-v2 is refused at wallet load on such a node, with the same message.
        # (Nothing may load at startup, or the node itself would refuse to start.)
        node.unloadwallet("w", False)
        node.unloadwallet(self.default_wallet_name, False)
        self.restart_node(0, extra_args=[a for a in self.extra_args[0] if a != "-permitv2outputs=1"] + ["-changetype=xcoin-v2"])
        assert_raises_rpc_error(-4, flag_error, node.loadwallet, "w")


if __name__ == "__main__":
    XcoinV3WalletTest(__file__).main()
