#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Special script to run each bench sanity check
"""
import shlex
import subprocess

from test_framework.test_framework import BitcoinTestFramework


# Benchmarks whose fixture is a real Bitcoin mainnet block (bench/data/
# block413567.raw). This chain cannot accept that block, so these two cannot be
# sanity-checked; they need an xCoin block of comparable size before they mean
# anything again. Every other benchmark runs (REGENESIS.md section 9).
XCOIN_INAPPLICABLE_BENCHES = {
    "DeserializeAndCheckBlockTest":
        "CheckBlock on a Bitcoin mainnet block: its outputs are P2PKH and P2SH, which the "
        "PQ-only output rule refuses (bad-txout-not-pq)",
    "ReadBlockBench":
        "BlockManager::ReadBlock re-checks proof of work on a Bitcoin mainnet block, whose "
        "SHA-256d header is not a MetalDAG solution",
    # Benchmarks of Bitcoin's signature verification. This chain spends witness v3
    # inputs with ML-DSA-65 and SLH-DSA-SHA2-128s; those two are benchmarked by
    # src/bench/xcoin_pq.cpp (bench_bitcoin -filter='XcoinVerify.*'), whose numbers
    # set the two validation weights in REGENESIS.md section 4.
    "ConnectBlockAllEcdsa":
        "a block of P2WPKH inputs verified with ECDSA; witness v0 outputs cannot be created here",
    "ConnectBlockAllSchnorr":
        "a block of P2TR key-path inputs verified with Schnorr; witness v1 outputs cannot be created here",
    "ConnectBlockMixedEcdsaSchnorr":
        "a block of P2WPKH and P2TR inputs; neither output type can be created here",
}


class BenchSanityCheck(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0  # No node/datadir needed

    def setup_network(self):
        pass

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_bench()
        reason = XCOIN_INAPPLICABLE_BENCHES.get(self.options.bench)
        if reason is not None:
            self.skip_on_xcoin(f"{self.options.bench}: {reason}")

    def add_options(self, parser):
        parser.add_argument(
            "--bench",
            default=".*",
            help="Regex to filter the bench to run (default=%(default)s)",
        )

    def run_test(self):
        cmd = self.get_binaries().bench_argv() + [
            f"-filter={self.options.bench}",
            "-sanity-check",
        ]
        self.log.info(f"Starting: {shlex.join(cmd)}")
        subprocess.run(cmd, check=True)
        self.log.info("Success!")


if __name__ == "__main__":
    BenchSanityCheck(__file__).main()
