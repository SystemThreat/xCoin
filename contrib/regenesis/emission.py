#!/usr/bin/env python3
"""xCoin emission schedule (FINAL founder decision 2026-09-14, charter section 4).

No premine, no founder allocation, nothing carried in. Block 0 mints nothing. From block 1
mining pays exactly 14 XCF per block for 750,000 blocks (seven years and 49 days at 300 s),
and the rate then halves every 750,000 blocks, each halving rounded down to a whole satoshi,
until it reaches zero: 31 eras. 14 x 750,000 x 2 = 21,000,000, so the series closes at the cap
less the satoshis lost to rounding thirty halvings; the final subsidy block also mints that
remainder, so that

    sum(era subsidies) + remainder == 21,000,000 XCF exactly.

Prints the table as src/consensus/params.h states it, and verifies the sum.
"""
import argparse

SAT = 100_000_000
CAP_SAT = 21_000_000 * SAT

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--era-blocks", type=int, default=750_000, help="blocks per era (750,000 = 7 y 49 d at 300 s)")
    ap.add_argument("--s0-sat", type=int, default=14 * SAT, help="era-0 subsidy in sats (default 14 XCF)")
    ap.add_argument("--block-seconds", type=int, default=300)
    a = ap.parse_args()
    subs = []
    s = a.s0_sat
    while s > 0:
        subs.append(s); s >>= 1
    emitted = sum(x * a.era_blocks for x in subs)
    remainder = CAP_SAT - emitted
    assert 0 <= remainder < SAT, "remainder must be under one XCF: pick s0 and era so that s0 * era * 2 == cap"
    years = a.era_blocks * a.block_seconds / 31_557_600
    print(f"cap        {CAP_SAT/SAT:>16,.8f} XCF; premine NONE; carried NONE")
    print(f"era blocks {a.era_blocks:,} ({years:.3f} years); S0 {a.s0_sat/SAT:.8f} XCF = {a.s0_sat:,} sat; {len(subs)} eras\n")
    print(f"{'era':>3} {'subsidy XCF':>14} {'start':>10} {'end':>10} {'era total XCF':>18} {'ends ~year':>10}")
    h = 0
    for e, x in enumerate(subs):
        h += a.era_blocks
        print(f"{e:>3} {x/SAT:>14.8f} {h-a.era_blocks+1:>10,} {h:>10,} {x*a.era_blocks/SAT:>18,.8f} {2026.75 + h*a.block_seconds/31_557_600:>10.1f}")
    print(f"{'':>3} {remainder/SAT:>14.8f} {'remainder':>10} {'':>10} {remainder/SAT:>18,.8f}            (minted with the final subsidy, height {h:,})\n")
    print("params.h rows:")
    for e, x in enumerate(subs):
        print(f"    {{ {1+e*a.era_blocks:>9}, {(e+1)*a.era_blocks:>9}, {x:>10}LL }},  // era {e:>2}: {x/SAT:>11.8f} XCF x {a.era_blocks:,} blocks")
    print(f"\nemitted {emitted/SAT:,.8f} + remainder {remainder/SAT:.8f} = {(emitted+remainder)/SAT:,.8f} XCF")
    print("OK: sums to exactly 21,000,000 XCF" if emitted + remainder == CAP_SAT else "MISMATCH")

if __name__ == "__main__":
    main()
