#!/usr/bin/env python3
"""xCoin emission table generator: policy JSON in, consensus/params.h rows out.

The hard cap is 100,000,000 XID with 8 decimals (1 XID = 100,000,000 sat), owner
decision 2026-09-25. The SHAPE of the emission under that cap is read from a policy
file, by default contrib/regenesis/emission-policy.json. That file is FINAL (owner
decision 2026-09-25): [EMISSION-SHAPE] the Annual Tenth, charter section 4, 65 rows
whose canonical rows file (--rows-out) has the SHA-256 the charter states.
Swapping the shape (only ever on a new chain; the charter never changes it):

    cp <final.json> contrib/regenesis/emission-policy.json   # then set "status": "FINAL (...)" in it
    python3 contrib/regenesis/emission.py --write-params         # rewrites the params.h block
    python3 contrib/regenesis/emission.py --check-params         # what a reviewer runs: exit 0 or 1
    python3 contrib/regenesis/emission.py --check-spots          # the list of shape statements is complete
    python3 contrib/regenesis/emission.py --rows <file>          # a canonical rows file matches byte for byte

then rewrite every place contrib/regenesis/EMISSION-SHAPE-SPOTS.md lists (charter
section 4 and its hash, the unit test annual_tenth_emission_shape, the docs, the
explorer). Both checks run in ctest (test/CMakeLists.txt).

The policy "status" decides EMISSION_SHAPE_IS_FINAL in the generated block: true only
when it starts with FINAL. While it is false, kernel/chainparams.cpp refuses to compile
GENESIS_IS_FINAL = true (outside a local -DXCOIN_REHEARSAL_BUILD=ON build) and
xcoin-genesis refuses -chain=main without -allowprovisional, so the placeholder
shape cannot end up in the mainnet genesis. --check-params also requires charter
section 4 to carry its PROVISIONAL comment exactly while the status is not FINAL.

The policy schema is the emission lab's (sim.py), so the file the lab evaluates is
the file this script turns into consensus rows, with no hand translation:

    {
      "name": "...",
      "status": "PROVISIONAL ..." | "FINAL ...",   # FINAL only once the owner has chosen this shape
      "cap_xcf": 100000000,           # the cap in whole coins; the lab's field name ("cap_xid" is accepted too)
      "decimals": 8,                  # must be 8: COIN is 10^8 sat (consensus/amount.h)
      "block_seconds": 300,           # must be 300: the node's target spacing
      "curve": {"type": "halving", "s0": 50, "era_blocks": 1000000}
             | {"type": "smooth", "s0": 50, "half_life_blocks": 1000000, "step_blocks": 4032}
             | {"type": "remaining_shift", "shift": 20, "chunk_blocks": 288}
             | {"type": "eras", "eras": [[blocks, reward], ...]},
      "calibrate": "s0" | "half_life",   # optional: solve that parameter so the curve alone meets the cap
      "slow_start_blocks": 0,
      "tail": {"type": "none"} | {"type": "floor", "per_block": 0.25},
      "completion": "final_block" | "extend_floor" | "extend_last",
      "min_output_sat": 10000,
      "notes": "..."
    }

Segments are built with exactly the lab's integer arithmetic (--sim PATH re-runs the
lab's own build_segments and requires an identical result). Two conventions differ
from the lab's report and are deliberate:

  * completion "final_block": the lab books the remainder as one extra block after
    the last era; the node mints it ON TOP of the last subsidy block
    (EMISSION_CLOSING_DUST_SAT, validation.cpp GetBlockSubsidy). Same total, and the
    last subsidy height is one lower. The remainder must be under 1 XID.
  * an uncapped policy (cap null) is refused: charter section 2 states a hard cap.

Without --write-params the script prints the schedule, the generated params.h block
and the check that era subsidies plus the closing remainder equal the cap exactly.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import math
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_POLICY = os.path.join(HERE, "emission-policy.json")
DEFAULT_PARAMS = os.path.join(ROOT, "src", "consensus", "params.h")
DEFAULT_AMOUNT = os.path.join(ROOT, "src", "consensus", "amount.h")
DEFAULT_CHARTER = os.path.join(HERE, "CHARTER.md")
DEFAULT_SPOTS = os.path.join(HERE, "EMISSION-SHAPE-SPOTS.md")
# The grep tag on every line or block that states the emission shape. Spelled in two
# pieces here so this line is not itself a tagged line.
SHAPE_TAG = "[EMISSION" + "-SHAPE]"
# Directories --check-spots does not walk: VCS data, build trees, vendored code.
SPOTS_SKIP_DIRS = {".git", "depends", "node_modules", "__pycache__", "leveldb", "secp256k1",
                   "crc32c", "minisketch", "libmultiprocess"}

TICKER = "XID"
NODE_DECIMALS = 8                 # COIN = 100,000,000 (consensus/amount.h)
NODE_BLOCK_SECONDS = 300          # nPowTargetSpacing on mainnet and testnet A
EMISSION_START_HEIGHT = 1         # consensus/params.h: block 0 mints nothing
YEAR_S = 31_557_600               # Julian year, as the lab uses
HORIZON_YEARS = 1000              # the lab's horizon; a schedule is cut there
MAX_ROWS_WARN = 1000              # GetBlockSubsidy scans the table linearly
BEGIN_MARK = "// BEGIN GENERATED EMISSION TABLE"
END_MARK = "// END GENERATED EMISSION TABLE"


class PolicyError(Exception):
    pass


# ── The lab's segment builder (sim.py build_segments / calibrate), same arithmetic ──

def build_segments(p):
    """Return (segments, total_sat, cap_sat, unit, blocks_per_year); segments are
    (start_height, end_height inclusive, reward_sat). Mirrors sim.py exactly."""
    unit = 10 ** p.get("decimals", 8)
    bs = p.get("block_seconds", 300)
    bpy = YEAR_S / bs
    horizon = int(HORIZON_YEARS * bpy)
    cap_coins = policy_cap(p)
    cap = None if cap_coins is None else int(round(cap_coins * unit))
    c = p["curve"]
    t = p.get("tail", {"type": "none"})
    floor = int(round(t.get("per_block", 0) * unit)) if t.get("type") == "floor" else 0
    ss = int(p.get("slow_start_blocks", 0))
    segs = []
    total = 0

    def add(a, b, r):
        nonlocal total
        if b < a or r <= 0:
            return True
        if cap is not None and total + (b - a + 1) * r > cap:
            n = (cap - total) // r
            if n > 0:
                segs.append((a, a + n - 1, r)); total += n * r
            rem = cap - total
            if rem > 0:
                segs.append((a + n, a + n, rem)); total += rem
            return False
        segs.append((a, b, r)); total += (b - a + 1) * r
        return True

    def curve_pieces():
        h = 1
        if c["type"] == "halving":
            r = int(round(c["s0"] * unit)); L = int(c["era_blocks"])
            while r > 0 and h <= horizon:
                yield h, h + L - 1, r
                h += L; r >>= 1
        elif c["type"] == "smooth":
            s0 = c["s0"] * unit; HL = c["half_life_blocks"]; N = int(c.get("step_blocks", 1))
            k = 0
            while h <= horizon:
                r = int(math.floor(s0 * 2 ** (-(k * N) / HL)))
                if r <= 0:
                    break
                yield h, h + N - 1, r
                h += N; k += 1
        elif c["type"] == "eras":
            for L, rw in c["eras"]:
                yield h, h + int(L) - 1, int(round(rw * unit))
                h += int(L)
        else:
            raise PolicyError(f"unknown curve type {c['type']!r}")

    if c["type"] == "remaining_shift":
        if cap is None:
            raise PolicyError("remaining_shift needs a cap")
        sh = int(c["shift"]); N = int(c.get("chunk_blocks", 288)); h = 1
        while h <= horizon and total < cap:
            r = max((cap - total) >> sh, floor)
            if r <= 0:
                break
            if not add(h, h + N - 1, r):
                break
            h += N
        return segs, total, cap, unit, bpy
    last_end, last_r = 0, 0
    for a, b, r in curve_pieces():
        if ss and a <= ss:
            steps = 100; blk = max(1, ss // steps)
            x = a
            while x <= min(b, ss):
                y = min(x + blk - 1, b, ss)
                rr = max(1, r * y // ss)
                if floor:
                    rr = max(rr, floor)
                if not add(x, y, rr):
                    return segs, total, cap, unit, bpy
                x = y + 1
            a = x
            if a > b:
                last_end, last_r = b, r
                continue
        rr = max(r, floor) if floor else r
        if not add(a, b, rr):
            return segs, total, cap, unit, bpy
        last_end, last_r = b, rr
    h = last_end + 1
    comp = p.get("completion", "final_block")
    if cap is not None and total < cap:
        rem = cap - total
        if floor or comp == "extend_floor":
            r = floor or 1
            n = rem // r
            add(h, h + n - 1, r); h += n
            if cap - total > 0:
                add(h, h, cap - total)
        elif comp == "extend_last" and last_r > 0:
            n = rem // last_r
            add(h, h + n - 1, last_r); h += n
            if cap - total > 0:
                add(h, h, cap - total)
        else:
            # The lab's stand-in for "minted with the final subsidy block".
            segs.append((last_end + 1, last_end + 1, rem)); total += rem
            p["_final_block_remainder"] = rem
    elif cap is None and floor:
        add(h, horizon, floor)      # uncapped tail (the lab evaluates it; to_rows refuses it)
    return segs, total, cap, unit, bpy


def calibrate(p):
    """Solve curve.s0 or curve.half_life_blocks so the curve alone meets the cap within
    one coin. Mirrors sim.py calibrate() (same bisection, same rounding)."""
    what = p.get("calibrate")
    if not what or policy_cap(p) is None:
        return p
    q = copy.deepcopy(p)
    q["cap_xcf"] = None; q.pop("cap_xid", None); q["tail"] = {"type": "none"}; q.pop("calibrate", None)
    target = policy_cap(p)
    key = "s0" if what == "s0" else "half_life_blocks"
    lo, hi = 1e-6, 1e9 if key == "s0" else 5e8
    for _ in range(200):
        mid = (lo + hi) / 2; q["curve"][key] = mid
        segs, total, *_ = build_segments(q)
        tot = total / 10 ** p.get("decimals", 8)
        if tot > target:
            hi = mid
        else:
            lo = mid
        if 0 <= target - tot < 1:
            break
    p = copy.deepcopy(p)
    p["curve"][key] = round(lo, 8) if key == "s0" else int(lo)
    p.pop("calibrate", None)
    p.setdefault("completion", "extend_last")
    p["_calibrated"] = f"{key} = {p['curve'][key]}"
    return p


def policy_cap(p):
    """The cap in whole coins: the lab's "cap_xcf", or "cap_xid". None = uncapped."""
    has_xcf, has_xid = "cap_xcf" in p, "cap_xid" in p
    if has_xcf and has_xid and p["cap_xcf"] != p["cap_xid"]:
        raise PolicyError(f"cap_xcf {p['cap_xcf']} and cap_xid {p['cap_xid']} disagree")
    if has_xid:
        return p["cap_xid"]
    return p.get("cap_xcf")


# ── From segments to consensus rows ──────────────────────────────────────────

def to_rows(p):
    """Return (policy_after_calibration, rows, closing_dust_sat, cap_sat). rows are
    (startHeight, endHeight, baseSubsidy_sat), back to back from height 1."""
    if p.get("decimals", 8) != NODE_DECIMALS:
        raise PolicyError(f"decimals {p.get('decimals')} is not the node's {NODE_DECIMALS}: 8 decimals are decided (COIN = 10^8 sat)")
    if p.get("block_seconds", 300) != NODE_BLOCK_SECONDS:
        raise PolicyError(f"block_seconds {p.get('block_seconds')} is not the node's {NODE_BLOCK_SECONDS} s target spacing; "
                          "changing the interval is a separate consensus change")
    if policy_cap(p) is None:
        raise PolicyError("the policy has no cap; charter section 2 states a hard cap, so an uncapped schedule cannot be generated")
    p = calibrate(p)
    segs, total, cap, unit, _ = build_segments(p)
    if total != cap:
        raise PolicyError(f"the schedule emits {total} sat, not the cap {cap} sat, within the {HORIZON_YEARS}-year horizon")
    dust = 0
    if p.get("_final_block_remainder"):
        # The lab's remainder block becomes the node's closing dust on the last subsidy block.
        a, b, r = segs[-1]
        assert a == b and r == p["_final_block_remainder"] and len(segs) >= 2
        segs = segs[:-1]; dust = r
    rows = []
    for a, b, r in segs:
        if rows and rows[-1][2] == r and rows[-1][1] + 1 == a:
            rows[-1] = (rows[-1][0], b, r)
        else:
            rows.append((a, b, r))
    # Structural checks the C++ static_asserts repeat.
    if not rows or rows[0][0] != EMISSION_START_HEIGHT:
        raise PolicyError("the table must start at height 1")
    for i, (a, b, r) in enumerate(rows):
        if b < a or r <= 0:
            raise PolicyError(f"row {i} is empty or pays nothing: {a}..{b} at {r} sat")
        if i and a != rows[i - 1][1] + 1:
            raise PolicyError(f"row {i} does not follow row {i - 1}")
        if b > 2**31 - 1:
            raise PolicyError(f"row {i} ends past the 32-bit height range")
    if not 0 <= dust < unit:
        raise PolicyError(f"closing remainder {dust} sat is not under 1 {TICKER}: calibrate the curve or use completion extend_last/extend_floor")
    if sum((b - a + 1) * r for a, b, r in rows) + dust != cap:
        raise PolicyError("internal: rows plus dust do not equal the cap")
    return p, rows, dust, cap


def shape_is_final(p):
    """The policy's shape is final only when its status says so explicitly: a status
    starting with FINAL. A missing status (an emission-lab candidate) is not final."""
    return str(p.get("status", "")).strip().upper().startswith("FINAL")


def halving_shape(p, rows):
    """For a plain halving curve (no slow start, no floor, final_block completion),
    return (era_blocks, era0_sat) when the rows are exactly that shape, else None."""
    c = p["curve"]
    if c["type"] != "halving" or p.get("slow_start_blocks", 0) or p.get("tail", {}).get("type", "none") != "none":
        return None
    L = int(c["era_blocks"])
    for i, (a, b, r) in enumerate(rows):
        if a != 1 + i * L or b != (i + 1) * L:
            return None
        if i and r != rows[i - 1][2] // 2:
            return None
    if rows[-1][2] != 1:
        return None
    return L, rows[0][2]


# ── Rendering ────────────────────────────────────────────────────────────────

def coins(sat, width=0):
    s = f"{sat // 10**8:,}.{sat % 10**8:08d}"
    return s.rjust(width)


def num(n):
    """A C++ digit-separated integer literal (1'000'000)."""
    return f"{n:,}".replace(",", "'")


def params_block(p, rows, dust, cap, policy_path):
    rel = os.path.relpath(policy_path, ROOT)
    status = p.get("status", "")
    final = shape_is_final(p)
    lines = [
        BEGIN_MARK + " " + "─" * (78 - len(BEGIN_MARK) - 1),
        "// Generated by  python3 contrib/regenesis/emission.py --write-params",
        f"// from          {rel}",
        f"// policy        \"{p.get('name', '')}\"",
    ]
    if status:
        lines.append(f"// status        {status}")
    lines.append(f"// {SHAPE_TAG} this whole block states the emission shape; it is regenerated, never edited.")
    if not final:
        lines += [
            "// PROVISIONAL: the cap (100,000,000 XID) is decided; this SHAPE is a placeholder",
            "// until the emission search picks the final one. Replace the policy file and",
            "// regenerate; do not edit these rows by hand (emission.py --check-params and",
            "// the regenesis_tests unit suite fail on any drift).",
        ]
    lines += [
        "",
        "/** Whether this table's SHAPE is final: true only when the policy status starts",
        " *  with FINAL. While it is false, kernel/chainparams.cpp refuses to compile",
        " *  GENESIS_IS_FINAL = true (except in a local -DXCOIN_REHEARSAL_BUILD=ON build),",
        " *  xcoin-genesis refuses -chain=main without -allowprovisional, and charter",
        " *  section 4 must carry its PROVISIONAL comment (regenesis_tests). */",
        f"static constexpr bool EMISSION_SHAPE_IS_FINAL = {'true' if final else 'false'};",
        "",
        "/** Rows in EMISSION_TABLE. */",
        f"static constexpr int NUM_EMISSION_ERAS = {len(rows)};",
        "",
        "/** Mainnet (and testnet A) emission schedule: back-to-back rows from height 1. */",
        "static constexpr EmissionEra EMISSION_TABLE[NUM_EMISSION_ERAS] = {",
        "    //  startHeight  endHeight  baseSubsidy(sat)",
    ]
    w = max(len(str(r)) for _, _, r in rows)
    ww = max(len(f"{r // 10**8}") for _, _, r in rows)
    for i, (a, b, r) in enumerate(rows):
        n = b - a + 1
        note = f"era {i:>2}: {coins(r).rjust(ww + 9)} {TICKER} x {n:,} blocks"
        if i == len(rows) - 1 and dust:
            note += " (the last block also mints the closing remainder)"
        lines.append(f"    {{ {a:>9}, {b:>9}, {str(r).rjust(w)}LL }},  // {note}")
    lines += [
        "};",
        "",
        f"/** Minted on top of the last subsidy block so the total is exactly the cap:",
        f" *  {coins(dust)} {TICKER} ({dust:,} sat). */",
        f"static constexpr int64_t EMISSION_CLOSING_DUST_SAT = {num(dust)}LL;",
    ]
    shape = halving_shape(p, rows)
    if shape:
        L, s0 = shape
        lines += [
            "",
            f"// Shape: halving. {coins(s0)} {TICKER} per block, halved every {L:,} blocks in whole",
            "// satoshis until the shift reaches zero. These constants and assertions exist only",
            "// for this shape; a policy of another shape generates none.",
            f"static constexpr int EMISSION_ERA_BLOCKS = {num(L)};",
            f"static constexpr int64_t EMISSION_ERA0_SUBSIDY_SAT = {num(s0)}LL;",
            "static_assert(EmissionTableContiguous(EMISSION_TABLE, NUM_EMISSION_ERAS, EMISSION_START_HEIGHT, EMISSION_ERA_BLOCKS),",
            "              \"halving shape: back-to-back eras from height 1, each exactly EMISSION_ERA_BLOCKS long\");",
            "static_assert(EMISSION_TABLE[0].baseSubsidy == EMISSION_ERA0_SUBSIDY_SAT, \"halving shape: era 0 pays EMISSION_ERA0_SUBSIDY_SAT\");",
            "static_assert(EmissionTableHalves(EMISSION_TABLE, NUM_EMISSION_ERAS), \"halving shape: each era pays half of the previous one, rounded down\");",
            "static_assert(EMISSION_TABLE[NUM_EMISSION_ERAS - 1].baseSubsidy == 1, \"halving shape: the table ends where the halving reaches zero\");",
        ]
    lines.append(END_MARK + " " + "─" * (78 - len(END_MARK) - 1))
    return "\n".join(lines) + "\n"


def report(p, rows, dust, cap, genesis_year):
    unit = 10 ** 8
    bs = p.get("block_seconds", 300)
    out = []
    out.append(f"policy     {p.get('name', '')}" + (f"  [{p['status']}]" if p.get("status") else ""))
    if p.get("_calibrated"):
        out.append(f"calibrated {p['_calibrated']}  (pin this value in the policy file before it goes to review)")
    out.append(f"cap        {coins(cap)} {TICKER} = {cap:,} sat; premine NONE; carried NONE")
    out.append(f"rows       {len(rows)}; last subsidy block {rows[-1][1]:,} (~{genesis_year + rows[-1][1] * bs / YEAR_S:.1f} at {bs} s)")
    if len(rows) > MAX_ROWS_WARN:
        out.append(f"WARNING    {len(rows)} rows: GetBlockSubsidy scans the table linearly; consider a coarser step")
    out.append("")
    out.append(f"{'era':>4} {'subsidy ' + TICKER:>20} {'start':>12} {'end':>12} {'era total ' + TICKER:>24} {'supply %':>9} {'ends ~year':>10}")
    supply = 0
    for i, (a, b, r) in enumerate(rows):
        supply += (b - a + 1) * r
        out.append(f"{i:>4} {coins(r, 20)} {a:>12,} {b:>12,} {coins((b - a + 1) * r, 24)} {100 * supply / cap:>9.4f} {genesis_year + b * bs / YEAR_S:>10.1f}")
    out.append(f"{'':>4} {coins(dust, 20)} {'remainder':>12} {'':>12} {coins(dust, 24)}  minted with the last subsidy block, height {rows[-1][1]:,}")
    emitted = sum((b - a + 1) * r for a, b, r in rows)
    out.append("")
    out.append(f"era subsidies {coins(emitted)} + remainder {coins(dust)} = {coins(emitted + dust)} {TICKER}")
    return "\n".join(out)


# ── params.h / amount.h ──────────────────────────────────────────────────────

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def split_params(text):
    b = text.find(BEGIN_MARK)
    e = text.find(END_MARK)
    if b < 0 or e < 0 or e < b:
        raise PolicyError("params.h has no BEGIN/END GENERATED EMISSION TABLE markers")
    e = text.index("\n", e) + 1
    return text[:b], text[b:e], text[e:]


def check_node_constants(params_text, amount_text, cap):
    problems = []
    m = re.search(r"MAX_SUPPLY_SAT = ([0-9']+)LL;", params_text)
    if not m or int(m.group(1).replace("'", "")) != cap:
        problems.append(f"consensus/params.h MAX_SUPPLY_SAT is {m.group(1) if m else 'missing'}, the policy cap is {num(cap)}")
    m = re.search(r"MAX_MONEY = (\d+) \* COIN;", amount_text)
    if not m or int(m.group(1)) * 10**8 != cap:
        problems.append(f"consensus/amount.h MAX_MONEY is {m.group(1) + ' * COIN' if m else 'missing'}, the policy cap is {cap // 10**8:,} coins")
    return problems


def check_charter(charter_text, p):
    """Charter section 4 carries its PROVISIONAL comment exactly while the policy's
    shape is not final (the same rule regenesis_tests checks against the build)."""
    marked = "PROVISIONAL" in charter_text
    if shape_is_final(p) and marked:
        return ["contrib/regenesis/CHARTER.md still says PROVISIONAL, but the policy status is FINAL: "
                "rewrite section 4 for the final shape and drop its PROVISIONAL comment"]
    if not shape_is_final(p) and not marked:
        return ["the policy status is not FINAL, but contrib/regenesis/CHARTER.md has no PROVISIONAL comment: "
                "the placeholder shape would be committed unmarked"]
    return []


def tree_files(root):
    """Relative paths of the source files: git's view (tracked plus untracked, minus
    ignored) when the tree is a git checkout, else a walk that skips build trees."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, check=True).stdout
        return sorted({p for p in out.decode("utf-8", "replace").split("\0") if p})
    except (OSError, subprocess.CalledProcessError):
        pass
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        top = os.path.relpath(dirpath, root) == "."
        dirnames[:] = sorted(d for d in dirnames if d not in SPOTS_SKIP_DIRS and not (top and d.startswith("build")))
        files += [os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/") for fn in filenames]
    return sorted(files)


def find_tagged(root, spots_path):
    """{relative path: number of lines carrying SHAPE_TAG}, the spots list itself excluded."""
    found = {}
    skip = os.path.abspath(spots_path)
    tag = SHAPE_TAG.encode()
    for rel in tree_files(root):
        if any(part in SPOTS_SKIP_DIRS for part in rel.split("/")[:-1]):
            continue
        path = os.path.join(root, rel)
        if os.path.abspath(path) == skip or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        n = sum(1 for line in data.split(b"\n") if tag in line)
        if n:
            found[rel] = n
    return found


def listed_spots(spots_text):
    """{path: tagged-line count} from the spots list's table rows: | `path` | N | ... |"""
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|", spots_text, re.M)}


def check_spots(root, spots_path):
    """Problems (empty when none) between the tagged lines in the tree and the list."""
    listed = listed_spots(read(spots_path))
    if not listed:
        return [f"{os.path.relpath(spots_path, root)} lists no tagged files"]
    found = find_tagged(root, spots_path)
    problems = []
    for rel in sorted(set(found) | set(listed)):
        have, want = found.get(rel, 0), listed.get(rel, 0)
        if have != want:
            problems.append(f"{rel}: {have} line(s) tagged {SHAPE_TAG}, {os.path.basename(spots_path)} lists {want}")
    return problems


def rows_text(rows, dust):
    """The canonical row format charter section 4 hashes: one 'first last sat' line per
    row (decimal, single spaces), then 'dust <sat>', each line ending in a newline."""
    return "".join(f"{a} {b} {r}\n" for a, b, r in rows) + f"dust {dust}\n"


def load_policy(path, name):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if isinstance(d, list):
        if name is None:
            if len(d) != 1:
                raise PolicyError(f"{path} holds {len(d)} policies; pick one with --name")
            return d[0]
        for p in d:
            if p.get("name") == name:
                return p
        raise PolicyError(f"no policy named {name!r} in {path}")
    return d


def crosscheck_sim(sim_path, p):
    spec = importlib.util.spec_from_file_location("emission_lab_sim", sim_path)
    sim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sim)
    q = copy.deepcopy(p)
    if "cap_xid" in q and "cap_xcf" not in q:
        q["cap_xcf"] = q["cap_xid"]
    q = sim.calibrate(q)
    lab_segs, lab_total, *_ = sim.build_segments(q)
    ours, our_total, *_ = build_segments(calibrate(copy.deepcopy(p)))
    if lab_segs != ours or lab_total != our_total:
        raise PolicyError(f"segments differ from {sim_path}'s build_segments: the port has drifted")
    return len(lab_segs)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=DEFAULT_POLICY, help="policy JSON (default: contrib/regenesis/emission-policy.json)")
    ap.add_argument("--name", help="policy name, when the file holds a list")
    ap.add_argument("--params", default=DEFAULT_PARAMS, help="consensus/params.h to check or rewrite")
    ap.add_argument("--amount", default=DEFAULT_AMOUNT, help="consensus/amount.h (MAX_MONEY) to check")
    ap.add_argument("--charter", default=DEFAULT_CHARTER, help="the charter whose PROVISIONAL comment must match the policy status")
    ap.add_argument("--spots", default=DEFAULT_SPOTS, help="the list of places that state the emission shape")
    ap.add_argument("--check-spots", action="store_true",
                    help="exit 1 unless every line tagged " + SHAPE_TAG + " in the tree is counted in the spots list, file by file")
    ap.add_argument("--check-params", action="store_true", help="exit 1 unless params.h holds exactly the rows this policy generates and MAX_SUPPLY_SAT and MAX_MONEY equal its cap")
    ap.add_argument("--write-params", action="store_true", help="replace the generated block in params.h with this policy's rows")
    ap.add_argument("--sim", help="the emission lab's sim.py: require its build_segments to produce identical segments")
    ap.add_argument("--genesis-date", default="2026-11-01", help="for the year column only (default: the mainnet launch date)")
    ap.add_argument("--rows-out", help="write the generated table in the canonical row format ('first last sat' lines, then 'dust <sat>')")
    ap.add_argument("--rows", help="a canonical rows file (for example the emission lab's): exit 1 unless the policy generates it byte for byte")
    ap.add_argument("--quiet", action="store_true", help="no schedule table")
    a = ap.parse_args()

    if a.check_spots:
        try:
            problems = check_spots(ROOT, a.spots)
        except OSError as e:
            print(f"emission.py: {e}", file=sys.stderr)
            return 2
        for msg in problems:
            print("MISMATCH: " + msg, file=sys.stderr)
        if problems:
            print(f"Every line or block that states the emission shape carries {SHAPE_TAG}, and "
                  f"{os.path.relpath(a.spots, ROOT)} counts them per file: tag the new spot or update the list.", file=sys.stderr)
            return 1
        n = listed_spots(read(a.spots))
        print(f"OK: {sum(n.values())} tagged lines in {len(n)} files, as {os.path.relpath(a.spots, ROOT)} lists")
        if not a.check_params and not a.write_params:
            return 0

    try:
        raw = load_policy(a.policy, a.name)
        p, rows, dust, cap = to_rows(copy.deepcopy(raw))
        g = datetime.date.fromisoformat(a.genesis_date)
        genesis_year = g.year + (g.timetuple().tm_yday - 1) / 365.25
        block = params_block(p, rows, dust, cap, a.policy)
        if a.sim:
            n = crosscheck_sim(a.sim, raw)
            print(f"OK: {n} segments identical to {a.sim}", file=sys.stderr)
        if not a.quiet and not a.check_params:
            print(report(p, rows, dust, cap, genesis_year))
            print()
            print("params.h block:")
            print(block)
        text = rows_text(rows, dust)
        digest = hashlib.sha256(text.encode()).hexdigest()
        print(f"rows sha256 {digest}", file=sys.stderr)
        if a.rows_out:
            with open(a.rows_out, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        if a.rows:
            with open(a.rows, "rb") as f:
                want = f.read()
            if want != text.encode():
                print(f"MISMATCH: {a.rows} (sha256 {hashlib.sha256(want).hexdigest()}) is not the table this policy generates", file=sys.stderr)
                return 1
            print(f"OK: {a.rows} is byte-identical to the generated table", file=sys.stderr)
        params_text = read(a.params)
        amount_text = read(a.amount)
        problems = check_node_constants(params_text, amount_text, cap)
        problems += check_charter(read(a.charter), p)
        if a.write_params:
            head, _, tail = split_params(params_text)
            with open(a.params, "w", encoding="utf-8") as f:
                f.write(head + block + tail)
            print(f"wrote the generated block into {os.path.relpath(a.params, ROOT)}", file=sys.stderr)
            params_text = read(a.params)
        _, current, _ = split_params(params_text)
        if current != block:
            problems.append(f"{os.path.relpath(a.params, ROOT)}: the generated block differs from what {os.path.relpath(a.policy, ROOT)} generates (run --write-params)")
        for msg in problems:
            print("MISMATCH: " + msg, file=sys.stderr)
        if problems and (a.check_params or a.write_params):
            return 1
        emitted = sum((b - x + 1) * r for x, b, r in rows)
        ok = emitted + dust == cap
        print(f"{'OK' if ok else 'MISMATCH'}: {len(rows)} rows + remainder sum to exactly {coins(cap)} {TICKER}"
              + ("; params.h and amount.h agree" if not problems else ""))
        return 0 if ok else 1
    except (PolicyError, OSError, ValueError, KeyError) as e:
        print(f"emission.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
