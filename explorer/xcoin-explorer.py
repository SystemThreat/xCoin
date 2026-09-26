#!/usr/bin/env python3
"""
xcoin-explorer — the self-contained block explorer behind superknet.com.

It serves the testnet A rehearsal today (RPC 19432, addresses txa1r…, label
"Rehearsal chain") and will serve mainnet (RPC 8332, addresses xpa1r…) once its
genesis is mined. One file, no framework, no node-side index: the explorer walks
every block itself and owns the UTXO set, so balances, the rich list and every
fee are chain truth.

What it shows:
  - blocks, transactions, witness v3 addresses (OP_3 <32-byte Merkle root>, the
    only spendable output type), the rich list, top miners and the pool's rigs
  - the block subsidy at the tip, read from the chain (the schedule is never hardcoded)
  - the fee of every non-coinbase transaction, exact, from the explorer's own
    UTXO set. The settlement levy is 0 bp on every chain (LEVY_BP below), so
    nothing about a levy renders unless XCOIN_LEVY_BP names a rate for a test chain
  - the network panel: charter_hash / currency_id / genesis from `getcharter`
  - a chain selector by RPC port: rehearsal (19432, the default) or mainnet (8332)

Sources of truth (read-only): xcoin-regenesis/contrib/regenesis/REGENESIS.md
sections 3, 4 and 6; src/script/xcoin_v3.h; src/consensus/genesis_distribution.*;
contrib/regenesis/carry_v3_vector.json. The Python here mirrors the wallet CLI
(x-Coin/wallet-cli-regenesis, wallet_cli.py) and NerdMiner's Swift
(x-Coin/nerdminer-regenesis, XcoinAddress.swift); tests/test_v3_addresses.py pins
the founder's conversion vector against all of them.

Run it:

  XCOIN_RPC_COOKIE=$HOME/.xcoin-rehearsal/node/testneta/.cookie \
  XCOIN_CHAIN=rehearsal XCOIN_EXPLORER_PORT=3101 python3 xcoin-explorer.py
  # then open http://localhost:3101/

Config (env):
  XCOIN_CHAIN           rehearsal (default) | mainnet — picks the RPC port below
  XCOIN_RPC_PORT        overrides it; 19432 = rehearsal, 8332 = mainnet
  XCOIN_RPC_HOST        default 127.0.0.1
  XCOIN_RPC_COOKIE      path of the node's .cookie file (preferred: no password anywhere)
  XCOIN_RPC_USER/PASSWORD fallback for local runs only
  XCOIN_EXPLORER_PORT   default 3101 (3001, 3333, 9333 and 9432 are reserved and refused)
  XCOIN_ADDRESS_HRP     override the address prefix (normally taken from the node)
  XCOIN_MAX_SUPPLY      default 100000000 (the cap, in XID)
  XCOIN_LEVY_BP         settlement levy in basis points, default 0 (the chain's rule);
                        a non-zero value is for a test chain only
  XCOIN_EXPLORER_URL    canonical/og base URL, default http://localhost:<port>
  XCOIN_EXPLORER_BIND   interface to bind, default 127.0.0.1
  XCOIN_ADDNODE         the peer line the home page suggests
  XCOIN_STATS_DIR       the pool's stats directory, default <here>/pool
  XCOIN_WEB_POOL_STATS  the browser pool's /stats URL, default empty
  XCOIN_EXPLORER_PUBLIC 1 to enable the analytics tag and the forum chat embed
                        (both OFF by default so a local run cannot pollute the
                        live site's numbers)
"""
import base64, hashlib, html, json, os, threading, time, urllib.request, urllib.error
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

# ── chain selector (by RPC port) ─────────────────────────────────────────────
# One file, two chains. The port picks the chain; the node's own `getblockchaininfo`
# confirms it at start-up and sets the address prefix, so a mislabelled port cannot
# make the explorer show xpa1r strings for a txa1r chain.
CHAIN_PROFILES = {
    # the rehearsal chain (testnet A: datadir testneta, P2P 19333, RPC 19432)
    "rehearsal": {"label": "Rehearsal chain", "hrp": "txa", "rpc_port": 19432, "chainfield": "test"},
    # mainnet, once its genesis is mined (chainparamsbase.cpp gives MAIN the RPC default 8332)
    "mainnet":   {"label": "Mainnet",         "hrp": "xpa", "rpc_port": 8332,  "chainfield": "main"},
}
CHAIN_BY_RPC_PORT = {19432: "rehearsal", 19434: "rehearsal", 8332: "mainnet"}
FORBIDDEN_RPC_PORTS = {9432, 9333}                # reserved by other services on this host
FORBIDDEN_BIND_PORTS = {3001, 3333, 9333, 9432}   # reserved by other services on this host

_chain = os.environ.get("XCOIN_CHAIN", "rehearsal").strip().lower()
if _chain not in CHAIN_PROFILES:
    raise SystemExit(f"XCOIN_CHAIN must be one of {', '.join(CHAIN_PROFILES)}")
_rpc_port = int(os.environ.get("XCOIN_RPC_PORT", CHAIN_PROFILES[_chain]["rpc_port"]))
_chain = CHAIN_BY_RPC_PORT.get(_rpc_port, _chain)

CFG = {
    "chain": _chain,
    "chain_label": CHAIN_PROFILES[_chain]["label"],
    "rpc_host": os.environ.get("XCOIN_RPC_HOST", "127.0.0.1"),
    "rpc_port": _rpc_port,
    "rpc_user": os.environ.get("XCOIN_RPC_USER", ""),
    "rpc_pass": os.environ.get("XCOIN_RPC_PASSWORD", ""),
    # Preferred: the node's own cookie file (XCOIN_RPC_COOKIE=/path/to/.cookie), read at every
    # call so a node restart never strands the explorer and no password sits in an environment
    # variable or a unit file (contrib/regenesis/WALLET-SECRETS.md). User/password stay only
    # as a fallback for local runs.
    "rpc_cookie": os.environ.get("XCOIN_RPC_COOKIE", ""),
    "port": int(os.environ.get("XCOIN_EXPLORER_PORT", "3101")),
    "max_supply": float(os.environ.get("XCOIN_MAX_SUPPLY", "100000000")),
    "hrp": os.environ.get("XCOIN_ADDRESS_HRP", CHAIN_PROFILES[_chain]["hrp"]),
}
HERE = os.path.dirname(os.path.abspath(__file__))
# A coinbase output paying this script is never credited to a miner. This chain has
# no premine and no founder output (REGENESIS.md sections 2 and 3), so the skip is a
# harmless no-op kept as a guard.
FOUNDER_SPK = "5220239fd93227acdc2ea29ee22bd97ed8fec19a827d5bbb24275823e5cfc6d92bee"
# The peer line the home page suggests. The rehearsal chain's P2P port is 19333.
NODE_HINT = os.environ.get("XCOIN_ADDNODE",
                           "addnode=127.0.0.1:19333" if CFG["chain"] == "rehearsal" else "addnode=<peer>:<p2p port>")
PUBLIC = os.environ.get("XCOIN_EXPLORER_PUBLIC", "") == "1"
SITE_URL = os.environ.get("XCOIN_EXPLORER_URL", f"http://localhost:{CFG['port']}").rstrip("/")
ASSET_VER = "20260905r1"  # bump on every JS/CSS change to bust browser + Cloudflare cache
# Pool stats are opt-in: XCOIN_STATS_DIR names the pool's stats directory and
# XCOIN_WEB_POOL_STATS the browser pool's /stats URL. Both default to nothing.
POOL_STATS_DIR = os.environ.get("XCOIN_STATS_DIR", os.path.join(HERE, "pool"))
POOL_MINERS_FILE = os.path.join(POOL_STATS_DIR, "pool_miners.json")
POOL_STATS_FILE = os.path.join(POOL_STATS_DIR, "pool_stats.json")
RIG_STATS_FILE  = os.environ.get("XCOIN_RIG_STATS", os.path.join(HERE, "rig-stats.json"))  # Nerd Miner rig agent
# Browser miners connect to the pool over WebSocket (wss://superknet.com/stratum).
# The explorer merges that pool's live stats with the local pool file so web miners
# are counted too. Fetched over HTTPS via the pool's GET /stats hook.
WEB_POOL_STATS_URL = os.environ.get("XCOIN_WEB_POOL_STATS", "")
_web_pool_cache = {"t": 0.0, "data": {}}
_web_pool_lock = threading.Lock()

def web_pool_stats():
    """VPS/browser pool stats (schema-compatible with the local pool file).
    Cached ~15s; never raises — returns {} if the pool is unreachable."""
    now = time.time()
    with _web_pool_lock:
        if now - _web_pool_cache["t"] < 15 and _web_pool_cache["t"]:
            return _web_pool_cache["data"]
    data = {}
    if not WEB_POOL_STATS_URL: return data
    try:
        req = urllib.request.Request(WEB_POOL_STATS_URL, headers={"User-Agent": "superknet"})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode("utf-8", "replace")) or {}
    except Exception:
        data = {}
    with _web_pool_lock:
        _web_pool_cache["t"] = now
        _web_pool_cache["data"] = data
    return data

DESC = ("SuperKnet — the post-quantum xCoin (XID) block explorer. "
        "Live blocks, transactions, witness v3 addresses, the rich list and top miners. "
        "100,000,000 XID cap, ML-DSA-65 and SLH-DSA leaves, MetalDAG proof of work.")
# FINAL emission shape (owner decision 2026-09-25): the Annual Tenth, charter section 4. [EMISSION-SHAPE]
# The one place the explorer states it.
EMISSION_NOTE = "The Annual Tenth · 50 XID after the ramp · 10% less every 110,000 blocks · 1.5 XID floor · 0.1 XID tail"
STATIC = {"favicon-16.png":"image/png","favicon-32.png":"image/png","favicon-48.png":"image/png",
          "favicon.ico":"image/x-icon","favicon.svg":"image/svg+xml",
          "apple-touch-icon.png":"image/png","xcoin.svg":"image/svg+xml",
          "og-image.png":"image/png","og-image.svg":"image/svg+xml"}

def rpc_credential():
    """`user:password` for the RPC Basic header: the cookie file's one line if XCOIN_RPC_COOKIE is
    set (re-read every call; the node rewrites it on restart), else the user/password pair."""
    if CFG["rpc_cookie"]:
        try:
            with open(CFG["rpc_cookie"], "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""
    return f"{CFG['rpc_user']}:{CFG['rpc_pass']}"

def rpc(method, params=None):
    payload = json.dumps({"jsonrpc":"1.0","id":"exp","method":method,"params":params or []}).encode()
    req = urllib.request.Request(f"http://{CFG['rpc_host']}:{CFG['rpc_port']}/", data=payload)
    req.add_header("Authorization","Basic "+base64.b64encode(rpc_credential().encode()).decode())
    req.add_header("Content-Type","application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            # Amounts arrive in XID as JSON numbers. A float holds them exactly only
            # below 2^26 XID (67,108,864; above it one float step is more than a sat),
            # so parse them as Decimal, as wallet/wallet_cli.py does.
            d = json.loads(r.read(), parse_float=Decimal)
            if d.get("error"): return None
            return d.get("result")
    except Exception:
        return None


def _json_default(o):
    """json.dumps hook for the public JSON API: rpc() hands back Decimal amounts, and
    the API keeps emitting them as plain JSON numbers, as it always has."""
    if isinstance(o, Decimal):
        return float(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def jdump(obj):
    """json.dumps for API responses that may carry Decimal values from rpc()."""
    return json.dumps(obj, default=_json_default)

# ── witness v3: hashing, addresses, single-leaf programs, the settlement levy ─
# REGENESIS.md sections 3, 4 and 6; src/script/xcoin_v3.h; the same arithmetic as
# wallet-cli-regenesis/wallet_cli.py and nerdminer-regenesis/XcoinAddress.swift.
# Consensus tags name the PROJECT (XCoin), never the ticker.
XCOIN_V3_LEAF_TAG = b"XCoinLeaf"
XCOIN_V3_BRANCH_TAG = b"XCoinBranch"
XCOIN_V3_NOKEY = hashlib.sha256(b"xcoin/v3/nokey").digest()
XCOIN_LEAF_PQ, XCOIN_LEAF_SLH = 0xc0, 0xc2        # ML-DSA-65 leaf, SLH-DSA-SHA2-128s leaf
LEAF_NAMES = {0xc0: "ML-DSA-65 (0xc0)", 0xc2: "SLH-DSA-SHA2-128s (0xc2)",
              0xc4: "reserved: proof predicate (0xc4)", 0xc6: "reserved: ledger commitment (0xc6)"}
WITVER_V2, WITVER_V3 = 2, 3
HRP_BY_CHAINFIELD = {"main": "xpa", "test": "txa", "testneta": "txa", "regtest": "nxrt"}
KNOWN_HRPS = ("xpa", "txa", "nxrt")
# The settlement levy. The chain's genesis rule is 0 bp (no levy, no cap), on every
# chain. XCOIN_LEVY_BP may name a rate for a test chain; at 0 nothing about a levy
# renders anywhere, and /api/stats reports levy_bp as 0.
LEVY_BP = int(os.environ.get("XCOIN_LEVY_BP", "0") or 0)
LEVY_DENOMINATOR = 10_000
SAT = 100_000_000

def tagged_hash(tag, msg):
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + msg).digest()

def compact_size(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def leaf_hash(version, script):
    return tagged_hash(XCOIN_V3_LEAF_TAG, bytes([version]) + compact_size(len(script)) + script)

def branch_hash(a, b):
    return tagged_hash(XCOIN_V3_BRANCH_TAG, (a + b) if a < b else (b + a))

def key32_checksig_script(key32):
    """0x20 <32 bytes> OP_CHECKSIG: the ML-DSA leaf (SHA-256 of the key) and the SLH leaf (the key)."""
    if len(key32) != 32: raise ValueError("leaf key must be 32 bytes")
    return b"\x20" + key32 + b"\xac"

def carried_program(pq_hash):
    """The single-leaf v3 program of a 32-byte ML-DSA-65 key hash: a one-leaf tree's root IS its leaf hash."""
    return leaf_hash(XCOIN_LEAF_PQ, key32_checksig_script(pq_hash))

def script_for_program(witver, program):
    """OP_<witver> <program>: 5220... for witness v2, 5320... for witness v3."""
    return bytes([0x50 + witver, len(program)]) + program

_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2bc830a3

def _polymod(values):
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1: chk ^= gen[i]
    return chk

def _hrp_expand(hrp): return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def _convertbits(data, frombits, tobits, pad):
    acc = bits = 0; ret = []
    maxv = (1 << tobits) - 1; max_acc = (1 << (frombits + tobits - 1)) - 1
    for v in data:
        if v < 0 or (v >> frombits): return None
        acc = ((acc << frombits) | v) & max_acc; bits += frombits
        while bits >= tobits:
            bits -= tobits; ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32m_encode(hrp, witver, program):
    data = [witver] + _convertbits(list(program), 8, 5, True)
    mod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ _BECH32M_CONST
    return (hrp + "1" + "".join(_B32[d] for d in data)
            + "".join(_B32[(mod >> 5 * (5 - i)) & 31] for i in range(6)))

def bech32m_decode(addr):
    """(hrp, witness version, program) of a bech32m address, or None if it is not one."""
    addr = (addr or "").strip()
    if not addr or any(ord(c) < 33 or ord(c) > 126 for c in addr): return None
    if addr.lower() != addr and addr.upper() != addr: return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90: return None
    hrp, rest = addr[:pos], addr[pos + 1:]
    if any(c not in _B32 for c in rest): return None
    data = [_B32.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M_CONST: return None
    data = data[:-6]
    if not data or data[0] > 16: return None
    prog = _convertbits(data[1:], 5, 8, False)
    if prog is None or not 2 <= len(prog) <= 40: return None
    return hrp, data[0], bytes(prog)

def is_v1_address(addr):
    """True for a witness v2 string (xpa1z... / txa1z...): a bare key hash, never payable on this chain."""
    d = bech32m_decode(addr)
    return bool(d) and d[0] in KNOWN_HRPS and d[1] == WITVER_V2 and len(d[2]) == 32

def is_v3_address(addr):
    d = bech32m_decode(addr)
    return bool(d) and d[0] in KNOWN_HRPS and d[1] == WITVER_V3 and len(d[2]) == 32

def convert_v1_address(addr, hrp=None):
    """Map a witness v2 xpa1z / txa1z string to the xpa1r / txa1r that pays the SAME key.
    Returns {v1, v3, key_hash, program, v3_script} or None when the input is not a v2 address."""
    d = bech32m_decode(addr)
    if not d or d[1] != WITVER_V2 or len(d[2]) != 32: return None
    got_hrp, _, key_hash = d
    if got_hrp not in KNOWN_HRPS: return None
    prog = carried_program(key_hash)
    use = hrp or got_hrp
    return {"v1": addr.strip().lower(), "v3": bech32m_encode(use, WITVER_V3, prog),
            "key_hash": key_hash.hex(), "program": prog.hex(),
            "v1_script": script_for_program(WITVER_V2, key_hash).hex(),
            "v3_script": script_for_program(WITVER_V3, prog).hex(), "hrp": use}

def address_from_spk_hex(hex_spk, hrp=None):
    """Decode OP_2/OP_3 <32 bytes> into an address, so the explorer never depends on the
    node having filled in scriptPubKey.address."""
    try:
        raw = bytes.fromhex(hex_spk or "")
    except ValueError:
        return None
    if len(raw) != 34 or raw[1] != 0x20: return None
    witver = raw[0] - 0x50
    if witver not in (WITVER_V2, WITVER_V3): return None
    return bech32m_encode(hrp or CFG["hrp"], witver, raw[2:])

def v3_program_of(addr):
    d = bech32m_decode(addr)
    return d[2] if d and d[1] == WITVER_V3 else None

# ── settlement levy (REGENESIS.md section 6; consensus/levy.h) ──────────────
def settlement_levy(out_sats, bp=None):
    """ceil(out_sats * bp / 10,000) in whole satoshis: the minimum fee of a non-coinbase
    transaction whose outputs are worth out_sats. Integer arithmetic, no floats. `bp`
    defaults to LEVY_BP, read at call time; the chain's rule is 0, so this is 0 unless
    a test chain names a rate."""
    out_sats = int(out_sats)
    if bp is None: bp = LEVY_BP
    if bp <= 0 or out_sats <= 0: return 0
    whole, rest = divmod(out_sats, LEVY_DENOMINATOR)
    return whole * bp + (rest * bp + LEVY_DENOMINATOR - 1) // LEVY_DENOMINATOR

def to_sats(v):
    """XID (as the RPC prints it) to whole satoshis. Exact for the Decimal values rpc()
    returns and for strings and ints; a float is exact only below 2^26 XID."""
    return int((Decimal(str(v)) * SAT).to_integral_value())

def sats_xat(s):
    """Whole satoshis as XID, in integer arithmetic: exact up to the 10^16-sat cap.
    (A float in XID units is exact only below 2^26 XID, 67,108,864: from there one
    float step is more than a sat. A float holding sats is exact to 2^53 sat.)"""
    if not s: return "0"
    s = int(s)
    sign, s = ("-", -s) if s < 0 else ("", s)
    return (sign + f"{s // SAT:,}.{s % SAT:08d}").rstrip("0").rstrip(".")

# ── self-built indexes (txid→block, address→txs, balances, series, miners) ────
# The scan walks every block from 0, so it also owns the UTXO set: that gives the
# rich list and the input value of every spend (hence the exact fee), all without a
# node-side index.
TXIDX = {}                 # txid -> blockhash
ADDRIDX = {}               # address -> [ {txid, height, time} ]  (most-recent-first)
UTXO = {}                  # "txid:n" -> (address or None, sats)
BAL = {}                   # address -> sats  (chain truth; drives the rich list)
TXMETA = {}                # txid -> {"in","out","fee","levy"} in sats (non-coinbase only)
SERIES = []                # [ {height, time, difficulty, txs, size} ]  recent blocks for charts
MINERS = {}                # miner address -> blocks mined
IDX_LOCK = threading.Lock()
LAST_IDX = -1
SERIES_MAX = 288           # ~1 day at 5-min blocks

def out_address(o):
    """The address of one vout: the node's, else decoded from the script."""
    spk = o.get("scriptPubKey", {}) or {}
    return spk.get("address") or address_from_spk_hex(spk.get("hex", ""))

def refresh_index():
    global LAST_IDX
    with IDX_LOCK:
        tip = rpc("getblockcount")
        if tip is None: return
        for h in range(LAST_IDX+1, tip+1):
            bh = rpc("getblockhash", [h])
            if not bh: break
            b = rpc("getblock", [bh, 2])
            if not b: break
            for t in b.get("tx", []):
                txid = t["txid"]
                TXIDX[txid] = bh
                coinbase = bool(t.get("vin")) and "coinbase" in t["vin"][0]
                # inputs: their value comes from our own UTXO set, so a fee is exact
                in_sats, in_known = 0, True
                if not coinbase:
                    for vin in t.get("vin", []):
                        key = f"{vin.get('txid')}:{vin.get('vout')}"
                        prev = UTXO.pop(key, None)
                        if prev is None:
                            pv = vin.get("prevout")   # getblock verbosity 3, if the caller has it
                            if pv is None: in_known = False; continue
                            prev = (out_address(pv), to_sats(pv.get("value", 0)))
                        addr, sats = prev
                        in_sats += sats
                        if addr:
                            BAL[addr] = BAL.get(addr, 0) - sats
                            if BAL[addr] <= 0: BAL.pop(addr, None)
                seen = set()
                out_sats = 0
                for n, o in enumerate(t.get("vout", [])):
                    sats = to_sats(o.get("value", 0))
                    out_sats += sats
                    addr = out_address(o)
                    if sats > 0 and (o.get("scriptPubKey", {}) or {}).get("type") != "nulldata":
                        UTXO[f"{txid}:{n}"] = (addr, sats)
                        if addr:
                            BAL[addr] = BAL.get(addr, 0) + sats
                    if addr and addr not in seen:
                        seen.add(addr)
                        ADDRIDX.setdefault(addr, [])
                        ADDRIDX[addr].insert(0, {"txid": txid, "height": h, "time": b["time"]})
                        if len(ADDRIDX[addr]) > 120: ADDRIDX[addr] = ADDRIDX[addr][:120]
                if not coinbase:
                    TXMETA[txid] = {"in": in_sats if in_known else None, "out": out_sats,
                                    "fee": (in_sats - out_sats) if in_known else None,
                                    "levy": settlement_levy(out_sats)}
            # miner = the first positive coinbase output (this chain has no premine)
            try:
                for o in b["tx"][0]["vout"]:
                    spk = o["scriptPubKey"]
                    addr = out_address(o)
                    if spk.get("hex") != FOUNDER_SPK and o["value"] > 0 and addr:
                        MINERS[addr] = MINERS.get(addr, 0) + 1
                        break
            except Exception: pass
            SERIES.append({"height": h, "time": b["time"], "difficulty": b["difficulty"],
                           "txs": b["nTx"], "size": b["size"]})
            if len(SERIES) > SERIES_MAX: del SERIES[:-SERIES_MAX]
            LAST_IDX = h

def block_fees(b):
    """(total fee, total levy required, all fees known) over a block's non-coinbase txs."""
    fee = levy = 0; known = True
    for t in b.get("tx", []):
        m = TXMETA.get(t["txid"])
        if m is None: continue
        levy += m["levy"]
        if m["fee"] is None: known = False
        else: fee += m["fee"]
    return fee, levy, known

def esc(s): return html.escape(str(s))
def xat(v):
    """An XID amount (Decimal from rpc(), int, str or float) formatted like sats_xat,
    through whole satoshis, so totals and balances past 2^26 XID keep their last sat."""
    try: return sats_xat(to_sats(v))
    except Exception: return str(v)
def short(s, n=16): s=str(s); return s if len(s)<=2*n else f"{s[:n]}…{s[-8:]}"

# ── HTML shell (acid-lime brutalist — the MineDifferent / xcoinminer.com system) ──
# One monospace stack, paper white, every box a 2px #111 rectangle, no radius,
# no shadows (except the hard lime offset on button hover), no blur, no gradients,
# no animation, no canvas backgrounds. Same CSS on every page.
CSS = """
:root{color-scheme:light;--ink:#0a0a0a;--paper:#fff;--muted:#626262;--line:#111;--soft-line:#d7d7d7;--accent:#c7ff2e;--accent-ink:#101600;--panel:#f6f6f3;--danger:#e84343;--wash:#f7ffd9;font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
*{box-sizing:border-box}
html,body{margin:0;background:var(--paper);color:var(--ink);font-family:inherit;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--soft-line);text-underline-offset:3px}
a:hover{text-decoration-color:var(--ink);background:var(--wash)}
.shell{width:min(1480px,calc(100% - 40px));margin:0 auto}
.topbar{position:sticky;top:0;z-index:10;background:rgba(255,255,255,.96)}
.ecosystem-bar{min-height:76px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.brand{display:flex;align-items:center;gap:14px;white-space:nowrap;text-decoration:none}
.brand:hover{background:transparent}
.brand-mark{width:42px;height:42px;flex:none;display:grid;place-items:center;background:var(--accent);border:2px solid var(--line);color:var(--accent-ink);font-weight:900;font-size:16px;letter-spacing:-.08em}
.brand-name{display:block;font-size:20px;font-weight:900;letter-spacing:-.04em;line-height:1.1}.brand-product{color:var(--muted);font-weight:800;letter-spacing:-.04em}
.brand-tag{display:block;text-transform:uppercase;font-size:12px;color:var(--muted);letter-spacing:.04em}
.ecosystem-nav,.local-nav{display:flex;gap:4px;align-items:center;flex-wrap:wrap}.ecosystem-nav{justify-content:center;margin-left:auto}
.ecosystem-nav a,.local-nav a{min-height:42px;display:flex;align-items:center;text-transform:uppercase;font-size:12.16px;font-weight:800;letter-spacing:.06em;padding:8px 10px;border:2px solid transparent;text-decoration:none}
.ecosystem-nav a:hover,.local-nav a:hover{background:var(--accent);border-color:var(--line)}
.ecosystem-nav a[aria-current="page"]{border-color:var(--line);background:var(--ink);color:#fff}
.local-nav a[aria-current="page"]{border-color:var(--line);background:var(--accent);color:var(--accent-ink)}
.network-status{display:flex;align-items:center;gap:7px;white-space:nowrap;font-size:11.2px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}.network-status::before{content:"";width:9px;height:9px;border:2px solid var(--line);background:var(--accent)}
.localbar{border-top:1px solid var(--soft-line);border-bottom:2px solid var(--line);background:#fff}.localbar .shell{min-height:42px;display:flex;align-items:center;justify-content:space-between;gap:12px}.local-nav a{padding:7px 9px;font-size:11.2px}
.mobile-menu{display:none;position:relative}.mobile-menu summary{list-style:none;cursor:pointer;border:2px solid var(--line);padding:7px 9px;min-height:44px;align-items:center;font-size:11.52px;font-weight:900;letter-spacing:.06em;text-transform:uppercase}.mobile-menu summary::-webkit-details-marker{display:none}.mobile-menu summary::after{content:" ●";color:#68a900}.mobile-menu[open] summary{background:var(--ink);color:#fff}.mobile-menu-panel{position:absolute;right:0;top:calc(100% + 10px);width:min(420px,calc(100vw - 22px));max-height:calc(100vh - 84px);overflow:auto;border:2px solid var(--line);background:#fff;padding:14px;box-shadow:7px 7px 0 var(--accent)}.mobile-menu-label{display:block;margin:2px 0 6px;color:var(--muted);font-size:10.4px;font-weight:900;letter-spacing:.1em;text-transform:uppercase}.mobile-menu-links{display:grid;grid-template-columns:1fr 1fr;margin-bottom:12px}.mobile-menu-links:last-child{margin-bottom:0}.mobile-menu-links a{min-height:44px;display:flex;align-items:center;padding:8px;text-decoration:none;font-size:12.48px;font-weight:800}.mobile-menu-links a[aria-current="page"]{background:var(--accent)}
main{padding:22px 0 40px}
.section{margin:0 0 22px}
.intro{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.65fr);gap:22px}
.manifesto{background:#0a0a0a;color:#fff;border:2px solid var(--line);padding:clamp(22px,3vw,40px)}
.eyebrow{color:var(--accent);font-size:.78rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase;margin:0 0 14px}
.eyebrow.dark{color:var(--accent-ink)}
.manifesto h1{font-size:clamp(2.35rem,6vw,5.9rem);line-height:.92;letter-spacing:-.08em;text-transform:uppercase;font-weight:900;margin:0 0 20px}
.manifesto h1 span{color:var(--accent)}
.lede{color:#ddd;font-size:1.02rem;max-width:62ch;margin:0 0 24px}
.cta-row{display:flex;gap:10px;flex-wrap:wrap}
.btn{display:inline-grid;place-items:center;min-height:48px;border:2px solid var(--line);padding:10px 16px;background:#fff;color:var(--ink);font:inherit;font-size:.85rem;font-weight:900;text-transform:uppercase;letter-spacing:.04em;text-decoration:none;cursor:pointer}
.btn:hover{box-shadow:6px 6px 0 var(--accent);background:#fff;color:var(--ink)}
.btn.primary{background:var(--accent);color:var(--accent-ink)}
.btn.primary:hover{background:var(--accent);color:var(--accent-ink);box-shadow:6px 6px 0 var(--ink)}
.manifesto .btn:not(.primary){background:#0a0a0a;color:#fff;border-color:#fff}
.manifesto .btn:not(.primary):hover{background:#0a0a0a;color:#fff}
.definition{background:var(--accent);color:var(--accent-ink);border:2px solid var(--line);padding:clamp(22px,3vw,34px);display:flex;flex-direction:column;justify-content:space-between;gap:8px}
.definition a{color:inherit;text-decoration-color:var(--accent-ink)}
.definition a:hover{background:#fff}
.big-number{font-size:clamp(3.2rem,7vw,6.4rem);font-weight:900;letter-spacing:-.08em;line-height:.9;margin:0;font-variant-numeric:tabular-nums}
.caption{font-size:.85rem;font-weight:700;margin:0}
.definition.compact{flex-direction:row;align-items:center;flex-wrap:wrap;gap:14px 22px;padding:18px 22px}
.definition.compact p{margin:0;font-weight:700;font-size:.95rem;flex:1 1 320px}
.workspace>.definition.compact{border:0;border-top:2px solid var(--line)}
.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:2px solid var(--line);background:#fff}
.summary-card{min-height:122px;padding:20px;border-right:1px solid var(--line);min-width:0}
.summary-card:last-child{border-right:0}
.summary-label{color:var(--muted);font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.summary-value{font-size:clamp(1.4rem,3vw,2.4rem);font-weight:900;letter-spacing:-.06em;line-height:1.05;margin:8px 0 6px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.summary-note{font-size:.78rem;color:var(--muted)}
.search{display:flex;border:2px solid var(--line);background:#fff}
.search input{flex:1;min-width:0;border:0;padding:12px 16px;font:inherit;background:#fff;color:var(--ink);outline:none}
.search input:focus{background:var(--wash)}
.search input::placeholder{color:var(--muted)}
.search button{border:0;border-left:2px solid var(--line);background:var(--accent);color:var(--accent-ink);font:inherit;font-weight:900;text-transform:uppercase;letter-spacing:.04em;padding:0 18px;cursor:pointer}
.search button:hover{background:var(--ink);color:#fff}
.workspace{border:2px solid var(--line);background:#fff}
.workspace-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 18px;background:var(--panel);border-bottom:2px solid var(--line);text-transform:uppercase;font-size:.75rem;font-weight:900;letter-spacing:.08em}
.workspace-head .meta{color:var(--muted);font-weight:700}
.workspace-head a{text-decoration:none}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th{text-align:left;text-transform:uppercase;font-size:.75rem;letter-spacing:.08em;font-weight:800;padding:12px 18px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:15px 18px;border-bottom:1px solid var(--soft-line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--wash)}
td.num,th.num{text-align:right;white-space:nowrap}
table.kv th{width:220px;font-size:.72rem;color:var(--muted);border-bottom:1px solid var(--soft-line);vertical-align:top;padding:15px 18px;white-space:normal}
table.kv tr:last-child th{border-bottom:0}
table.kv td{word-break:break-all}
.rank-badge{display:inline-grid;place-items:center;min-width:42px;height:32px;padding:0 8px;border:1px solid var(--line);background:#fff;font-weight:900;text-decoration:none}
tr.top-ten .rank-badge{background:var(--accent)}
.pill{display:inline-block;border:1px solid var(--line);background:var(--accent);color:var(--accent-ink);font-size:.62rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em;padding:3px 7px;vertical-align:middle;white-space:nowrap}
.pill.ghost{background:#fff;color:var(--muted);border-color:var(--soft-line)}
.muted{color:var(--muted)}
.hash{word-break:break-all;overflow-wrap:anywhere}
.miner-cell{display:flex;flex-direction:column;gap:2px;min-width:0}
.miner-cell b{font-weight:900}
.miner-cell a{font-size:.8rem;color:var(--muted)}
code{background:var(--panel);border:1px solid var(--soft-line);padding:2px 6px;font-family:inherit}
pre{background:var(--panel);border:2px solid var(--line);padding:16px 18px;margin:0 0 14px;overflow-x:auto;font-family:inherit;font-weight:700}
.note-panel{border:2px solid var(--line);background:#fff;padding:24px}
.note-panel h2{font-size:1rem;text-transform:uppercase;letter-spacing:.06em;margin:0 0 14px}
.note-panel p{margin:0 0 12px;max-width:72ch}
.note-panel p:last-child{margin-bottom:0}
.note-panel .kv th{width:180px}
.note-panel .table-wrap{margin:0 -24px -24px;border-top:2px solid var(--line)}
.xcoin-note{background:#0a0a0a;color:#fff}
.xcoin-note h2,.xcoin-note strong{color:var(--accent)}
.xcoin-note a{color:#fff;text-decoration-color:#555}
.xcoin-note a:hover{background:transparent;text-decoration-color:var(--accent)}
.xcoin-note code{background:#0a0a0a;color:var(--accent);border-color:#555}
.notes{display:grid;grid-template-columns:1.1fr .9fr;gap:22px}
.head-panel .eyebrow{color:var(--ink);margin-bottom:8px}
h1.h-small{font-size:clamp(1.5rem,3.2vw,2.6rem);text-transform:none;letter-spacing:-.05em;font-weight:900;line-height:1.1;margin:0;word-break:break-all;overflow-wrap:anywhere}
.head-panel .cta-row{margin-top:18px}
.head-panel .hash{margin:10px 0 0;color:var(--muted)}
.hebrew{direction:rtl;unicode-bidi:isolate;display:inline-block;max-width:100%;font-size:1.05rem;line-height:1.9}
.site-footer{padding:26px 0 46px;color:var(--muted);font-size:12px}.ecosystem-footer{display:flex;justify-content:space-between;gap:20px;border-top:2px solid var(--line);padding-top:16px;flex-wrap:wrap}.ecosystem-footer strong{display:block;color:var(--ink);font-size:13.12px;text-transform:uppercase;letter-spacing:.06em}.footer-nav{display:flex;gap:10px;flex-wrap:wrap;margin-top:5px}.footer-nav a{text-decoration:none}.footer-nav a:hover{background:var(--accent);color:var(--ink)}.ecosystem-meta{margin:0;text-align:right}.local-footer{margin-top:16px;padding-top:12px;border-top:1px solid var(--soft-line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}.site-footer a{color:inherit}
@media(max-width:900px){
  .intro,.notes{grid-template-columns:1fr}
  .summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .summary-card{border-bottom:1px solid var(--line)}
  .summary-card:nth-child(2n){border-right:0}
  .summary-card:nth-last-child(-n+2){border-bottom:0}
  table.kv th{width:140px}
}
@media(max-width:1180px) and (min-width:981px){.ecosystem-bar{gap:10px}.brand-tag{display:none}.ecosystem-nav a{font-size:11.2px;padding:7px 8px}}
@media(max-width:980px){.ecosystem-nav,.network-status,.localbar{display:none}.mobile-menu{display:block}.mobile-menu summary{display:flex}.ecosystem-bar{min-height:64px}.brand-tag{display:none}}
@media(max-width:600px){
  .shell{width:min(100% - 22px,1480px)}
  .ecosystem-bar{min-height:60px;gap:8px}.brand{gap:9px}.brand-mark{width:38px;height:38px}.brand-name{font-size:16.8px}.ecosystem-meta{text-align:left}
  .summary-grid{grid-template-columns:1fr}
  .summary-card{border-right:0;border-bottom:1px solid var(--line)}
  .summary-card:last-child{border-bottom:0}
  .nav a{padding:6px 7px;font-size:.72rem}
  .definition.compact{flex-direction:column;align-items:flex-start}
}
"""

def local_nav(path, mobile=False):
    current = ("richlist" if path == "/richlist" else
               "addresses" if path.startswith("/address/") else
               "transactions" if path.startswith("/tx/") else
               "mempool" if path == "/mempool" else "blocks")
    cls = "mobile-menu-links" if mobile else "local-nav"
    label = ' aria-label="SuperKnet mobile"' if mobile else ' aria-label="SuperKnet"'
    items = [("blocks", "/#blocks", "Blocks"), ("transactions", "/#search", "Transactions"),
             ("addresses", "/#search", "Addresses"), ("richlist", "/richlist", "Rich list"),
             ("miners", "/#miners", "Miners"), ("mempool", "/mempool", "Mempool")]
    links = "".join(f'<a href="{href}"{" aria-current=\"page\"" if key == current else ""}>{text}</a>' for key, href, text in items)
    return f'<nav class="{cls}"{label}>{links}</nav>'

def footer():
    return ('<footer class="site-footer"><div class="shell ecosystem-footer"><div><strong>xCoin Ecosystem</strong>'
            '<nav class="footer-nav" aria-label="xCoin ecosystem footer"><a href="https://xcoinproject.com/">Overview</a>'
            '<a href="https://xcoinminer.com/">Mine</a><a href="https://superknet.com/" aria-current="page">Explorer</a>'
            '<a href="https://minedifferent.com/">Community</a><a href="https://movepunk.com/" target="xat_move">Movement</a><a href="https://xcoinproject.com/docs">Docs</a></nav></div>'
            f'<p class="ecosystem-meta">xCoin (XID) · {esc(CFG["chain_label"])}<br>Built by <a href="https://distributedledgertechnologies.com/" target="xat_dlt">Distributed Ledger Technologies</a></p></div>'
            '<div class="shell local-footer"><span>SuperKnet · xCoin Explorer · every number is from the chain</span>'
            '<span><a href="https://distributedledgertechnologies.com" target="_blank" rel="noopener">DLT ↗</a></span></div></footer>')

# A local run must not report into the live site's analytics, so both third-party
# tags are off unless XCOIN_EXPLORER_PUBLIC=1.
ANALYTICS = ('<script async src="https://www.googletagmanager.com/gtag/js?id=G-05LX73T19M"></script>'
             "<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}"
             "gtag('js',new Date());gtag('config','G-05LX73T19M');</script>") if PUBLIC else ""
CHAT_EMBED = '<script src="https://minedifferent.com/embed/chat.js?v=2" defer></script>' if PUBLIC else ""

def page(title, body, path="/", script=""):
    """Shared shell: <head> (meta, analytics, CSS), sticky topbar, <main>, footer.
    `path` sets canonical/og:url; `script` is an optional inline <script> body."""
    url = f"{SITE_URL}{path}"
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · SuperKnet</title>
<meta name="description" content="{esc(DESC)}">
<link rel="canonical" href="{url}">
<link rel="icon" type="image/svg+xml" href="/favicon.svg?v={ASSET_VER}">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png?v={ASSET_VER}">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png?v={ASSET_VER}">
<link rel="apple-touch-icon" href="/apple-touch-icon.png?v={ASSET_VER}">
<link rel="shortcut icon" href="/favicon.ico?v={ASSET_VER}">
<meta name="theme-color" content="#c7ff2e">
<script src="/js/xat-instance.js?v={ASSET_VER}" data-site="xat_explorer" data-title="SuperKnet"></script>
{ANALYTICS}
<meta property="og:type" content="website">
<meta property="og:site_name" content="SuperKnet">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(DESC)}">
<meta property="og:url" content="{url}">
<meta property="og:image" content="{SITE_URL}/og-image.png?v=4">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{esc(title)}">
<meta name="twitter:description" content="{esc(DESC)}">
<meta name="twitter:image" content="{SITE_URL}/og-image.png?v=4">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"WebSite","name":"SuperKnet","url":"{SITE_URL}/","description":"{esc(DESC)}"}}</script>
<style>{CSS}</style></head><body>
<header class="topbar">
  <div class="shell ecosystem-bar">
    <a class="brand" href="https://xcoinproject.com/"><span class="brand-mark">XC</span><span><span class="brand-name">xCoin <span class="brand-product">/ SuperKnet</span></span><span class="brand-tag">xCoin Explorer</span></span></a>
    <nav class="ecosystem-nav" aria-label="xCoin ecosystem"><a href="https://xcoinproject.com/">Overview</a><a href="https://xcoinminer.com/">Mine</a><a href="https://superknet.com/" aria-current="page">Explorer</a><a href="https://minedifferent.com/">Community</a><a href="https://movepunk.com/" target="xat_move">Movement</a><a href="https://xcoinproject.com/docs">Docs</a></nav>
    <span class="network-status">{"Testnet" if CFG["chain"] == "rehearsal" else "Mainnet"}</span>
    <details class="mobile-menu"><summary>Menu</summary><div class="mobile-menu-panel"><span class="mobile-menu-label">xCoin</span><nav class="mobile-menu-links" aria-label="xCoin ecosystem mobile"><a href="https://xcoinproject.com/">Overview</a><a href="https://xcoinminer.com/">Mine</a><a href="https://superknet.com/" aria-current="page">Explorer</a><a href="https://minedifferent.com/">Community</a><a href="https://movepunk.com/" target="xat_move">Movement</a><a href="https://xcoinproject.com/docs">Docs</a></nav><span class="mobile-menu-label">SuperKnet</span>{local_nav(path, mobile=True)}</div></details>
  </div>
  <div class="localbar"><div class="shell">{local_nav(path)}</div></div>
</header>
<main class="shell">
{body}
</main>
{footer()}
{('<script>' + script + '</script>') if script else ''}
{CHAT_EMBED}</body></html>"""

def summary_card(label, value, note="", sid=""):
    val = f'<span data-s="{sid}">{value}</span>' if sid else str(value)
    return (f'<div class="summary-card"><div class="summary-label">{esc(label)}</div>'
            f'<div class="summary-value">{val}</div>'
            f'{("<div class=summary-note>" + esc(note) + "</div>") if note else ""}</div>')

def hr_fmt(hps):
    """Hash rate as (value, unit) with an adaptive unit."""
    try: hps = float(hps or 0)
    except (TypeError, ValueError): hps = 0.0
    if hps >= 1e9: return f"{hps/1e9:,.2f}", "GH/s"
    if hps >= 1e6: return f"{hps/1e6:,.2f}", "MH/s"
    if hps >= 1e3: return f"{hps/1e3:,.1f}", "kH/s"
    return f"{hps:,.0f}", "H/s"

def ago(sec):
    """Compact age: 42s · 7m · 3h · 2d."""
    try: sec = int(sec)
    except (TypeError, ValueError): return "—"
    if sec < 0: sec = 0
    if sec < 60: return f"{sec}s"
    if sec < 3600: return f"{sec//60}m"
    if sec < 86400: return f"{sec//3600}h"
    return f"{sec//86400}d"

# Home-page live refresh (replaces web/js/live.js): poll /api/stats, fill [data-s]
# cells, and ask the forum how many people are online right now.
HOME_JS = r"""
(function(){
  var $=function(s){return document.querySelector(s)};
  function fmt(n){return Number(n).toLocaleString('en-US')}
  function hr(h){h=Number(h)||0;if(h>=1e9)return (h/1e9).toFixed(2)+' GH/s';if(h>=1e6)return (h/1e6).toFixed(2)+' MH/s';if(h>=1e3)return (h/1e3).toFixed(1)+' kH/s';return Math.round(h)+' H/s'}
  function set(k,v){document.querySelectorAll('[data-s="'+k+'"]').forEach(function(e){e.textContent=v})}
  function tick(){
    fetch('/api/stats',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      set('height',fmt(d.height));
      set('supply',fmt(Math.round(d.supply)));
      set('difficulty',d.difficulty<1000?Number(d.difficulty).toFixed(4):fmt(Math.round(d.difficulty)));
      set('hashrate',hr(d.hashrate));
      set('mempool',fmt(d.mempool));
    }).catch(function(){});
  }
  var t=null;
  function startLive(){if(!document.querySelector('[data-s]')||t)return;tick();t=setInterval(tick,8000)}
  function stopLive(){clearInterval(t);t=null}
  document.addEventListener('visibilitychange',function(){if(document.hidden)stopLive();else if(!XI||XI.status==='primary')startLive()});
  var XI=window.XATInstance;
  if(XI){XI.ready.then(function(){if(XI.status==='primary')startLive();XI.onChange(function(s){if(s==='primary')startLive();else stopLive()})})}else startLive();
  var md=$('#mdOnline');
  if(md&&(!XI||XI.status!=='dormant')){
    var urls=['https://minedifferent.com/api/online','https://minedifferent.com/api/online'];
    (function next(i){
      if(i>=urls.length)return;
      fetch(urls[i],{cache:'no-store'}).then(function(r){if(!r.ok)throw 0;return r.json()}).then(function(d){
        var n=(d&&typeof d.online==='number')?d.online:(typeof d==='number'?d:null);
        if(n===null)throw 0;
        md.textContent=fmt(n)+' on the forum · ';
      }).catch(function(){next(i+1)});
    })(0);
  }
})();
"""

_CHARTER = {"t": 0.0, "d": None}
def charter():
    """`getcharter` (REGENESIS.md section 1): charter_hash, currency_id, genesis_hash,
    v1_genesis_hash, genesis_is_final. Cached — it is fixed for a given binary."""
    if _CHARTER["d"] is None or time.time() - _CHARTER["t"] > 300:
        d = rpc("getcharter")
        if d: _CHARTER["d"] = d; _CHARTER["t"] = time.time()
    return _CHARTER["d"] or {}

def tip_subsidy(tip):
    """The block subsidy at the tip, read from the chain itself (`getblockstats`), so the
    explorer never hardcodes the schedule. Falls back to the coinbase value if
    getblockstats is unavailable."""
    st = rpc("getblockstats", [tip, ["subsidy"]]) or {}
    if "subsidy" in st: return Decimal(int(st["subsidy"])) / SAT
    bh = rpc("getblockhash", [tip]); b = rpc("getblock", [bh, 2]) if bh else None
    try: return sum(Decimal(str(o["value"])) for o in b["tx"][0]["vout"])
    except Exception: return Decimal(0)

def charter_panel():
    """The network panel: chain identity, the charter commitment and the consensus rules.
    The settlement levy row appears only when LEVY_BP is non-zero (a test chain)."""
    c = charter()
    final = c.get("genesis_is_final")
    final_pill = ('<span class="pill">final</span>' if final is True else
                  '<span class="pill ghost">provisional</span>' if final is False else
                  '<span class="muted">unknown</span>')
    def row(k, v, note=""):
        return (f'<tr><th>{esc(k)}</th><td>{v}'
                f'{(" <span class=muted>· " + esc(note) + "</span>") if note else ""}</td></tr>')
    chain_note = (f'RPC {CFG["rpc_host"]}:{CFG["rpc_port"]}' + (
        " · the testnet A rehearsal; mainnet genesis is not mined yet" if CFG["chain"] == "rehearsal" else ""))
    levy_row = (row("Settlement levy", f"{LEVY_BP} bp of every transaction's outputs",
                    "consensus minimum fee, integer satoshis, rounded up") if LEVY_BP > 0 else "")
    rows = (row("Chain", f'{esc(CFG["chain_label"])} <span class="muted">· addresses {esc(CFG["hrp"])}1r…</span>',
                chain_note)
            + row("Charter hash", f'<code>{esc(c.get("charter_hash", "—"))}</code>', "SHA-256 of CHARTER.md")
            + row("Currency id", f'<code>{esc(c.get("currency_id", "—"))}</code>', "SHA-256(genesis header || charter text)")
            + row("Genesis", f'<code>{esc(c.get("genesis_hash", "—"))}</code>', "")
            + row("Genesis is final", final_pill,
                  "" if final else "provisional: do not attest or timestamp this currency id")
            + row("Proof of work", "MetalDAG", "300 s target spacing · coinbase maturity 1,000 blocks")
            + row("Block subsidy", "read from the chain at the tip", EMISSION_NOTE + f" · {CFG['max_supply']:,.0f} XID cap")
            + levy_row
            + row("Output rule", "witness v3 only", "OP_3 <32-byte Merkle root> or OP_RETURN; no witness v2 anywhere"))
    return f"""
<section class="note-panel section" id="network">
  <h2>Network</h2>
  <p>The charter commitment this node compiled in, straight from <code>getcharter</code>. The currency id
  binds the genesis header to the charter text: two chains with the same money rules but different charters
  are different currencies.</p>
  <div class="table-wrap"><table class="kv"><tbody>{rows}</tbody></table></div>
</section>
"""

# ── views ────────────────────────────────────────────────────────────────────
def view_overview():
    info = rpc("getblockchaininfo") or {}
    tip = info.get("blocks", 0)
    utxo = rpc("gettxoutsetinfo") or {}
    supply = float(utxo.get("total_amount", 0))
    diff = info.get("difficulty", 0)
    mp = rpc("getmempoolinfo") or {}
    times = []
    for h in range(max(1, tip-11), tip+1):
        bh = rpc("getblockhash", [h]);  hdr = rpc("getblockheader", [bh]) if bh else None
        if hdr: times.append(hdr["time"])
    spacing = round((times[-1]-times[0])/max(1,len(times)-1)) if len(times) > 1 else 0
    hashrate = rpc("getnetworkhashps") or 0
    subsidy = tip_subsidy(tip)
    pct = min(100, supply/CFG["max_supply"]*100)
    diff_txt = f"{diff:,.4f}" if diff < 1000 else f"{diff:,.0f}"
    hr_v, hr_u = hr_fmt(hashrate)
    # worker names from the pool's persistent miner registry (address -> {worker,...})
    try:
        with open(POOL_MINERS_FILE) as f:
            _workers = {a: (m.get("worker") or "default") for a, m in json.load(f).items()}
    except Exception:
        _workers = {}
    # ── Latest blocks (12): height / hash / miner / txs / size / age
    rows = ""
    _now = int(time.time())
    for h in range(tip, max(-1, tip-12), -1):
        bh = rpc("getblockhash", [h]);  b = rpc("getblock", [bh, 2]) if bh else None
        if not b: continue
        who = coinbase_recipient(b)
        if who and who != "—":
            w = _workers.get(who)
            miner = (f'<div class="miner-cell">{("<b>" + esc(w) + "</b>") if w else ""}'
                     f'<a class="hash" href="/address/{esc(who)}">{short(who,14)}</a></div>')
        else:
            miner = '<span class="muted">—</span>'
        rows += (f'<tr><td><a class="rank-badge" href="/block/{h}">{h:,}</a></td>'
                 f'<td><a class="hash" href="/block/{bh}">{short(bh,12)}</a></td>'
                 f'<td>{miner}</td><td class="num">{b.get("nTx", len(b.get("tx",[])))}</td>'
                 f'<td class="num">{b.get("size",0):,} B</td><td class="num muted">{ago(_now - b["time"])} ago</td></tr>')
    rows = rows or '<tr><td colspan=6 class=muted>no blocks yet</td></tr>'
    # ── Top miners (chain truth: coinbase credits counted by the indexer)
    with IDX_LOCK:
        top = sorted(MINERS.items(), key=lambda x:-x[1])[:10]
        total_mined = sum(MINERS.values()) or 1
    mrows = ""
    for i, (a, c) in enumerate(top, 1):
        w = _workers.get(a)
        mrows += (f'<tr{" class=top-ten" if i <= 3 else ""}><td><span class="rank-badge">{i}</span></td>'
                  f'<td><div class="miner-cell">{("<b>" + esc(w) + "</b>") if w else ""}'
                  f'<a class="hash" href="/address/{esc(a)}">{short(a,14)}</a></div></td>'
                  f'<td class="num">{c:,}</td><td class="num muted">{c/total_mined*100:.1f}%</td></tr>')
    mrows = mrows or '<tr><td colspan=4 class=muted>no miners yet</td></tr>'
    # ── Active rigs: every miner registered at a pool (native Mac pool + browser pool),
    #    lifetime totals, sorted by blocks then shares. Top 3 rows get .top-ten.
    _ps = {}
    try:
        with open(POOL_STATS_FILE) as f:
            _ps = json.load(f)
    except Exception:
        _ps = {}
    # ── Community-pool stats — native rigs (local pool) + browser miners (VPS pool),
    #    merged so web miners are counted. Blocks come from the CHAIN (coinbase credit
    #    to pool addresses), never a cumulative counter, so the figure can't exceed the
    #    tip or count wiped/orphaned blocks (the old counter reported 620 on a 436 chain).
    _wps = web_pool_stats()
    _nat_lb = _ps.get("leaderboard", [])       # native rigs (local pool file)
    _web_lb = _wps.get("leaderboard", [])      # browser miners (VPS pool)
    _all_lb = _nat_lb + _web_lb
    _tnow = int(time.time())
    def _active(lb, ps):
        v = ps.get("active_miners")
        return v if isinstance(v, int) else sum(1 for r in lb if r.get("last", 0) > _tnow - 300)
    nat_active = _active(_nat_lb, _ps); web_active = _active(_web_lb, _wps)
    pool_active = nat_active + web_active
    pool_total = ((_ps.get("total_miners") or len(_nat_lb))
                  + (_wps.get("total_miners") or len(_web_lb)))
    pool_hr = (_ps.get("hashrate_hps", 0) or 0) + (_wps.get("hashrate_hps", 0) or 0)
    pool_shares = sum(r.get("shares", 0) for r in _all_lb)
    _pool_addrs = {r.get("address") for r in _all_lb if r.get("address")}
    with IDX_LOCK:
        pool_blocks = sum(MINERS.get(a, 0) for a in _pool_addrs)
    pool_blocks = min(pool_blocks, tip)        # chain-truth, hard-capped at the tip
    _phv, _phu = hr_fmt(pool_hr)
    prows = ""
    _lb = sorted((r for r in _all_lb if r.get("address")),
                 key=lambda r: (-(r.get("blocks", 0) or 0), -(r.get("shares", 0) or 0), -(r.get("last", 0) or 0)))
    for i, r in enumerate(_lb, 1):
        on = (r.get("last", 0) or 0) > _tnow - 300
        seen = '<span class="pill">live</span>' if on else f'<span class="muted">{ago(_tnow - (r.get("last", 0) or 0))} ago</span>'
        prows += (f'<tr{" class=top-ten" if i <= 3 else ""}><td><span class="rank-badge">{i}</span></td>'
                  f'<td><div class="miner-cell"><b>{esc(r.get("worker") or "default")}</b>'
                  f'<a class="hash" href="/address/{esc(r["address"])}">{short(r["address"],14)}</a></div></td>'
                  f'<td class="num">{(r.get("blocks", 0) or 0):,}</td><td class="num">{(r.get("shares", 0) or 0):,}</td>'
                  f'<td class="num">{(r.get("hashrate_mhs", 0) or 0):.2f} MH/s</td><td class="num">{seen}</td></tr>')
    prows = prows or '<tr><td colspan=6 class=muted>no rigs yet — yours could be the first</td></tr>'
    if CFG["chain"] == "rehearsal":
        eyebrow = "xCoin · testnet A rehearsal"
        chain_lede = (f"This explorer serves the <strong>testnet A rehearsal</strong> (addresses {esc(CFG['hrp'])}1r…). "
                      "Mainnet genesis is not mined yet.")
    else:
        eyebrow = "xCoin · mainnet"
        chain_lede = f"This explorer serves <strong>mainnet</strong> (addresses {esc(CFG['hrp'])}1r…)."
    body = f"""
<section class="intro section">
  <div class="manifesto">
    <p class="eyebrow">{eyebrow}</p>
    <h1>The chain, in the open. <span>Join the miners.</span></h1>
    <p class="lede">Every block, every miner, every share, from the node itself. {chain_lede} If you own a Mac you can be on this leaderboard tonight.</p>
    <div class="cta-row">
      <a class="btn primary" href="https://xcoinminer.com">Mine xCoin</a>
      <a class="btn" href="https://minedifferent.com">Join the forum</a>
      <a class="btn" href="#node">Run a node</a>
    </div>
  </div>
  <div class="definition">
    <p class="eyebrow dark">Rigs mining now</p>
    <p class="big-number">{pool_active:,}</p>
    <p class="caption"><span id="mdOnline"></span><span data-s="hashrate">{hr_v} {hr_u}</span> network</p>
  </div>
</section>
<section class="summary-grid section">
  {summary_card("Height", f"{tip:,}", "blocks on chain", sid="height")}
  {summary_card("Network hashrate", f"{hr_v} {hr_u}", "estimate from recent blocks", sid="hashrate")}
  {summary_card("Difficulty", diff_txt, "retargets every block", sid="difficulty")}
  {summary_card("Supply", f"{supply:,.0f}", f"of {CFG['max_supply']:,.0f} XID", sid="supply")}
</section>
<section class="summary-grid section">
  {summary_card("Block reward", f"{subsidy:,.8f}".rstrip("0").rstrip("."), "XID · era subsidy at the tip, from the chain")}
  {summary_card("Avg block", f"{spacing}s", "last 12 · target 300s")}
  {summary_card("Mempool", f"{mp.get('size',0):,}", "pending transactions", sid="mempool")}
  {summary_card("Mined", f"{pct:.3f}%", "of the cap · no premine")}
</section>
<form class="search section" id="search" action="/search"><input name="q" placeholder="search block height / hash / txid / {CFG['hrp']}1r address" autocomplete="off" spellcheck="false"><button type="submit">Find</button></form>
<section class="workspace section" id="miners">
  <div class="workspace-head"><span>Active rigs · lifetime totals</span><span class="meta">{pool_active:,} live · {pool_total:,} all-time · pool pays your address · 0% fee</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Miner</th><th class="num">Blocks</th><th class="num">Shares</th><th class="num">Hashrate</th><th class="num">Last seen</th></tr></thead>
    <tbody>{prows}</tbody>
  </table></div>
  <div class="definition compact">
    <p>Not on this list yet? Mine from your browser in 30 seconds → <a href="https://xcoinminer.com">xcoinminer.com</a></p>
    <a class="btn" href="https://xcoinminer.com">Start mining</a>
  </div>
</section>
<section class="workspace section" id="blocks">
  <div class="workspace-head"><span>Latest blocks</span><span class="meta">tip {tip:,} · {spacing}s avg spacing</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Height</th><th>Hash</th><th>Miner</th><th class="num">Txs</th><th class="num">Size</th><th class="num">Age</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Top miners · blocks on chain</span><span class="meta">coinbase credits counted by this explorer's own index</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Miner</th><th class="num">Blocks</th><th class="num">Share</th></tr></thead>
    <tbody>{mrows}</tbody>
  </table></div>
</section>
<section class="notes section">
  <div class="note-panel">
    <h2>Browser miners</h2>
    <p>The community pool takes native Mac rigs and in-browser miners alike. 0% fee, pays straight to your address, blocks counted from the chain.</p>
    <div class="table-wrap"><table class="kv"><tbody>
      <tr><th>Pool hashrate</th><td>{_phv} {_phu}</td></tr>
      <tr><th>Active miners</th><td>{pool_active:,} <span class="muted">of {pool_total:,} all-time</span></td></tr>
      <tr><th>Browser miners</th><td>{web_active:,} <span class="muted">mining in-browser now</span></td></tr>
      <tr><th>Pool shares</th><td>{pool_shares:,} <span class="muted">cumulative</span></td></tr>
      <tr><th>Blocks found</th><td>{pool_blocks:,} <span class="muted">on this chain</span></td></tr>
      <tr><th>Fee</th><td>0% <span class="muted">forever · pays your address</span></td></tr>
    </tbody></table></div>
  </div>
  <div class="note-panel xcoin-note">
    <h2>Join the community</h2>
    <p><strong>Mine:</strong> <a href="https://xcoinminer.com">xcoinminer.com</a>, browser or native Mac.</p>
    <p><strong>Talk:</strong> <a href="https://minedifferent.com">minedifferent.com</a>, sign in with NerdMiner login (your xCoin identity), no passwords.</p>
    <p><strong>Post your rig:</strong> <a href="https://minedifferent.com">one thread per Mac model</a>, your hashrate on the record.</p>
    <p><strong>Run a node:</strong> <a href="#node"><code>{esc(NODE_HINT)}</code></a> in your <code>nex.conf</code>.</p>
  </div>
</section>
{charter_panel()}
<section class="note-panel section" id="node">
  <h2>Run a node</h2>
  <pre>{esc(NODE_HINT)}</pre>
  <p>One line in your <code>nex.conf</code> points a fresh node at a peer on this chain; it syncs from there and discovers the rest of the network on its own. Every number on this page comes from a node exactly like it.</p>
</section>
"""
    return page("xCoin Explorer", body, script=HOME_JS)

def api_stats():
    info = rpc("getblockchaininfo") or {}
    utxo = rpc("gettxoutsetinfo") or {}
    mp = rpc("getmempoolinfo") or {}
    with IDX_LOCK:
        series = [{"h": s["height"], "d": s["difficulty"]} for s in SERIES[-120:]]
    return {
        "height": info.get("blocks", 0),
        "supply": float(utxo.get("total_amount", 0)),
        "difficulty": info.get("difficulty", 0),
        "hashrate": rpc("getnetworkhashps") or 0,
        "mempool": mp.get("size", 0),
        "series": series,
        "chain": CFG["chain"],
        "hrp": CFG["hrp"],
        "levy_bp": LEVY_BP,
        "charter": charter(),
    }

# ---- Nerd Miner: rig telemetry + address balances (additive, optional) ----
def _rigs():
    """Latest Mac-health samples written by rig-agent.py, keyed by worker."""
    try:
        with open(RIG_STATS_FILE) as f:
            d = json.load(f)
        return {w: r for w, r in d.items() if isinstance(r, dict)}
    except Exception:
        return {}

_BAL_CACHE = {}   # address -> (ts, amount)
def _balances(addrs, ttl=30):
    """XID balance per distinct address (scantxoutset on its scriptPubKey), cached `ttl` seconds."""
    out, now = {}, time.time()
    for a in {x for x in addrs if x}:
        c = _BAL_CACHE.get(a)
        if c and now - c[0] < ttl:
            out[a] = c[1]; continue
        amt = None
        try:
            spk = (rpc("validateaddress", [a]) or {}).get("scriptPubKey")
            if spk:
                scan = rpc("scantxoutset", ["start", [{"desc": f"raw({spk})"}]]) or {}
                amt = float(scan.get("total_amount", 0) or 0)
        except Exception:
            pass
        _BAL_CACHE[a] = (now, amt); out[a] = amt
    return out


def api_block(key):
    """Read-only JSON of one block (getblock verbosity 2) by hash or height.
    Used by the public README's verify-it-yourself recipes; works for genesis too."""
    key = (key or "").strip()
    if len(key) == 64 and all(c in "0123456789abcdef" for c in key.lower()):
        bh = key.lower()
    elif key.isdigit() and len(key) <= 9:
        bh = rpc("getblockhash", [int(key)])
    else:
        return None
    return rpc("getblock", [bh, 2]) if bh else None

def api_network():
    # Chain stats + pool miner registry + collective MetalDAG "nerd stats".
    info = rpc("getblockchaininfo") or {}
    utxo = rpc("gettxoutsetinfo") or {}
    chain_hps = float(rpc("getnetworkhashps") or 0)       # rough chain estimate
    pool = {}
    try:
        with open(POOL_STATS_FILE) as f:
            pool = json.load(f)
    except Exception:
        pool = {}
    # Prefer the pool's ACTUAL hashrate (from submitted shares) — accurate + realtime;
    # fall back to the chain estimate only when no miners are submitting.
    pool_hps = float(pool.get("hashrate_hps", 0) or 0)
    hashps = pool_hps if pool_hps > 0 else chain_hps
    bandwidth_gbs = hashps * 8192.0 / 1e9                  # 64 accesses x 128 B per hash
    dag_reads = hashps * 64.0
    return {
        "height": info.get("blocks", 0),
        "supply": float(utxo.get("total_amount", 0)),
        "difficulty": info.get("difficulty", 0),
        "hashrate_mhs": hashps / 1e6,
        "bandwidth_gbs": bandwidth_gbs,
        "dag_reads_per_sec": dag_reads,
        "active_miners": pool.get("active_miners", 0),
        "total_miners": pool.get("total_miners", 0),
        "leaderboard": pool.get("leaderboard", []),
        "updated": pool.get("updated", 0),
        "rigs": _rigs(),
        "balances": _balances([r.get("address") for r in pool.get("leaderboard", [])]),
    }

def view_mempool():
    """Pending transactions: txid, vsize, fee. A levy column appears only when LEVY_BP is non-zero."""
    ids = rpc("getrawmempool") or []
    with_levy = LEVY_BP > 0
    rows = ""
    for txid in ids[:50]:
        e = rpc("getmempoolentry", [txid]) or {}
        fee_sats = to_sats(e.get("fees", {}).get("base", 0))
        levy_cell = ""
        if with_levy:
            t = rpc("getrawtransaction", [txid, True])
            levy = settlement_levy(sum(to_sats(o["value"]) for o in t["vout"])) if t else None
            levy_cell = '<td class="num">' + ('<span class="muted">—</span>' if levy is None else
                        f'{sats_xat(levy)} XID' + (' <span class="pill">below levy</span>' if fee_sats < levy else '')) + '</td>'
        rows += (f'<tr><td><a class="hash" href="/tx/{txid}">{short(txid,18)}</a></td>'
                 f'<td class="num">{e.get("vsize","?")} vB</td>'
                 f'<td class="num">{sats_xat(fee_sats)} XID</td>{levy_cell}</tr>')
    meta = f"showing {min(len(ids),50):,} of {len(ids):,}" + (f" · levy = {LEVY_BP} bp of the outputs" if with_levy else "")
    levy_head = '<th class="num">Levy required</th>' if with_levy else ""
    body = f"""
<section class="note-panel head-panel section">
  <p class="eyebrow">Mempool</p>
  <h1 class="h-small">{len(ids):,} pending</h1>
  <p class="hash">Unconfirmed transactions waiting for a block.</p>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Transactions</span><span class="meta">{meta}</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>TXID</th><th class="num">vsize</th><th class="num">Fee</th>{levy_head}</tr></thead>
    <tbody>{rows or '<tr><td colspan=4 class=muted>mempool is empty — all caught up</td></tr>'}</tbody>
  </table></div>
</section>
"""
    return page("Mempool", body, path="/mempool")

def coinbase_recipient(b):
    try:
        for o in b["tx"][0]["vout"]:
            spk = o["scriptPubKey"]
            if spk.get("hex") != FOUNDER_SPK and o["value"] > 0:
                return spk.get("address") or spk.get("hex","")
    except: pass
    return "—"

def view_block(key):
    bh = key if len(key) == 64 else rpc("getblockhash", [int(key)]) if key.lstrip("-").isdigit() else None
    b = rpc("getblock", [bh, 2]) if bh else None
    if not b: return page("Block not found", error_panel("Block not found", "No block with that height or hash on this chain."))
    tip = rpc("getblockcount") or b["height"]
    nav = ""
    if b["height"] > 0: nav += f'<a class="btn" href="/block/{b["height"]-1}">‹ #{b["height"]-1:,}</a>'
    if b["height"] < tip: nav += f'<a class="btn" href="/block/{b["height"]+1}">#{b["height"]+1:,} ›</a>'
    refresh_index()
    txrows = ""
    for t in b["tx"]:
        out = sum(o["value"] for o in t["vout"])
        cb = "coinbase" in t.get("vin",[{}])[0] if t.get("vin") else False
        v3 = any(o["scriptPubKey"].get("type") == "witness_v3_pq"
                 or (o["scriptPubKey"].get("hex", "").startswith("5320") and len(o["scriptPubKey"].get("hex", "")) == 68)
                 for o in t["vout"])
        with IDX_LOCK:
            m = TXMETA.get(t["txid"])
        if cb or m is None:
            feecell = '<span class="muted">—</span>'
        elif m["fee"] is None:
            feecell = (f'<span class="muted">levy {sats_xat(m["levy"])}</span>' if LEVY_BP > 0
                       else '<span class="muted">not resolved</span>')
        else:
            short_pay = LEVY_BP > 0 and m["fee"] < m["levy"]
            feecell = (f'{sats_xat(m["fee"])} XID'
                       + (' <span class="pill">below levy</span>' if short_pay else ''))
        pills = ("<span class=pill>coinbase</span>" if cb else "") + (" <span class=pill>witness v3</span>" if v3 else "")
        txrows += (f'<tr><td><a class="hash" href="/tx/{t["txid"]}">{short(t["txid"],14)}</a></td>'
                   f'<td class="num">{len(t["vin"])}</td><td class="num">{len(t["vout"])}</td>'
                   f'<td class="num">{xat(out)} XID</td><td class="num">{feecell}</td><td>{pills}</td></tr>')
    with IDX_LOCK:
        blk_fee, blk_levy, blk_known = block_fees(b)
    fees_paid = (sats_xat(blk_fee) + " XID paid") if blk_known else "not fully indexed"
    if LEVY_BP > 0:
        fee_row = (f'<tr><th>Fees / levy</th><td>{fees_paid} <span class="muted">· {sats_xat(blk_levy)} XID '
                   f'required by the {LEVY_BP} bp settlement levy</span></td></tr>')
    else:
        fee_row = f'<tr><th>Fees</th><td>{fees_paid}</td></tr>'
    who = coinbase_recipient(b)
    mined_to = f'<a href="/address/{esc(who)}">{esc(who)}</a>' if is_v3_address(who) else esc(who)
    body = f"""
<section class="note-panel head-panel section">
  <p class="eyebrow">Block</p>
  <h1 class="h-small">#{b['height']:,}</h1>
  <p class="hash">{esc(b['hash'])}</p>
  <div class="cta-row">{nav}<a class="btn" href="/api/block/{b['height']}">JSON</a></div>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Header</span><span class="meta">{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(b['time']))}</span></div>
  <div class="table-wrap"><table class="kv"><tbody>
    <tr><th>Hash</th><td>{esc(b['hash'])}</td></tr>
    <tr><th>Time</th><td>{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(b['time']))} <span class="muted">· {ago(int(time.time()) - b['time'])} ago</span></td></tr>
    <tr><th>Confirmations</th><td>{b.get('confirmations',0):,}</td></tr>
    <tr><th>Transactions</th><td>{b['nTx']}</td></tr>
    <tr><th>Size / weight</th><td>{b['size']:,} B / {b.get('weight',0):,} WU</td></tr>
    <tr><th>Difficulty</th><td>{b['difficulty']:,.6f}</td></tr>
    <tr><th>Bits / nonce</th><td>{b['bits']} / {b['nonce']}</td></tr>
    <tr><th>Merkle root</th><td>{esc(b['merkleroot'])}</td></tr>
    <tr><th>Mined to</th><td>{mined_to}</td></tr>
    {fee_row}
  </tbody></table></div>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Transactions</span><span class="meta">{b['nTx']}</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>TXID</th><th class="num">In</th><th class="num">Out</th><th class="num">Value</th><th class="num">Fee</th><th></th></tr></thead>
    <tbody>{txrows}</tbody>
  </table></div>
</section>
"""
    return page(f"Block #{b['height']}", body, path=f"/block/{b['height']}")

def prevout_of(vin):
    """(address, sats) of one spent output, resolved through the explorer's own txid index
    so the node needs no txindex. Returns (None, None) when it cannot be resolved."""
    ptxid, n = vin.get("txid"), vin.get("vout")
    if ptxid is None or n is None: return (None, None)
    pv = vin.get("prevout")                      # present with getblock verbosity 3
    if pv: return (out_address(pv), to_sats(pv.get("value", 0)))
    pbh = TXIDX.get(ptxid)
    pt = rpc("getrawtransaction", [ptxid, True, pbh]) if pbh else rpc("getrawtransaction", [ptxid, True])
    try:
        o = pt["vout"][n]
        return (out_address(o), to_sats(o["value"]))
    except Exception:
        return (None, None)

def decode_v3_witness(items):
    """Decode a witness v3 spend from its witness stack: [stack items…] [leaf script]
    [control block] [annex]?  (REGENESIS.md section 4). The control block is
    leaf_version(1) || XCOIN_V3_NOKEY(32) || path(32 × m), so its length gives the depth
    of the tree the spender revealed. Returns None when the stack is not a v3 spend."""
    if not items: return None
    stack = list(items)
    annex = False
    if len(stack) >= 2 and stack[-1].startswith("50"):
        annex = True; stack = stack[:-1]
    if len(stack) < 2: return None
    try:
        control = bytes.fromhex(stack[-1]); script = bytes.fromhex(stack[-2])
    except ValueError:
        return None
    if len(control) < 33 or (len(control) - 33) % 32 or control[1:33] != XCOIN_V3_NOKEY:
        return None
    version = control[0] & 0xfe
    depth = (len(control) - 33) // 32
    root = leaf_hash(version, script)
    for i in range(depth):
        root = branch_hash(root, control[33 + 32 * i: 65 + 32 * i])
    return {"leaf_version": version, "leaf": LEAF_NAMES.get(version, f"unknown leaf version 0x{version:02x}"),
            "depth": depth, "single_leaf": depth == 0, "annex": annex,
            "script": script.hex(), "root": root.hex()}

def decode_inscription(spk):
    """The UTF-8 text of an OP_RETURN payload when it is Hebrew scripture, else None."""
    if spk.get("type") != "nulldata": return None
    try:
        raw = bytes.fromhex(spk.get("hex", ""))
        if raw[:1] != b"\x6a": return None
        op = raw[1]
        off = 2 if op < 0x4c else (3 if op == 0x4c else (4 if op == 0x4d else 6))
        text = raw[off:].decode("utf-8")
        return text if any("\u0590" <= c <= "\u05ff" for c in text) else None
    except (ValueError, IndexError, UnicodeDecodeError):
        return None

def view_tx(txid):
    refresh_index()
    bh = TXIDX.get(txid)
    t = rpc("getrawtransaction", [txid, True, bh]) if bh else rpc("getrawtransaction", [txid, True])
    if not t: return page("Tx not found", error_panel("Transaction not found", "Coinbase/older txids may need the index to catch up."))
    cb = bool(t["vin"]) and "coinbase" in t["vin"][0]
    # ── inputs, and with them the fee: sum(inputs) - sum(outputs) ────────────
    inrows = ""
    in_sats, in_known = 0, True
    if cb:
        inrows = '<tr><td colspan="3"><span class="pill">coinbase</span> newly minted</td></tr>'
    else:
        for vin in t["vin"][:200]:
            addr, sats = prevout_of(vin)
            if sats is None: in_known = False
            else: in_sats += sats
            who = (f'<a class="hash" href="/address/{esc(addr)}">{short(addr, 14)}</a>' if addr
                   else '<span class="muted">unresolved</span>')
            w = decode_v3_witness(vin.get("txinwitness") or [])
            if w:
                who += (f'<div class="muted">{esc(w["leaf"])} · '
                        + ("single leaf" if w["single_leaf"] else f'{w["depth"]}-deep path')
                        + ("· annex" if w["annex"] else "") + "</div>")
            inrows += (f'<tr><td><a class="hash" href="/tx/{esc(vin.get("txid",""))}">{short(vin.get("txid",""),12)}</a>'
                       f':{esc(vin.get("vout",""))}</td><td>{who}</td>'
                       f'<td class="num">{(sats_xat(sats) + " XID") if sats is not None else "—"}</td></tr>')
        if len(t["vin"]) > 200: in_known = False
    # ── outputs ─────────────────────────────────────────────────────────────
    outrows = ""
    out_sats = 0
    v3_outs = 0
    for o in t["vout"]:
        spk = o["scriptPubKey"]
        sats = to_sats(o["value"])
        out_sats += sats
        addr = out_address(o)
        hexspk = spk.get("hex", "")
        v3 = spk.get("type") == "witness_v3_pq" or (hexspk.startswith("5320") and len(hexspk) == 68)
        v2 = spk.get("type") == "witness_v2_pq" or (hexspk.startswith("5220") and len(hexspk) == 68)
        if v3: v3_outs += 1
        inscribed = decode_inscription(spk)
        if inscribed is not None:
            tgt = f'<span class="hebrew" dir="rtl" lang="he">{esc(inscribed)}</span>'
        elif addr:
            tgt = f'<a class="hash" href="/address/{esc(addr)}">{esc(addr)}</a>'
        else:
            tgt = f'<span class="muted">{esc(spk.get("type",""))}</span>'
        pills = ""
        if v3: pills += ' <span class="pill">witness v3</span>'
        if v2: pills += ' <span class="pill ghost">witness v2 · not spendable here</span>'
        outrows += f'<tr><td>{tgt}{pills}</td><td class="num">{sats_xat(sats)} XID</td></tr>'
    # ── the fee, and the settlement levy when a test chain has one (LEVY_BP > 0) ──
    with_levy = LEVY_BP > 0 and not cb
    levy = settlement_levy(out_sats) if with_levy else 0
    fee = (in_sats - out_sats) if (in_known and not cb) else None
    if cb:
        fee_rows = '<tr><th>Fee</th><td><span class="muted">coinbase — mints the subsidy, pays no fee</span></td></tr>'
        if LEVY_BP > 0:
            fee_rows += '<tr><th>Levy required</th><td><span class="muted">none: the levy applies to non-coinbase transactions</span></td></tr>'
        fee_meta = "coinbase"
    else:
        verdict = ""
        if fee is None:
            feecell = '<span class="muted">not resolvable from this node</span>'
            fee_meta = "fee not resolved"
        else:
            feecell = f'<strong>{sats_xat(fee)} XID</strong>'
            fee_meta = f"fee {sats_xat(fee)} XID"
            if with_levy:
                if fee < levy:
                    verdict = ' <span class="pill">below the levy</span>'
                else:
                    over = fee - levy
                    verdict = (' <span class="pill">levy met</span>'
                               + (f' <span class="muted">· {sats_xat(over)} XID above it</span>' if over else ''))
        fee_rows = f'<tr><th>Fee paid</th><td>{feecell}{verdict}</td></tr>'
        if with_levy:
            fee_rows += (f'<tr><th>Levy required</th><td>{sats_xat(levy)} XID '
                         f'<span class="muted">· ceil({LEVY_BP} × {out_sats:,} / {LEVY_DENOMINATOR:,}) sat, '
                         f'{LEVY_BP} bp of the outputs</span></td></tr>')
            fee_meta = f"levy {sats_xat(levy)} XID"
    body = f"""
<section class="note-panel head-panel section">
  <p class="eyebrow">Transaction</p>
  <h1 class="h-small">{esc(t['txid'])}</h1>
  <p class="hash">{'in block <a href="/block/' + bh + '">' + short(bh,14) + '</a>' if bh else 'mempool / unindexed'}{' · <span class=pill>coinbase</span>' if cb else ''}{f' · <span class=pill>{v3_outs} witness v3 outputs</span>' if v3_outs else ''}</p>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Details</span><span class="meta">{sats_xat(out_sats)} XID out · {fee_meta}</span></div>
  <div class="table-wrap"><table class="kv"><tbody>
    <tr><th>TXID</th><td>{esc(t['txid'])}</td></tr>
    <tr><th>Block</th><td>{('<a href="/block/'+bh+'">'+esc(bh)+'</a>') if bh else '<span class=muted>mempool / unindexed</span>'}</td></tr>
    <tr><th>Size / vsize</th><td>{t.get('size',0):,} B / {t.get('vsize',0):,} vB</td></tr>
    <tr><th>Total in</th><td>{(sats_xat(in_sats) + ' XID') if (in_known and not cb) else '<span class=muted>—</span>'}</td></tr>
    <tr><th>Total out</th><td><strong>{sats_xat(out_sats)} XID</strong></td></tr>
    {fee_rows}
  </tbody></table></div>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Inputs</span><span class="meta">{len(t['vin'])}</span></div>
  <div class="table-wrap"><table><thead><tr><th>Outpoint</th><th>From</th><th class="num">Value</th></tr></thead><tbody>{inrows}</tbody></table></div>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Outputs</span><span class="meta">{len(t['vout'])}</span></div>
  <div class="table-wrap"><table><thead><tr><th>To</th><th class="num">Value</th></tr></thead><tbody>{outrows}</tbody></table></div>
</section>
"""
    return page("Transaction", body, path=f"/tx/{esc(t['txid'])}")

def v1_refusal_page(conv):
    """A witness v2 xpa1z / txa1z string is not payable on this chain (witness v3 only).
    Show what it encodes and send the reader to the witness v3 address of the SAME key."""
    v3 = conv["v3"]
    other_chain = ""
    if conv["hrp"] != CFG["hrp"]:
        mine = convert_v1_address(conv["v1"], hrp=CFG["hrp"])["v3"]
        other_chain = (f'<p><strong>Different chain.</strong> <code>{esc(conv["hrp"])}</code> is not this '
                       f'chain\'s prefix. The same key on this chain reads '
                       f'<a href="/address/{esc(mine)}"><code>{esc(mine)}</code></a>.</p>')
    body = f"""
<section class="note-panel head-panel section">
  <p class="eyebrow">Witness v2 string</p>
  <h1 class="h-small">{esc(conv["v1"])}</h1>
  <p class="hash"><span class="pill ghost">witness v2</span> not payable on this chain</p>
  <div class="cta-row"><a class="btn primary" href="/address/{esc(v3)}">Open the witness v3 address</a></div>
</section>
<section class="note-panel section">
  <h2>Witness v3 only</h2>
  <p>Every spendable output on this chain is witness v3: <code>OP_3 &lt;32-byte Merkle root&gt;</code>. A
  witness v2 string names a bare ML-DSA-65 key hash and nothing here can pay it. The same key does have an
  address on this chain: its <strong>single-leaf witness v3 form</strong>, one ML-DSA-65 leaf (version
  <code>0xc0</code>) over the script <code>0x20 &lt;key hash&gt; OP_CHECKSIG</code>. A one-leaf tree's root
  is its leaf hash, so the key, the key hash, the sighash and the signature are the same — only the
  envelope differs.</p>
  <p>Pay the witness v3 address, never the <code>{esc(conv["hrp"])}1z…</code> string.</p>
  {other_chain}
  <div class="table-wrap"><table class="kv"><tbody>
    <tr><th>Witness v2 string</th><td><code>{esc(conv["v1"])}</code></td></tr>
    <tr><th>Key hash</th><td><code>{esc(conv["key_hash"])}</code> <span class="muted">· SHA-256 of the ML-DSA-65 public key</span></td></tr>
    <tr><th>Witness v2 script</th><td><code>{esc(conv["v1_script"])}</code> <span class="muted">· OP_2 &lt;H&gt;</span></td></tr>
    <tr><th>Merkle root</th><td><code>{esc(conv["program"])}</code> <span class="muted">· tagged_hash("XCoinLeaf", 0xc0 || 0x22 || 0x20 || H || 0xac)</span></td></tr>
    <tr><th>Witness v3 address</th><td><a href="/address/{esc(v3)}"><code>{esc(v3)}</code></a></td></tr>
    <tr><th>Witness v3 script</th><td><code>{esc(conv["v3_script"])}</code> <span class="muted">· OP_3 &lt;R&gt;</span></td></tr>
  </tbody></table></div>
</section>
"""
    return page("Witness v2 string", body, path=f"/address/{esc(conv['v1'])}")

def view_address(addr, came_from=None):
    addr = (addr or "").strip()
    # A witness v2 string is not payable here; map it to the witness v3 address of the same key.
    conv = convert_v1_address(addr)          # same prefix in, same prefix out: an honest mapping
    if conv: return v1_refusal_page(conv)
    v = rpc("validateaddress", [addr])
    if not v or not v.get("isvalid"):
        note = (v or {}).get("error") or "That is not a valid xCoin address on this chain."
        return page("Invalid address", error_panel("Invalid address", note))
    spk = v["scriptPubKey"]
    program = v3_program_of(addr)
    scan = rpc("scantxoutset", ["start", [{"desc": f"raw({spk})"}]]) or {}
    utxos = scan.get("unspents", [])
    bal = scan.get("total_amount", 0)
    refresh_index()
    with IDX_LOCK:
        hist = list(ADDRIDX.get(addr, []))
        mined = MINERS.get(addr, 0)
    a = esc(addr)
    kind = "witness v3 · post-quantum" if program else esc(v.get("type", ""))
    if program:
        badge = '<span class="pill">witness v3</span>'
        tree = ('Script tree committed by the 32-byte Merkle root below; its leaves are revealed '
                'only when a coin here is spent.')
    else:
        badge = ""
        tree = ""
    from_row = ""
    if came_from and is_v1_address(came_from):
        from_row = (f'<tr><th>Witness v2 string</th><td><code>{esc(came_from)}</code> '
                    f'<span class="muted">· not payable on this chain; this page is the witness v3 '
                    f'address of the same key</span></td></tr>')
    rows = ""
    for u in sorted(utxos, key=lambda x:-x.get("height",0))[:200]:
        rows += (f'<tr><td><a class="hash" href="/tx/{u["txid"]}">{short(u["txid"],14)}</a>:{u["vout"]}</td>'
                 f'<td class="num"><a href="/block/{u.get("height","")}">{u.get("height","")}</a></td>'
                 f'<td class="num">{xat(u["amount"])} XID</td></tr>')
    hrows = ""
    for e in hist[:120]:
        age = int(time.time()) - e["time"]
        hrows += (f'<tr><td><a class="hash" href="/tx/{e["txid"]}">{short(e["txid"],16)}</a></td>'
                  f'<td class="num"><a href="/block/{e["height"]}">{e["height"]}</a></td>'
                  f'<td class="num muted">{ago(age)} ago</td></tr>')
    body = f"""
<section class="definition compact section">
  <p>This address on MineDifferent → <a href="https://minedifferent.com/u/{a}">/u/{short(addr,12)}</a></p>
  <p class="muted" style="color:var(--accent-ink)">Mine to this address: paste it as your payout address at <a href="https://xcoinminer.com">xcoinminer.com</a> and every block credit lands here.</p>
  <a class="btn" href="https://minedifferent.com/u/{a}">Profile</a>
</section>
<section class="note-panel head-panel section">
  <p class="eyebrow">Address</p>
  <h1 class="h-small">{a}</h1>
  <p class="hash">{badge} ML-DSA-65 · {xat(bal)} XID</p>
</section>
<section class="summary-grid section">
  {summary_card("Balance", f"{xat(bal)}", "XID")}
  {summary_card("Unspent outputs", f"{len(utxos):,}", "coins here now")}
  {summary_card("Received in", f"{len(hist):,}", "transactions indexed")}
  {summary_card("Blocks mined", f"{mined:,}", "coinbase credits on chain")}
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Script</span><span class="meta">{kind}</span></div>
  <div class="table-wrap"><table class="kv"><tbody>
    <tr><th>Address</th><td>{a}</td></tr>
    <tr><th>scriptPubKey</th><td><code>{esc(spk)}</code>{' <span class="muted">· OP_3 &lt;32-byte Merkle root&gt;</span>' if program else ''}</td></tr>
    {f'<tr><th>Merkle root</th><td><code>{program.hex()}</code></td></tr>' if program else ''}
    {f'<tr><th>Script tree</th><td>{esc(tree)}</td></tr>' if tree else ''}
    {from_row}
  </tbody></table></div>
</section>
<section class="notes section">
  <div class="workspace">
    <div class="workspace-head"><span>Unspent outputs</span><span class="meta">{len(utxos):,}</span></div>
    <div class="table-wrap"><table><thead><tr><th>Outpoint</th><th class="num">Height</th><th class="num">Value</th></tr></thead>
    <tbody>{rows or '<tr><td colspan=3 class=muted>no coins here yet</td></tr>'}</tbody></table></div>
  </div>
  <div class="workspace">
    <div class="workspace-head"><span>Transaction history</span><span class="meta">{len(hist):,}</span></div>
    <div class="table-wrap"><table><thead><tr><th>TXID</th><th class="num">Block</th><th class="num">Age</th></tr></thead>
    <tbody>{hrows or '<tr><td colspan=3 class=muted>no activity indexed yet</td></tr>'}</tbody></table></div>
  </div>
</section>
"""
    return page("Address", body, path=f"/address/{a}")

def view_richlist():
    """Every address holding coins now, from the explorer's own UTXO scan."""
    refresh_index()
    with IDX_LOCK:
        rows_src = sorted(BAL.items(), key=lambda kv: -kv[1])[:250]
        total = sum(BAL.values())
        holders = len(BAL)
    trs = ""
    for i, (addr, sats) in enumerate(rows_src, 1):
        trs += (f'<tr{" class=top-ten" if i <= 3 else ""}><td><span class="rank-badge">{i}</span></td>'
                f'<td><a class="hash" href="/address/{esc(addr)}">{short(addr, 20)}</a></td>'
                f'<td class="num">{sats_xat(sats)} XID</td>'
                f'<td class="num muted">{(sats / total * 100) if total else 0:.3f}%</td></tr>')
    trs = trs or '<tr><td colspan=4 class=muted>no balances indexed yet</td></tr>'
    body = f"""
<section class="note-panel head-panel section">
  <p class="eyebrow">Rich list</p>
  <h1 class="h-small">{holders:,} addresses hold coins</h1>
  <p class="hash">{sats_xat(total)} XID in the UTXO set · every address is a witness v3 address ({esc(CFG["hrp"])}1r…)</p>
</section>
<section class="workspace section">
  <div class="workspace-head"><span>Top {min(len(rows_src), 250):,} balances</span><span class="meta">counted by this explorer's own scan of every block</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Address</th><th class="num">Balance</th><th class="num">Share</th></tr></thead>
    <tbody>{trs}</tbody>
  </table></div>
</section>
"""
    return page("Rich list", body, path="/richlist")

def error_panel(title, note=""):
    """404 / error body: one note-panel with an h2 and a way back."""
    return (f'<section class="note-panel section"><h2>{esc(title)}</h2>'
            f'{("<p class=muted>" + esc(note) + "</p>") if note else ""}'
            f'<p><a class="btn" href="/">Back to the chain</a></p></section>')

def route_search(q):
    """Height, block hash, txid, a witness v3 address, a witness v2 string (mapped to the
    witness v3 address of the same key, the string passed along in ?from=), or a bare
    32-byte ML-DSA-65 key hash (converted the same way)."""
    q = (q or "").strip()
    if not q: return ("/", None)
    if q.isdigit(): return ("/block/"+q, None)
    low = q.lower()
    if is_v3_address(low): return ("/address/"+low, None)
    if is_v1_address(low):
        conv = convert_v1_address(low)
        return (f"/address/{conv['v3']}?from={conv['v1']}", None)
    if len(q) == 64 and all(c in "0123456789abcdef" for c in low):
        if rpc("getblockheader", [low]): return ("/block/"+low, None)
        if rpc("getrawtransaction", [low, True]) or TXIDX.get(low): return ("/tx/"+low, None)
        # a bare key hash: its single-leaf witness v3 address
        try:
            prog = carried_program(bytes.fromhex(low))
            return ("/address/" + bech32m_encode(CFG["hrp"], WITVER_V3, prog), None)
        except ValueError:
            return ("/tx/"+low, None)
    if low.startswith(tuple(h + "1" for h in KNOWN_HRPS)): return ("/address/"+low, None)
    return ("/", None)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")  # allow macmetalminer.com to read stats
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); p = unquote(u.path)
        try:
            if p == "/" : return self._send(view_overview())
            if p == "/api/stats": return self._send(jdump(api_stats()), ctype="application/json")
            if p == "/api/network": return self._send(jdump(api_network()), ctype="application/json")
            if p.startswith("/api/block/"):
                b = api_block(p[len("/api/block/"):])
                if b is None: return self._send(json.dumps({"error": "unknown block"}), ctype="application/json", code=404)
                return self._send(jdump(b), ctype="application/json")
            if p == "/mempool": return self._send(view_mempool())
            if p == "/xat-sw.js":
                with open(os.path.join(HERE,"web/xat-sw.js"),"rb") as f: return self._send(f.read(),ctype="application/javascript")
            if p in ("/js/energy-stream.js", "/js/live.js", "/js/xat-instance.js"):
                fn = p.split("/")[-1]
                with open(os.path.join(HERE,"web/js",fn),"rb") as f: return self._send(f.read(),ctype="application/javascript")
            if p.lstrip("/") in STATIC:
                fn = p.lstrip("/")
                with open(os.path.join(HERE,"web",fn),"rb") as f: return self._send(f.read(), ctype=STATIC[fn])
            if p == "/robots.txt":
                return self._send(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n", ctype="text/plain")
            if p == "/sitemap.xml":
                return self._send(f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{SITE_URL}/</loc><priority>1.0</priority></url><url><loc>{SITE_URL}/mempool</loc></url><url><loc>{SITE_URL}/richlist</loc></url></urlset>', ctype="application/xml")
            if p == "/search":
                q = parse_qs(u.query).get("q",[""])[0]; dest,_ = route_search(q)
                self.send_response(302); self.send_header("Location", dest); self.end_headers(); return
            if p.startswith("/block/"): return self._send(view_block(p[7:]))
            if p.startswith("/tx/"): return self._send(view_tx(p[4:]))
            if p == "/richlist": return self._send(view_richlist())
            if p == "/api/charter": return self._send(jdump(charter()), ctype="application/json")
            if p.startswith("/address/"):
                came = parse_qs(u.query).get("from", [""])[0]
                return self._send(view_address(p[9:], came_from=came))
            return self._send(page("Not found", error_panel("404", f"Nothing at that path. Try a block height, a hash, a txid or a {CFG['hrp']}1r address.")), 404)
        except Exception as e:
            return self._send(page("Error", error_panel("Explorer error", str(e))), 500)

def main():
    # Guard rails: 9432/9333, 3333 and 3001 are reserved by other services on this host.
    if CFG["rpc_port"] in FORBIDDEN_RPC_PORTS:
        raise SystemExit(f"RPC port {CFG['rpc_port']} is reserved. This explorer serves an xCoin node: "
                         "use 19432 (rehearsal) or 8332 (mainnet).")
    if CFG["port"] in FORBIDDEN_BIND_PORTS:
        raise SystemExit(f"Port {CFG['port']} is reserved (explorer 3001, pool 3333, node 9333/9432). "
                         "Pick a spare port, e.g. XCOIN_EXPLORER_PORT=3101.")
    if CFG["rpc_cookie"]:
        if not rpc_credential():
            raise SystemExit(f"Cannot read the RPC cookie at {CFG['rpc_cookie']} (is the node running, and is this user allowed to read it?).")
    elif not CFG["rpc_user"] or not CFG["rpc_pass"]:
        raise SystemExit("Set XCOIN_RPC_COOKIE to the node's .cookie file (preferred), or XCOIN_RPC_USER / XCOIN_RPC_PASSWORD.")
    info = rpc("getblockchaininfo")
    if info is None:
        raise SystemExit(f"Cannot reach the node's RPC at {CFG['rpc_host']}:{CFG['rpc_port']}.")
    # The node has the last word on which chain this is, so a mislabelled port cannot make
    # the explorer print xpa1r strings for a txa1r chain.
    field = info.get("chain", "")
    if not os.environ.get("XCOIN_ADDRESS_HRP"):
        CFG["hrp"] = HRP_BY_CHAINFIELD.get(field, CFG["hrp"])
    if field == "main":
        CFG["chain"], CFG["chain_label"] = "mainnet", CHAIN_PROFILES["mainnet"]["label"]
    elif field in ("test", "testneta"):
        CFG["chain"], CFG["chain_label"] = "rehearsal", CHAIN_PROFILES["rehearsal"]["label"]
    c = charter()
    if not c:
        raise SystemExit("The node has no `getcharter` RPC, so it is not an xCoin node this explorer "
                         "can serve. Point it at a rehearsal node (RPC 19432) or a mainnet node (8332).")
    if c.get("genesis_is_final") is False:
        print("note: genesis_is_final is false — this chain's currency id is provisional, "
              "do not attest or timestamp it.")
    def index_loop():
        while True:
            try: refresh_index()
            except Exception: pass
            time.sleep(15)
    threading.Thread(target=index_loop, daemon=True).start()
    bind = os.environ.get("XCOIN_EXPLORER_BIND", "127.0.0.1")   # local by default
    srv = ThreadingHTTPServer((bind, CFG["port"]), H)
    print(f"xcoin-explorer · {CFG['chain_label']} · addresses {CFG['hrp']}1r…"
          + (f" · settlement levy {LEVY_BP} bp (test chain)" if LEVY_BP > 0 else ""))
    print(f"  node    {CFG['rpc_host']}:{CFG['rpc_port']}  chain={field}  height={info.get('blocks', 0):,}")
    print(f"  charter {c.get('charter_hash', '?')}")
    print(f"  currency{' ' * 1}{c.get('currency_id', '?')}  genesis_is_final={c.get('genesis_is_final')}")
    print(f"  serving http://{bind}:{CFG['port']}/")
    srv.serve_forever()

if __name__ == "__main__":
    main()
