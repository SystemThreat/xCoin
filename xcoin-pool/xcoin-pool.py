#!/usr/bin/env python3
"""
xcoin-pool — a minimal SOLO Stratum pool for Xcoin (XID).

Point a MetalDAG-capable Stratum miner (for example NerdMiner) at this pool: when
one of your shares meets the network target you find a block and receive the full
block reward at your own xpa1r... address (txa1r... on the rehearsal chain).
Ordinary Bitcoin ASICs do not compute MetalDAG and cannot mine xCoin directly.
No accounts, no fees.

  Miner setup (MetalDAG-capable Stratum miner):
    URL:  stratum+tcp://<this-host>:3333
    User: <your xpa1r... address>[.workername]
    Pass: x

Addresses are witness v3 (contrib/regenesis/REGENESIS.md section 4): the 32-byte
program is a Merkle root over algorithm-tagged leaves and the coinbase pays
OP_3 <root>. A legacy witness v2 string (xpa1z.../txa1z...) is REFUSED: this
chain has no witness v2 output at all (a v2 payout would be rejected as
bad-txout-not-pq).

The pool talks to a local xCoin node via JSON-RPC (getblocktemplate / submitblock).
Config is entirely environment-driven — no hardcoded hosts or credentials:

    XCOIN_RPC_HOST      (default 127.0.0.1)
    XCOIN_RPC_PORT      (default 8332, mainnet's per src/chainparamsbase.cpp; the rehearsal chain's is 19432)
    XCOIN_RPC_COOKIE    (preferred) path of the cookie file nexd writes on every start:
                         <datadir>/<chain>/.cookie, mode 600. No password exists anywhere.
    XCOIN_RPC_USER      (fallback) with XCOIN_RPC_PASSWORD: a secret in the environment,
    XCOIN_RPC_PASSWORD   which contrib/regenesis/WALLET-SECRETS.md forbids; the pool warns.
    XCOIN_STRATUM_HOST  (default 0.0.0.0)
    XCOIN_STRATUM_PORT  (default 3333; use another port for the rehearsal chain)
    XCOIN_START_DIFF    (default 0.001 — initial accounting difficulty)
    XCOIN_ADDRESS_HRP   (default xpa; txa on the rehearsal chain, nxrt on regtest)
    XCOIN_NATPMP        (default 1; set 0 to keep the stratum port off the router)
    XCOIN_STATS_DIR     (default ~/.xcoin, which is the LIVE pool's directory: its published
                         stats and Discord webhook files live there. A rehearsal pool MUST set
                         this to somewhere else or it overwrites the live pool and announces to
                         the live channel.)

Standard library only. Python 3.8+.
"""
import asyncio, base64, hashlib, json, logging, os, re, secrets, socket, struct, subprocess, time, urllib.request, urllib.error

log = logging.getLogger("xcoin-pool")

CFG = {
    "rpc_host": os.environ.get("XCOIN_RPC_HOST", "127.0.0.1"),
    "rpc_port": int(os.environ.get("XCOIN_RPC_PORT", "8332")),
    "rpc_user": os.environ.get("XCOIN_RPC_USER", ""),
    "rpc_pass": os.environ.get("XCOIN_RPC_PASSWORD", ""),
    "rpc_cookie": os.environ.get("XCOIN_RPC_COOKIE", ""),
    "stratum_host": os.environ.get("XCOIN_STRATUM_HOST", "0.0.0.0"),
    "stratum_port": int(os.environ.get("XCOIN_STRATUM_PORT", "3333")),
    # Sized for an Apple Silicon GPU (tens of MH/s): about one share every few seconds at
    # 0.05. A CPU miner starts slower and vardiff halves toward it; set XCOIN_START_DIFF
    # lower (e.g. 0.001) for a CPU-only rehearsal.
    "start_diff": float(os.environ.get("XCOIN_START_DIFF", "0.05")),
    "vardiff_target": float(os.environ.get("XCOIN_VARDIFF_TARGET", "15")),
    "vardiff_interval": float(os.environ.get("XCOIN_VARDIFF_INTERVAL", "60")),
    "vardiff_min": float(os.environ.get("XCOIN_VARDIFF_MIN", "0.000001")),
    "vardiff_max": float(os.environ.get("XCOIN_VARDIFF_MAX", "1000000")),
    "hrp": os.environ.get("XCOIN_ADDRESS_HRP", "xpa"),
    "poll_secs": float(os.environ.get("XCOIN_POLL_SECS", "3")),
    # Block links in Discord notifications. Same variable the explorer reads,
    # so a rebrand or a private explorer only has to be set in one place.
    "explorer_url": os.environ.get("XCOIN_EXPLORER_URL", "https://superknet.com").rstrip("/"),
}

# There is NO premine and NO founder output: every block from height 1 pays
# coinbasevalue (subsidy + fees) to the miner.
# Bitcoin difficulty-1 target (share difficulty reference).
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
# Audit finding 14: per-connection mining.submit budget, and the flood count that drops a client.
SUBMIT_RATE_PER_SEC = 20
SUBMIT_FLOOD_DISCONNECT = 200
# Above this share rate the pool doubles a miner's difficulty immediately (observe_share).
FAST_RAMP_SHARES_PER_SEC = 5

# Consensus limits this pool has to respect when it assembles a coinbase.
MAX_COINBASE_SCRIPTSIG = 100     # consensus/tx_check.cpp: bad-cb-length (2..100 bytes)
MIN_COINBASE_SCRIPTSIG = 2
MAX_OP_RETURN_RELAY = 80         # policy/policy.h: per-output data carrier cap
MAX_BLOCK_DATACARRIER_BYTES = 8_000     # consensus/consensus.h: 100 anchors of 80 bytes per block, at every height

# Settlement levy (REGENESIS.md section 6, src/consensus/levy.h). The chain
# ships WITHOUT one: the genesis schedule row is zero rate, zero cap, so no
# transaction owes a levy (founder decision 2026-09-14). The machinery stays in
# consensus, dormant; a future soft fork can switch it on with a schedule row,
# and if it does every NON-COINBASE transaction must pay at least
# min(ceil(sum(outputs) * bp / 10,000), cap) satoshis, integer arithmetic.
# The helpers below default to the genesis rule (nothing owed) and take the
# reference rate for tests. Coinbases are exempt in any case, so nothing this
# solo pool builds owes it (see payout_fee_floor_sats and test_coinbase.py::LevyTests).
SETTLEMENT_LEVY_BP = 0                  # genesis rule: no levy
SETTLEMENT_LEVY_CAP_SAT = 0             # genesis rule: no levy
SETTLEMENT_LEVY_REFERENCE_BP = 5        # consensus/params.h SETTLEMENT_LEVY_BP: the documented activation rate
SETTLEMENT_LEVY_REFERENCE_CAP_SAT = 10_000  # consensus/params.h SETTLEMENT_LEVY_CAP_SAT: 0.0001 XID
LEVY_DENOMINATOR = 10_000

# ── RPC ──────────────────────────────────────────────────────────────────────
def _rpc_credentials():
    """'user:password' for the node. Preferred: XCOIN_RPC_COOKIE, the path of the cookie
    file nexd writes on every start (<datadir>/<chain>/.cookie, mode 600, owner only).
    Read on every call because the node rewrites it on restart. Fallback: XCOIN_RPC_USER
    and XCOIN_RPC_PASSWORD from the environment, which main() warns about."""
    path = CFG["rpc_cookie"]
    if path:
        with open(path) as f:
            cred = f.readline().strip()
        if ":" not in cred:
            raise RuntimeError(f"{path}: not a nexd cookie file (expected user:password)")
        return cred
    return f"{CFG['rpc_user']}:{CFG['rpc_pass']}"

def rpc(method, params=None):
    payload = json.dumps({"jsonrpc": "1.0", "id": "xcoin-pool", "method": method, "params": params or []}).encode()
    req = urllib.request.Request(f"http://{CFG['rpc_host']}:{CFG['rpc_port']}/", data=payload)
    try:
        auth = base64.b64encode(_rpc_credentials().encode()).decode()
    except OSError as e:
        log.error("RPC %s: cannot read cookie %s: %s", method, CFG["rpc_cookie"], e); return None
    except RuntimeError as e:
        log.error("RPC %s: %s", method, e); return None
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
            if d.get("error"):
                log.error("RPC %s error: %s", method, d["error"]); return None
            return d.get("result")
    except urllib.error.HTTPError as e:
        log.error("RPC %s HTTP %s: %s", method, e.code, e.read().decode(errors="replace")[:200]); return None
    except Exception as e:
        log.error("RPC %s failed: %s", method, e); return None

# ── serialization / crypto helpers (faithful to the reference pool) ──────────
def dsha256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

# ── Persistent miner registry (logs every miner indefinitely) ────────────────
STATS_DIR   = os.environ.get("XCOIN_STATS_DIR", os.path.expanduser("~/.xcoin"))
# Create it: XCOIN_STATS_DIR is the variable that keeps a rehearsal pool out of the
# LIVE pool's ~/.xcoin, and a fresh directory that does not exist yet must not be a
# reason to set it aside (the writes below would fail one by one at run time).
os.makedirs(STATS_DIR, exist_ok=True)
MINERS_FILE = os.path.join(STATS_DIR, "pool_miners.json")
STATS_FILE  = os.path.join(STATS_DIR, "pool_stats.json")
RIGS_FILE   = os.path.join(STATS_DIR, "pool_rigs.json")
MINERS = {}  # address -> {first,last,shares,blocks,best,recent[]}
RIGS = {}    # "address|worker" -> independent rig totals/live rate

def load_miners():
    global MINERS, RIGS
    try:
        with open(MINERS_FILE) as f: MINERS = json.load(f)
        log.info("loaded %d known miners", len(MINERS))
    except Exception:
        MINERS = {}
    try:
        with open(RIGS_FILE) as f: RIGS = json.load(f)
    except Exception:
        RIGS = {}

SESSION_SEQ_FILE = os.path.join(STATS_DIR, "web_session_seq.txt")
WEB_WORKER = re.compile(r"^web(-[a-z0-9]+)?$")   # the site's default names: web, web-solo

def next_web_session():
    """Every browser session gets its own number, web-solo-00001, web-solo-00002, ...
    The counter lives in the statistics directory and survives restarts; the
    sequence never repeats, so two tabs (or one tab twice) are two rigs on the
    explorer instead of one merged entry. Founder request 2026-09-15."""
    n = 0
    try:
        with open(SESSION_SEQ_FILE) as f:
            n = int(f.read().strip() or 0)
    except (OSError, ValueError):
        n = 0
    n += 1
    tmp = SESSION_SEQ_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(n))
    os.replace(tmp, SESSION_SEQ_FILE)
    return n

def session_worker_name(worker):
    """A browser's default worker name becomes a numbered session name; a name
    the miner chose (rig1, wayne, rehearsal1) is kept as is."""
    if WEB_WORKER.match(worker):
        return f"{worker}-{next_web_session():05d}"
    return worker

def touch_rig(addr, worker):
    now = int(time.time()); key = f"{addr}|{worker}"
    r = RIGS.get(key)
    if not r:
        r = {"address": addr, "worker": worker, "first": now, "last": now,
             "shares": 0, "blocks": 0, "recent": []}
        RIGS[key] = r
    r["last"] = now
    return r

def record_rig_share(addr, worker, diff):
    now = int(time.time()); r = touch_rig(addr, worker)
    r["shares"] = r.get("shares", 0) + 1
    recent = r.setdefault("recent", []); recent.append({"t": now, "d": float(diff)})
    r["recent"] = [x for x in recent if x.get("t", 0) > now - 600]

def record_rig_block(addr, worker):
    r = touch_rig(addr, worker); r["blocks"] = r.get("blocks", 0) + 1

def touch_miner(addr):
    now = int(time.time())
    m = MINERS.get(addr)
    if not m:
        m = {"first": now, "last": now, "shares": 0, "blocks": 0, "best": 0.0, "recent": []}
        MINERS[addr] = m
    m["last"] = now
    return m

def record_share(addr, diff):
    now = int(time.time())
    m = touch_miner(addr)
    m["shares"] = m.get("shares", 0) + 1
    if diff > m.get("best", 0): m["best"] = diff
    r = m.setdefault("recent", []); r.append({"t": now, "d": float(diff)})
    # Accept legacy timestamp-only entries while migrating the persisted registry.
    m["recent"] = [x for x in r if (x.get("t", 0) if isinstance(x, dict) else x) > now - 600]

def recent_work_hps(m, now, window=600.0):
    """Hashrate from actual vardiff-weighted accepted work over a time window."""
    work = 0.0
    for item in m.get("recent", []):
        if isinstance(item, dict):
            timestamp, difficulty = item.get("t", 0), item.get("d", CFG["start_diff"])
        else:
            timestamp, difficulty = item, CFG["start_diff"]
        if timestamp > now - window:
            work += float(difficulty) * (2 ** 32)
    return work / window

REPORTED_HPS_TTL = 15.0   # seconds a mining.hashrate self-report stays "fresh"

def measured_hps(m, now):
    """The pool's own figure: hashrate from accepted, vardiff-weighted shares. A
    miner cannot inflate it without doing the work (audit finding L4)."""
    return recent_work_hps(m, now)

def reported_hps(m, now):
    """The miner's SELF-REPORTED device counter (mining.hashrate) while fresh, else
    None. Display only, always labelled as reported: it is never summed into a
    pool total or substituted for the measured figure."""
    if m.get("reported_at", 0) > now - REPORTED_HPS_TTL:
        try:
            return max(0.0, float(m.get("reported_hps", 0)))
        except (TypeError, ValueError):
            return None
    return None

def record_block(addr):
    touch_miner(addr)["blocks"] = MINERS[addr].get("blocks", 0) + 1

# Discord block announcements. The webhook URL is a secret: it is NEVER in this
# file — set XCOIN_DISCORD_WEBHOOK or put the URL in <STATS_DIR>/discord-webhook.txt.
def _discord_webhook_url():
    url = os.environ.get("XCOIN_DISCORD_WEBHOOK", "").strip()
    if url:
        return url
    try:
        with open(os.path.join(STATS_DIR, "discord-webhook.txt")) as f:
            return f.read().strip()
    except OSError:
        return ""

def discord_block_found(worker, addr, height, blockhash, reward="?"):
    url = _discord_webhook_url()
    if not url:
        return
    payload = json.dumps({
        "username": "Xcoin Pool",
        "allowed_mentions": {"parse": []},  # never ping anyone from miner-supplied text
        "embeds": [{
            "title": f"⛏️ Block {height} found!",
            "color": 0xE7003C,
            "fields": [
                {"name": "Miner", "value": f"`{worker}`", "inline": False},
                {"name": "Address", "value": f"`{addr}`", "inline": False},
                {"name": "Reward", "value": f"{reward} XID", "inline": True},
                {"name": "Block", "value": f"[`{blockhash[:16]}…`]({CFG['explorer_url']}/block/{blockhash})", "inline": True},
            ],
        }],
    }).encode()
    def _post():
        try:
            req = urllib.request.Request(url, data=payload,
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "xcoin-pool/1.0"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            log.warning("discord webhook failed: %s", e)
    import threading
    threading.Thread(target=_post, daemon=True).start()

# Live leaderboard in Discord (#leaderboard): one self-updating message listing every
# connected rig — worker, hardware (from the stratum subscribe user-agent), connect
# duration, hashrate, shares, blocks. Webhook URL (secret, never in this file):
# XCOIN_DISCORD_LEADERBOARD env or <STATS_DIR>/discord-leaderboard-webhook.txt.
LB_MSGID_FILE = os.path.join(STATS_DIR, "discord-leaderboard-msgid.txt")

def _leaderboard_webhook_url():
    url = os.environ.get("XCOIN_DISCORD_LEADERBOARD", "").strip()
    if url:
        return url
    try:
        with open(os.path.join(STATS_DIR, "discord-leaderboard-webhook.txt")) as f:
            return f.read().strip()
    except OSError:
        return ""

def _fmt_duration(secs):
    secs = int(secs)
    d, r = divmod(secs, 86400); h, r = divmod(r, 3600); m = r // 60
    if d: return f"{d}d {h}h"
    if h: return f"{h}h {m:02d}m"
    return f"{m}m"

def _fmt_rate(hps):
    return f"{hps/1e6:.2f} MH/s" if hps >= 1e5 else f"{hps/1e3:.1f} kH/s"

def build_leaderboard_embed():
    now = time.time()
    def rate_hps(m):
        return measured_hps(m, now)
    lines = []
    live = sorted([s for s in SESSIONS if getattr(s, "address", None)],
                  key=lambda s: getattr(s, "connected_at", now))
    for s in live:
        m = MINERS.get(s.address, {})
        # The agent was sanitized at mining.subscribe (sanitize_agent); do it again
        # here so a session built any other way can never inject into the embed.
        agent = sanitize_agent(getattr(s, "agent", "?"))
        hw = agent[agent.find("(")+1:agent.rfind(")")] if "(" in agent else agent
        # Self-reported device counters are shown as such, next to the measured
        # figure, never in its place and never in the pool total.
        self_rep = reported_hps(RIGS.get(f"{s.address}|{s.worker}", {}), now)
        rep_txt = f" (miner reports {_fmt_rate(self_rep)})" if self_rep is not None else ""
        lines.append(
            f"**{s.worker}** · {hw}\n"
            f"`{s.address[:14]}…{s.address[-6:]}` · up {_fmt_duration(now - getattr(s, 'connected_at', now))}"
            f" · {_fmt_rate(rate_hps(m))}{rep_txt} · {m.get('shares', 0)} shares · **{m.get('blocks', 0)} blocks**")
    offline = sorted([(a, m) for a, m in MINERS.items()
                      if a not in {s.address for s in live} and m.get("blocks", 0) > 0],
                     key=lambda kv: kv[1].get("blocks", 0), reverse=True)[:10]
    if offline:
        lines.append("")
        lines.append("__Offline (all-time blocks)__")
        for a, m in offline:
            lines.append(f"**{m.get('worker', 'default')}** · `{a[:14]}…{a[-6:]}` · {m.get('blocks', 0)} blocks · {m.get('shares', 0)} shares")
    total_hps = sum(rate_hps(m) for m in MINERS.values())
    return {
        "username": "Xcoin Pool",
        "allowed_mentions": {"parse": []},  # never ping anyone from miner-supplied text
        "embeds": [{
            "title": f"⛏️ Xcoin Pool Leaderboard — {len(live)} rig(s) online",
            "color": 0xE7003C,
            "description": "\n".join(lines) if lines else "_No miners connected._",
            "footer": {"text": f"pool {_fmt_rate(total_hps)} · share diff {CFG['start_diff']} · updates every 5 min"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }

def post_leaderboard():
    url = _leaderboard_webhook_url()
    if not url:
        return
    payload = json.dumps(build_leaderboard_embed()).encode()
    hdrs = {"Content-Type": "application/json", "User-Agent": "xcoin-pool/1.0"}
    def _post():
        try:
            msgid = ""
            try:
                with open(LB_MSGID_FILE) as f: msgid = f.read().strip()
            except OSError:
                pass
            if msgid:  # edit the existing message in place
                req = urllib.request.Request(f"{url}/messages/{msgid}", data=payload,
                                             headers=hdrs, method="PATCH")
                try:
                    urllib.request.urlopen(req, timeout=10).read()
                    return
                except urllib.error.HTTPError as e:
                    if e.code != 404:  # message deleted -> fall through and repost
                        raise
            req = urllib.request.Request(url + "?wait=true", data=payload, headers=hdrs)
            resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
            with open(LB_MSGID_FILE, "w") as f:
                f.write(str(resp.get("id", "")))
        except Exception as e:
            log.warning("discord leaderboard failed: %s", e)
    import threading
    threading.Thread(target=_post, daemon=True).start()

def save_stats():
    now = int(time.time())
    try:
        tmp = MINERS_FILE + ".tmp"
        with open(tmp, "w") as f: json.dump(MINERS, f)
        os.replace(tmp, MINERS_FILE)
    except Exception as e:
        log.error("save miners: %s", e)
    try:
        tmp = RIGS_FILE + ".tmp"
        with open(tmp, "w") as f: json.dump(RIGS, f)
        os.replace(tmp, RIGS_FILE)
    except Exception as e:
        log.error("save rigs: %s", e)
    active = [r for r in RIGS.values() if r.get("last", 0) > now - 300]
    # hashrate_hps / hashrate_mhs are the pool's MEASURED figures: independently
    # verified vardiff work over ten minutes. A miner's mining.hashrate self-report
    # is published separately as reported_hashrate_* and is never mixed in
    # (audit finding L4).
    def rate_hps(m):
        return measured_hps(m, now)
    net_hps = sum(rate_hps(r) for r in active)
    reported = [reported_hps(r, now) for r in active]
    net_reported_hps = sum(h for h in reported if h is not None)
    lb = sorted(RIGS.values(),
                key=lambda r: (r.get("blocks", 0), r.get("shares", 0)), reverse=True)[:50]
    def entry(r):
        self_rep = reported_hps(r, now)
        return {
            "address": r.get("address", "?"), "worker": r.get("worker", "default"),
            "blocks": r.get("blocks", 0), "shares": r.get("shares", 0),
            "since": r.get("first", 0), "last": r.get("last", 0),
            "hashrate_mhs": round(rate_hps(r) / 1e6, 2),
            "bandwidth_gbs": round(rate_hps(r) * 8192.0 / 1e9, 2),
            # self-reported by the miner (mining.hashrate), unverified; null when stale
            "reported_hashrate_mhs": None if self_rep is None else round(self_rep / 1e6, 2),
        }
    leaderboard = [entry(r) for r in lb]
    stats = {"updated": now, "active_miners": len(active), "total_miners": len(RIGS),
             "share_diff": CFG["start_diff"], "hashrate_hps": net_hps,
             "reported_hashrate_hps": net_reported_hps,   # sum of unverified self-reports, display only
             "leaderboard": leaderboard}
    try:
        tmp = STATS_FILE + ".tmp"
        with open(tmp, "w") as f: json.dump(stats, f)
        os.replace(tmp, STATS_FILE)
    except Exception as e:
        log.error("save stats: %s", e)

async def stats_loop():
    last_lb = 0.0
    while True:
        try: save_stats()
        except Exception as e: log.error("stats loop: %s", e)
        if time.time() - last_lb >= 300:  # refresh Discord leaderboard every 5 min
            last_lb = time.time()
            try: post_leaderboard()
            except Exception as e: log.error("leaderboard: %s", e)
        await asyncio.sleep(10)

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def push(data):
    n = len(data)
    if n < 0x4c: return bytes([n]) + data
    if n <= 0xff: return b"\x4c" + bytes([n]) + data
    if n <= 0xffff: return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data

# ── witness v3 addresses (REGENESIS.md section 4) ──────────────────────────
# The pure-Python side of src/script/xcoin_v3.h. Every tag is scoped to the
# PROJECT name, never the ticker.
XCOIN_V3_LEAF_TAG = b"XCoinLeaf"
XCOIN_V3_BRANCH_TAG = b"XCoinBranch"
XCOIN_LEAF_PQ = 0xc0             # ML-DSA-65 leaf: 0x20 <SHA-256(pubkey)> OP_CHECKSIG
XCOIN_LEAF_SLH = 0xc2            # SLH-DSA-SHA2-128s leaf (never built here)
WITVER_V2, WITVER_V3 = 2, 3
WITNESS_V3_SIZE = 32
REGTEST_HRP = "nxrt"             # the only chain where a witness v2 payout is legal
KNOWN_HRPS = ("xpa", "txa", REGTEST_HRP)

class AddressError(ValueError):
    """A worker address this pool refuses to pay, with the reason a miner can act on."""

def tagged_hash(tag, msg):
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + msg).digest()

def leaf_hash(version, script):
    """tagged_hash("XCoinLeaf", leaf_version || compact_size(script) || script)."""
    return tagged_hash(XCOIN_V3_LEAF_TAG, bytes([version]) + varint(len(script)) + script)

def branch_hash(a, b):
    """tagged_hash("XCoinBranch", sorted(a, b)). Unused here: the pool only ever
    needs the ONE-leaf tree, whose root is its leaf hash."""
    return tagged_hash(XCOIN_V3_BRANCH_TAG, (a + b) if a < b else (b + a))

def key32_checksig_script(key32):
    if len(key32) != 32: raise AddressError("leaf key must be 32 bytes")
    return b"\x20" + key32 + b"\xac"

def single_leaf_program(pq_hash):
    """The single-leaf v3 program of a key hash H: the ML-DSA-65 leaf (0xc0) over
    0x20 <H> OP_CHECKSIG. A one-leaf tree's root IS the leaf hash."""
    return leaf_hash(XCOIN_LEAF_PQ, key32_checksig_script(pq_hash))

def script_for_program(witver, program):
    """OP_<witver> <program>: the 34-byte witness scriptPubKey."""
    return bytes([0x50 + witver, len(program)]) + program

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
_BECH32M_CONST = 0x2bc830a3

def _polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= _GEN[i] if ((b >> i) & 1) else 0
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
    return (hrp + "1" + "".join(_CHARSET[d] for d in data)
            + "".join(_CHARSET[(mod >> 5 * (5 - i)) & 31] for i in range(6)))

def bech32m_decode(addr):
    """(hrp, witness version, program) of a bech32m address. Raises AddressError."""
    if any(ord(c) < 33 or ord(c) > 126 for c in addr): raise AddressError("address has an invalid character")
    if addr.lower() != addr and addr.upper() != addr: raise AddressError("address mixes upper and lower case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90: raise AddressError("malformed address")
    hrp, rest = addr[:pos], addr[pos + 1:]
    if any(c not in _CHARSET for c in rest): raise AddressError("address has an invalid data character")
    data = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M_CONST: raise AddressError("address checksum is wrong (bech32m required)")
    data = data[:-6]
    if not data or data[0] > 16: raise AddressError("bad witness version")
    prog = _convertbits(data[1:], 5, 8, False)
    if prog is None or not 2 <= len(prog) <= 40: raise AddressError("bad witness program")
    return hrp, data[0], bytes(prog)

def v2_refusal(addr):
    """The refusal for a witness v2 string on a chain that admits only v3 outputs."""
    return AddressError(
        f"{addr} is a legacy witness v2 address; this chain accepts only witness v3 "
        f"(post-quantum script tree) addresses. Generate one in the node wallet (getnewaddress).")

def parse_address(addr, hrp=None):
    """(witness version, 32-byte program) for a worker address this pool can pay.
    Raises AddressError with a message meant for the miner."""
    hrp = hrp or CFG["hrp"]
    got_hrp, witver, program = bech32m_decode(addr.strip())
    if got_hrp != hrp:
        if got_hrp in KNOWN_HRPS:
            raise AddressError(f"{addr} is a {got_hrp!r} address; this pool serves the {hrp!r} chain")
        raise AddressError(f"{addr}: unknown address prefix {got_hrp!r} "
                           f"(this pool serves {hrp!r}; xCoin uses {', '.join(KNOWN_HRPS)})")
    if len(program) != WITNESS_V3_SIZE:
        raise AddressError(f"{addr}: witness program is {len(program)} bytes, expected {WITNESS_V3_SIZE}")
    if witver == WITVER_V3:
        return WITVER_V3, program
    if witver == WITVER_V2:
        # Regtest keeps v2 outputs valid (permitV2Outputs) so the inherited test
        # fixtures still mine; mainnet and the rehearsal chain do not.
        if hrp == REGTEST_HRP:
            return WITVER_V2, program
        raise v2_refusal(addr)
    raise AddressError(f"{addr}: witness version {witver} is not an xCoin address")

def payout_script(addr, hrp=None):
    """The scriptPubKey the coinbase pays this worker: OP_3 <root> (OP_2 <program>
    only on regtest). Raises AddressError with a message meant for the miner."""
    witver, program = parse_address(addr, hrp)
    return script_for_program(witver, program)

def decode_address(addr, hrp=None):
    """(witness version, program) or None. Kept for callers that only want a
    yes/no; authorize uses payout_script so it can explain a refusal."""
    try:
        return parse_address(addr, hrp)
    except AddressError:
        return None

# ── settlement levy (REGENESIS.md section 6, src/consensus/levy.h) ───────────
def settlement_levy_uncapped(out_sats, bp=SETTLEMENT_LEVY_BP):
    """ceil(out_sats * bp / 10,000) before the cap: Consensus::SettlementLevyUncapped."""
    out_sats = int(out_sats)
    if bp <= 0 or out_sats <= 0: return 0
    whole, rest = divmod(out_sats, LEVY_DENOMINATOR)
    return whole * bp + (rest * bp + LEVY_DENOMINATOR - 1) // LEVY_DENOMINATOR

def settlement_levy(out_sats, bp=SETTLEMENT_LEVY_BP, cap_sat=SETTLEMENT_LEVY_CAP_SAT):
    """min(ceil(out_sats * bp / 10,000), cap_sat): the consensus minimum fee of a
    NON-COINBASE transaction paying out_sats. Integer arithmetic, exactly
    Consensus::SettlementLevy (the 10,000-sat cap included)."""
    return min(settlement_levy_uncapped(out_sats, bp), int(cap_sat))

def levy_from_inputs(in_sats, bp=SETTLEMENT_LEVY_BP, cap_sat=SETTLEMENT_LEVY_CAP_SAT):
    """The smallest fee f with f >= settlement_levy(in_sats - f): what a spender
    who lets the whole remainder go to outputs owes, capped like the levy itself
    (Consensus::SettlementLevyFromInputs)."""
    in_sats = int(in_sats)
    if bp <= 0 or in_sats <= 0: return 0
    d = LEVY_DENOMINATOR + bp
    whole, rest = divmod(in_sats, d)
    return min(whole * bp + (rest * bp + d - 1) // d, int(cap_sat))

def payout_fee_floor_sats(total_in_sats, byte_fee_sats=0):
    """The fee any payout transaction this pool might one day build MUST pay:
    max(relay byte floor, settlement levy). This pool is SOLO — it pays the miner
    in the coinbase and builds no non-coinbase transaction at all — so no code
    path here may assume it can keep a fee below this and still be mined."""
    return max(int(byte_fee_sats), levy_from_inputs(total_in_sats))

def bits_to_target(bits_hex):
    bits = int(bits_hex, 16)
    exp = bits >> 24; mant = bits & 0xffffff
    return mant * (1 << (8 * (exp - 3))) if exp > 3 else mant >> (8 * (3 - exp))

def diff_to_target(diff):
    return int(MAX_TARGET / diff) if diff > 0 else MAX_TARGET

def target_to_diff(target):
    return MAX_TARGET / target if target > 0 else float("inf")

def credited_diff(share_diff, net_target):
    """The difficulty an accepted share is CREDITED at: the threshold the miner
    actually had to meet. A share is accepted when it clears the share target or
    is an outright block, so on a chain easier than the share difficulty (a young
    chain near powLimit, or a share difficulty vardiff pushed above the network's)
    the work behind a share is the network difficulty, not the share difficulty.
    Crediting the larger figure inflated the measured hashrate by share/net (the
    rehearsal showed 4.7e14 H/s for a 9 MH/s rig) and fed vardiff a sample that
    doubled it to vardiff_max."""
    return min(float(share_diff), target_to_diff(net_target))

def check_payout_spk(spk, hrp=None):
    """The miner payout script must be a 34-byte witness program: OP_3 <root> on
    mainnet and the rehearsal chain, OP_2 <program> only on regtest. Anything
    else is a bug in the caller, and OP_2 on this chain would be mined and then
    rejected as ``bad-txout-not-pq`` (REGENESIS.md section 3)."""
    hrp = hrp or CFG["hrp"]
    if not isinstance(spk, (bytes, bytearray)) or len(spk) != 34 or spk[1] != 0x20:
        raise ValueError("payout scriptPubKey must be 34 bytes of OP_<n> <32-byte program>; "
                         "pass payout_script(address), not the bare program")
    ver = spk[0] - 0x50
    if ver == WITVER_V3:
        return bytes(spk)
    if ver == WITVER_V2 and hrp == REGTEST_HRP:
        return bytes(spk)
    raise ValueError(f"payout scriptPubKey is witness v{ver}: only witness v3 (OP_3 <root>) "
                     f"outputs are valid on the {hrp!r} chain (bad-txout-not-pq)")

def build_coinbase(height, reward_sats, en_size, wc_hex, payout_spk):
    """Coinbase split as (part1, extranonce slot, part2).

    ``reward_sats`` is getblocktemplate's ``coinbasevalue``: the miner's share
    (subsidy + fees), paid to ``payout_spk`` — the miner's witness v3 script
    ``OP_3 <root>``, from ``payout_script(address)`` — followed by the witness
    commitment ``wc_hex``. Every height, block 1 included, is built the same way.
    """
    if height <= 16:
        height_push = bytes([0x00]) if height == 0 else bytes([0x50 + height])
    else:
        hb = height.to_bytes((height.bit_length() + 7)//8 or 1, "little")
        if hb[-1] >= 0x80: hb += b"\x00"
        height_push = push(hb)
    tag = b"/xcoin/"
    pre = height_push + push(tag)
    ss_len = len(pre) + en_size
    # consensus/tx_check.cpp: a coinbase scriptSig outside 2..100 bytes is
    # bad-cb-length, and the block is rejected after the work is spent.
    if not MIN_COINBASE_SCRIPTSIG <= ss_len <= MAX_COINBASE_SCRIPTSIG:
        raise ValueError("coinbase scriptSig would be %d bytes (height push %d + tag %d + extranonce %d); "
                         "the consensus limit is %d..%d (bad-cb-length)"
                         % (ss_len, len(height_push), len(push(tag)), en_size,
                            MIN_COINBASE_SCRIPTSIG, MAX_COINBASE_SCRIPTSIG))
    part1 = (1).to_bytes(4,"little") + varint(1) + b"\x00"*32 + b"\xff\xff\xff\xff" + varint(ss_len) + pre

    outs = b""; nout = 0
    spk = check_payout_spk(payout_spk)
    outs += reward_sats.to_bytes(8,"little") + varint(len(spk)) + spk; nout += 1
    if True:
        if wc_hex:
            wc = bytes.fromhex(wc_hex)
            # The witness commitment is the only OP_RETURN this pool ever writes,
            # and BIP-141 fixes it at 38 bytes: well inside the data-carrier rules.
            if len(wc) > MAX_OP_RETURN_RELAY:
                raise ValueError("default_witness_commitment is %d bytes, over MAX_OP_RETURN_RELAY (%d)"
                                 % (len(wc), MAX_OP_RETURN_RELAY))
            outs += (0).to_bytes(8,"little") + varint(len(wc)) + wc; nout += 1
    part2 = b"\xff\xff\xff\xff" + varint(nout) + outs + (0).to_bytes(4,"little")
    return part1, part2

def merkle_branch(tx_hashes_le):
    """Sibling hashes for the coinbase (index 0)."""
    branch = []; layer = list(tx_hashes_le)
    while layer:
        branch.append(layer[0])
        if len(layer) % 2: layer.append(layer[-1])
        layer = [dsha256(layer[i] + layer[i+1]) for i in range(2, len(layer), 2)]
    return branch  # note: first element unused for coinbase; recomputed from cb below

# ── job manager ──────────────────────────────────────────────────────────────
class Jobs:
    def __init__(self):
        self.tmpl = None
        self.branch_le = []
        self.tx_hashes_le = []

    def refresh(self):
        """Fetch a template. Returns "tip" when the tip moved (miners must drop their
        jobs), "txs" when the tip is the same but the transaction set changed (a new
        job is worth pushing; old jobs stay valid because every job snapshots its own
        transactions), or None when nothing that matters changed."""
        t = rpc("getblocktemplate", [{"rules": ["segwit"]}])
        if not t:
            return None
        prev = t.get("previousblockhash")
        txids = [tx["txid"] for tx in t.get("transactions", [])]
        if self.tmpl and self.tmpl.get("previousblockhash") == prev:
            if [tx["txid"] for tx in self.tmpl.get("transactions", [])] == txids:
                self.tmpl = t
                return None  # same tip, same transactions: no new job needed
            change = "txs"
        else:
            change = "tip"
        # merkle branch for coinbase = siblings from the NON-coinbase txids. The
        # branch, and the transaction data it commits to, are snapshotted into every
        # job at notify() time: a solved header is only ever paired with the body it
        # was built for (audit finding 4: pairing a per-job root with the live
        # template's body produced bad-txnmrklroot and lost the block).
        txs = t.get("transactions", [])
        self.tx_hashes_le = [bytes.fromhex(tx["txid"])[::-1] for tx in txs]
        # branch: place coinbase at index 0, siblings are the reduction of the tx list
        layer = [b"\x00"*32] + self.tx_hashes_le  # placeholder cb at 0
        branch = []
        idx = 0
        while len(layer) > 1:
            if len(layer) % 2: layer.append(layer[-1])
            if idx ^ 1 < len(layer):
                branch.append(layer[idx ^ 1])
            layer = [dsha256(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
            idx >>= 1
        self.branch_le = branch
        self.tmpl = t
        return change

JOBS = Jobs()
SESSIONS = set()

# ── stratum session ──────────────────────────────────────────────────────────
MAX_AGENT_LEN = 120

def sanitize_agent(agent):
    """The mining.subscribe user-agent as the pool stores and shows it. Untrusted
    text that ends up in Discord embeds: keep printable ASCII that cannot carry
    markdown, mentions, links or control characters (audit finding L3), same
    spirit as the worker-name filter in mining.authorize."""
    text = re.sub(r"[^A-Za-z0-9 .,;:/()+-]", "", str(agent))
    text = re.sub(r" {2,}", " ", text).strip()[:MAX_AGENT_LEN]
    return text or "?"

def parse_submit_params(en2_hex, ntime_hex, nonce_hex, vbits_hex, en2_size):
    """(en2 bytes, ntime, nonce, version-bits-or-None) of a mining.submit, or
    ValueError. Every field is miner-supplied: a malformed one is a rejected
    share, never an exception (audit findings L1 and L2)."""
    if not isinstance(en2_hex, str) or not isinstance(ntime_hex, str) or not isinstance(nonce_hex, str):
        raise ValueError("submit fields must be hex strings")
    en2 = bytes.fromhex(en2_hex)
    if len(en2) != en2_size:
        raise ValueError(f"extranonce2 is {len(en2)} bytes, expected {en2_size}")
    ntime = int(ntime_hex, 16)
    if not 0 <= ntime <= 0xffffffff:
        raise ValueError("ntime is not a 32-bit value")
    nonce = int(nonce_hex, 16)
    if not 0 <= nonce <= 0xffffffff:
        raise ValueError("nonce is not a 32-bit value")
    vbits = None
    if vbits_hex not in (None, ""):
        if not isinstance(vbits_hex, str):
            raise ValueError("version bits must be a hex string")
        vbits = int(vbits_hex, 16)
        if not 0 <= vbits <= 0xffffffff:
            raise ValueError("version bits are not a 32-bit value")
    return en2, ntime, nonce, vbits

class Session:
    def __init__(self, reader, writer):
        self.r = reader; self.w = writer
        self.peer = writer.get_extra_info("peername")
        self.connected_at = time.time()
        self.en1 = secrets.token_bytes(4)
        self.en2_size = 4
        self.diff = CFG["start_diff"]
        self.hashrate_ewma = None
        self.last_share_at = None
        self.last_vardiff_at = time.time()
        self.vardiff_samples = 0
        self.spk = None          # payout scriptPubKey (OP_3 <root>) of the worker
        self.worker = "?"
        self.agent = "?"
        self.reject_reason = None   # why the last validate() said no, for the reply
        self.jobs = {}
        self.jobn = 0
        self.subscribed = False
        # Audit finding 14: one client must not stall the pool. Submits are validated one
        # at a time per connection, off the event loop, and rationed per second.
        self._submit_lock = asyncio.Lock()
        self._submit_times = []
        self._rate_limited = 0

    async def send(self, obj):
        self.w.write((json.dumps(obj) + "\n").encode()); await self.w.drain()

    async def notify(self, clean):
        t = JOBS.tmpl
        if not t or self.spk is None:
            return
        reward = t["coinbasevalue"]
        # scriptSig extranonce slot must fit extranonce1 (from subscribe) + extranonce2.
        p1, p2 = build_coinbase(t["height"], reward, len(self.en1) + self.en2_size,
                                t.get("default_witness_commitment"), self.spk)
        self.jobn += 1
        jid = f"{self.jobn:x}"
        prev_le = bytes.fromhex(t["previousblockhash"])[::-1]
        # stratum prevhash is sent as 8 little-endian 32-bit words
        prev_stratum = b"".join(prev_le[i:i+4][::-1] for i in range(0, 32, 4)).hex()
        self.jobs[jid] = {"p1": p1, "p2": p2, "prev_le": prev_le,
                          "version": t["version"], "bits": t["bits"],
                          "target": bits_to_target(t["bits"]), "height": t["height"],
                          "mintime": int(t.get("mintime", t["curtime"])),
                          "share_diff": self.diff,
                          # what the miner is actually paid by THIS template: the
                          # subsidy of the height's emission era plus the fees the
                          # node collected (which include every transaction's
                          # settlement levy). Never a hardcoded 50.
                          "reward_sats": int(reward),
                          "branch_le": list(JOBS.branch_le),
                          # the exact transactions this job's merkle branch commits to
                          "txs": [tx["data"] for tx in (t.get("transactions") or [])]}
        # keep only a few recent jobs
        if len(self.jobs) > 8:
            for k in list(self.jobs)[:-8]: self.jobs.pop(k, None)
        params = [jid, prev_stratum,
                  p1.hex(), p2.hex(),
                  [b.hex() for b in JOBS.branch_le],
                  f"{t['version']:08x}",
                  t["bits"], f"{t['curtime']:08x}", clean]
        await self.send({"id": None, "method": "mining.notify", "params": params})

    async def set_diff(self):
        await self.send({"id": None, "method": "mining.set_difficulty", "params": [self.diff]})

    def network_diff(self):
        """Difficulty of the current template, or None before the first template."""
        t = JOBS.tmpl
        if not t or "bits" not in t:
            return None
        try:
            return target_to_diff(bits_to_target(t["bits"]))
        except (TypeError, ValueError):
            return None

    async def apply_diff(self, requested):
        """Install a bounded vardiff target and issue fresh work at that target.
        A share difficulty above the network's is meaningless (every qualifying
        share is a block), so the ceiling is the smaller of vardiff_max and the
        template's difficulty."""
        ceiling = CFG["vardiff_max"]
        net = self.network_diff()
        if net is not None:
            ceiling = min(ceiling, net)
        bounded = max(CFG["vardiff_min"], min(ceiling, float(requested)))
        # Never change by more than 2x in either direction in one retune.
        bounded = max(self.diff * 0.5, min(self.diff * 2.0, bounded))
        if abs(bounded - self.diff) <= self.diff * 0.05:
            return
        self.diff = bounded
        self.last_vardiff_at = time.time()
        await self.set_diff()
        await self.notify(clean=True)
        log.info("vardiff %s: %.8g", self.worker, self.diff)

    async def observe_share(self, credit=None):
        """Estimate this miner's MetalDAG work rate and retune toward one share/15s.

        Share difficulty is pool accounting only. It never changes nBits or the
        probability that a submitted hash is a block. ``credit`` is the difficulty
        the share was credited at (credited_diff); it defaults to the session's
        share difficulty for callers that have no job in hand.
        """
        now = time.time()
        elapsed = float("inf")
        work_diff = self.diff if credit is None else float(credit)
        if self.last_share_at is not None:
            elapsed = max(0.001, now - self.last_share_at)
            sample = work_diff * (2 ** 32) / elapsed
            self.hashrate_ewma = sample if self.hashrate_ewma is None else (0.2 * sample + 0.8 * self.hashrate_ewma)
            self.vardiff_samples += 1
        self.last_share_at = now
        # Fast ramp: a miner arriving with far more hashrate than the start difficulty
        # assumes would submit faster than the flood budget (SUBMIT_RATE_PER_SEC) long
        # before the first scheduled retune, and be dropped for it. Whenever shares
        # arrive faster than FAST_RAMP_SHARES_PER_SEC, double the difficulty at once
        # (apply_diff bounds each step to 2x); from 0.001 to a GPU's steady level is a
        # handful of shares, well inside the burst allowance.
        if self.vardiff_samples >= 2 and elapsed < 1.0 / FAST_RAMP_SHARES_PER_SEC:
            await self.apply_diff(self.diff * 2.0)
            return
        if (self.hashrate_ewma is not None and self.vardiff_samples >= 4 and
                now - self.last_vardiff_at >= CFG["vardiff_interval"]):
            ideal = self.hashrate_ewma * CFG["vardiff_target"] / (2 ** 32)
            await self.apply_diff(ideal)

    def _reject(self, reason=None):
        self.reject_reason = reason
        return (False, False, None, None)

    async def validate(self, jid, en2_hex, ntime_hex, nonce_hex, vbits_hex):
        self.reject_reason = None
        j = self.jobs.get(jid) if isinstance(jid, str) else None
        if not j:
            if os.environ.get("XCOIN_POOL_DEBUG"):
                log.warning("DBG stale/unknown jid=%s known=%s worker=%s", jid, list(self.jobs)[-4:], getattr(self, "worker", "?"))
            return self._reject()
        try:
            ntime = int(ntime_hex, 16)
        except (TypeError, ValueError):
            return self._reject("bad params: ntime")
        # Reject attacker-controlled epochs before calling the node's expensive
        # MetalDAG RPC. Consensus rejects blocks more than two hours ahead, and
        # BIP113/BIP34-era templates expose the minimum valid header time.
        if ntime < j["mintime"] or ntime > int(time.time()) + 2 * 60 * 60:
            return (False, False, None, None)
        # A job built on a tip that is no longer the node's is stale: its block would be
        # rejected and its share is worth nothing.
        if JOBS.tmpl and j["prev_le"] != bytes.fromhex(JOBS.tmpl["previousblockhash"])[::-1]:
            return (False, False, None, None)
        # Miner-supplied hex: malformed, wrong-length or out-of-range values are a
        # clean reject (audit findings L1, L2). extranonce2 MUST be exactly the
        # advertised en2_size: build_coinbase baked len(en1) + en2_size into the
        # scriptSig length varint, so any other length is a block the node rejects.
        try:
            en2, ntime, nonce, vbits = parse_submit_params(en2_hex, ntime_hex, nonce_hex, vbits_hex, self.en2_size)
        except (TypeError, ValueError, OverflowError) as e:
            return self._reject(f"bad params: {e}")
        cb = j["p1"] + self.en1 + en2 + j["p2"]
        root = dsha256(cb)
        for sib in j["branch_le"]:
            root = dsha256(root + sib)
        version = j["version"]
        if vbits is not None:
            # BIP 320 version rolling minus header bits 28..29: on the v2 chain
            # those two bits are the PoW-algorithm id (REGENESIS.md section 7)
            # and must stay 0 until the multi-algorithm activation, so a rolled
            # bit 28 would make the block "bad-pow-algo". Bits 13..27 only.
            mask = 0x0fffe000
            version = (version & ~mask) | (vbits & mask)
        header = (version.to_bytes(4,"little") + j["prev_le"] + root +
                  ntime.to_bytes(4,"little") + int(j["bits"],16).to_bytes(4,"little") +
                  nonce.to_bytes(4,"little"))
        h = dsha256(header)                                # block IDENTITY hash (SHA256d, unchanged)
        # MetalDAG proof-of-work: the node computes the memory-hard PoW hash (light verify)
        # so the pool doesn't have to reimplement it. Returned big-endian; compare as int.
        # Off the event loop: a slow node must never freeze every other miner (audit finding 14).
        powhex = await asyncio.to_thread(rpc, "getmetaldagpowhash", [header.hex()])
        if powhex is None:
            return (False, False, None, None)              # node unavailable — reject safely
        hi = int.from_bytes(bytes.fromhex(powhex), "big")  # MetalDAG PoW value
        is_block = hi <= j["target"]                       # PoW meets the network target
        stgt = diff_to_target(j["share_diff"])
        if os.environ.get("XCOIN_POOL_DEBUG"):
            log.warning("DBG worker=%s h=%s ntime=%s nonce=%s sdiff=%s\n  hi  =%064x\n  stgt=%064x\n  net =%064x\n  meets_share=%s is_block=%s ACCEPT=%s",
                        getattr(self, "worker", "?"), j.get("height"), ntime_hex, nonce_hex, j["share_diff"],
                        hi, stgt, j["target"], hi <= stgt, is_block, (hi <= stgt or is_block))
        # Accept if it clears the share target OR it is an outright block. (On a
        # very-easy chain the network target can be easier than the share target,
        # so a real block must never be rejected as a low-difficulty share.)
        if hi > stgt and not is_block:
            return (False, False, None, None)
        if is_block:
            # Serialize the coinbase in SEGWIT form: insert marker+flag after the
            # version, and append the witness (one input, reserved value = 32 zero
            # bytes) before the locktime. The merkle root above used the NON-witness
            # coinbase txid (as the miner computed it); the witness reserved value
            # matches the template's default_witness_commitment.
            seg_cb = cb[:4] + b"\x00\x01" + cb[4:-4] + b"\x01\x20" + b"\x00"*32 + cb[-4:]
            others = [bytes.fromhex(d) for d in j["txs"]]   # the job's own snapshot, never the live template
            block = header + varint(1 + len(others)) + seg_cb + b"".join(others)
            return (True, True, block.hex(), h[::-1].hex())
        return (True, False, None, None)

    async def handle(self):
        SESSIONS.add(self)
        try:
            while True:
                line = await self.r.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if not isinstance(msg, dict):
                    continue
                try:
                    await self.dispatch(msg)
                except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
                    raise
                except Exception as e:
                    # A malformed request is that request's problem, not the session's
                    # (audit finding L1): answer with a stratum error and keep serving.
                    log.warning("bad request from %s (%s): %s: %s", self.peer, self.worker, type(e).__name__, e)
                    try:
                        await self.send({"id": msg.get("id"), "result": None, "error": [20, "bad params", None]})
                    except Exception:
                        break
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        finally:
            SESSIONS.discard(self)
            try: self.w.close()
            except Exception: pass

    async def dispatch(self, msg):
        mid = msg.get("id"); method = msg.get("method"); params = msg.get("params") or []
        if method == "mining.subscribe":
            self.subscribed = True
            # miner user-agent, e.g. "MMM-CLI/1.0.0 (Apple M3 Pro; Mac15,6)". Untrusted
            # text shown in the Discord leaderboard: sanitized like the worker name.
            self.agent = sanitize_agent(params[0]) if params else "?"
            self.connected_at = time.time()
            await self.send({"id": mid, "result": [[["mining.notify", "xcoin"]], self.en1.hex(), self.en2_size], "error": None})
        elif method == "mining.authorize":
            user = params[0] if params else ""
            addr = user.split(".")[0]
            # worker NAME = the part after the dot ("xpa1r….rig1" -> "rig1")
            # Untrusted text that ends up in Discord embeds and the explorer:
            # keep it to a plain identifier so it can never carry markdown,
            # mentions or control characters.
            self.worker = re.sub(r"[^A-Za-z0-9_.-]", "", user.split(".", 1)[1] if "." in user else "default")[:32] or "default"
            self.worker = session_worker_name(self.worker)
            self.address = addr
            try:
                self.spk = payout_script(addr)
                ok, why = True, None
            except AddressError as e:
                # A legacy witness v2 string lands here: the message tells the miner
                # to use a witness v3 address from the node wallet.
                self.spk, ok, why = None, False, str(e)
                log.warning("miner refused: %s -> %s", self.peer, why)
            await self.send({"id": mid, "result": ok, "error": None if ok else [24, why, None]})
            if ok:
                log.info("miner authorized: %s -> %s (%s)", self.peer, addr, self.worker)
                touch_miner(addr)["worker"] = self.worker  # persist name in the registry
                touch_rig(addr, self.worker)
                # Tell the miner the name it is registered under (a browser session
                # learns its number this way). client.show_message is the stratum
                # convention for a human-readable notice; miners that ignore it lose nothing.
                await self.send({"id": None, "method": "client.show_message",
                                 "params": [f"registered as {self.worker}"]})
                await self.set_diff()
                await asyncio.to_thread(JOBS.refresh)
                await self.notify(clean=True)
        elif method == "mining.submit":
            if len(params) < 5:
                await self.send({"id": mid, "result": False, "error": [20, "bad params", None]}); return
            _, jid, en2, ntime, nonce = params[:5]
            vbits = params[5] if len(params) > 5 else None
            # Per-connection submit budget: SUBMIT_RATE_PER_SEC a second, then refused without
            # touching the node; a client that keeps flooding is dropped (audit finding 14).
            now = time.time()
            self._submit_times = [t for t in self._submit_times if now - t < 1.0]
            if len(self._submit_times) >= SUBMIT_RATE_PER_SEC:
                self._rate_limited += 1
                await self.send({"id": mid, "result": False, "error": [23, "rate limited", None]})
                if self._rate_limited > SUBMIT_FLOOD_DISCONNECT:
                    log.warning("dropping %s (%s): submit flood", self.peer, self.worker)
                    self.w.close()
                return
            self._submit_times.append(now)
            async with self._submit_lock:
                valid, is_block, block_hex, bh = await self.validate(jid, en2, ntime, nonce, vbits)
            if valid:
                await self.send({"id": mid, "result": True, "error": None})
                j = self.jobs[jid]
                credit = credited_diff(j["share_diff"], j["target"])   # what the miner had to meet
                record_share(getattr(self, "address", "?"), credit)     # persistent stats
                record_rig_share(getattr(self, "address", "?"), self.worker, credit)
                await self.observe_share(credit)
                if is_block:
                    log.warning("BLOCK FOUND %s (height %s) by %s", bh, self.jobs[jid]["height"], self.worker)
                    res = await asyncio.to_thread(rpc, "submitblock", [block_hex])
                    # submitblock returns null on success; distinguish real acceptance
                    # from an RPC error by checking whether the tip is now our block.
                    if await asyncio.to_thread(rpc, "getbestblockhash") == bh:
                        h = self.jobs[jid]["height"]
                        record_block(getattr(self, "address", "?"))
                        record_rig_block(getattr(self, "address", "?"), self.worker)
                        save_stats()  # persist the win immediately
                        log.warning("block ACCEPTED by nexd: %s", bh)
                        reward_xat = self.jobs[jid].get("reward_sats", 0) / 1e8
                        discord_block_found(self.worker, getattr(self, "address", "?"), h, bh,
                                            reward=f"{reward_xat:.8f}".rstrip("0").rstrip("."))
                        # Tell the winning miner so its client counts the block
                        # (the GUI handles method "mining.block_found" [hash, height, reward]).
                        try:
                            await self.send({"id": None, "method": "mining.block_found",
                                             "params": [bh, h, reward_xat]})
                        except Exception:
                            pass
                    else:
                        log.error("block REJECTED by nexd: %s", res)
                    change = await asyncio.to_thread(JOBS.refresh)
                    if change:
                        for s in list(SESSIONS): await s.notify(clean=(change == "tip"))
            else:
                why = self.reject_reason or "low difficulty / stale"
                await self.send({"id": mid, "result": False, "error": [20 if why.startswith("bad params") else 23, why, None]})
        elif method == "mining.hashrate":
            # Live device counter for display over the existing Stratum connection,
            # shown only as "reported": accepted shares are the pool's own figure
            # (measured_hps) and this value never replaces or joins them.
            if getattr(self, "address", None) and params:
                try:
                    hps = float(params[0])
                    if 0 <= hps <= 1e15:
                        m = touch_rig(self.address, self.worker)
                        m["reported_hps"] = hps
                        m["reported_at"] = int(time.time())
                        m["worker"] = self.worker
                except (TypeError, ValueError):
                    pass
        elif method in ("mining.extranonce.subscribe", "mining.multi_version"):
            await self.send({"id": mid, "result": True, "error": None})
        elif method == "mining.suggest_difficulty":
            # A suggestion is a hint, not authority to disable vardiff or create a
            # share-flood. Clamp it through the same controller used by observations.
            try:
                d = float(params[0])
                if d > 0: await self.apply_diff(d)
            except Exception: pass
            await self.send({"id": mid, "result": True, "error": None})
        else:
            await self.send({"id": mid, "result": None, "error": [20, f"unknown {method}", None]})

# ── main ─────────────────────────────────────────────────────────────────────
async def poll_loop():
    while True:
        try:
            change = await asyncio.to_thread(JOBS.refresh)
            if change:
                for s in list(SESSIONS):
                    await s.notify(clean=(change == "tip"))
        except Exception as e:
            log.error("poll error: %s", e)
        # If a previously fast miner thermally throttles, lower its share target
        # without touching consensus difficulty. Rate-limit this to one step/interval.
        now = time.time()
        for s in list(SESSIONS):
            silent = now - (s.last_share_at or getattr(s, "connected_at", now))
            if (silent >= max(90.0, CFG["vardiff_target"] * 6) and
                    now - s.last_vardiff_at >= CFG["vardiff_interval"]):
                try:
                    await s.apply_diff(s.diff * 0.5)
                except Exception as e:
                    log.warning("silent vardiff failed for %s: %s", s.worker, e)
        await asyncio.sleep(CFG["poll_secs"])

def require_own_node():
    """The own-node rule: the pool's node is THIS machine's node, or the pool
    does not run. Only literal loopback addresses pass — a hostname that merely
    resolves to loopback is an evasion nobody legitimately needs."""
    host = str(CFG["rpc_host"]).strip().strip("[]").lower()
    ok = host == "localhost"
    if not ok:
        try:
            import ipaddress
            ok = ipaddress.ip_address(host).is_loopback
        except ValueError:
            ok = False
    if not ok:
        raise SystemExit(
            f"XCOIN_RPC_HOST={CFG['rpc_host']}: refused. The own-node rule: to run a pool "
            "you run a full node ON THIS MACHINE and point the pool at it over loopback "
            "(XCOIN_RPC_HOST=127.0.0.1). A pool that leans on a remote node adds nothing "
            "to the network; a pool on its own node is one more independent verifier. "
            "Install the node: github.com/SystemThreat/xCoin")

async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    require_own_node()
    if CFG["rpc_cookie"]:
        if not os.path.isfile(CFG["rpc_cookie"]):
            raise SystemExit(f"XCOIN_RPC_COOKIE={CFG['rpc_cookie']}: no such file. Is nexd running with that datadir?")
    elif CFG["rpc_user"] and CFG["rpc_pass"]:
        log.warning("XCOIN_RPC_PASSWORD puts a secret in the environment; prefer "
                    "XCOIN_RPC_COOKIE=<datadir>/<chain>/.cookie (contrib/regenesis/WALLET-SECRETS.md)")
    else:
        raise SystemExit("Set XCOIN_RPC_COOKIE to the node's .cookie file (preferred), "
                         "or XCOIN_RPC_USER and XCOIN_RPC_PASSWORD.")
    info = rpc("getblockchaininfo")
    if not info:
        raise SystemExit("Cannot reach nexd RPC — is the node running and are the creds right?")
    log.info("connected to nexd: chain=%s height=%s", info.get("chain"), info.get("blocks"))
    log.info("own-node rule satisfied: RPC on loopback — this pool stands on its own verifier")

    # The address HRP is the node's, not the environment's. Trusting the env var means one
    # wrong export can point a rehearsal pool at the wrong rule set: with hrp=nxrt the pool
    # would accept a witness v2 payout on a chain whose consensus forbids it. Derive it from
    # the chain the node actually reports and refuse to start on a contradiction.
    CHAIN_HRP = {"main": "xpa", "test": "txa", "regtest": REGTEST_HRP}
    node_chain = info.get("chain")
    expected = CHAIN_HRP.get(node_chain)
    if expected is None:
        raise SystemExit(f"Unknown chain {node_chain!r} from getblockchaininfo; refusing to start.")
    if CFG["hrp"] != expected:
        raise SystemExit(
            f"Address HRP {CFG['hrp']!r} contradicts the node's chain {node_chain!r}, which uses {expected!r}. "
            f"Set XCOIN_ADDRESS_HRP={expected} or point XCOIN_RPC_PORT at the right node; refusing to start."
        )
    log.info("address HRP %s confirmed against the node's chain %s", expected, node_chain)
    load_miners()
    JOBS.refresh()
    srv = await asyncio.start_server(lambda r, w: Session(r, w).handle(), CFG["stratum_host"], CFG["stratum_port"])
    log.info("xcoin-pool stratum listening on %s:%s (solo)", CFG["stratum_host"], CFG["stratum_port"])
    asyncio.create_task(poll_loop())
    asyncio.create_task(stats_loop())
    asyncio.create_task(natpmp_loop())
    async with srv:
        await srv.serve_forever()

# ── NAT-PMP auto port-forward ─────────────────────────────────────────────────
# Keeps the stratum port reachable from the public internet when the pool runs
# behind a home router that speaks NAT-PMP. The lease is short-lived by design,
# so natpmp_loop() re-requests it well before it expires. If the router doesn't
# answer, we warn once per cycle so the operator knows to add a manual forward.
def _default_gateway():
    try:
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3).stdout
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("gateway:"):
                return ln.split(":", 1)[1].strip()
    except Exception:
        pass
    try:  # Linux fallback
        out = subprocess.run(["sh", "-c", "ip route | awk '/default/{print $3; exit}'"],
                             capture_output=True, text=True, timeout=3).stdout.strip()
        return out or None
    except Exception:
        return None

def natpmp_map(port, lifetime=7200):
    gw = _default_gateway()
    if not gw:
        return None, "no default gateway found"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
        s.sendto(struct.pack(">BBHHHI", 0, 2, 0, port, port, lifetime), (gw, 5351))  # op2 = map TCP
        d, _ = s.recvfrom(32); s.close()
        _, _, res, _, _, outp, life = struct.unpack(">BBHIHHI", d[:16])
        return (0, f"external TCP {outp}, lease {life}s") if res == 0 else (res, f"router code {res}")
    except Exception as e:
        return None, str(e)

async def natpmp_loop():
    if os.environ.get("XCOIN_NATPMP", "1").lower() not in ("1", "true", "yes", "on"):
        log.info("NAT-PMP auto-forward disabled (XCOIN_NATPMP=0)"); return
    port = CFG["stratum_port"]
    while True:
        code, msg = await asyncio.to_thread(natpmp_map, port, 7200)
        if code == 0:
            log.info("NAT-PMP: forwarded TCP %d (%s)", port, msg)
        else:
            log.warning("NAT-PMP: could not forward TCP %d (%s) — add a manual router port-forward "
                        "%d→%d if remote miners can't connect", port, msg, port, port)
        await asyncio.sleep(3300)  # renew before the 7200s lease lapses

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
