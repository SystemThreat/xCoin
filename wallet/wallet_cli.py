#!/usr/bin/env python3
"""xcoin-wallet transaction CLI using Xcoin's consensus-native PQ RPCs.

All money is handled as Decimal end-to-end (RPC responses are parsed with
parse_float=Decimal and amounts are sent to the node as 8-decimal strings),
so no float ever touches an amount that gets signed or broadcast.
"""

import argparse, base64, getpass, hashlib, hmac, json, os, shutil, subprocess, sys, time, urllib.request, urllib.error
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path

DEFAULT_CONFIG = Path.home() / ".xcoin" / "nex.conf"

def default_wallet():
    """Prefer wallet.mmm, then any other .mmm (e.g. wallet001.mmm), then legacy."""
    d = Path.home() / ".xcoin"
    if (d / "wallet.mmm").exists(): return d / "wallet.mmm"
    others = sorted(d.glob("*.mmm")) if d.exists() else []
    if others: return others[0]
    if (d / "wallet.seed").exists(): return d / "wallet.seed"
    return d / "wallet.mmm"

COINBASE_MATURITY = 100          # consensus/consensus.h
PQ_SIGNATURE_SIZE = 3309         # ML-DSA-65 signature (pqkey.h)
PQ_PUBKEY_SIZE = 1952            # ML-DSA-65 public key
# Witness stack per input: count(1) + push(3)+sig+sighashbyte + push(3)+pubkey
WITNESS_PER_INPUT = 1 + 3 + (PQ_SIGNATURE_SIZE + 1) + 3 + PQ_PUBKEY_SIZE
INPUT_BASE_SIZE = 36 + 1 + 4     # outpoint + empty scriptSig len + sequence
OUTPUT_SIZE = 8 + 1 + 34         # value + script len + witness-v2 script
DUST_CHANGE = Decimal("0.00001") # change below this is folded into the fee
DEFAULT_MAX_FEE = Decimal("0.1")

class WalletError(RuntimeError): pass

def money(v, what="amount"):
    try: return Decimal(str(v)).quantize(Decimal("0.00000001"))
    except InvalidOperation: raise WalletError(f"invalid {what}: {v!r}")

def money_ceil_sat(v):
    return v.quantize(Decimal("0.00000001"), rounding=ROUND_CEILING)

def fmt(v): return f"{money(v):f} XID"
def fmt8(v): return f"{money(v):.8f}"

def jdefault(o):
    if isinstance(o, Decimal): return fmt8(o)
    raise TypeError(f"not JSON serializable: {type(o)}")

def emit_json(data): print(json.dumps(data, indent=2, default=jdefault))

# --- .mmm wallet file format ---------------------------------------------
# magic(10) | salt(16) | nonce(16) | ciphertext(32-64) | hmac-sha256(32)
# key material: scrypt(passphrase, salt) -> enc_key(32) + mac_key(32)
# cipher: seed XOR shake256(enc_key || nonce); integrity: encrypt-then-MAC.
# With a passphrase this is real encryption; with an empty passphrase the file
# is still opaque + tamper-evident, but anyone with this open-source CLI could
# decode it — the passphrase is what makes it truly CLI-and-you-only.
MMM_MAGIC = b"XCOINMMM1\n"    # passphrase / plaintext-passphrase wallet
MMM2_MAGIC = b"XCOINMMM2\n"   # NTAG 424 DNA card-bound wallet
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 15, 8, 1

def _scrypt(secret, salt):
    dk = hashlib.scrypt(secret, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=128 * 1024 * 1024, dklen=64)
    return dk[:32], dk[32:]

def _mmm_keys(passphrase, salt):
    return _scrypt(passphrase.encode(), salt)

def _card_module():
    """Lazy import — passphrase wallets never need pyscard/cryptography for cards."""
    d = str(Path(__file__).resolve().parent)
    if d not in sys.path: sys.path.insert(0, d)
    try:
        import card_seed
        return card_seed
    except Exception as e:
        raise WalletError(f"card support unavailable ({e}); install pyscard + cryptography")

def mmm2_encode(seed_hex, factor_bytes, family_hex, passphrase=""):
    payload = bytes.fromhex(seed_hex)
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _scrypt(factor_bytes + passphrase.encode(), salt)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(payload))
    body = MMM2_MAGIC + bytes.fromhex(family_hex) + salt + nonce + bytes(a ^ b for a, b in zip(payload, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()

def mmm2_family(blob):
    return blob[10:18].hex()

def mmm2_decode(blob, factor_bytes, passphrase=""):
    if len(blob) < len(MMM2_MAGIC) + 8 + 16 + 16 + 32 + 32: raise WalletError("corrupt .mmm (card) wallet file")
    salt, nonce = blob[18:34], blob[34:50]
    ct, mac = blob[50:-32], blob[-32:]
    if not 32 <= len(ct) <= 64: raise WalletError("corrupt .mmm (card) wallet file")
    enc_key, mac_key = _scrypt(factor_bytes + passphrase.encode(), salt)
    if not hmac.compare_digest(hmac.new(mac_key, blob[:-32], hashlib.sha256).digest(), mac):
        raise WalletError("wrong card (or passphrase), or corrupt wallet file")
    stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream)).hex()

def is_card_wallet(path):
    try:
        with open(path, "rb") as f: return f.read(len(MMM2_MAGIC)) == MMM2_MAGIC
    except OSError: return False

def mmm_encode(seed_hex, passphrase):
    payload = bytes.fromhex(seed_hex)
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _mmm_keys(passphrase, salt)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(payload))
    body = MMM_MAGIC + salt + nonce + bytes(a ^ b for a, b in zip(payload, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()

def mmm_decode(blob, passphrase):
    if len(blob) < len(MMM_MAGIC) + 16 + 16 + 32 + 32: raise WalletError("corrupt .mmm wallet file")
    salt, nonce = blob[10:26], blob[26:42]
    ct, mac = blob[42:-32], blob[-32:]
    if not 32 <= len(ct) <= 64: raise WalletError("corrupt .mmm wallet file")
    enc_key, mac_key = _mmm_keys(passphrase, salt)
    if not hmac.compare_digest(hmac.new(mac_key, blob[:-32], hashlib.sha256).digest(), mac):
        raise WalletError("wrong passphrase (or corrupt .mmm wallet file)")
    stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream)).hex()

def _valid_seed(seed):
    return len(seed) in range(64, 129, 2) and all(c in "0123456789abcdef" for c in seed.lower())

# A passphrase reaches this process in exactly two ways: typed at the terminal, or
# handed over a file descriptor by a parent program (--passphrase-fd N; NerdMiner
# login uses a pipe). Never the environment: an environment variable is readable
# by every other program the user runs and lands in shell history in plain text,
# so XCOIN_WALLET_PASSPHRASE is refused at startup (see main()).
PASSPHRASE_FROM_FD = None

def supplied_passphrase():
    """The passphrase a parent handed over --passphrase-fd, or None."""
    return PASSPHRASE_FROM_FD

def read_passphrase_fd(fd):
    """Read one line from fd (the passphrase), strip the newline, close the fd."""
    global PASSPHRASE_FROM_FD
    try:
        with os.fdopen(int(fd), "r", closefd=True) as f:
            PASSPHRASE_FROM_FD = f.readline().rstrip("\r\n")
    except (OSError, ValueError) as e:
        raise WalletError(f"--passphrase-fd {fd}: cannot read it ({e})")

def can_prompt():
    """True when this process may read the terminal: stdin is a tty AND we are the
    terminal's foreground process group. A child that a parent program started
    in its own process group (NerdMiner login) is not: reading the terminal would
    get it SIGTTIN and a silent hang, so it must report that it cannot ask and let
    the parent ask instead (the text below is what NerdMiner looks for)."""
    try:
        return sys.stdin.isatty() and os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()
    except OSError:
        return False

NO_TERMINAL = "no terminal available to ask for the passphrase"

def unlock_passphrase_candidates():
    """Cheap candidates first: no-passphrase wallets never prompt."""
    yield ""
    pw = supplied_passphrase()
    if pw is not None: yield pw

def card_passphrase():
    pw = supplied_passphrase()
    if pw is not None: return pw
    if can_prompt(): return getpass.getpass("Card wallet passphrase (Enter if none): ")
    return ""

def read_seed_card(blob):
    """Unlock a card-bound wallet: tap the matching card, read its factor over
    an authenticated+encrypted channel, derive the wallet key. The factor and
    seed live only in mlock'd secure buffers here."""
    cs = _card_module()
    cs.disable_core_dumps()
    want_family = mmm2_family(blob)
    transport = cs.PCSCTransport()
    try:
        factor, auth = cs.read_factor(transport)
    finally:
        transport.close()
    try:
        if cs.family_of(factor.bytes()) != want_family:
            raise WalletError("this card does not belong to this wallet (family mismatch)")
        pw = card_passphrase()
        seed = mmm2_decode(blob, factor.bytes(), pw)
        if not _valid_seed(seed): raise WalletError("decryption produced an invalid seed")
        return seed.lower()
    finally:
        factor.close()

def read_seed(path):
    try: blob = Path(path).read_bytes()
    except FileNotFoundError: raise WalletError(f"no wallet at {path}; run `xcoin-wallet new`")
    if blob.startswith(MMM2_MAGIC):
        return read_seed_card(blob)
    if blob.startswith(MMM_MAGIC):
        for pw in unlock_passphrase_candidates():
            try: seed = mmm_decode(blob, pw)
            except WalletError: continue
            if _valid_seed(seed): return seed.lower()
        if not can_prompt():
            raise WalletError(f"wallet is passphrase-protected and {NO_TERMINAL}; run it from a terminal or hand the passphrase over --passphrase-fd")
        for _ in range(3):
            try:
                seed = mmm_decode(blob, getpass.getpass("Wallet passphrase: "))
                if _valid_seed(seed): return seed.lower()
            except WalletError as e:
                print(f"error: {e}", file=sys.stderr)
        raise WalletError("could not unlock wallet")
    try: seed = blob.decode().strip()
    except UnicodeDecodeError: raise WalletError("wallet seed file is invalid")
    if not _valid_seed(seed): raise WalletError("wallet seed file is invalid")
    return seed.lower()

def new_passphrase(args):
    """Ask (twice) for a passphrase for a wallet being created; '' = none."""
    pw = supplied_passphrase()
    if pw is not None: return pw
    if not can_prompt() or args.json: return ""
    while True:
        a = getpass.getpass("Encryption passphrase (Enter for none): ")
        if not a:
            print("No passphrase: the .mmm file is opaque + tamper-evident, but not secret from")
            print("someone who has both the file and this open-source CLI. A passphrase fixes that.")
            return ""
        b = getpass.getpass("Confirm passphrase: ")
        if a == b: return a
        print("passphrases do not match, try again", file=sys.stderr)

def write_seed(path, seed, passphrase=None):
    """New wallets are written in .mmm format; plaintext is legacy/read-only."""
    p = Path(path); p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(mmm_encode(seed, passphrase or ""))

def parse_conf(path):
    out = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); out[k.strip()] = v.strip()
    except FileNotFoundError: pass
    return out

class RPC:
    def __init__(self, args):
        self.conf = parse_conf(args.config)
        self.host = args.rpc_host or self.conf.get("rpcconnect", "127.0.0.1")
        self.port = args.rpc_port or int(self.conf.get("rpcport", "9432"))
        self.user = args.rpc_user or self.conf.get("rpcuser") or os.getenv("XCOIN_RPC_USER")
        self.password = args.rpc_password or self.conf.get("rpcpassword") or os.getenv("XCOIN_RPC_PASSWORD")
        if not self.user or not self.password:
            raise WalletError("RPC credentials missing; set them in nex.conf or use --rpc-user/--rpc-password")
    def call(self, method, params=None, timeout=60):
        body = json.dumps({"jsonrpc": "1.0", "id": "xcoin-wallet", "method": method,
                           "params": params or []}, default=jdefault).encode()
        req = urllib.request.Request(f"http://{self.host}:{self.port}/", data=body,
                                     headers={"Content-Type": "application/json"})
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = json.load(response, parse_float=Decimal)
        except urllib.error.HTTPError as e:
            # The node answers RPC-level errors with HTTP 500 + a JSON body;
            # surface the real message instead of a generic connection error.
            try: result = json.loads(e.read().decode(), parse_float=Decimal)
            except Exception: raise WalletError(f"RPC {method} failed: HTTP {e.code}")
        except Exception as e:
            raise WalletError(f"cannot reach nexd RPC at {self.host}:{self.port}: {e}")
        if result.get("error"):
            raise WalletError(f"RPC {method}: {result['error'].get('message', result['error'])}")
        return result.get("result")

def keytool_path():
    """The native ML-DSA keytool binary (offline signer), alongside this script."""
    p = Path(__file__).resolve().parent / "xcoin-wallet"
    return p if p.exists() and os.access(p, os.X_OK) else None

def sign_offline(seed, raw, prev):
    """Sign the raw tx with the native keytool — the seed never leaves this host
    or reaches the node. Seed + tx + prevouts go to the tool over stdin (never
    argv). Returns the signed tx hex."""
    tool = keytool_path()
    if not tool:
        raise WalletError("offline signer not found: build the native keytool (`NEX=.. ./build.sh`) "
                          "; there is no alternative: the seed never leaves this host")
    lines = [seed, raw]
    for u in prev:
        sats = int((money(u["amount"]) * Decimal("100000000")).to_integral_value())
        lines.append(f'{u["txid"]} {u["vout"]} {u["scriptPubKey"]} {sats} {u["keyindex"]}')
    stdin = ("\n".join(lines) + "\n").encode()
    try:
        proc = subprocess.run([str(tool), "sign"], input=stdin, capture_output=True, timeout=120)
    except Exception as e:
        raise WalletError(f"offline signer could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"offline signing failed: {proc.stderr.decode(errors='replace').strip()}")
    out = proc.stdout.decode().strip()
    if not out or any(c not in "0123456789abcdef" for c in out.lower()):
        raise WalletError("offline signer returned no valid transaction")
    return out


def derive_offline(seed, index):
    """Derive address `index` with the native keytool — the seed never leaves this
    host or reaches the node. The seed goes to the tool over stdin (never argv).
    Returns {address, identity, scriptPubKey, ...}: `address` is the witness v2
    xpa1z… form, `identity` the forum handle xid1… of the same key (bech32m over
    SHA-256(pubkey) with no witness version: a handle, nothing can be paid to it)."""
    tool = keytool_path()
    if not tool:
        raise WalletError("offline keytool not found: build the native keytool (`NEX=.. ./build.sh`) "
                          "; there is no alternative: the seed never leaves this host")
    try:
        proc = subprocess.run([str(tool), "_address", "--index", str(int(index))],
                              input=(seed + "\n").encode(), capture_output=True, timeout=60)
    except Exception as e:
        raise WalletError(f"offline keytool could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"offline derivation failed: {proc.stderr.decode(errors='replace').strip()}")
    try:
        info = json.loads(proc.stdout.decode())
    except ValueError:
        raise WalletError("offline keytool returned no valid address")
    if not isinstance(info, dict) or not info.get("address") or not info.get("scriptPubKey") or not info.get("identity"):
        raise WalletError("offline keytool returned an incomplete address (rebuild it: `NEX=.. ./build.sh`)")
    return info

def derive(rpc, seed, index):
    """Address for key `index`, derived OFFLINE: the seed never reaches the node."""
    return derive_offline(seed, index)

def scan(rpc, script):
    result = rpc.call("scantxoutset", ["start", [f"raw({script})"]], timeout=300)
    if not result or not result.get("success"): raise WalletError("UTXO scan failed")
    return result

def require_seed(args): return read_seed(args.file)

def classify_utxos(result):
    """Split scan results into (mature, immature) with normalized Decimal amounts."""
    tip = result.get("height", 0)
    mature, immature = [], []
    for u in result.get("unspents", []):
        u["amount"] = money(u["amount"])
        confs = u.get("confirmations")
        if confs is None: confs = tip - u.get("height", tip) + 1
        u["confirmations"] = confs
        if u.get("coinbase") and confs < COINBASE_MATURITY:
            u["blocks_to_maturity"] = COINBASE_MATURITY - confs
            immature.append(u)
        else:
            mature.append(u)
    return mature, immature

def estimate_sizes(n_in, n_out):
    """(total_bytes, vsize) for a fully signed PQ transaction."""
    def varint(n): return 1 if n < 0xfd else 3
    base = 4 + varint(n_in) + INPUT_BASE_SIZE * n_in + varint(n_out) + OUTPUT_SIZE * n_out + 4
    witness = 2 + WITNESS_PER_INPUT * n_in  # marker+flag + per-input stacks
    total = base + witness
    vsize = (base * 4 + witness + 3) // 4
    return total, vsize

def fee_for(n_in, n_out, feerate):
    _, vsize = estimate_sizes(n_in, n_out)
    return money_ceil_sat(feerate * vsize / 1000)

def resolve_feerate(rpc, args):
    """Return (feerate XID/kvB, source). Never below the node's relay floor."""
    floor = Decimal("0.00000100")
    try:
        mi = rpc.call("getmempoolinfo")
        floor = max(money(mi.get("minrelaytxfee", floor)), money(mi.get("mempoolminfee", 0)))
    except WalletError: pass
    if args.feerate is not None:
        rate = money(args.feerate, "feerate")
        if rate < floor: raise WalletError(f"feerate {fmt8(rate)} is below the relay floor {fmt8(floor)}")
        return rate, "--feerate"
    try:
        est = rpc.call("estimatesmartfee", [6])
        if est and est.get("feerate"): return max(money(est["feerate"]), floor), "estimatesmartfee"
    except WalletError: pass
    fallback = rpc.conf.get("fallbackfee")
    if fallback: return max(money(fallback, "fallbackfee"), floor), "fallbackfee"
    return max(floor * 10, floor), "relay floor x10"

def select_coins(mature, amount, feerate=None, fixed_fee=None):
    """Largest-first selection (fewer huge PQ inputs = smaller tx = lower fee).

    Returns (selected, fee, change). With feerate the fee grows as inputs are
    added; sub-dust change is folded into the fee either way.
    """
    selected, total = [], Decimal(0)
    for u in sorted(mature, key=lambda x: x["amount"], reverse=True):
        selected.append(u); total += u["amount"]
        fee = fixed_fee if fixed_fee is not None else fee_for(len(selected), 2, feerate)
        if total >= amount + fee:
            change = money(total - amount - fee)
            if 0 < change < DUST_CHANGE:
                fee = money(fee + change); change = Decimal(0)
            return selected, money(fee), change
    fee = fixed_fee if fixed_fee is not None else fee_for(max(len(selected), 1), 2, feerate)
    raise WalletError(f"insufficient spendable funds: have {fmt(total)}, need about {fmt(amount + fee)}")

def wallet_scan(args):
    rpc, seed = RPC(args), require_seed(args); info = derive(rpc, seed, args.index)
    return rpc, seed, info, scan(rpc, info["scriptPubKey"])

def maturity_note(immature):
    if not immature: return ""
    soonest = min(u["blocks_to_maturity"] for u in immature)
    total = sum(u["amount"] for u in immature)
    return f"{fmt(total)} immature ({len(immature)} coinbase UTXO{'s' if len(immature) != 1 else ''}, next spendable in {soonest} block{'s' if soonest != 1 else ''})"

def clipboard_copy(text):
    """Copy via pbcopy stdin — the secret never appears in argv, env, or ps."""
    if not shutil.which("pbcopy"): raise WalletError("pbcopy not found (clipboard support is macOS-only)")
    subprocess.run(["pbcopy"], input=text.encode(), check=True)

def clipboard_paste():
    if not shutil.which("pbpaste"): raise WalletError("pbpaste not found (clipboard support is macOS-only)")
    return subprocess.run(["pbpaste"], capture_output=True, check=True).stdout.decode()

def clipboard_clear():
    subprocess.run(["pbcopy"], input=b"", check=True)

def schedule_clipboard_clear(seconds, secret):
    """Detached watcher that clears the clipboard after N seconds — but only if
    it still holds the seed (compared by SHA-256, so no secret is passed to the
    watcher in any form)."""
    digest = hashlib.sha256(secret.encode()).hexdigest()
    script = ('sleep "$1"; '
              'if [ "$(pbpaste | /usr/bin/shasum -a 256 | cut -d" " -f1)" = "$2" ]; '
              'then printf "" | pbcopy; fi')
    subprocess.Popen(["/bin/sh", "-c", script, "clipwipe", str(int(seconds)), digest],
                     start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def offer_wipe(args):
    """After a seed was shown, wipe it from the screen AND scrollback on request.

    `clear` only blanks the visible screen — the seed survives in terminal
    scrollback. ESC[3J purges scrollback too (Terminal.app, iTerm2). The seed
    stays retrievable from the wallet file (mode 600) via `xcoin-wallet seed`.
    """
    if getattr(args, "no_clear", False) or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    try:
        input("\nWrite the seed down now. Press Enter to WIPE it from screen + scrollback (Ctrl-C to leave it)... ")
    except (KeyboardInterrupt, EOFError):
        print("\nseed left on screen — clear it yourself with Cmd+K (Terminal/iTerm)"); return
    print("\033[2J\033[3J\033[H", end="", flush=True)
    print("Seed wiped from screen and scrollback. (If your terminal still shows it, use Cmd+K.)")
    print("It remains safe in the wallet file; re-display any time with `xcoin-wallet seed`.")

def cmd_new(args):
    p = Path(args.file)
    if p.exists(): raise WalletError(f"refusing to overwrite existing wallet {p}")
    if args.card:
        return cmd_new_card(args, p)
    seed = os.urandom(32).hex(); write_seed(p, seed, new_passphrase(args))
    data = {"file": str(p)}
    if not args.offline:
        data["address"] = derive(RPC(args), seed, 0)["address"]
    if args.json:
        # The seed is deliberately NOT included in JSON output; read the file
        # or use `seed --json --yes`.
        emit_json(data); return
    print(f"Created wallet: {p}\nSeed: {seed}\n\nWRITE THE SEED DOWN OFFLINE. Anyone with it controls the wallet.")
    offer_wipe(args)
    print(f"Wallet file:     {p}")
    if "address" in data: print(f"Primary address: {data['address']}")

def cmd_new_card(args, p):
    """Create a card-bound wallet. The seed is generated, encrypted to the
    card, and NEVER displayed — no paper backup exists by design, so a duplicate
    backup card is offered immediately."""
    cs = _card_module(); cs.disable_core_dumps()
    if not args.offline and args.json:
        raise WalletError("card wallet creation is interactive; use --offline for JSON")
    factor = cs.SecureBuffer(os.urandom(cs.FACTOR_LEN))
    seedbuf = cs.SecureBuffer(os.urandom(32))
    try:
        family = cs.family_of(factor.bytes())
        print("Provisioning the PRIMARY card — tap and hold it on the reader.", file=sys.stderr)
        transport = cs.PCSCTransport()
        try:
            record = cs.provision_card(transport, factor, family, label=args.label or "primary")
        finally:
            transport.close()
        auth_file = cs.auth_path(record["uid"])   # provision_card already saved it (crash-safe)
        pw = new_passphrase(args)   # optional second factor
        blob = mmm2_encode(seedbuf.hex(), factor.bytes(), family, pw)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(blob)
        address = derive(RPC(args), seedbuf.hex(), 0)["address"] if not args.offline else None
        permanent = not args.resettable
        if permanent:
            cs.make_permanent(record["uid"])   # commit: discard master+write keys — IRREVERSIBLE
        data = {"file": str(p), "card_uid": record["uid"], "family": family,
                "auth_file": str(auth_file), "passphrase_protected": bool(pw),
                "permanent": permanent}
        if address: data["address"] = address
    finally:
        seedbuf.close(); factor.close()
    if args.json: emit_json(data); return
    print(f"\nCard-bound wallet created: {p}")
    print(f"  Primary card UID: {data['card_uid']}   family: {family}")
    print(f"  Card keys stored: {data['auth_file']} (mode 600)")
    print("  The seed was NEVER displayed and cannot be — the card is the key.")
    if data["permanent"]:
        print("  SEALED PERMANENTLY: master + write keys discarded — this card can never")
        print("  be reset or reused, and its factor can never be rewritten.")
    if "address" in data: print(f"  Primary address:  {data['address']}")
    print("\nIMPORTANT: with no printed seed, this card is your ONLY backup.")
    print("Make a DUPLICATE backup card now:  xcoin-wallet card-backup --file " + str(p))

def cmd_card_backup(args):
    """Make a DUPLICATE backup card carrying the same factor as this wallet.
    Tap the existing card (to read the factor), then tap a factory card."""
    cs = _card_module(); cs.disable_core_dumps()
    p = Path(args.file)
    if not is_card_wallet(p): raise WalletError(f"{p} is not a card-bound wallet")
    want_family = mmm2_family(p.read_bytes())
    print("Step 1/2 — tap an EXISTING card for this wallet (to copy its key).", file=sys.stderr)
    t1 = cs.PCSCTransport()
    try: factor, _auth = cs.read_factor(t1)
    finally: t1.close()
    try:
        if cs.family_of(factor.bytes()) != want_family:
            raise WalletError("that card does not belong to this wallet")
        input("Step 2/2 — remove it, place a FACTORY card, then press Enter... ")
        t2 = cs.PCSCTransport()
        try:
            record = cs.provision_card(t2, factor, want_family, label=args.label or "backup")
        finally:
            t2.close()
        auth_file = cs.auth_path(record["uid"])
        permanent = not args.resettable
        if permanent:
            cs.make_permanent(record["uid"])
    finally:
        factor.close()
    if args.json: emit_json({"backup_card_uid": record["uid"], "auth_file": str(auth_file),
                             "family": want_family, "permanent": permanent}); return
    print(f"\nBackup card ready — UID {record['uid']} (family {want_family}).")
    print(f"Card keys stored: {auth_file}")
    if permanent: print("Sealed permanently (master + write keys discarded).")
    print("Either card now unlocks this wallet. Store them in separate physical locations.")

def cmd_card_test(args):
    """Read-only proof that a provisioned card authenticates and yields a factor.
    Does not touch any wallet file; safe to run anytime."""
    cs = _card_module(); cs.disable_core_dumps()
    t = cs.PCSCTransport()
    try: factor, auth = cs.read_factor(t)
    finally: t.close()
    try:
        fam = cs.family_of(factor.bytes())
    finally:
        factor.close()
    if args.json: emit_json({"ok": True, "uid": auth["uid"], "family": fam, "label": auth.get("label")}); return
    print(f"Card OK — UID {auth['uid']}, family {fam}, label {auth.get('label','?')}")
    print("EV2 authentication succeeded and a wallet factor was read over the encrypted channel.")

def cmd_card_reset(args):
    """Factory-reset a card (wipe factor + restore factory keys) and remove its
    auth file. Guarded: refuses unless --yes. Never touches a wallet file."""
    cs = _card_module(); cs.disable_core_dumps()
    if not args.yes: raise WalletError("card-reset erases the card; pass --yes to confirm")
    t = cs.PCSCTransport()
    try: uid = cs.factory_reset_card(t)
    finally: t.close()
    auth = cs.auth_path(uid)
    moved = None
    if auth.exists():
        moved = auth.with_suffix(".auth.removed")
        shutil.move(auth, moved)
    if args.json: emit_json({"reset_uid": uid, "auth_moved_to": str(moved) if moved else None}); return
    print(f"Card {uid} returned to factory state.")
    if moved: print(f"Its key file was moved to {moved} (kept, not deleted — remove it yourself once sure).")
    print("WARNING: if this was the last card for a wallet, that wallet is now UNRECOVERABLE.")

def cmd_card_list(args):
    """List provisioned cards known to this Mac (from ~/.xcoin/card-*.auth)."""
    cs = _card_module()
    rows = []
    for f in sorted(cs.AUTH_DIR.glob("card-*.auth")):
        try: rec = json.loads(f.read_text())
        except Exception: continue
        rows.append({"uid": rec.get("uid"), "family": rec.get("family"),
                     "label": rec.get("label"), "created": rec.get("created")})
    if args.json: emit_json(rows); return
    if not rows: print("No provisioned cards on this Mac."); return
    for r in rows:
        print(f"{r['uid']}  family={r['family']}  {r.get('label','')}  ({r.get('created','')})")

def cmd_seed(args):
    """Re-display or copy the master seed from the wallet file, with guarded output."""
    if is_card_wallet(args.file):
        raise WalletError("this is a card-bound wallet — the seed is sealed to the card and is "
                          "never revealed by design. Use the card to sign; back it up with `card-backup`.")
    seed = require_seed(args)
    if args.copy:
        if not args.yes:
            if not sys.stdin.isatty():
                raise WalletError("refusing to copy the seed non-interactively; pass --yes to override")
            answer = input(f"Copy the MASTER SEED to the clipboard? Auto-clears in {args.timeout}s. [y/N] ").strip().lower()
            if answer != "y": raise WalletError("cancelled")
        clipboard_copy(seed)
        if args.timeout > 0: schedule_clipboard_clear(args.timeout, seed)
        note = f"clipboard auto-clears in {args.timeout}s" if args.timeout > 0 else "clipboard will NOT auto-clear (--timeout 0)"
        msg = (f"Seed copied to clipboard ({note}).\n"
               "WARNING: clipboard managers keep history, and Handoff/Universal Clipboard\n"
               "can sync the clipboard to your other Apple devices. Paste it, then clear.")
        if args.json: emit_json({"copied": True, "timeout": args.timeout}); return
        print(msg); return
    if args.json:
        if not args.yes: raise WalletError("seed --json requires --yes (explicit confirmation to emit the seed)")
        emit_json({"file": str(args.file), "seed": seed}); return
    if not args.yes:
        if not sys.stdin.isatty():
            raise WalletError("refusing to print the seed non-interactively; pass --yes to override")
        answer = input("This prints your MASTER SEED. Anyone who sees it controls the wallet.\nType REVEAL to continue: ").strip()
        if answer != "REVEAL": raise WalletError("cancelled")
    print(f"Seed: {seed}")
    offer_wipe(args)

def cmd_receive(args):
    # Address derivation is offline: no node, no RPC credentials needed.
    # `address`/`receive` print the address; `--identity` (or the `identity`
    # subcommand) prints the same key's forum handle xid1… instead.
    info = derive(None, require_seed(args), args.index)
    if args.json:
        emit_json({"address": info["address"], "identity": info["identity"], "index": args.index, "scriptPubKey": info["scriptPubKey"]}); return
    print(info["identity"] if args.identity else info["address"])
    if args.verbose:
        print(f"index: {args.index}\nscriptPubKey: {info['scriptPubKey']}")
        print(f"address: {info['address']}" if args.identity else f"identity: {info['identity']}")

def cmd_signmessage(args):
    """Sign a text message with the ML-DSA-65 key at --index, for a service that
    verifies FIPS 204 signatures (MineDifferent sign-in). The signer is named by
    its forum identity xid1… by default: `{address}` in the template is replaced
    by the xid1… string and the JSON "address" field carries it (NerdMiner posts
    that field to the forum as 'address'), so one unlock signs a message that
    names the signer. `--as address` names the witness v2 xpa1z… form instead.
    Prints one JSON line {"address","identity","witness_v2_address","pubkey",
    "sig","message_hex","index"}; the seed goes to the native keytool over stdin
    and never reaches the node or the network."""
    seed = read_seed(args.file)
    index = int(args.index)
    tool = keytool_path()
    if not tool:
        raise WalletError("offline keytool not found: build the native keytool (`NEX=.. ./build.sh`)")
    template = args.template if args.template is not None else args.message
    if template is None or template == "":
        raise WalletError("signmessage needs --template TEXT (with {address}) or --message TEXT")
    info = derive_offline(seed, index)
    signer = info["address"] if args.sign_as == "address" else info["identity"]
    message = template.replace("{address}", signer)
    # Multi-line messages are fine (the forum's challenge is four lines): the
    # message travels to the keytool as one hex line, never as raw text.
    msg_hex = message.encode("utf-8").hex()
    try:
        proc = subprocess.run([str(tool), "_signmsg", "--index", str(index)],
                              input=(seed + "\n" + msg_hex + "\n").encode(), capture_output=True, timeout=120)
    except Exception as e:
        raise WalletError(f"offline keytool could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"signing failed: {proc.stderr.decode(errors='replace').strip()}")
    try:
        out = json.loads(proc.stdout.decode())
    except ValueError:
        raise WalletError("offline keytool returned no signature")
    if out.get("address") != info["address"]:
        raise WalletError("keytool address does not match the derived address")
    if out.get("identity") != info["identity"]:
        raise WalletError("keytool identity does not match the derived identity")
    result = {"address": signer, "identity": info["identity"], "witness_v2_address": info["address"],
              "pubkey": out["pubkey"], "sig": out["sig"], "message_hex": msg_hex, "index": index}
    print(json.dumps(result))

def cmd_addresses(args):
    seed = require_seed(args)                  # offline derivation: no RPC needed
    rows = []
    for i in range(args.start, args.start + args.count):
        info = derive(None, seed, i)
        row = {"index": i, "address": info["address"]}
        if args.identity: row["identity"] = info["identity"]
        rows.append(row)
    if args.json: emit_json(rows); return
    for r in rows: print(f"{r['index']:5d}  {r['address']}" + (f"  {r['identity']}" if args.identity else ""))

def cmd_balance(args):
    _, _, info, result = wallet_scan(args)
    mature, immature = classify_utxos(result)
    spendable = sum((u["amount"] for u in mature), Decimal(0))
    pending = sum((u["amount"] for u in immature), Decimal(0))
    data = {"address": info["address"], "index": args.index,
            "spendable": spendable, "immature": pending, "total": spendable + pending,
            "utxos": len(mature) + len(immature), "immature_utxos": len(immature),
            "height": result.get("height")}
    if args.json: emit_json(data); return
    print(f"Address:       {info['address']}\nIndex:         {args.index}")
    print(f"Spendable:     {fmt(spendable)}")
    if immature:
        print(f"Immature:      {maturity_note(immature)}")
    print(f"Total:         {fmt(spendable + pending)}\nUTXOs:         {data['utxos']}\nScan height:   {data['height']}")

def cmd_utxos(args):
    _, _, _, result = wallet_scan(args)
    mature, immature = classify_utxos(result)
    rows = [{"txid": u["txid"], "vout": u["vout"], "amount": u["amount"],
             "height": u.get("height"), "confirmations": u["confirmations"],
             "coinbase": bool(u.get("coinbase")), "spendable": u not in immature,
             **({"blocks_to_maturity": u["blocks_to_maturity"]} if u in immature else {})}
            for u in mature + immature]
    if args.json: emit_json(rows); return
    if not rows: print("No unspent outputs."); return
    for r in rows:
        note = " coinbase" if r["coinbase"] else ""
        if not r["spendable"]: note += f" IMMATURE ({r['blocks_to_maturity']} blocks left)"
        print(f"{r['txid']}:{r['vout']}  {fmt(r['amount'])}  height={r['height']} confs={r['confirmations']}{note}")
    print(f"Total: {fmt(sum(r['amount'] for r in rows))}  (spendable: {fmt(sum(r['amount'] for r in rows if r['spendable']))})")

def cmd_send(args):
    rpc, seed, own, result = wallet_scan(args)
    chain = rpc.call("getblockchaininfo").get("chain", "?")
    valid = rpc.call("validateaddress", [args.destination])
    if not valid or not valid.get("isvalid"): raise WalletError("destination is not a valid address for this node")
    amount = money(args.amount)
    if amount <= 0: raise WalletError("amount must be positive")
    max_fee = money(args.max_fee, "max-fee")
    mature, immature = classify_utxos(result)

    try:
        if args.fee is not None:
            fixed = money(args.fee, "fee")
            if fixed < 0: raise WalletError("fee must be non-negative")
            selected, fee, change = select_coins(mature, amount, fixed_fee=fixed)
            fee_desc = f"{fmt(fee)} (fixed via --fee)"
        else:
            feerate, source = resolve_feerate(rpc, args)
            selected, fee, change = select_coins(mature, amount, feerate=feerate)
            fee_desc = f"{fmt(fee)} ({fmt8(feerate)}/kvB via {source})"
    except WalletError as e:
        if immature and "insufficient" in str(e):
            raise WalletError(f"{e}; note: {maturity_note(immature)}")
        raise
    if fee > max_fee:
        raise WalletError(f"fee {fmt(fee)} exceeds --max-fee {fmt(max_fee)}; pass a higher --max-fee to allow it")

    est_total, est_vsize = estimate_sizes(len(selected), 2 if change > 0 else 1)
    if not args.json:
        print("Transaction preview")
        print(f"  Chain:       {chain}")
        print(f"  From:        {own['address']} (index {args.index})")
        print(f"  To:          {args.destination}")
        print(f"  Amount:      {fmt(amount)}")
        print(f"  Fee:         {fee_desc}")
        print(f"  Change:      {fmt(change)}")
        print(f"  Inputs:      {len(selected)}  (~{est_total} bytes, ~{est_vsize} vbytes signed)")
        print("  Signing:     OFFLINE keytool (seed stays here)")
        if immature: print(f"  Excluded:    {maturity_note(immature)}")
    if not args.yes:
        if args.json: raise WalletError("--json send requires --yes (no interactive prompt in JSON mode)")
        answer = input("Type SEND to sign" + (" (dry run)" if args.dry_run else " and broadcast") + ": ").strip()
        if answer != "SEND": raise WalletError("cancelled")

    outputs = [{args.destination: fmt8(amount)}]
    if change > 0: outputs.append({own["address"]: fmt8(change)})
    raw = rpc.call("createrawtransaction", [[{"txid": u["txid"], "vout": u["vout"]} for u in selected], outputs])
    prev = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": u["scriptPubKey"],
             "amount": u["amount"], "keyindex": args.index} for u in selected]

    # Sign OFFLINE in the native keytool: the seed never reaches the node.
    signed_hex = sign_offline(seed, raw, prev); signer = "offline keytool"

    accept = rpc.call("testmempoolaccept", [[signed_hex]])
    verdict = accept[0] if accept else {}
    decoded = rpc.call("decoderawtransaction", [signed_hex])
    data = {"txid": decoded.get("txid"), "size": len(signed_hex) // 2,
            "vsize": decoded.get("vsize"), "fee": fee, "change": change, "signer": signer,
            "inputs": len(selected), "mempool_accept": bool(verdict.get("allowed")),
            "broadcast": False}
    if not verdict.get("allowed"):
        data["reject_reason"] = verdict.get("reject-reason", "unknown")

    if args.dry_run:
        if args.json: emit_json(data); return
        print(f"Dry run: signed OK, NOT broadcast.\nTXID: {data['txid']}\nSigned bytes: {data['size']} ({data['vsize']} vbytes)")
        if data["mempool_accept"]: print("Mempool check: would be accepted")
        else: print(f"Mempool check: would be REJECTED ({data['reject_reason']})")
        return
    if not data["mempool_accept"]:
        raise WalletError(f"node would reject this transaction ({data['reject_reason']}); nothing was broadcast")
    txid = rpc.call("sendrawtransaction", [signed_hex])
    data.update(txid=txid, broadcast=True)
    if args.json: emit_json(data); return
    print(f"Broadcast successful\nTXID: {txid}")

def cmd_history(args):
    rpc, seed = RPC(args), require_seed(args)
    info = derive(rpc, seed, args.index); script = info["scriptPubKey"]
    tip = rpc.call("getblockcount")
    events, my_outpoints = [], {}
    for h in range(args.from_height, tip + 1):
        block = rpc.call("getblock", [rpc.call("getblockhash", [h]), 2], timeout=300)
        for tx in block.get("tx", []):
            received = Decimal(0); spent = Decimal(0)
            is_coinbase = any("coinbase" in vin for vin in tx.get("vin", []))
            for vin in tx.get("vin", []):
                key = (vin.get("txid"), vin.get("vout"))
                if key in my_outpoints: spent += my_outpoints.pop(key)
            for out in tx.get("vout", []):
                if out.get("scriptPubKey", {}).get("hex") == script:
                    amt = money(out["value"])
                    received += amt; my_outpoints[(tx["txid"], out["n"])] = amt
            if received or spent:
                events.append({"txid": tx["txid"], "height": h, "time": block.get("time"),
                               "received": received, "spent": spent, "net": received - spent,
                               "coinbase": is_coinbase, "confirmations": tip - h + 1})
    for txid in rpc.call("getrawmempool", []):
        try: tx = rpc.call("getrawtransaction", [txid, 1])
        except WalletError: continue
        received = sum((money(o["value"]) for o in tx.get("vout", [])
                        if o.get("scriptPubKey", {}).get("hex") == script), Decimal(0))
        spent = sum((my_outpoints[(v.get("txid"), v.get("vout"))] for v in tx.get("vin", [])
                     if (v.get("txid"), v.get("vout")) in my_outpoints), Decimal(0))
        if received or spent:
            events.append({"txid": txid, "height": None, "time": None, "received": received,
                           "spent": spent, "net": received - spent, "coinbase": False, "confirmations": 0})
    if args.json: emit_json({"address": info["address"], "index": args.index, "tip": tip, "events": events}); return
    if not events: print(f"No transactions for {info['address']}"); return
    print(f"History for {info['address']} (index {args.index}, tip {tip})")
    for e in events:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e["time"])) if e["time"] else "mempool         "
        where = f"{e['height']:>7}" if e["height"] is not None else "unconf."
        sign = "+" if e["net"] >= 0 else ""
        note = " coinbase" if e["coinbase"] else ""
        if e["coinbase"] and e["confirmations"] < COINBASE_MATURITY:
            note += f" (immature, {COINBASE_MATURITY - e['confirmations']} blocks left)"
        print(f"{where}  {when}  {sign}{fmt(e['net'])}  {e['txid']}{note}")

def cmd_info(args):
    rpc = RPC(args)
    chain = rpc.call("getblockchaininfo"); net = rpc.call("getnetworkinfo"); mem = rpc.call("getmempoolinfo")
    data = {"chain": chain.get("chain"), "blocks": chain.get("blocks"), "headers": chain.get("headers"),
            "bestblockhash": chain.get("bestblockhash"), "difficulty": str(chain.get("difficulty")),
            "mediantime": chain.get("mediantime"), "initialblockdownload": chain.get("initialblockdownload"),
            "size_on_disk": chain.get("size_on_disk"), "warnings": chain.get("warnings"),
            "version": net.get("subversion"), "connections": net.get("connections"),
            "connections_in": net.get("connections_in"), "connections_out": net.get("connections_out"),
            "relayfee": money(net.get("relayfee", 0)),
            "mempool_txs": mem.get("size"), "mempool_bytes": mem.get("bytes"),
            "mempool_min_fee": money(mem.get("mempoolminfee", 0))}
    if args.json: emit_json(data); return
    sync = "synced" if not data["initialblockdownload"] else "SYNCING (initial block download)"
    print(f"Chain:         {data['chain']} ({sync})")
    print(f"Height:        {data['blocks']} (headers {data['headers']})")
    print(f"Best block:    {data['bestblockhash']}")
    print(f"Median time:   {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['mediantime']))}")
    print(f"Difficulty:    {data['difficulty']}")
    print(f"Node:          {data['version']}  peers={data['connections']} (in {data['connections_in']} / out {data['connections_out']})")
    print(f"Mempool:       {data['mempool_txs']} txs, {data['mempool_bytes']} bytes, min fee {fmt8(data['mempool_min_fee'])}/kvB")
    print(f"Relay fee:     {fmt8(data['relayfee'])}/kvB")
    for w in data.get("warnings") or []: print(f"Warning:       {w}")

def cmd_restore(args):
    p = Path(args.file)
    if p.exists(): raise WalletError(f"refusing to overwrite existing wallet {p}; use reset or another --file")
    sources = [bool(args.seed), args.paste, bool(args.from_file)]
    if sum(sources) > 1: raise WalletError("pick one seed source: argument, --paste, or --from-file")
    used_clipboard = False
    if args.paste:
        seed = clipboard_paste(); used_clipboard = True
    elif args.from_file:
        src = Path(args.from_file).expanduser()
        try: seed = src.read_text()
        except OSError as e: raise WalletError(f"cannot read seed file {src}: {e}")
    elif args.seed:
        print("warning: seed passed on the command line lands in your shell history and `ps` output;\n"
              "         prefer the hidden prompt, --paste, or --from-file — see README 'Seed hygiene'", file=sys.stderr)
        seed = args.seed
    else:
        seed = getpass.getpass("Seed (hidden): ")
    seed = seed.strip().lower()
    if not _valid_seed(seed):
        raise WalletError("seed must be 32-64 bytes of hex" + (" (clipboard did not hold a valid seed)" if used_clipboard else ""))
    write_seed(p, seed, new_passphrase(args))
    if used_clipboard:
        clipboard_clear()
    note = "; clipboard cleared" if used_clipboard else ""
    if args.json: emit_json({"file": str(p), "restored": True, "clipboard_cleared": used_clipboard}); return
    print(f"Wallet restored to {p}{note}")

def cmd_backup(args):
    src = Path(args.file)
    if is_card_wallet(src):
        # Copy the encrypted file only — never touch the card. Useless without it.
        dst = Path(args.destination).expanduser()
        if dst.is_dir(): dst /= f"xcoin-wallet-{time.strftime('%Y%m%d-%H%M%S')}.mmm"
        if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
        dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst); os.chmod(dst, 0o600)
        if args.json: emit_json({"backup": str(dst), "card_bound": True}); return
        print(f"Encrypted wallet file copied: {dst}")
        print("This file is useless without the card. To back up the KEY itself, use `card-backup`.")
        return
    read_seed(src)
    encrypted = src.read_bytes().startswith(MMM_MAGIC)
    dst = Path(args.destination).expanduser()
    if dst.is_dir(): dst /= f"xcoin-wallet-{time.strftime('%Y%m%d-%H%M%S')}" + (".mmm" if encrypted else ".seed")
    if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst); os.chmod(dst, 0o600)
    if args.json: emit_json({"backup": str(dst), "encrypted": encrypted}); return
    print(f"Backup created: {dst}")
    if not encrypted:
        print("note: this backup is PLAINTEXT (legacy format); run `xcoin-wallet encrypt` to switch to .mmm")

def cmd_encrypt(args):
    """Convert a legacy plaintext wallet to .mmm, or re-key an existing .mmm wallet."""
    src = Path(args.file)
    if is_card_wallet(src):
        raise WalletError("this is a card-bound wallet; converting it to a passphrase would expose the seed. "
                          "Use `card-backup` for redundancy or `card-reset` to retire a card.")
    seed = read_seed(src)                      # prompts for the current passphrase if needed
    was_mmm = src.read_bytes().startswith(MMM_MAGIC)
    if supplied_passphrase() is None and not can_prompt():
        raise WalletError(f"encrypt needs a passphrase and {NO_TERMINAL}: run it from a terminal or hand it over --passphrase-fd")
    pw = new_passphrase(args)
    if was_mmm:
        tmp = src.with_name(src.name + ".rekey-tmp")
        if tmp.exists(): raise WalletError(f"stale temp file exists: {tmp}")
        write_seed(tmp, seed, pw); os.replace(tmp, src)
        if args.json: emit_json({"file": str(src), "rekeyed": True}); return
        print(f"Wallet re-encrypted in place: {src}"); return
    target = src.with_suffix(".mmm")
    if target.exists(): raise WalletError(f"target already exists: {target}")
    write_seed(target, seed, pw)
    moved = src.with_name(src.name + ".plaintext-backup")
    if moved.exists(): raise WalletError(f"backup destination exists: {moved}")
    shutil.move(src, moved); os.chmod(moved, 0o600)
    if args.json: emit_json({"file": str(target), "plaintext_moved_to": str(moved)}); return
    print(f"Encrypted wallet written: {target}")
    print(f"Old PLAINTEXT seed moved to: {moved}")
    print("Verify the new wallet (e.g. `xcoin-wallet address`), then store that file offline or delete it yourself.")

def cmd_reset(args):
    src = Path(args.file); read_seed(src)
    if not args.yes: raise WalletError("reset requires --yes and --backup <path>")
    dst = Path(args.backup).expanduser()
    if dst.is_dir(): dst /= f"xcoin-wallet-reset-{time.strftime('%Y%m%d-%H%M%S')}.seed"
    if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True); shutil.move(src, dst); os.chmod(dst, 0o600)
    if args.json: emit_json({"moved_to": str(dst)}); return
    print(f"Wallet reset. Original seed moved safely to: {dst}\nRun `xcoin-wallet new` to create a new wallet.")

def parser():
    p = argparse.ArgumentParser(prog="xcoin-wallet", description="Post-quantum Xcoin self-custody wallet")
    p.add_argument("--file", default=str(default_wallet())); p.add_argument("--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--rpc-host"); p.add_argument("--rpc-port", type=int); p.add_argument("--rpc-user"); p.add_argument("--rpc-password")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--passphrase-fd", type=int, metavar="N", help="read the wallet passphrase from file descriptor N (a pipe from a parent program); never from the environment")
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("new", help="create a new wallet")
    q.add_argument("--offline", action="store_true")
    q.add_argument("--no-clear", action="store_true", help="skip the screen/scrollback wipe offer")
    q.add_argument("--card", action="store_true", help="bind the wallet to an NTAG 424 DNA card (seed never displayed)")
    q.add_argument("--label", help="label for the provisioned card")
    q.add_argument("--resettable", action="store_true", help="keep factory-key rollback (card can be reset); default is permanent/sealed")
    q.set_defaults(fn=cmd_new)
    q = sub.add_parser("card-provision", help="alias: create a card-bound wallet"); q.add_argument("--offline", action="store_true"); q.add_argument("--label"); q.add_argument("--resettable", action="store_true"); q.set_defaults(fn=cmd_new, card=True, no_clear=True)
    q = sub.add_parser("card-backup", help="make a duplicate backup card for a card wallet"); q.add_argument("--label"); q.add_argument("--resettable", action="store_true"); q.set_defaults(fn=cmd_card_backup)
    q = sub.add_parser("card-test", help="prove a provisioned card authenticates (read-only)"); q.set_defaults(fn=cmd_card_test)
    q = sub.add_parser("card-reset", help="factory-reset a card and remove its key file"); q.add_argument("--yes", action="store_true"); q.set_defaults(fn=cmd_card_reset)
    q = sub.add_parser("card-list", help="list provisioned cards on this Mac"); q.set_defaults(fn=cmd_card_list)
    q = sub.add_parser("seed", help="re-display or copy the master seed (guarded)")
    q.add_argument("--copy", action="store_true", help="copy to clipboard instead of printing (macOS)")
    q.add_argument("--timeout", type=int, default=60, help="auto-clear clipboard after N seconds (0 = never)")
    q.add_argument("--yes", action="store_true"); q.add_argument("--no-clear", action="store_true"); q.set_defaults(fn=cmd_seed)
    for name, fn in (("receive", cmd_receive), ("address", cmd_receive)):
        q = sub.add_parser(name, help="show a receiving address"); q.add_argument("--index", type=int, default=0); q.add_argument("--verbose", action="store_true")
        q.add_argument("--identity", action="store_true", help="show the key's forum identity (xid1…) instead: a chat handle, nothing can be paid to it")
        q.set_defaults(fn=fn)
    q = sub.add_parser("identity", help="show the forum identity (xid1…) of the key at --index; same as `address --identity`")
    q.add_argument("--index", type=int, default=101, help="key index (the forum identity convention is 101)"); q.add_argument("--verbose", action="store_true"); q.set_defaults(fn=cmd_receive, identity=True)
    q = sub.add_parser("addresses", help="list derived addresses"); q.add_argument("--start", type=int, default=0); q.add_argument("--count", type=int, default=5)
    q.add_argument("--identity", action="store_true", help="also list each key's forum identity (xid1…)"); q.set_defaults(fn=cmd_addresses)
    for name, fn in (("balance", cmd_balance), ("status", cmd_balance), ("utxos", cmd_utxos)):
        q = sub.add_parser(name, help="show balance/UTXOs (maturity-aware)"); q.add_argument("--index", type=int, default=0); q.set_defaults(fn=fn)
    q = sub.add_parser("send", help="send XID (fee auto-estimated unless --fee)")
    q.add_argument("destination"); q.add_argument("amount")
    q.add_argument("--fee", help="absolute fee in XID (overrides --feerate)")
    q.add_argument("--feerate", help="fee rate in XID/kvB (default: auto)")
    q.add_argument("--max-fee", default=str(DEFAULT_MAX_FEE), help=f"refuse fees above this (default {DEFAULT_MAX_FEE} XID)")
    q.add_argument("--index", type=int, default=0); q.add_argument("--yes", action="store_true"); q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_send)
    q = sub.add_parser("history", help="transaction history (scans the chain)")
    q.add_argument("--index", type=int, default=0); q.add_argument("--from-height", type=int, default=0); q.set_defaults(fn=cmd_history)
    q = sub.add_parser("info", help="node/chain/mempool status"); q.set_defaults(fn=cmd_info)
    for name in ("restore", "import"):
        q = sub.add_parser(name, help="restore wallet from a seed")
        q.add_argument("seed", nargs="?")
        q.add_argument("--paste", action="store_true", help="read the seed from the clipboard, then clear it (macOS)")
        q.add_argument("--from-file", help="read the seed from a file (e.g. a USB-stick backup)")
        q.set_defaults(fn=cmd_restore)
    q = sub.add_parser("backup", help="copy the wallet file somewhere safe"); q.add_argument("destination"); q.set_defaults(fn=cmd_backup)
    q = sub.add_parser("encrypt", help="convert to / re-key the encrypted .mmm wallet format"); q.set_defaults(fn=cmd_encrypt)
    q = sub.add_parser("signmessage", help="sign a one-line message with the key at --index (FIPS 204 ML-DSA-65); used by NerdMiner login")
    q.add_argument("--template", help="message with {address} standing for the signer's name: its forum identity xid1… (default) or, with --as address, its xpa1z… address")
    q.add_argument("--message", help="literal message (no substitution)")
    q.add_argument("--index", type=int, default=101, help="key index (the forum identity convention is 101)")
    q.add_argument("--as", dest="sign_as", choices=("identity", "address"), default="identity",
                   help="sign as the forum identity xid1… (default) or as the witness v2 address xpa1z…")
    q.set_defaults(fn=cmd_signmessage)
    q = sub.add_parser("reset", help="move the seed away (never deletes)"); q.add_argument("--backup", required=True); q.add_argument("--yes", action="store_true"); q.set_defaults(fn=cmd_reset)
    return p

def main(argv=None):
    if os.getenv("XCOIN_WALLET_PASSPHRASE") is not None:
        print("error: XCOIN_WALLET_PASSPHRASE is not accepted: an environment variable is readable by every "
              "program you run and lands in shell history in plain text. Type the passphrase when asked, "
              "or hand it to the wallet over a pipe with --passphrase-fd N.", file=sys.stderr)
        return 2
    # --passphrase-fd is a top-level option, but a parent program may put it after the
    # subcommand; accept it anywhere by lifting it out before argparse sees the rest.
    argv = list(sys.argv[1:] if argv is None else argv)
    fd_value = None
    i = 0
    while i < len(argv):
        if argv[i] == "--passphrase-fd" and i + 1 < len(argv):
            fd_value = argv[i + 1]; del argv[i:i + 2]; continue
        if argv[i].startswith("--passphrase-fd="):
            fd_value = argv[i].split("=", 1)[1]; del argv[i]; continue
        i += 1
    if fd_value is not None:
        argv = ["--passphrase-fd", fd_value] + argv
    p = parser(); args = p.parse_args(argv)
    try:
        if args.passphrase_fd is not None:
            read_passphrase_fd(args.passphrase_fd)
        args.fn(args)
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr); return 130
    except WalletError as e:
        print(f"error: {e}", file=sys.stderr); return 1
    except Exception as e:
        # card_seed.CardError (lazily imported) and other card/hardware faults
        try: from card_seed import CardError
        except Exception: CardError = ()
        if CardError and isinstance(e, CardError):
            print(f"error: {e}", file=sys.stderr); return 1
        raise
    return 0

if __name__ == "__main__": raise SystemExit(main())
