#!/bin/bash
# Can a stranger join xCoin?
#
# Everything else about peer discovery can look right and still not work. This
# asks the only question that matters: starting from nothing — no peers.dat, no
# -addnode, no local knowledge — does a fresh node find the network by itself?
#
# Run it before genesis, and again after any change to vSeeds, vFixedSeeds or
# the DNS records. It reads only; it starts a throwaway node in a temp datadir
# and removes it.
set -u
NEXD=${NEXD:-build/bin/nexd}
CLI=${CLI:-build/bin/nex-cli}
WAIT=${WAIT:-90}
fail=0
say() { printf '%s\n' "$*"; }
chk() { if [ "$2" = pass ]; then say "  PASS  $1"; else say "  FAIL  $1"; fail=1; fi; }

say "== 1. DNS seeds resolve, and to something that is not a CDN =="
SEEDS="seed.xcoinproject.com seed.superknet.com seed.xcoinminer.com seed.minedifferent.com seed.movepunk.com"
# Core asks for x9.<name> first (SeedsServiceFlags = NODE_NETWORK|NODE_WITNESS = 9,
# net.cpp:2366). A zone with only a bare record makes every node fall back to an
# ADDR_FETCH connection instead of a real seed lookup, so check the wildcard too.
for host in $SEEDS; do
  x9=$(dig +short "x9.$host" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
  [ -n "$x9" ] && chk "x9.$host resolves (wildcard present)" pass \
                || chk "x9.$host does NOT resolve — add *.seed.<domain>" fail
done
for host in $SEEDS; do
  ips=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
  if [ -z "$ips" ]; then
    chk "$host resolves" fail
  else
    bad=$(printf '%s\n' "$ips" | grep -cE '^(104\.(1[6-9]|2[0-9]|3[01])\.|172\.6[4-9]\.|172\.7[0-1]\.|198\.41\.|188\.114\.|162\.15[89]\.)' || true)
    if [ "$bad" != 0 ]; then
      chk "$host is DNS-only (got Cloudflare anycast: $(echo $ips | tr '\n' ' '))" fail
      say "        -> the record is PROXIED. Set it to DNS only (grey cloud)."
    else
      chk "$host -> $(echo $ips | tr '\n' ' ')" pass
    fi
  fi
done

say ""
say "== 2. every seed address actually accepts a connection on 9333 =="
for host in $SEEDS; do
  for ip in $(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.' || true); do
    if nc -z -G 6 "$ip" 9333 >/dev/null 2>&1; then chk "$ip:9333 open" pass; else chk "$ip:9333 open" fail; fi
  done
done

say ""
say "== 3. compiled-in fixed seeds are present and are not Bitcoin's =="
# Parse the array exactly — a line-window grep spills into the next array and
# reports the whole file's bytes, which is how this check first lied to me.
read -r n b <<<"$(python3 - <<'PYEOF'
import re, pathlib, sys
try: s = pathlib.Path('src/chainparamsseeds.h').read_text()
except OSError: print("0 0"); sys.exit()
m = re.search(r'chainparams_seed_main\[\] = \{(.*?)\};', s, re.S)
body = m.group(1) if m else ''
vals = [v.strip() for v in body.replace('\n', '').split(',') if v.strip()]
n = len(vals)
# BIP155 IPv4 entry is 8 bytes: id, len, 4 address bytes, 2 port bytes (big-endian)
bad = sum(1 for i in range(0, n - 7, 8)
          if vals[i] == '0x01' and (int(vals[i+6], 16) << 8 | int(vals[i+7], 16)) == 8333)
print(n, bad)
PYEOF
)"
[ "${n:-0}" -gt 0 ] && chk "chainparams_seed_main has $n bytes ($((n/8)) address(es))" pass || chk "chainparams_seed_main is empty" fail
[ "${b:-0}" = 0 ] && chk "no entries on Bitcoin's port 8333" pass || chk "$b entries still on port 8333" fail

say ""
say "== 4. THE REAL TEST: a node that knows nothing finds a peer =="
if [ ! -x "$NEXD" ]; then
  say "  SKIP  $NEXD not built"
else
  D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
  "$NEXD" -datadir="$D" -daemon -listen=0 -printtoconsole=0 >/dev/null 2>&1
  ok=fail
  for i in $(seq 1 "$WAIT"); do
    c=$("$CLI" -datadir="$D" getconnectioncount 2>/dev/null || echo 0)
    if [ "${c:-0}" -gt 0 ] 2>/dev/null; then ok=pass; break; fi
    sleep 1
  done
  c=$("$CLI" -datadir="$D" getconnectioncount 2>/dev/null || echo 0)
  chk "fresh node reached $c peer(s) within ${WAIT}s with no -addnode" "$ok"
  "$CLI" -datadir="$D" stop >/dev/null 2>&1
fi

say ""
[ "$fail" = 0 ] && say "OK — a stranger can join." || say "NOT OK — a stranger downloading the software cannot find the network."
exit "$fail"
