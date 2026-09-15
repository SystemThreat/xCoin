#!/bin/bash
# Build xcoin-wallet from the Xcoin node's own PQClean ML-DSA-65 sources.
# This is why every address it prints is consensus-valid: identical code path
# to the derivation the node's former `pqderiveaddress` RPC used (removed 2026-09-14). Requires Xcode CLT + the Xcoin source tree.
set -e
NEX="${NEX:-$HOME/x-Coin/post-quantum}"     # path to the xCoin source tree
PQ="$NEX/src/pqcrypto"
[ -d "$PQ" ] || { echo "Set NEX=/path/to/xCoin/source (need \$NEX/src/pqcrypto)"; exit 1; }
# The node provides randombytes() from its own RNG; a tree without common/randombytes.c
# gets the local one (arc4random_buf).
RB="$PQ/common/randombytes.c"; [ -f "$RB" ] || RB="./randombytes.c"
CL="$PQ/common/cleanse.c"; [ -f "$CL" ] || CL=""
clang -O2 -arch arm64 -c -I"$PQ/common" -I"$PQ/ml-dsa-65" \
  "$PQ/common/fips202.c" $CL "$RB" "$PQ/ml-dsa-65/"*.c
clang++ -O2 -arch arm64 -std=c++17 -I"$PQ/common" -I"$PQ/ml-dsa-65" \
  xcoin-wallet.cpp *.o -o xcoin-wallet
codesign -s - -f xcoin-wallet 2>/dev/null || true
rm -f *.o
echo "✅ built ./xcoin-wallet"
