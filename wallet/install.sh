#!/bin/bash
# Install the xcoin-wallet CLI:
#   $PREFIX/bin/xcoin-wallet  -> wallet_cli.py launcher (the full wallet CLI)
#   $PREFIX/bin/xcoin-keytool -> native C++ binary (offline key/address derivation)
#
# The in-tree names are untouched: ./xcoin-wallet stays the native binary,
# ./xcoin-wallet-cli stays the Python launcher. Only the installed symlinks
# give the Python CLI the final `xcoin-wallet` name. Existing files at the
# destinations are never overwritten unless they are symlinks into this repo.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
mkdir -p "$BIN"

link() { # link <source> <destname>
  src="$HERE/$1"; dst="$BIN/$2"
  [ -e "$src" ] || { echo "skip $2: $src not built"; return 0; }
  if [ -e "$dst" ] && [ "$(readlink "$dst" 2>/dev/null)" != "$src" ]; then
    echo "refusing to overwrite $dst (not a symlink into this repo)"; exit 1
  fi
  ln -sf "$src" "$dst"
  echo "installed $dst -> $src"
}

link xcoin-wallet-cli xcoin-wallet
link xcoin-wallet     xcoin-keytool

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "NOTE: $BIN is not on your PATH; add:  export PATH=\"$BIN:\$PATH\"" ;;
esac
