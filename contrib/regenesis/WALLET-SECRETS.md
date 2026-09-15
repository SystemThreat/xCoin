# How a secret reaches an xCoin wallet

The interface contract for any wallet on this chain. It exists so that the first
person who writes a third-party xCoin wallet inherits a good default instead of
copying a workaround.

## The rule

**Never an environment variable.**

An environment variable is readable by any process running as the same user
(`ps -E` on macOS, `/proc/PID/environ` on Linux), is inherited by every child
process and by their children, lands in shell history unless
`HIST_IGNORE_SPACE` happens to be set — it is off by default in both zsh and
bash — survives into crash dumps and core files, and cannot be scoped or
expired. It also quietly removes a factor from multi-factor wallets whenever it
is consulted before the hardware is.

Bitcoin Core reads no environment variable for any secret anywhere in its tree.
It grew `-stdin`, `-stdinrpcpass` and `-stdinwalletpassphrase` for precisely
this reason. xCoin follows that.

## The four ways in, in priority order

    1.  --passphrase-fd N      one line from file descriptor N
    2.  --passphrase-file PATH first line of PATH, which must be mode 600
    3.  a prompt on /dev/tty   when a human is present
    4.  no secret at all       name-locked card wallets: the filename is the key

**1 is what one program should use to drive another.** The secret exists only
inside a pipe between two processes. It never appears in `argv`, in the
environment, in `ps` output, or in any history file.

**3 must read `/dev/tty`, never stdin.** stdin can be a pipe, and a pipe must
never be able to answer a passphrase prompt. When there is no terminal, fail
with an error that names options 1 and 2 — never fall back to stdin, and never
hang.

**4 is the best of all**, because a secret that is never typed cannot be
observed being typed.

## For the program doing the driving

If your program launches a wallet, **prompt in your own process and pipe the
answer down.** Do not expect the wallet to reach the terminal itself: a child in
its own process group that reads the terminal is sent `SIGTTIN` and suspended by
the kernel, silently and forever, because a background process may not take the
foreground's keystrokes.

`NerdMiner login` is the reference implementation. It runs the wallet once with
nothing supplied — which is all a no-passphrase or name-locked wallet ever
needs — and only if that fails for want of a terminal does it prompt with
`getpass()` and re-run with `--passphrase-fd 0`.

## History

`XCOIN_WALLET_PASSPHRASE` existed until 2026-09-09. It was never a wallet
requirement; it was a way around the `SIGTTIN` bug above. Both are gone. The
wallet CLI now refuses to start if the variable is set, rather than honouring it
quietly.
