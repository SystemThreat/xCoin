# Fuzzing HX1 (XIP-4)

How to run the HX1 fuzz targets for 24 to 48 hours with AddressSanitizer and
UndefinedBehaviorSanitizer, what each target covers, and what to do with a
finding. Every command below is exactly what the 10-minute reference runs used
(see "Reference numbers" at the end); only the durations change.

## Targets

| Target | What it exercises |
|---|---|
| `mlkem768_encaps` | `mlkem768::Encaps` on an arbitrary 1184-byte key: never crashes, refuses a key exactly when the FIPS 203 section 7.2 modulus check (re-implemented in the harness) fails, and is a function of (ek, m) |
| `mlkem768_decaps` | `mlkem768::Decaps` on an arbitrary ciphertext and an arbitrary or seed-derived key: never crashes, refuses a key exactly when the section 7.3 hash check (re-implemented) fails, decapsulates any ciphertext deterministically, and tells a tampered ciphertext from the real one only by the secret |
| `mlkem768_keygen` | `mlkem768::KeyGen` from arbitrary seeds: FIPS 203 key layout, both checks pass, round trip through Encaps and Decaps |
| `p2p_transport_hx1_record` | `V2Transport::ClassifyHybridRecord` against the XIP-4 classification table (written out independently in the harness): none / malformed / HX1, first record only, trailing bytes ignored |
| `p2p_transport_hx1_initiator` | An outbound `V2Transport` in modes 0, 1 and 2 against a scripted responder that sends fuzzer-chosen garbage, decoys, version packet contents (empty, junk, a real offer, a fuzzer-supplied or CCTV-style bad key, mutated records), then stage-2 packets under the right or a wrong key, delivered in fuzzer-chosen pieces. Checks the version packet the transport answers with, the 4095-byte first-packet limit in both directions, key confirmation, counters, `GetInfo` and `GetHybridStatus` (classical retry), and injected local ML-KEM failures |
| `p2p_transport_hx1_responder` | The same for an inbound `V2Transport`: the offer it sends, silence between VP_R and VP_I, every version packet class from the initiator, implicit rejection of a random ciphertext, the 20-byte confirmation packet, v1 refusal in require mode, and injected key generation / decapsulation failures |
| `p2p_transport_bidirectional_v2` | Two real transports, every pair of modes (the XIP-4 interop matrix: hybrid, classical, or a refusal by the require side), with interleaved partial sends and receives |
| `p2p_transport_bidirectional_v1v2` | A v1 initiator against a v2 responder in every mode; require refuses v1 |
| `bip324_cipher_roundtrip` | `BIP324Cipher` in every mode, with the stage-2 switch at a fuzzer-chosen packet, the kept ECDH secret, `DiscardStage2Secret`, wrong-length inputs, and `DeriveStage2Keys` |
| `p2p_transport_serialization` | The v1 transport; unchanged by HX1, in the same source file as the bidirectional targets |

Seed corpora for all of them come from the pinned vectors in `src/test/data`
(XIP-4 V1 to V6, NIST ACVP, C2SP CCTV) through
`contrib/testgen/gen_hx1_fuzz_seeds.py`.

## Build (macOS, Homebrew llvm with libFuzzer)

Apple's clang has no libFuzzer; Homebrew's llvm (23.1.1 was used) does. The
flags are the `libfuzzer` preset from `CMakePresets.json` plus the libc++
hardening define from `ci/test/00_setup_env_mac_native_fuzz.sh`. Homebrew's
sqlite is named explicitly because the SDK's sqlite headers otherwise shadow
libc++'s. Do not add `-Wl,-stack_size`: with ASan the binary then overflows its
main stack before `main`.

```sh
cd /path/to/xCoin-hx1
CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++ \
cmake -S . -B build-fuzz -G Ninja \
  -DBUILD_FOR_FUZZING=ON -DSANITIZERS=fuzzer,address,undefined \
  -DCMAKE_C_FLAGS='-ftrivial-auto-var-init=pattern' \
  -DCMAKE_CXX_FLAGS='-ftrivial-auto-var-init=pattern' \
  -DAPPEND_CPPFLAGS='-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG' \
  -DSQLite3_INCLUDE_DIR=/opt/homebrew/opt/sqlite/include \
  -DSQLite3_LIBRARY=/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib \
  -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF -DWITH_CCACHE=OFF -DWITH_EMBEDDED_ASMAP=OFF
cmake --build build-fuzz --target fuzz -j6
PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 build-fuzz/bin/fuzz 2>&1 | grep -E 'mlkem768|hx1|bidirectional|bip324_cipher'
```

The last line must list all nine HX1 targets.

## Directories, seeds and environment

```sh
REPO=$PWD
BUILD=$REPO/build-fuzz
FUZZDIR=$HOME/hx1-fuzz            # corpora, logs and findings; keep it between runs
mkdir -p $FUZZDIR/corpus $FUZZDIR/logs $FUZZDIR/artifacts
python3 contrib/testgen/gen_hx1_fuzz_seeds.py $FUZZDIR/seeds

# CI's sanitizer settings (ci/test/03_test_script.sh). The LSan file suppresses only
# libFuzzer's own RSS-limit thread, which LeakSanitizer reports on macOS.
export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1"
export LSAN_OPTIONS="suppressions=$REPO/test/sanitizer_suppressions/lsan"
export UBSAN_OPTIONS="suppressions=$REPO/test/sanitizer_suppressions/ubsan:print_stacktrace=1:halt_on_error=1:report_error_type=1"

TARGETS="mlkem768_encaps mlkem768_decaps mlkem768_keygen
p2p_transport_hx1_record p2p_transport_hx1_initiator p2p_transport_hx1_responder
p2p_transport_bidirectional_v2 p2p_transport_bidirectional_v1v2
bip324_cipher_roundtrip p2p_transport_serialization"
```

## The 24 to 48 hour run

One libFuzzer process per target, all ten at once (the machine has 12 cores;
`nice` keeps the node and the desktop responsive). New coverage-increasing
inputs go to `$FUZZDIR/corpus/<target>`, so a second day continues from the
first: rerun the same loop.

```sh
HOURS=24                           # or 48
for t in $TARGETS; do
  mkdir -p $FUZZDIR/corpus/$t
  seeds=""; [ -d $FUZZDIR/seeds/$t ] && seeds=$FUZZDIR/seeds/$t
  FUZZ=$t nohup nice -n 10 $BUILD/bin/fuzz \
      -max_total_time=$((HOURS * 3600)) -max_len=8192 -print_final_stats=1 \
      -artifact_prefix=$FUZZDIR/artifacts/$t- \
      $FUZZDIR/corpus/$t $seeds > $FUZZDIR/logs/$t.log 2>&1 &
done
```

Watching it:

```sh
ls $FUZZDIR/artifacts/                       # empty means nothing found
for t in $TARGETS; do printf '%-34s ' $t; grep -E '^#[0-9]+' $FUZZDIR/logs/$t.log | tail -1; done
```

Each status line shows `cov:` (edges covered), `ft:` (features), `corp:` (corpus
size) and `exec/s`. `cov` should climb for the first hours and then flatten; a
process that stops printing status lines has died, and its log ends with the
reason. The run passes when, at the end, `$FUZZDIR/artifacts/` is empty and
every log ends with `Done N runs` and `stat::number_of_executed_units`.

The first-packet limit, the mode matrix and the bad-key checks are each reached
by the seeds, so coverage of those paths is present from the first minute; the
long run is for what the seeds do not reach.

## When something is found

A file appears as `$FUZZDIR/artifacts/<target>-crash-<sha1>` (or `-timeout-`,
`-oom-`, `-leak-`) and the log holds the sanitizer report or the failed
`assert`. Every finding is reproducible from the file alone:

```sh
FUZZ=$t $BUILD/bin/fuzz $FUZZDIR/artifacts/$t-crash-<sha1>                       # reproduce
FUZZ=$t $BUILD/bin/fuzz -minimize_crash=1 -runs=200000 \
    -exact_artifact_path=$FUZZDIR/artifacts/$t-min $FUZZDIR/artifacts/$t-crash-<sha1>   # minimise
base64 < $FUZZDIR/artifacts/$t-min                                                   # for the report
```

Report the target, the log excerpt (the first sanitizer frame or the assert
line) and the base64 of the minimised input. An `assert` in a harness
(`src/test/fuzz/mlkem768.cpp`, `p2p_transport_hx1.cpp`,
`p2p_transport_serialization.cpp`, `bip324.cpp`) means the transport or the
wrapper did not do what XIP-4 says, or the harness's reading of the XIP is
wrong; either is a finding. A sanitizer report in `src/net.cpp`,
`src/bip324.cpp`, `src/crypto/mlkem768.cpp` or `src/crypto/mlkem-native/` is a
bug to fix before mainnet. The 10-minute reference runs found none.

## Regression pass over the corpora

To run every input once without fuzzing, for example after a code change:

```sh
for t in $TARGETS; do
  seeds=""; [ -d $FUZZDIR/seeds/$t ] && seeds=$FUZZDIR/seeds/$t
  FUZZ=$t $BUILD/bin/fuzz -runs=0 $FUZZDIR/corpus/$t $seeds 2>&1 | tail -1
done
```

or, in the tree's usual form, `$BUILD/test/fuzz/test_runner.py --par 4
$FUZZDIR/corpus $TARGETS`.

## Keeping the corpora small

libFuzzer keeps every coverage-increasing input. Before archiving or committing
a corpus, merge it down to the inputs that still add coverage:

```sh
mkdir -p $FUZZDIR/corpus-min/$t
seeds=""; [ -d $FUZZDIR/seeds/$t ] && seeds=$FUZZDIR/seeds/$t
FUZZ=$t $BUILD/bin/fuzz -merge=1 $FUZZDIR/corpus-min/$t $FUZZDIR/corpus/$t $seeds
```

## Reference numbers

ASan+UBSan libFuzzer runs of 10 minutes per target, four targets at a time under `nice -n 10` on a loaded 12-core M3 Pro (load average 10 to 14 from other work), 2026-09-25. No crash, timeout, OOM or leak artifact and no sanitizer report in any run.

| Target | State | Executions | exec/s | cov | ft | corpus | artifacts |
|---|---|---|---|---|---|---|---|
| mlkem768_encaps | still running when this table was written | 592237 | 1198 | 966 | 1617 | 59/49Kb | 0 |
| mlkem768_decaps | still running when this table was written | 301755 | 535 | 1523 | 3272 | 68/37Kb | 0 |
| mlkem768_keygen | still running when this table was written | 202585 | 354 | 1421 | 1795 | 60/960b | 0 |
| p2p_transport_hx1_record | still running when this table was written | 1048576 | 2490 | 149 | 213 | 16/1376b | 0 |
| p2p_transport_hx1_initiator | not started |  |  |  |  |  | |
| p2p_transport_hx1_responder | not started |  |  |  |  |  | |
| p2p_transport_bidirectional_v2 | not started |  |  |  |  |  | |
| p2p_transport_bidirectional_v1v2 | not started |  |  |  |  |  | |
| bip324_cipher_roundtrip | not started |  |  |  |  |  | |
| p2p_transport_serialization | not started |  |  |  |  |  | |

`cov` and `ft` are libFuzzer's covered edges and features at the end of the run; a 24-hour run should end well above these.
