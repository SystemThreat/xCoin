# MetalDAG — Xcoin memory-hard PoW (Apple-Silicon-favoring)

Ethash-family, memory-bandwidth-hard proof-of-work. Deters ASICs (memory-hard) and
ages out low-VRAM GPUs (growing DAG), while Apple Silicon's large, high-bandwidth
unified memory makes Macs the most efficient miner. See design:
`NEX/BITCOIN FORK/metaldag-pow-design.md`.

## Status
- `metaldag-ref.cpp` — **canonical reference verifier**, validated:
  - Keccak-256 matches known original-Keccak vectors ("" and "abc").
  - Memory-hard `mkcache`, on-demand `calc_dataset_item` (light verification — no full DAG),
    deterministic `hashimoto_light`, and a working target/PoW check.
- This file is the spec the Metal miner (MMM) must match byte-for-byte.

## Next
1. Wire `hashimoto_light` into the node's `CheckProofOfWork` (consensus) — replaces SHA-256d.
2. Real Xcoin sizing: epoch seed from height; `DAG_INIT=4 GiB`, `+128 MiB/epoch`.
3. Convert MMM's `SHA256.metal` kernel to MetalDAG; cross-check against this reference.
4. Re-genesis on MetalDAG.

Build the self-test:  `clang++ -O2 -std=c++17 -o metaldag-ref metaldag-ref.cpp && ./metaldag-ref`
