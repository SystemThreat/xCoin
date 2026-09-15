//
//  MetalDAGEngine.swift
//  MacMetal Miner — MetalDAG (memory-hard, Apple-Silicon-favoring) mining engine for Xcoin.
//
//  Replaces the SHA-256d path. The block header format is unchanged (80 bytes); only the
//  proof-of-work hash changes to keccak256(header76) → hashimoto over a per-epoch DAG.
//  CPU builds the small cache; the GPU builds the full DAG (build_dag) and mines it
//  (metaldag_mine) — both in MetalDAG.metal. Cross-checked byte-for-byte vs the Xcoin node.
//
//  MIT License.
//
import Foundation
import Metal

// MARK: - Keccak (original Keccak, 0x01 pad — NOT NIST SHA3)
enum Keccak {
    static let RC: [UInt64] = [
     0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
     0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
     0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
     0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
     0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
     0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
    static let ROT = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
    static let PI  = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]

    static func f1600(_ st: inout [UInt64]) {
        for r in 0..<24 {
            var bc = [UInt64](repeating: 0, count: 5)
            for i in 0..<5 { bc[i] = st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20] }
            for i in 0..<5 {
                let t = bc[(i+4)%5] ^ ((bc[(i+1)%5] << 1) | (bc[(i+1)%5] >> 63))
                var j = 0; while j < 25 { st[j+i] ^= t; j += 5 }
            }
            var t = st[1]
            for i in 0..<24 { let j = PI[i]; let tmp = st[j]; let n = ROT[i]; st[j] = (t << n) | (t >> (64-n)); t = tmp }
            var j = 0
            while j < 25 {
                let b0=st[j],b1=st[j+1],b2=st[j+2],b3=st[j+3],b4=st[j+4]
                st[j] ^= ~b1 & b2; st[j+1] ^= ~b2 & b3; st[j+2] ^= ~b3 & b4; st[j+3] ^= ~b4 & b0; st[j+4] ^= ~b0 & b1
                j += 5
            }
            st[0] ^= RC[r]
        }
    }
    // Sponge with original 0x01 padding, arbitrary input (single-thread CPU use).
    static func hash(_ input: [UInt8], rate: Int, outLen: Int) -> [UInt8] {
        var st = [UInt8](repeating: 0, count: 200)
        var pt = 0
        for b in input {
            st[pt] ^= b; pt += 1
            if pt == rate { permuteBytes(&st); pt = 0 }
        }
        st[pt] ^= 0x01
        st[rate-1] ^= 0x80
        permuteBytes(&st)
        return Array(st[0..<outLen])
    }
    private static func permuteBytes(_ st: inout [UInt8]) {
        var lanes = [UInt64](repeating: 0, count: 25)
        for i in 0..<25 { var v: UInt64 = 0; for k in 0..<8 { v |= UInt64(st[i*8+k]) << (8*k) }; lanes[i] = v }
        f1600(&lanes)
        for i in 0..<25 { let v = lanes[i]; for k in 0..<8 { st[i*8+k] = UInt8((v >> (8*k)) & 0xff) } }
    }
    static func keccak256(_ input: [UInt8]) -> [UInt8] { hash(input, rate: 136, outLen: 32) }
    static func keccak512(_ input: [UInt8]) -> [UInt8] { hash(input, rate: 72,  outLen: 64) }
}

// MARK: - Epoch sizing (matches src/metaldag/metaldag.cpp + chainparams)
struct MetalDAGParams {
    var baseTime: UInt64       // epoch counts from here (genesis time), not from 1970
    var epochSeconds: UInt64
    var dagInitBytes: UInt64
    var dagGrowthBytes: UInt64
    var cacheDivisor: UInt64
    // xCoin mainnet: 4 GiB launch DAG growing 128 MiB per 14-day epoch, epochs counted
    // from the genesis timestamp (src/kernel/chainparams.cpp metaldagBaseTime). The
    // mainnet genesis is not final yet, so its base time is 0 here: pass --base <genesis
    // time> until the final value is pasted in at genesis. Mining mainnet with base 0
    // would put every hash on the wrong DAG, so main() refuses it.
    static let mainnetBaseTimePending: UInt64 = 0
    static let mainnet = MetalDAGParams(baseTime: mainnetBaseTimePending, epochSeconds: 14*24*3600,
                                        dagInitBytes: 4*1024*1024*1024,
                                        dagGrowthBytes: 128*1024*1024,
                                        cacheDivisor: 128)
    // xCoin testnet A (the rehearsal chain, addresses txa1r...): the mainnet sizing with
    // the testnet A genesis time. Must match src/kernel/chainparams.cpp exactly:
    // TESTNET_GENESIS_TIME = 1789379971 (2026-09-14T09:59:31Z), 4 GiB + 128 MiB/epoch.
    static let testnet = MetalDAGParams(baseTime: 1789379971, epochSeconds: 14*24*3600,
                                        dagInitBytes: 4*1024*1024*1024,
                                        dagGrowthBytes: 128*1024*1024,
                                        cacheDivisor: 128)
    // Regtest: flat 1 MiB DAG (growth 0) so it builds instantly; matches the node.
    static let regtest = MetalDAGParams(baseTime: 1296688602, epochSeconds: 1000,
                                        dagInitBytes: 1*1024*1024,
                                        dagGrowthBytes: 0,
                                        cacheDivisor: 128)
}
struct EpochSizing { var epoch: UInt64; var cacheBytes: UInt64; var fullBytes: UInt64 }

enum MetalDAGSizing {
    static func isPrime(_ n: UInt64) -> Bool {
        if n < 2 { return false }
        if n % 2 == 0 { return n == 2 }
        var i: UInt64 = 3; while i*i <= n { if n % i == 0 { return false }; i += 2 }
        return true
    }
    static func largestPrimeSized(_ target: UInt64, unit: UInt64) -> UInt64 {
        var items = target / unit; if items < 2 { items = 2 }
        while items > 2 && !isPrime(items) { items -= 1 }
        return items * unit
    }
    static func sizing(nTime: UInt32, _ p: MetalDAGParams) -> EpochSizing {
        let rel = UInt64(nTime) > p.baseTime ? UInt64(nTime) - p.baseTime : 0
        let epoch = rel / p.epochSeconds
        var rawFull = p.dagInitBytes + p.dagGrowthBytes * epoch
        var rawCache = rawFull / p.cacheDivisor
        if rawFull  < 128*2 { rawFull  = 128*2 }
        if rawCache < 64*2  { rawCache = 64*2 }
        return EpochSizing(epoch: epoch,
                           cacheBytes: largestPrimeSized(rawCache, unit: 64),
                           fullBytes:  largestPrimeSized(rawFull,  unit: 128))
    }
    // seed(epoch): keccak256 chain from 32 zero bytes.
    static func seed(epoch: UInt64) -> [UInt8] {
        var s = [UInt8](repeating: 0, count: 32)
        var e: UInt64 = 0
        while e < epoch { s = Keccak.keccak256(s); e += 1 }
        return s
    }
}

// MARK: - Cache generation (mkcache — CPU; matches the node)
enum MetalDAGCache {
    static func make(cacheBytes: UInt64, seed: [UInt8]) -> [UInt8] {
        let n = Int(cacheBytes / 64)
        var cache = [UInt8](repeating: 0, count: n * 64)
        // o[0] = keccak512(seed); o[i] = keccak512(o[i-1])
        var prev = Keccak.keccak512(seed)
        for k in 0..<64 { cache[k] = prev[k] }
        for i in 1..<n {
            prev = Keccak.keccak512(prev)
            for k in 0..<64 { cache[i*64 + k] = prev[k] }
        }
        // 3 rounds of RandMemoHash
        for _ in 0..<3 {
            for i in 0..<n {
                let v = Int(readU32(cache, i*64) % UInt32(n))
                let a = ((i + n - 1) % n) * 64
                var tmp = [UInt8](repeating: 0, count: 64)
                for w in 0..<16 {
                    let x = readU32(cache, a + w*4) ^ readU32(cache, v*64 + w*4)
                    writeU32(&tmp, w*4, x)
                }
                let h = Keccak.keccak512(tmp)
                for k in 0..<64 { cache[i*64 + k] = h[k] }
            }
        }
        return cache
    }
    @inline(__always) static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | (UInt32(b[o+1])<<8) | (UInt32(b[o+2])<<16) | (UInt32(b[o+3])<<24)
    }
    @inline(__always) static func writeU32(_ b: inout [UInt8], _ o: Int, _ v: UInt32) {
        b[o]=UInt8(v&0xff); b[o+1]=UInt8((v>>8)&0xff); b[o+2]=UInt8((v>>16)&0xff); b[o+3]=UInt8((v>>24)&0xff)
    }
}

// MARK: - Engine
final class MetalDAGEngine {
    struct Found { let nonce: UInt32; let hash: [UInt32] }
    private let device: MTLDevice
    private let queue: MTLCommandQueue
    private let buildPipe: MTLComputePipelineState
    private let minePipe: MTLComputePipelineState
    private var dagBuf: MTLBuffer?
    private var dagItems: UInt32 = 0
    private(set) var currentEpoch: UInt64 = .max

    init?(device: MTLDevice, library: MTLLibrary) {
        guard let bf = library.makeFunction(name: "build_dag"),
              let mf = library.makeFunction(name: "metaldag_mine"),
              let bp = try? device.makeComputePipelineState(function: bf),
              let mp = try? device.makeComputePipelineState(function: mf),
              let q  = device.makeCommandQueue() else { return nil }
        self.device = device; self.queue = q; self.buildPipe = bp; self.minePipe = mp
    }

    /// Convenience: compile the embedded MetalDAG kernels (metalDAGShaderSource) and init.
    convenience init?(device: MTLDevice) {
        guard let lib = try? device.makeLibrary(source: metalDAGShaderSource, options: nil) else { return nil }
        self.init(device: device, library: lib)
    }

    /// Items generated per GPU dispatch. Keeps each command short so a multi-GB DAG
    /// build can't trip the macOS GPU watchdog (which would hang the app).
    static let buildChunkItems = 1 << 19   // 512K items (~32 MiB) per dispatch

    /// Build (or rebuild) the DAG for the epoch implied by `nTime`. Returns DAG size in
    /// bytes. Skips rebuild if the epoch is unchanged. `progress` is called with 0…1 as
    /// the DAG is generated (a full 4 GiB DAG takes a while — like Ethereum's DAG gen).
    @discardableResult
    func ensureDAG(nTime: UInt32, params: MetalDAGParams, progress: ((Double) -> Void)? = nil) -> UInt64 {
        let sz = MetalDAGSizing.sizing(nTime: nTime, params)
        if sz.epoch == currentEpoch, dagBuf != nil { return sz.fullBytes }
        let seed = MetalDAGSizing.seed(epoch: sz.epoch)
        progress?(0.0)
        let cache = MetalDAGCache.make(cacheBytes: sz.cacheBytes, seed: seed)
        let cacheBuf = device.makeBuffer(bytes: cache, length: cache.count, options: .storageModeShared)!
        let items = Int(sz.fullBytes / 64)
        let dag = device.makeBuffer(length: items * 64, options: .storageModeShared)!
        var cacheN = UInt32(cache.count / 64)
        let tg = min(buildPipe.maxTotalThreadsPerThreadgroup, 256)
        var start = 0
        while start < items {
            let count = min(MetalDAGEngine.buildChunkItems, items - start)
            let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
            e.setComputePipelineState(buildPipe)
            e.setBuffer(cacheBuf, offset: 0, index: 0)
            e.setBytes(&cacheN, length: 4, index: 1)
            e.setBuffer(dag, offset: 0, index: 2)
            var si = UInt32(start); e.setBytes(&si, length: 4, index: 3)
            e.dispatchThreads(MTLSize(width: count, height: 1, depth: 1),
                              threadsPerThreadgroup: MTLSize(width: tg, height: 1, depth: 1))
            e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
            start += count
            progress?(Double(start) / Double(items))
        }
        self.dagBuf = dag; self.dagItems = UInt32(items); self.currentEpoch = sz.epoch
        return sz.fullBytes
    }

    /// Mine `count` nonces starting at `nonceStart` over the current DAG.
    /// header76 = the 76-byte block-header prefix (no nonce). targetMSWFirst = 8 words, [0]=MSW.
    func mine(header76: [UInt8], targetMSWFirst: [UInt32], nonceStart: UInt32, count: Int) -> (found: [Found], hashes: UInt32) {
        guard let dag = dagBuf else { return ([], 0) }
        // headerHash = keccak256(76-byte prefix) → 8 LE words.
        let hh = Keccak.keccak256(header76)
        var hhWords = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 { hhWords[i] = MetalDAGCache.readU32(hh, i*4) }
        var di = dagItems
        var ns = nonceStart
        var tgt = targetMSWFirst
        let hhBuf = device.makeBuffer(bytes: &hhWords, length: 32, options: .storageModeShared)!
        let tgtBuf = device.makeBuffer(bytes: &tgt, length: 32, options: .storageModeShared)!
        let hashCount = device.makeBuffer(length: 4, options: .storageModeShared)!
        let resCount  = device.makeBuffer(length: 4, options: .storageModeShared)!
        let results   = device.makeBuffer(length: 100 * MemoryLayout<UInt32>.stride * 10, options: .storageModeShared)!
        memset(hashCount.contents(), 0, 4); memset(resCount.contents(), 0, 4)
        let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(minePipe)
        e.setBuffer(dag, offset: 0, index: 0)
        e.setBytes(&di, length: 4, index: 1)
        e.setBuffer(hhBuf, offset: 0, index: 2)
        e.setBytes(&ns, length: 4, index: 3)
        e.setBuffer(hashCount, offset: 0, index: 4)
        e.setBuffer(resCount, offset: 0, index: 5)
        e.setBuffer(results, offset: 0, index: 6)
        e.setBuffer(tgtBuf, offset: 0, index: 7)
        let tg = min(minePipe.maxTotalThreadsPerThreadgroup, 256)
        e.dispatchThreads(MTLSize(width: count, height: 1, depth: 1),
                          threadsPerThreadgroup: MTLSize(width: tg, height: 1, depth: 1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
        let nFound = Int(resCount.contents().bindMemory(to: UInt32.self, capacity: 1).pointee)
        let hashes = hashCount.contents().bindMemory(to: UInt32.self, capacity: 1).pointee
        // MiningResult layout: {uint nonce; uint hash[8]; uint zeros;} = 10 words.
        let rp = results.contents().bindMemory(to: UInt32.self, capacity: 100 * 10)
        var found: [Found] = []
        for k in 0..<min(nFound, 100) {
            let base = k * 10
            found.append(Found(nonce: rp[base], hash: Array(UnsafeBufferPointer(start: rp + base + 1, count: 8))))
        }
        return (found, hashes)
    }

    /// Pool share target = MAX_TARGET / difficulty (mirrors the pool's diff_to_target()).
    /// Supports fractional difficulties (e.g. 0.001) via 20-bit fixed point:
    /// target = (0xFFFF·2^208 << 20) / round(diff · 2^20), long-divided over 9 words.
    static func targetWords(fromDifficulty d: Double) -> [UInt32] {
        let fixed = UInt64(min(4294967295.0, max(1.0, (d * 1048576.0).rounded())))
        // dividend = MAX_TARGET << 20 = 0xFFFF · 2^228, as 9 words MSW-first (288 bits)
        var dividend = [UInt32](repeating: 0, count: 9)
        dividend[1] = 0x000FFFF0
        var quotient = [UInt32](repeating: 0, count: 9)
        var rem: UInt64 = 0
        for i in 0..<9 {
            let cur = (rem << 32) | UInt64(dividend[i])
            quotient[i] = UInt32(cur / fixed)
            rem = cur % fixed
        }
        if quotient[0] != 0 {           // diff so low the target overflows 256 bits: saturate
            return [UInt32](repeating: 0xFFFFFFFF, count: 8)
        }
        return Array(quotient[1...8])
    }

    /// Expand a compact nBits target into 8 words, MSW first (for the mine kernel).
    static func targetWords(fromNBits nBits: UInt32) -> [UInt32] {
        let exponent = Int(nBits >> 24)
        let mantissa = nBits & 0x007fffff
        var target = [UInt8](repeating: 0, count: 32) // big-endian 256-bit
        // value = mantissa * 256^(exponent-3); place mantissa bytes at the right offset.
        let bytes = [UInt8((mantissa >> 16) & 0xff), UInt8((mantissa >> 8) & 0xff), UInt8(mantissa & 0xff)]
        let start = 32 - exponent // index of the most-significant mantissa byte
        for i in 0..<3 {
            let idx = start + i
            if idx >= 0 && idx < 32 { target[idx] = bytes[i] }
        }
        var words = [UInt32](repeating: 0, count: 8) // MSW first
        for w in 0..<8 {
            words[w] = (UInt32(target[w*4])<<24) | (UInt32(target[w*4+1])<<16) | (UInt32(target[w*4+2])<<8) | UInt32(target[w*4+3])
        }
        return words
    }
}
