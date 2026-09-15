// MetalDAG Metal-kernel cross-check + benchmark.
// Loads dag.bin + header.bin from the C++ reference, runs the hashimoto kernel on
// the GPU, verifies nonce 42 == the reference result, then benchmarks hashrate.
import Foundation
import Metal

let MSL = """
#include <metal_stdlib>
using namespace metal;

constant ulong RC[24] = {
 0x0000000000000001UL,0x0000000000008082UL,0x800000000000808aUL,0x8000000080008000UL,
 0x000000000000808bUL,0x0000000080000001UL,0x8000000080008081UL,0x8000000000008009UL,
 0x000000000000008aUL,0x0000000000000088UL,0x0000000080008009UL,0x000000008000000aUL,
 0x000000008000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,
 0x8000000000008002UL,0x8000000000000080UL,0x000000000000800aUL,0x800000008000000aUL,
 0x8000000080008081UL,0x8000000000008080UL,0x0000000080000001UL,0x8000000080008008UL};
constant int ROT[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant int PIt[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rol(ulong x,int n){ return (x<<n)|(x>>(64-n)); }
inline void keccakf(thread ulong* st){
  for(int r=0;r<24;r++){
    ulong bc[5],t;
    for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
    for(int i=0;i<5;i++){ t=bc[(i+4)%5]^rol(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
    t=st[1];
    for(int i=0;i<24;i++){ int j=PIt[i]; ulong tmp=st[j]; st[j]=rol(t,ROT[i]); t=tmp; }
    for(int j=0;j<25;j+=5){ ulong b0=st[j],b1=st[j+1],b2=st[j+2],b3=st[j+3],b4=st[j+4];
      st[j]^=(~b1)&b2; st[j+1]^=(~b2)&b3; st[j+2]^=(~b3)&b4; st[j+3]^=(~b4)&b0; st[j+4]^=(~b0)&b1; }
    st[0]^=RC[r];
  }
}
// keccak512 of 40 input bytes (10 LE words) -> 16 LE words
inline void keccak512_40(thread const uint* in10, thread uint* out16){
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<5;k++) st[k]=(ulong)in10[2*k] | ((ulong)in10[2*k+1]<<32);
  st[5]^=0x01UL;                 // pad at byte 40
  st[8]^=0x8000000000000000UL;   // pad at byte 71 (rate 72)
  keccakf(st);
  for(int k=0;k<8;k++){ out16[2*k]=(uint)(st[k]&0xffffffff); out16[2*k+1]=(uint)(st[k]>>32); }
}
// keccak256 of 96 input bytes (24 LE words) -> 8 LE words
inline void keccak256_96(thread const uint* in24, thread uint* out8){
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<12;k++) st[k]=(ulong)in24[2*k] | ((ulong)in24[2*k+1]<<32);
  st[12]^=0x01UL;                // pad at byte 96
  st[16]^=0x8000000000000000UL;  // pad at byte 135 (rate 136)
  keccakf(st);
  for(int k=0;k<4;k++){ out8[2*k]=(uint)(st[k]&0xffffffff); out8[2*k+1]=(uint)(st[k]>>32); }
}
inline uint fnv(uint a,uint b){ return (a*0x01000193u) ^ b; }

kernel void hashimoto(device const uint* dag   [[buffer(0)]],
                      constant uint* hdr        [[buffer(1)]],   // 8 words
                      constant uint& n          [[buffer(2)]],   // full_size/64
                      constant uint& startNonce [[buffer(3)]],
                      device uint* out          [[buffer(4)]],   // 8 words per thread
                      uint gid [[thread_position_in_grid]]){
  uint nonce = startNonce + gid;
  uint in10[10];
  for(int i=0;i<8;i++) in10[i]=hdr[i];
  in10[8]=nonce; in10[9]=0;
  uint s[16]; keccak512_40(in10,s);
  uint mix[32]; for(int i=0;i<32;i++) mix[i]=s[i%16];
  for(uint i=0;i<64;i++){
    uint p = fnv(i ^ s[0], mix[i%32]) % (n/2) * 2;
    for(uint j=0;j<2;j++){ uint base=(p+j)*16; for(int k=0;k<16;k++) mix[j*16+k]=fnv(mix[j*16+k], dag[base+k]); }
  }
  uint cmix[8];
  for(uint i=0;i<32;i+=4) cmix[i/4]=fnv(fnv(fnv(mix[i],mix[i+1]),mix[i+2]),mix[i+3]);
  uint fin[24]; for(int i=0;i<16;i++) fin[i]=s[i]; for(int i=0;i<8;i++) fin[16+i]=cmix[i];
  uint res[8]; keccak256_96(fin,res);
  for(int i=0;i<8;i++) out[gid*8+i]=res[i];
}
"""

func load(_ p:String)->Data{ return FileManager.default.contents(atPath:p) ?? Data() }
let dir="/private/tmp/claude-501/-Users-david/fb137d2e-ec3c-41b5-91a7-31087ce9c44a/scratchpad/"
let dag = load(dir+"dag.bin")
let hdr = load(dir+"header.bin")
guard dag.count>0, hdr.count==32 else { print("missing dag.bin/header.bin"); exit(1) }
let n = UInt32(dag.count/64)

guard let dev = MTLCreateSystemDefaultDevice() else { print("no Metal device"); exit(1) }
print("GPU: \(dev.name)  unified-memory: \(dev.hasUnifiedMemory)")
let lib = try! dev.makeLibrary(source:MSL, options:nil)
let fn = lib.makeFunction(name:"hashimoto")!
let pipe = try! dev.makeComputePipelineState(function:fn)
let q = dev.makeCommandQueue()!

let dagBuf = dev.makeBuffer(bytes:[UInt8](dag), length:dag.count, options:.storageModeShared)!
var hdrWords=[UInt32](repeating:0,count:8)
hdr.withUnsafeBytes{ p in for i in 0..<8 { hdrWords[i]=p.load(fromByteOffset:i*4, as:UInt32.self) } }
let hdrBuf = dev.makeBuffer(bytes:hdrWords, length:32, options:.storageModeShared)!

func run(count:Int, start:UInt32)->MTLBuffer{
  let out = dev.makeBuffer(length:count*32, options:.storageModeShared)!
  let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(pipe)
  e.setBuffer(dagBuf,offset:0,index:0); e.setBuffer(hdrBuf,offset:0,index:1)
  var nn=n; e.setBytes(&nn,length:4,index:2)
  var st=start; e.setBytes(&st,length:4,index:3)
  e.setBuffer(out,offset:0,index:4)
  let tg=min(pipe.maxTotalThreadsPerThreadgroup,256)
  e.dispatchThreads(MTLSize(width:count,height:1,depth:1), threadsPerThreadgroup:MTLSize(width:tg,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
  return out
}

// ── cross-check nonce 42 against the C++ reference ──
let out = run(count:64, start:0)
let op = out.contents().bindMemory(to:UInt32.self, capacity:64*8)
var hexs=""
for i in 0..<8 { let wbytes=withUnsafeBytes(of:op[42*8+i].littleEndian){Array($0)}; for b in wbytes { hexs+=String(format:"%02x",b) } }
let want="3eb179b2564613c423228f2290c3bd1551a708c5ff3440a5580109f7dd4414d2"
print("Metal   nonce42 = \(hexs)")
print("C++ ref nonce42 = \(want)")
print(hexs==want ? "✅ CROSS-CHECK PASS — Metal kernel matches the C++ reference" : "❌ MISMATCH")

// ── benchmark ──
if hexs==want {
  let N = 4_000_000
  _ = run(count:1024, start:0) // warm
  let t0=Date()
  _ = run(count:N, start:0)
  let dt = -t0.timeIntervalSinceNow
  print(String(format:"benchmark: %d hashes in %.3fs = %.1f MH/s (prototype 1 MiB DAG)", N, dt, Double(N)/dt/1e6))
}
