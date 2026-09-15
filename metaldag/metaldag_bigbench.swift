// MetalDAG realistic throughput benchmark — measures the memory-BANDWIDTH-bound
// hashrate at real DAG sizes (256 MiB … 4 GiB). Correctness already proven by the
// cross-check; here we only need real DRAM traffic, so the DAG is filled with a
// pseudo-random pattern (contents irrelevant to timing, only the access pattern).
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
inline void keccak512_40(thread const uint* in10, thread uint* out16){
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<5;k++) st[k]=(ulong)in10[2*k] | ((ulong)in10[2*k+1]<<32);
  st[5]^=0x01UL; st[8]^=0x8000000000000000UL; keccakf(st);
  for(int k=0;k<8;k++){ out16[2*k]=(uint)(st[k]&0xffffffff); out16[2*k+1]=(uint)(st[k]>>32); }
}
inline void keccak256_96(thread const uint* in24, thread uint* out8){
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<12;k++) st[k]=(ulong)in24[2*k] | ((ulong)in24[2*k+1]<<32);
  st[12]^=0x01UL; st[16]^=0x8000000000000000UL; keccakf(st);
  for(int k=0;k<4;k++){ out8[2*k]=(uint)(st[k]&0xffffffff); out8[2*k+1]=(uint)(st[k]>>32); }
}
inline uint fnv(uint a,uint b){ return (a*0x01000193u) ^ b; }
// fill the DAG buffer with a pseudo-random pattern (real DRAM, nonzero pages)
kernel void fillDag(device uint* dag [[buffer(0)]], uint gid [[thread_position_in_grid]]){
  dag[gid] = fnv(gid*16u+1u, gid ^ 0x9e3779b9u);
}
kernel void hashimoto(device const uint* dag [[buffer(0)]],
                      constant uint* hdr [[buffer(1)]],
                      constant uint& n [[buffer(2)]],
                      constant uint& startNonce [[buffer(3)]],
                      device uint* out [[buffer(4)]],
                      uint gid [[thread_position_in_grid]]){
  uint nonce = startNonce + gid;
  uint in10[10]; for(int i=0;i<8;i++) in10[i]=hdr[i]; in10[8]=nonce; in10[9]=0;
  uint s[16]; keccak512_40(in10,s);
  uint mix[32]; for(int i=0;i<32;i++) mix[i]=s[i%16];
  for(uint i=0;i<64;i++){
    uint p = fnv(i ^ s[0], mix[i%32]) % (n/2) * 2;
    for(uint j=0;j<2;j++){ uint base=(p+j)*16; for(int k=0;k<16;k++) mix[j*16+k]=fnv(mix[j*16+k], dag[base+k]); }
  }
  uint cmix[8]; for(uint i=0;i<32;i+=4) cmix[i/4]=fnv(fnv(fnv(mix[i],mix[i+1]),mix[i+2]),mix[i+3]);
  uint fin[24]; for(int i=0;i<16;i++) fin[i]=s[i]; for(int i=0;i<8;i++) fin[16+i]=cmix[i];
  uint res[8]; keccak256_96(fin,res);
  // reduce to one word so the compiler can't drop the work, tiny write traffic
  out[gid] = res[0];
}
"""

let dev = MTLCreateSystemDefaultDevice()!
print("GPU: \(dev.name)   maxBuffer: \(dev.maxBufferLength/1024/1024) MiB   recommendedWorkingSet: \(dev.recommendedMaxWorkingSetSize/1024/1024) MiB\n")
let lib = try! dev.makeLibrary(source:MSL, options:nil)
let q = dev.makeCommandQueue()!
let fillPipe = try! dev.makeComputePipelineState(function:lib.makeFunction(name:"fillDag")!)
let hashPipe = try! dev.makeComputePipelineState(function:lib.makeFunction(name:"hashimoto")!)
var hdrWords:[UInt32] = (0..<8).map{ UInt32($0 &* 7 &+ 1) }
let hdrBuf = dev.makeBuffer(bytes:&hdrWords, length:32, options:.storageModeShared)!

func fill(_ buf:MTLBuffer,_ words:Int){
  let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(fillPipe); e.setBuffer(buf,offset:0,index:0)
  e.dispatchThreads(MTLSize(width:words,height:1,depth:1), threadsPerThreadgroup:MTLSize(width:256,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
func bench(_ dag:MTLBuffer,_ n:UInt32,_ count:Int)->Double{
  let out=dev.makeBuffer(length:count*4, options:.storageModeShared)!
  let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(hashPipe)
  e.setBuffer(dag,offset:0,index:0); e.setBuffer(hdrBuf,offset:0,index:1)
  var nn=n; e.setBytes(&nn,length:4,index:2); var st:UInt32=0; e.setBytes(&st,length:4,index:3)
  e.setBuffer(out,offset:0,index:4)
  let tg=min(hashPipe.maxTotalThreadsPerThreadgroup,256)
  e.dispatchThreads(MTLSize(width:count,height:1,depth:1), threadsPerThreadgroup:MTLSize(width:tg,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); _=out
  let t0=Date()
  let cb2=q.makeCommandBuffer()!; let e2=cb2.makeComputeCommandEncoder()!
  e2.setComputePipelineState(hashPipe)
  e2.setBuffer(dag,offset:0,index:0); e2.setBuffer(hdrBuf,offset:0,index:1)
  e2.setBytes(&nn,length:4,index:2); e2.setBytes(&st,length:4,index:3); e2.setBuffer(out,offset:0,index:4)
  e2.dispatchThreads(MTLSize(width:count,height:1,depth:1), threadsPerThreadgroup:MTLSize(width:tg,height:1,depth:1))
  e2.endEncoding(); cb2.commit(); cb2.waitUntilCompleted()
  return -t0.timeIntervalSinceNow
}

print("  DAG      MH/s      GB/s     note")
let count = 3_000_000
for mib in [64, 256, 1024, 2048, 4096] {
  let bytes = mib*1024*1024
  if bytes > dev.maxBufferLength { print("\(mib) MiB > maxBuffer, skip"); continue }
  guard let dag = dev.makeBuffer(length:bytes, options:.storageModeShared) else { print("\(mib) MiB alloc fail"); continue }
  let words = bytes/4
  fill(dag, words)
  let n = UInt32(bytes/64)
  let dt = bench(dag, n, count)
  let mhs = Double(count)/dt/1e6
  let gbs = Double(count) * 64.0 * 128.0 / dt / 1e9   // 64 reads × 128 B per hash
  let cacheNote = mib <= 64 ? "cache-resident (compute-bound)" : "DRAM (bandwidth-bound)"
  let mhsStr = String(format:"%8.1f", mhs)
  let gbsStr = String(format:"%8.1f", gbs)
  print("\(mib)MiB \(mhsStr)  \(gbsStr)   \(cacheNote)")
}
