// Auto-generated from MetalDAG.metal — the MetalDAG GPU kernels as an embeddable MSL string.
import Foundation
let metalDAGShaderSource = ##"""
//
//  MetalDAG.metal
//  MacMetal Miner — MetalDAG (Ethash-family, memory-hard) GPU kernels for Xcoin.
//
//  Replaces SHA256.metal. Two kernels:
//    build_dag       — CPU builds the small cache; this generates the full DAG from it.
//    metaldag_mine   — one nonce per thread: hashimoto over the DAG, compare to target.
//
//  Byte-for-byte identical to the Xcoin node's verifier (src/metaldag/metaldag.cpp)
//  and the C++ reference. MIT License.
//
#include <metal_stdlib>
using namespace metal;

// ─────────────── Keccak-f[1600] (original Keccak, 0x01 pad) ───────────────
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
inline void keccak512_40(thread const uint* in10, thread uint* out16){ // 40-byte input
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<5;k++) st[k]=(ulong)in10[2*k] | ((ulong)in10[2*k+1]<<32);
  st[5]^=0x01UL; st[8]^=0x8000000000000000UL; keccakf(st);
  for(int k=0;k<8;k++){ out16[2*k]=(uint)(st[k]&0xffffffff); out16[2*k+1]=(uint)(st[k]>>32); }
}
inline void keccak512_64(thread const uint* in16, thread uint* out16){ // 64-byte input
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<8;k++) st[k]=(ulong)in16[2*k] | ((ulong)in16[2*k+1]<<32);
  st[8]^=0x8000000000000001UL; keccakf(st);   // pad byte 64 (0x01) + rate-end byte 71 (0x80)
  for(int k=0;k<8;k++){ out16[2*k]=(uint)(st[k]&0xffffffff); out16[2*k+1]=(uint)(st[k]>>32); }
}
inline void keccak256_96(thread const uint* in24, thread uint* out8){ // 96-byte input
  ulong st[25]; for(int i=0;i<25;i++) st[i]=0;
  for(int k=0;k<12;k++) st[k]=(ulong)in24[2*k] | ((ulong)in24[2*k+1]<<32);
  st[12]^=0x01UL; st[16]^=0x8000000000000000UL; keccakf(st);
  for(int k=0;k<4;k++){ out8[2*k]=(uint)(st[k]&0xffffffff); out8[2*k+1]=(uint)(st[k]>>32); }
}
inline uint fnv(uint a,uint b){ return (a*0x01000193u) ^ b; }

// ─────────────── DAG generation ───────────────
// calc_dataset_item: derive one 64-byte DAG item (16 words) from the cache.
inline void dag_item(device const uint* cache, uint n, uint i, thread uint* out16){
  uint mix[16];
  for(int k=0;k<16;k++) mix[k] = cache[(i % n)*16 + k];
  mix[0] ^= i;
  keccak512_64(mix, mix);
  for(uint j=0;j<256;j++){
    uint cache_index = fnv(i ^ j, mix[j % 16]);
    uint base = (cache_index % n) * 16;
    for(int k=0;k<16;k++) mix[k] = fnv(mix[k], cache[base + k]);
  }
  keccak512_64(mix, out16);
}
// Generate DAG item `startItem + gid` from the cache. Dispatched in chunks so no
// single GPU command runs long enough to trip the macOS GPU watchdog (a full 4 GiB
// DAG is ~67M items — one giant dispatch would hang the app).
kernel void build_dag(device const uint* cache [[buffer(0)]],
                      constant uint& n          [[buffer(1)]],   // cache item count
                      device uint* dag          [[buffer(2)]],
                      constant uint& startItem  [[buffer(3)]],   // first DAG item of this chunk
                      uint gid [[thread_position_in_grid]]){
  uint i = startItem + gid;
  uint out16[16];
  dag_item(cache, n, i, out16);
  for(int k=0;k<16;k++) dag[i*16 + k] = out16[k];
}

// ─────────────── hashimoto (mining hot path) ───────────────
// headerHash8 = keccak256(76-byte header prefix); dagItems = full_size/64.
inline void hashimoto(device const uint* dag, uint dagItems,
                      thread const uint* headerHash8, uint nonce, thread uint* res8){
  uint in10[10];
  for(int i=0;i<8;i++) in10[i]=headerHash8[i];
  in10[8]=nonce; in10[9]=0;                      // 32-bit nonce, hi word 0
  uint s[16]; keccak512_40(in10, s);
  uint mix[32]; for(int i=0;i<32;i++) mix[i]=s[i%16];
  for(uint i=0;i<64;i++){
    uint p = fnv(i ^ s[0], mix[i%32]) % (dagItems/2) * 2;
    for(uint j=0;j<2;j++){ uint base=(p+j)*16; for(int k=0;k<16;k++) mix[j*16+k]=fnv(mix[j*16+k], dag[base+k]); }
  }
  uint cmix[8];
  for(uint i=0;i<32;i+=4) cmix[i/4]=fnv(fnv(fnv(mix[i],mix[i+1]),mix[i+2]),mix[i+3]);
  uint fin[24]; for(int i=0;i<16;i++) fin[i]=s[i]; for(int i=0;i<8;i++) fin[16+i]=cmix[i];
  keccak256_96(fin, res8);
}

struct MiningResult { uint nonce; uint hash[8]; uint zeros; };

// Debug/cross-check: write the raw 256-bit PoW hash (8 words) per nonce.
kernel void metaldag_hash_out(device const uint* dag [[buffer(0)]],
                              constant uint& dagItems [[buffer(1)]],
                              constant uint* headerHash [[buffer(2)]],
                              constant uint& nonceStart [[buffer(3)]],
                              device uint* out [[buffer(4)]],
                              uint gid [[thread_position_in_grid]]){
  uint hh[8]; for(int i=0;i<8;i++) hh[i]=headerHash[i];
  uint res[8]; hashimoto(dag, dagItems, hh, nonceStart+gid, res);
  for(int i=0;i<8;i++) out[gid*8+i]=res[i];
}

// Production mining kernel — mirrors sha256_mine's interface (target = 8 words, MSW first).
kernel void metaldag_mine(device const uint* dag        [[buffer(0)]],
                          constant uint& dagItems        [[buffer(1)]],
                          constant uint* headerHash       [[buffer(2)]],  // 8 words
                          constant uint& nonceStart       [[buffer(3)]],
                          device atomic_uint* hashCount   [[buffer(4)]],
                          device atomic_uint* resultCount [[buffer(5)]],
                          device MiningResult* results    [[buffer(6)]],
                          constant uint* target           [[buffer(7)]],  // 8 words, target[0]=MSW
                          uint gid [[thread_position_in_grid]]){
  uint nonce = nonceStart + gid;
  uint hh[8]; for(int i=0;i<8;i++) hh[i]=headerHash[i];
  uint res[8]; hashimoto(dag, dagItems, hh, nonce, res);   // res[7] = most-significant word
  atomic_fetch_add_explicit(hashCount, 1, memory_order_relaxed);
  bool below=false;
  // uint256 stores 32-bit limbs little-endian; res[7] is the numeric MSW.
  for(int i=0;i<8;i++){ uint hw=res[7-i], tw=target[i]; if(hw<tw){below=true;break;} if(hw>tw){below=false;break;} }
  if(below){
    uint idx = atomic_fetch_add_explicit(resultCount, 1, memory_order_relaxed);
    if(idx < 100){ results[idx].nonce = nonce; results[idx].zeros = 0;
      for(int i=0;i<8;i++) results[idx].hash[i]=res[i]; }
  }
}

"""##
