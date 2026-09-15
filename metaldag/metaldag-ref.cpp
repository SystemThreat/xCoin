// MetalDAG reference verifier (Ethash-family, light-cache verification).
// Prototype for Xcoin node-side PoW. Keccak (original, 0x01 pad) + mkcache +
// calc_dataset_item + hashimoto_light. Assumes little-endian host (arm64/x86).
//
// This is the canonical reference; the Metal miner must match it byte-for-byte.
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <array>
#include <string>

// ─────────────────────────── Keccak-f[1600] ───────────────────────────
static const uint64_t KECCAK_RC[24] = {
 0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
 0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
 0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
 0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
 0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
 0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int KECCAK_ROT[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int KECCAK_PI[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
static inline uint64_t rol64(uint64_t x,int n){return (x<<n)|(x>>(64-n));}
static void keccakf(uint64_t st[25]){
  for(int r=0;r<24;r++){
    uint64_t bc[5],t;
    for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
    for(int i=0;i<5;i++){ t=bc[(i+4)%5]^rol64(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
    t=st[1];
    for(int i=0;i<24;i++){ int j=KECCAK_PI[i]; uint64_t tmp=st[j]; st[j]=rol64(t,KECCAK_ROT[i]); t=tmp; }
    for(int j=0;j<25;j+=5){ for(int i=0;i<5;i++) bc[i]=st[j+i]; for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5]; }
    st[0]^=KECCAK_RC[r];
  }
}
// Keccak sponge (original padding delimiter 0x01, as Ethash uses — NOT SHA3's 0x06).
static void keccak(int rate_bytes, const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen){
  uint8_t st8[200]; memset(st8,0,200);
  size_t pt=0;
  for(size_t i=0;i<inlen;i++){ st8[pt++]^=in[i]; if(pt==(size_t)rate_bytes){ keccakf((uint64_t*)st8); pt=0; } }
  st8[pt]^=0x01;                       // Keccak pad
  st8[rate_bytes-1]^=0x80;
  keccakf((uint64_t*)st8);
  memcpy(out,st8,outlen);
}
static void keccak256(const uint8_t* in,size_t n,uint8_t out[32]){ keccak(136,in,n,out,32); }
static void keccak512(const uint8_t* in,size_t n,uint8_t out[64]){ keccak(72 ,in,n,out,64); }

// ─────────────────────────── Ethash params (Xcoin sizing) ───────────────────────────
static const uint32_t HASH_BYTES=64, MIX_BYTES=128, WORD_BYTES=4;
static const uint32_t DATASET_PARENTS=256, CACHE_ROUNDS=3, ACCESSES=64;
static inline uint32_t fnv(uint32_t a,uint32_t b){ return (a*0x01000193u) ^ b; }

typedef std::array<uint8_t,64> Item;              // one 64-byte hash item (16 LE words)
static inline uint32_t* w(Item& it){ return (uint32_t*)it.data(); }
static inline const uint32_t* w(const Item& it){ return (const uint32_t*)it.data(); }

// cache generation (memory-hard: CACHE_ROUNDS passes of RandMemoHash)
static std::vector<Item> mkcache(size_t cache_size, const uint8_t seed[32]){
  size_t n = cache_size / HASH_BYTES;
  std::vector<Item> o(n);
  keccak512(seed,32,o[0].data());
  for(size_t i=1;i<n;i++) keccak512(o[i-1].data(),64,o[i].data());
  for(uint32_t r=0;r<CACHE_ROUNDS;r++){
    for(size_t i=0;i<n;i++){
      uint32_t v = w(o[i])[0] % (uint32_t)n;
      Item tmp;
      for(int k=0;k<16;k++) w(tmp)[k] = w(o[(i+n-1)%n])[k] ^ w(o[v])[k];
      keccak512(tmp.data(),64,o[i].data());
    }
  }
  return o;
}

// derive DAG item i from the cache (this is what a light verifier recomputes on demand)
static Item calc_dataset_item(const std::vector<Item>& cache, uint32_t i){
  size_t n = cache.size();
  const uint32_t r = HASH_BYTES / WORD_BYTES;      // 16
  Item mix = cache[i % n];
  w(mix)[0] ^= i;
  keccak512(mix.data(),64,mix.data());
  for(uint32_t j=0;j<DATASET_PARENTS;j++){
    uint32_t cache_index = fnv(i ^ j, w(mix)[j % r]);
    const Item& c = cache[cache_index % n];
    for(int k=0;k<16;k++) w(mix)[k] = fnv(w(mix)[k], w(c)[k]);
  }
  keccak512(mix.data(),64,mix.data());
  return mix;
}

// hashimoto light: header(32) + nonce(64-bit) → {mix_digest(32), result(32)}
struct HashimotoOut { uint8_t mix[32]; uint8_t result[32]; };
static HashimotoOut hashimoto_light(size_t full_size, const std::vector<Item>& cache,
                                    const uint8_t header[32], uint64_t nonce){
  size_t n = full_size / HASH_BYTES;
  const uint32_t w_words = MIX_BYTES / WORD_BYTES; // 32
  const uint32_t mixhashes = MIX_BYTES / HASH_BYTES; // 2
  uint8_t s_in[40];
  memcpy(s_in,header,32);
  for(int k=0;k<8;k++) s_in[32+k] = (uint8_t)(nonce >> (8*k)); // nonce little-endian
  uint8_t s[64]; keccak512(s_in,40,s);
  const uint32_t* sw = (const uint32_t*)s;
  uint32_t mix[32];
  for(uint32_t i=0;i<w_words;i++) mix[i] = sw[i % (HASH_BYTES/WORD_BYTES)];
  for(uint32_t i=0;i<ACCESSES;i++){
    uint32_t p = fnv(i ^ sw[0], mix[i % w_words]) % (uint32_t)(n / mixhashes) * mixhashes;
    uint32_t newdata[32];
    for(uint32_t j=0;j<mixhashes;j++){
      Item di = calc_dataset_item(cache, p + j);
      for(int k=0;k<16;k++) newdata[j*16+k] = w(di)[k];
    }
    for(uint32_t k=0;k<w_words;k++) mix[k] = fnv(mix[k], newdata[k]);
  }
  HashimotoOut out;
  uint32_t cmix[8];
  for(uint32_t i=0;i<w_words;i+=4)
    cmix[i/4] = fnv(fnv(fnv(mix[i],mix[i+1]),mix[i+2]),mix[i+3]);
  memcpy(out.mix, cmix, 32);
  uint8_t final_in[96]; memcpy(final_in,s,64); memcpy(final_in+64,cmix,32);
  keccak256(final_in,96,out.result);
  return out;
}

// ─────────────────────────── self-test ───────────────────────────
static std::string hex(const uint8_t* b,size_t n){ std::string s; char t[3]; for(size_t i=0;i<n;i++){snprintf(t,3,"%02x",b[i]); s+=t;} return s; }

int main(){
  // 1. Keccak-256("") must equal the known ORIGINAL-Keccak empty hash.
  uint8_t h[32]; keccak256((const uint8_t*)"",0,h);
  std::string got = hex(h,32);
  std::string want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
  printf("keccak256(\"\") = %s\n  %s\n", got.c_str(), got==want ? "MATCH (Keccak correct)" : "MISMATCH!!");
  // keccak256("abc")
  keccak256((const uint8_t*)"abc",3,h);
  printf("keccak256(\"abc\") = %s\n  expect 4e03657a...(orig keccak)\n", hex(h,32).c_str());

  // 2. Build a small cache/DAG (prototype sizes) and verify determinism + hashimoto.
  size_t cache_size = 1024*64;        // 64 KiB cache (small for the test)
  size_t full_size  = 1024*1024;      // 1 MiB DAG (light-verify never builds it fully)
  uint8_t seed[32]; memset(seed,0,32);
  auto cache = mkcache(cache_size, seed);
  printf("cache items: %zu  (memory-hard: %u rounds)\n", cache.size(), CACHE_ROUNDS);

  uint8_t header[32]; for(int i=0;i<32;i++) header[i]=(uint8_t)(i*7+1);
  auto a = hashimoto_light(full_size, cache, header, 42);
  auto b = hashimoto_light(full_size, cache, header, 42);
  printf("hashimoto result (nonce 42): %s\n", hex(a.result,32).c_str());
  printf("determinism (same nonce -> same result): %s\n", memcmp(a.result,b.result,32)==0?"YES":"NO");
  auto c = hashimoto_light(full_size, cache, header, 43);
  printf("different nonce -> different result: %s\n", memcmp(a.result,c.result,32)!=0?"YES":"NO");

  // 3. Demonstrate a target check (the consensus test): scan nonces for one under a target.
  uint8_t target[32]; memset(target,0xff,32); target[0]=0x00; target[1]=0x0f; // easy target
  uint64_t found=0; bool hit=false;
  for(uint64_t nonce=0; nonce<200000; nonce++){
    auto r = hashimoto_light(full_size, cache, header, nonce);
    // compare result <= target as big-endian 256-bit
    int cmp=0; for(int i=31;i>=0;i--){ if(r.result[i]!=target[i]){ cmp = r.result[i]<target[i]?-1:1; break; } }
    if(cmp<=0){ found=nonce; hit=true; break; }
  }
  printf("PoW target scan: %s at nonce %llu\n", hit?"FOUND":"none", (unsigned long long)found);
  // verify the found nonce reproduces (what a node's CheckProofOfWork would do)
  if(hit){ auto v=hashimoto_light(full_size,cache,header,found); printf("verify re-derives same result: %s\n", memcmp(v.result, hashimoto_light(full_size,cache,header,found).result,32)==0?"YES":"NO"); }
  return 0;
}
