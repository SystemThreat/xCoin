// Copyright (c) 2026 The Xcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <metaldag/metaldag.h>

#include <chain.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <util/time.h>

#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace metaldag {
namespace {

// ─────────────────────────── Keccak-f[1600] ───────────────────────────
// Original Keccak (0x01 padding), as Ethash uses — NOT NIST SHA3 (0x06).
const uint64_t KECCAK_RC[24] = {
 0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
 0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
 0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
 0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
 0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
 0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
const int KECCAK_ROT[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
const int KECCAK_PI[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline uint64_t rol64(uint64_t x,int n){ return (x<<n)|(x>>(64-n)); }
void keccakf(uint64_t st[25]){
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
// Keccak sponge with original 0x01 padding. Endian-independent: message bytes are
// absorbed into, and squeezed out of, the 64-bit lanes in explicit little-endian
// order, so the digest is byte-for-byte identical on every architecture (H-01).
void keccak(int rate_bytes, const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen){
    uint64_t st[25]; std::memset(st,0,sizeof st);
    size_t pt=0;
    for(size_t i=0;i<inlen;i++){
        st[pt>>3] ^= (uint64_t)in[i] << (8*(pt&7));
        if(++pt==(size_t)rate_bytes){ keccakf(st); pt=0; }
    }
    st[pt>>3] ^= (uint64_t)0x01 << (8*(pt&7));
    st[(size_t)(rate_bytes-1)>>3] ^= (uint64_t)0x80 << (8*((size_t)(rate_bytes-1)&7));
    keccakf(st);
    for(size_t i=0;i<outlen;i++) out[i] = (uint8_t)(st[i>>3] >> (8*(i&7)));
}
inline void keccak256(const uint8_t* in,size_t n,uint8_t out[32]){ keccak(136,in,n,out,32); }
inline void keccak512(const uint8_t* in,size_t n,uint8_t out[64]){ keccak(72 ,in,n,out,64); }

inline uint32_t fnv(uint32_t a,uint32_t b){ return (a*0x01000193u) ^ b; }

using Item = std::array<uint8_t,64>;                 // 64-byte hash item = 16 LE words
// Explicit little-endian word access. On a little-endian host these compile to the
// same loads/stores the old reinterpret_cast produced (PoW hash unchanged); on any
// other architecture they keep the algorithm correct instead of endian-divergent.
inline uint32_t rd32(const Item& it,int k){ return ReadLE32(it.data()+4*k); }
inline void     wr32(Item& it,int k,uint32_t v){ WriteLE32(it.data()+4*k, v); }

// ─────────────────────────── DAG derivation ───────────────────────────
std::vector<Item> mkcache(size_t cache_size, const uint8_t seed[32]){
    size_t n = cache_size / HASH_BYTES;
    std::vector<Item> o(n);
    keccak512(seed,32,o[0].data());
    for(size_t i=1;i<n;i++) keccak512(o[i-1].data(),64,o[i].data());
    for(uint32_t r=0;r<CACHE_ROUNDS;r++){
        for(size_t i=0;i<n;i++){
            uint32_t v = rd32(o[i],0) % (uint32_t)n;
            Item tmp;
            for(int k=0;k<16;k++) wr32(tmp,k, rd32(o[(i+n-1)%n],k) ^ rd32(o[v],k));
            keccak512(tmp.data(),64,o[i].data());
        }
    }
    return o;
}

// The dataset index is 64-bit (audit finding C4): the full DAG's item count is
// full_size / 64, which passes 2^32 at epoch 4065 of the 4 GiB + 128 MiB/epoch
// schedule (512 GiB), long before the 64 GiB cache cap binds (epoch 65,504).
// The index enters the Ethash mixing (mix[0] ^= i, fnv(i ^ j, ...)) as its low
// 32 bits, exactly what the 32-bit arithmetic did for every index below 2^32,
// so no result changes for any epoch a 32-bit nTime can reach (at most 2072 on
// mainnet); only cache[i % n] and the caller's address arithmetic are widened.
Item calc_dataset_item(const std::vector<Item>& cache, uint64_t i){
    size_t n = cache.size();
    const uint32_t r = HASH_BYTES / WORD_BYTES;      // 16
    const uint32_t i32 = static_cast<uint32_t>(i);
    Item mix = cache[i % n];
    wr32(mix,0, rd32(mix,0) ^ i32);
    keccak512(mix.data(),64,mix.data());
    for(uint32_t j=0;j<DATASET_PARENTS;j++){
        uint32_t cache_index = fnv(i32 ^ j, rd32(mix, j % r));
        const Item& c = cache[cache_index % n];
        for(int k=0;k<16;k++) wr32(mix,k, fnv(rd32(mix,k), rd32(c,k)));
    }
    keccak512(mix.data(),64,mix.data());
    return mix;
}

// header(32) + nonce → 32-byte result (light: derives DAG items from the cache).
void hashimoto_light(uint64_t full_size, const std::vector<Item>& cache,
                     const uint8_t header[32], uint64_t nonce, uint8_t result[32]){
    const uint64_t n = full_size / HASH_BYTES;
    const uint32_t w_words = MIX_BYTES / WORD_BYTES;     // 32
    const uint32_t mixhashes = MIX_BYTES / HASH_BYTES;   // 2
    uint8_t s_in[40];
    std::memcpy(s_in,header,32);
    for(int k=0;k<8;k++) s_in[32+k] = (uint8_t)(nonce >> (8*k));  // nonce little-endian
    uint8_t s[64]; keccak512(s_in,40,s);
    auto sw = [&](uint32_t idx){ return ReadLE32(s + 4*idx); };  // s as 16 LE words
    uint32_t mix[32];
    for(uint32_t i=0;i<w_words;i++) mix[i] = sw(i % (HASH_BYTES/WORD_BYTES));
    for(uint32_t i=0;i<ACCESSES;i++){
        // 64-bit modulus: a (uint32_t) cast of n / mixhashes wrapped once the DAG
        // held 2^32 pairs (see calc_dataset_item). The fnv output is 32-bit, so
        // beyond that point the modulus no longer reduces it, as in Ethash.
        const uint64_t p = uint64_t{fnv(i ^ sw(0), mix[i % w_words])} % (n / mixhashes) * mixhashes;
        uint32_t newdata[32];
        for(uint32_t j=0;j<mixhashes;j++){
            Item di = calc_dataset_item(cache, p + j);
            for(int k=0;k<16;k++) newdata[j*16+k] = rd32(di,k);
        }
        for(uint32_t k=0;k<w_words;k++) mix[k] = fnv(mix[k], newdata[k]);
    }
    uint32_t cmix[8];
    for(uint32_t i=0;i<w_words;i+=4)
        cmix[i/4] = fnv(fnv(fnv(mix[i],mix[i+1]),mix[i+2]),mix[i+3]);
    uint8_t final_in[96]; std::memcpy(final_in,s,64);
    for(int i=0;i<8;i++) WriteLE32(final_in+64+4*i, cmix[i]);  // cmix as LE bytes
    keccak256(final_in,96,result);
}

// ─────────────────────────── epoch sizing ───────────────────────────
bool is_prime(uint64_t n){
    if(n<2) return false;
    if(n%2==0) return n==2;
    for(uint64_t i=3;i*i<=n;i+=2) if(n%i==0) return false;
    return true;
}
// Largest size ≤ target that aligns to `unit` and whose item-count is prime
// (Ethash's rule — prime item counts avoid short cyclic access patterns).
uint64_t largest_prime_sized(uint64_t target, uint32_t unit){
    uint64_t items = target / unit;
    if(items < 2) items = 2;
    while(items > 2 && !is_prime(items)) items--;
    return items * (uint64_t)unit;
}

// seed(epoch): keccak256 chain from 32 zero bytes. Cached.
const uint8_t* seed_for_epoch(uint64_t epoch){
    static std::mutex m;
    static std::vector<std::array<uint8_t,32>> seeds;
    std::lock_guard<std::mutex> lk(m);
    if(seeds.empty()){ seeds.emplace_back(); seeds[0].fill(0); }
    while(seeds.size() <= epoch){
        std::array<uint8_t,32> nxt;
        keccak256(seeds.back().data(),32,nxt.data());
        seeds.push_back(nxt);
    }
    return seeds[epoch].data();
}

// The resident verification caches, keyed by (epoch, cache_size) — M-01: distinct
// param sets (main/test/regtest) in one process must not collide on a bare epoch —
// and evicted least recently USED. Evicting by lowest key let a peer alternate two
// old epochs and force a rebuild per header (audit finding 2); with LRU and
// METALDAG_CACHE_ENTRIES slots a peer needs that many distinct cold epochs, and
// MayVerifyFromNetwork rations those builds.
struct CacheSlot {
    std::shared_ptr<const std::vector<Item>> cache;
    uint64_t last_use{0};
};
std::mutex g_cache_mutex;
std::map<std::pair<uint64_t,uint64_t>, CacheSlot> g_cache_by_key; // under g_cache_mutex
uint64_t g_cache_clock{0};                                          // under g_cache_mutex

// Build (or fetch) the verification cache for an epoch. Keeps the most recently
// used epochs so per-block verification is a cheap hashimoto, not a cache rebuild.
std::shared_ptr<const std::vector<Item>> get_cache(uint64_t epoch, uint64_t cache_size){
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    const auto key = std::make_pair(epoch, cache_size);
    auto it = g_cache_by_key.find(key);
    if(it != g_cache_by_key.end()){ it->second.last_use = ++g_cache_clock; return it->second.cache; }
    auto built = std::make_shared<std::vector<Item>>(mkcache(cache_size, seed_for_epoch(epoch)));
    auto sp = std::shared_ptr<const std::vector<Item>>(built);
    g_cache_by_key[key] = CacheSlot{sp, ++g_cache_clock};
    while(g_cache_by_key.size() > METALDAG_CACHE_ENTRIES){
        auto victim = g_cache_by_key.begin();
        for(auto jt = g_cache_by_key.begin(); jt != g_cache_by_key.end(); ++jt){
            if(jt->second.last_use < victim->second.last_use) victim = jt;
        }
        g_cache_by_key.erase(victim);
    }
    return sp;
}

} // anonymous namespace

bool CacheResident(uint32_t nTime, const Consensus::Params& params){
    const EpochSizing e = GetEpochSizing(nTime, params);
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    return g_cache_by_key.find(std::make_pair(e.epoch, e.cache_size)) != g_cache_by_key.end();
}

bool MayVerifyFromNetwork(const CBlockHeader& header, const Consensus::Params& params, uint32_t best_header_time, int64_t now, CacheBuildBudget& budget){
    if (CacheResident(header.nTime, params)) return true;
    const uint64_t epoch = GetEpochSizing(header.nTime, params).epoch;
    const uint64_t best_epoch = GetEpochSizing(best_header_time, params).epoch;
    const uint32_t now_time = now > 0 && now <= int64_t{std::numeric_limits<uint32_t>::max()} ? static_cast<uint32_t>(now) : std::numeric_limits<uint32_t>::max();
    const uint64_t now_epoch = GetEpochSizing(now_time, params).epoch;
    const uint64_t lo = best_epoch > 0 ? best_epoch - 1 : 0;
    const uint64_t hi = now_epoch + 1;
    if (epoch >= lo && epoch <= hi) return true;
    if (epoch > hi) return false; // beyond any time this node could accept: never affordable, never built
    return budget.Take(now);
}

// ─────────────────────────── public API ───────────────────────────
EpochSizing GetEpochSizing(uint32_t nTime, const Consensus::Params& params){
    EpochSizing e;
    uint64_t epoch_seconds = params.metaldagEpochSeconds ? params.metaldagEpochSeconds : 1209600; // ~14d
    // Epoch counts from the chain's genesis time, so the DAG is DAG_INIT at launch
    // (not billions-of-seconds-since-1970 epochs deep).
    uint64_t base = (uint64_t)params.metaldagBaseTime;
    uint64_t rel  = (uint64_t)nTime > base ? (uint64_t)nTime - base : 0;
    e.epoch = rel / epoch_seconds;
    uint64_t raw_full  = params.metaldagDagInitBytes + params.metaldagDagGrowthBytes * e.epoch;
    uint32_t divisor   = params.metaldagCacheDivisor ? params.metaldagCacheDivisor : 128;
    uint64_t raw_cache = raw_full / divisor;
    if(raw_full  < MIX_BYTES*2)  raw_full  = MIX_BYTES*2;
    if(raw_cache < HASH_BYTES*2) raw_cache = HASH_BYTES*2;
    e.full_size  = largest_prime_sized(raw_full,  MIX_BYTES);
    e.cache_size = largest_prime_sized(raw_cache, HASH_BYTES);
    return e;
}

uint256 PoWHash(const CBlockHeader& header, const Consensus::Params& params){
    EpochSizing e = GetEpochSizing(header.nTime, params);
    // No wall clock here (audit finding 6): stored headers are re-verified at startup
    // and from disk, and a lagging clock must not fail them. Network and RPC input is
    // gated by time before it reaches this function (net_processing's cold-epoch
    // budget; the time-too-new check that validation runs before hashing).
    // Absolute backstop (64 GiB): only reachable with an absurdly wrong clock.
    if (e.cache_size > METALDAG_MAX_CACHE_BYTES) {
        uint256 fail; std::memset(fail.begin(), 0xFF, 32); return fail;
    }
    auto cache = get_cache(e.epoch, e.cache_size);

    // "header hash" input = keccak256 over the 76-byte header prefix (all fields
    // except the 4-byte nNonce, which enters hashimoto separately as the nonce).
    DataStream ss;
    ss << header;                 // 80 bytes, nNonce last
    uint8_t hh[32];
    keccak256(reinterpret_cast<const uint8_t*>(ss.data()), 76, hh);

    uint8_t result[32];
    hashimoto_light(e.full_size, *cache, hh, (uint64_t)header.nNonce, result);

    uint256 out;
    std::memcpy(out.begin(), result, 32);
    return out;
}

} // namespace metaldag
