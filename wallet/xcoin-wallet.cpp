// xcoin-wallet — post-quantum (ML-DSA-65) wallet for xCoin (XID).
//
// Buyer-facing companion to Mac Metal Miner. Generates and recovers the
// post-quantum key that owns your mining rewards, and prints your xpa1z…
// receiving address to paste into the miner.
//
// Derivation is BYTE-IDENTICAL to the one the node's former `pqderiveaddress` RPC used (removed 2026-09-14)
// (src/pqhd.cpp + src/pqkey.cpp), built from the node's own PQClean ML-DSA-65
// sources — so every address this tool prints is a real, consensus-valid,
// spendable Xcoin address. The seed is the complete backup: the same seed
// always regenerates the same key and address.
//
// SPDX-License-Identifier: MIT

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include <CommonCrypto/CommonDigest.h>   // macOS SHA-256 (no external libs)

extern "C" {
#include "fips202.h"                     // PQClean SHAKE-256 (incremental API)
}

// PQClean ML-DSA-65 deterministic keygen + signing (from the node's own sources)
extern "C" {
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen,
        const uint8_t* m, size_t mlen, const uint8_t* sk);
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen,
        const uint8_t* m, size_t mlen, const uint8_t* pk);
}
#include <cstdlib>   // arc4random_buf — macOS CSPRNG for fresh seed generation

static const size_t PQ_PK   = 1952;   // ML-DSA-65 public key bytes
static const size_t PQ_SK   = 4032;   // ML-DSA-65 secret key bytes
static const size_t PQ_SIG  = 3309;   // ML-DSA-65 signature bytes (max)

// Must match src/pqhd.h exactly.
static const char* PQ_MASTER_DOMAIN = "NEX-PQ-MASTER";
static const char* PQ_CHILD_DOMAIN  = "NEX-PQ-CHILD";
static const char* HRP              = "xpa";   // Xcoin bech32m human-readable part
static const uint8_t WITVER         = 2;       // xpa1z… = witness version 2
static const char* IDENTITY_HRP     = "xid";   // forum identity xid1…: bech32m, no witness version, not an address

// ── hex helpers ───────────────────────────────────────────────────────────────
static std::string to_hex(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 15]; }
    return s;
}
static bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

// ── HD derivation (exactly src/pqhd.cpp: DerivePQKeyFromSeed) ──────────────────
static void derive_master_secret(const std::vector<uint8_t>& seed, uint8_t out[32]) {
    // SHAKE-256(masterSeed || "NEX-PQ-MASTER") → 32 bytes
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, seed.data(), seed.size());
    shake256_inc_absorb(&ctx, (const uint8_t*)PQ_MASTER_DOMAIN, strlen(PQ_MASTER_DOMAIN));
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, 32, &ctx);
    shake256_inc_ctx_release(&ctx);
}
static bool derive_pubkey(const std::vector<uint8_t>& seed, uint32_t index, std::vector<uint8_t>& pk) {
    uint8_t masterSecret[32];
    derive_master_secret(seed, masterSecret);

    // SHAKE-256(masterSecret || uint32_le(index) || "NEX-PQ-CHILD") → 32-byte xi
    uint8_t idxLE[4] = { (uint8_t)(index & 0xFF), (uint8_t)((index >> 8) & 0xFF),
                         (uint8_t)((index >> 16) & 0xFF), (uint8_t)((index >> 24) & 0xFF) };
    uint8_t childSeed[32];
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, masterSecret, 32);
    shake256_inc_absorb(&ctx, idxLE, 4);
    shake256_inc_absorb(&ctx, (const uint8_t*)PQ_CHILD_DOMAIN, strlen(PQ_CHILD_DOMAIN));
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(childSeed, 32, &ctx);
    shake256_inc_ctx_release(&ctx);

    pk.assign(PQ_PK, 0);
    std::vector<uint8_t> sk(PQ_SK, 0);
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(pk.data(), sk.data(), childSeed);

    // zeroize secrets
    memset(masterSecret, 0, sizeof(masterSecret));
    memset(childSeed, 0, sizeof(childSeed));
    memset(sk.data(), 0, sk.size());
    return ret == 0;
}

// ── bech32m (BIP-350) ─────────────────────────────────────────────────────────
static const char* B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint32_t polymod(const std::vector<uint8_t>& v) {
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t x : v) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ x;
        for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
static std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> r;
    for (char c : hrp) r.push_back((uint8_t)c >> 5);
    r.push_back(0);
    for (char c : hrp) r.push_back((uint8_t)c & 31);
    return r;
}
static std::vector<uint8_t> convertbits(const std::vector<uint8_t>& data) {  // 8→5, padded
    int acc = 0, bits = 0; std::vector<uint8_t> ret;
    for (uint8_t v : data) { acc = (acc << 8) | v; bits += 8; while (bits >= 5) { bits -= 5; ret.push_back((acc >> bits) & 31); } }
    if (bits) ret.push_back((acc << (5 - bits)) & 31);
    return ret;
}
// bech32m string for `hrp` over 5-bit `data` (a witness version, when there is one, is data[0]).
static std::string bech32m_encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> chk = hrp_expand(hrp);
    chk.insert(chk.end(), data.begin(), data.end());
    for (int i = 0; i < 6; i++) chk.push_back(0);
    uint32_t mod = polymod(chk) ^ 0x2bc830a3;   // bech32m constant
    std::string out = hrp + "1";
    for (uint8_t v : data) out += B32[v];
    for (int i = 0; i < 6; i++) out += B32[(mod >> (5 * (5 - i))) & 31];
    return out;
}
// Witness v2 address xpa1z…: HRP "xpa", the version byte, then the 32-byte program.
static std::string bech32m_address(const std::vector<uint8_t>& prog32) {
    std::vector<uint8_t> data; data.push_back(WITVER);
    for (uint8_t v : convertbits(prog32)) data.push_back(v);
    return bech32m_encode(HRP, data);
}
// Forum identity xid1…: HRP "xid", NO witness version byte, then the 32-byte
// program (SHA-256 of the public key, the same bytes the addresses commit to).
// 62 chars: "xid1" + 52 data + 6 checksum. Without a version byte and under a
// non-chain HRP no node ever parses it as an address, so nothing can be paid to
// it: it is a chat/forum handle for the key, not a place to send coins.
static std::string bech32m_identity(const std::vector<uint8_t>& prog32) {
    return bech32m_encode(IDENTITY_HRP, convertbits(prog32));
}

// Derive the FULL keypair (public + secret) for a key index. Caller must
// zeroize sk. Used only by the offline signer.
static bool derive_keypair(const std::vector<uint8_t>& seed, uint32_t index,
                           std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    uint8_t masterSecret[32];
    derive_master_secret(seed, masterSecret);
    uint8_t idxLE[4] = { (uint8_t)(index & 0xFF), (uint8_t)((index >> 8) & 0xFF),
                         (uint8_t)((index >> 16) & 0xFF), (uint8_t)((index >> 24) & 0xFF) };
    uint8_t childSeed[32];
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, masterSecret, 32);
    shake256_inc_absorb(&ctx, idxLE, 4);
    shake256_inc_absorb(&ctx, (const uint8_t*)PQ_CHILD_DOMAIN, strlen(PQ_CHILD_DOMAIN));
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(childSeed, 32, &ctx);
    shake256_inc_ctx_release(&ctx);
    pk.assign(PQ_PK, 0); sk.assign(PQ_SK, 0);
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(pk.data(), sk.data(), childSeed);
    memset(masterSecret, 0, sizeof(masterSecret));
    memset(childSeed, 0, sizeof(childSeed));
    return ret == 0;
}

// ── transaction (de)serialization + BIP143 sighash (matches the node) ──────────
static void put_u32le(std::vector<uint8_t>& v, uint32_t x) { for (int i=0;i<4;i++) v.push_back((x>>(8*i))&0xFF); }
static void put_u64le(std::vector<uint8_t>& v, uint64_t x) { for (int i=0;i<8;i++) v.push_back((x>>(8*i))&0xFF); }
static void put_compact(std::vector<uint8_t>& v, uint64_t n) {
    if (n < 0xfd) v.push_back((uint8_t)n);
    else if (n <= 0xffff) { v.push_back(0xfd); v.push_back(n&0xFF); v.push_back((n>>8)&0xFF); }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); put_u32le(v,(uint32_t)n); }
    else { v.push_back(0xff); put_u64le(v,n); }
}
struct Reader {
    const uint8_t* p; const uint8_t* end; bool ok=true;
    Reader(const std::vector<uint8_t>& b): p(b.data()), end(b.data()+b.size()) {}
    uint32_t u32() { if(p+4>end){ok=false;return 0;} uint32_t x=0; for(int i=0;i<4;i++) x|=(uint32_t)p[i]<<(8*i); p+=4; return x; }
    uint64_t u64() { if(p+8>end){ok=false;return 0;} uint64_t x=0; for(int i=0;i<8;i++) x|=(uint64_t)p[i]<<(8*i); p+=8; return x; }
    uint64_t compact() {
        if(p>=end){ok=false;return 0;} uint8_t c=*p++;
        if(c<0xfd) return c;
        if(c==0xfd){ if(p+2>end){ok=false;return 0;} uint64_t x=p[0]|(p[1]<<8); p+=2; return x; }
        if(c==0xfe){ return u32(); }
        return u64();
    }
    void bytes(uint8_t* out, size_t n) { if(p+n>end){ok=false;return;} memcpy(out,p,n); p+=n; }
    std::vector<uint8_t> vec(size_t n) { std::vector<uint8_t> r(n); bytes(r.data(),n); return r; }
};
struct TxIn  { uint8_t hash[32]; uint32_t vout; std::vector<uint8_t> scriptSig; uint32_t sequence; };
struct TxOut { uint64_t value; std::vector<uint8_t> spk; };
struct Tx    { uint32_t version; std::vector<TxIn> vin; std::vector<TxOut> vout; uint32_t locktime; };

static bool parse_tx(const std::vector<uint8_t>& raw, Tx& tx) {
    Reader r(raw);
    tx.version = r.u32();
    uint64_t nin = r.compact();
    bool segwit = false;
    if (nin == 0) {                    // segwit marker 0x00, flag follows
        uint8_t flag = 0; r.bytes(&flag,1); segwit = true; nin = r.compact();
    }
    for (uint64_t i=0;i<nin && r.ok;i++) {
        TxIn in; r.bytes(in.hash,32); in.vout=r.u32();
        in.scriptSig = r.vec(r.compact()); in.sequence=r.u32();
        tx.vin.push_back(std::move(in));
    }
    uint64_t nout = r.compact();
    for (uint64_t i=0;i<nout && r.ok;i++) {
        TxOut o; o.value=r.u64(); o.spk=r.vec(r.compact()); tx.vout.push_back(std::move(o));
    }
    if (segwit) {                      // skip any existing witness stacks
        for (uint64_t i=0;i<tx.vin.size() && r.ok;i++) { uint64_t items=r.compact(); for(uint64_t j=0;j<items;j++) r.vec(r.compact()); }
    }
    tx.locktime = r.u32();
    return r.ok;
}

static void dsha256(const uint8_t* d, size_t n, uint8_t out[32]) {
    uint8_t h[32]; CC_SHA256(d,(CC_LONG)n,h); CC_SHA256(h,32,out);
}
static void dsha256(const std::vector<uint8_t>& d, uint8_t out[32]) { dsha256(d.data(), d.size(), out); }

// BIP143 sighash for input nIn. scriptCode is the witnessScript (== scriptPubKey
// for witness-v2 PQ). amount in satoshis. SIGHASH_ALL only.
static void bip143_sighash(const Tx& tx, size_t nIn, const std::vector<uint8_t>& scriptCode,
                           uint64_t amount, uint8_t out[32]) {
    std::vector<uint8_t> pre, tmp;
    uint8_t hp[32], hs[32], ho[32];
    for (auto& in : tx.vin) { tmp.insert(tmp.end(), in.hash, in.hash+32); put_u32le(tmp, in.vout); }
    dsha256(tmp, hp); tmp.clear();
    for (auto& in : tx.vin) put_u32le(tmp, in.sequence);
    dsha256(tmp, hs); tmp.clear();
    for (auto& o : tx.vout) { put_u64le(tmp, o.value); put_compact(tmp, o.spk.size()); tmp.insert(tmp.end(), o.spk.begin(), o.spk.end()); }
    dsha256(tmp, ho);

    put_u32le(pre, tx.version);
    pre.insert(pre.end(), hp, hp+32);
    pre.insert(pre.end(), hs, hs+32);
    pre.insert(pre.end(), tx.vin[nIn].hash, tx.vin[nIn].hash+32);
    put_u32le(pre, tx.vin[nIn].vout);
    put_compact(pre, scriptCode.size());
    pre.insert(pre.end(), scriptCode.begin(), scriptCode.end());
    put_u64le(pre, amount);
    put_u32le(pre, tx.vin[nIn].sequence);
    pre.insert(pre.end(), ho, ho+32);
    put_u32le(pre, tx.locktime);
    put_u32le(pre, 1);                 // nHashType = SIGHASH_ALL (int32 LE)
    dsha256(pre, out);
}

// address + scriptPubKey from a public key
static void address_from_pk(const std::vector<uint8_t>& pk, std::string& addr, std::string& spk, std::string& proghex) {
    uint8_t prog[32];
    CC_SHA256(pk.data(), (CC_LONG)pk.size(), prog);     // witness program = SHA-256(pubkey)
    std::vector<uint8_t> p(prog, prog + 32);
    addr = bech32m_address(p);
    proghex = to_hex(prog, 32);
    spk = "5220" + proghex;                              // OP_2 <32-byte push>
}
// forum identity (xid1…) from a public key: bech32m over SHA-256(pubkey), no witness version
static std::string identity_from_pk(const std::vector<uint8_t>& pk) {
    uint8_t prog[32];
    CC_SHA256(pk.data(), (CC_LONG)pk.size(), prog);
    return bech32m_identity(std::vector<uint8_t>(prog, prog + 32));
}

// ── wallet file (seed at rest) ────────────────────────────────────────────────
static std::string home_dir() {
    const char* h = getenv("HOME");
    if (h && *h) return h;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : ".";
}
static std::string default_wallet_path() { return home_dir() + "/.xcoin/wallet.seed"; }

static bool read_seed_file(const std::string& path, std::string& seedhex) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return false; }
    fclose(f);
    seedhex = buf;
    while (!seedhex.empty() && (seedhex.back() == '\n' || seedhex.back() == '\r' || seedhex.back() == ' '))
        seedhex.pop_back();
    return !seedhex.empty();
}
static bool write_seed_file(const std::string& path, const std::string& seedhex) {
    std::string dir = path.substr(0, path.find_last_of('/'));
    mkdir(dir.c_str(), 0700);
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    std::string line = seedhex + "\n";
    ssize_t w = write(fd, line.c_str(), line.size());
    close(fd);
    chmod(path.c_str(), 0600);
    return w == (ssize_t)line.size();
}

// ── CLI ───────────────────────────────────────────────────────────────────────
static const char* RED = "\033[38;5;197m", *DIM = "\033[2m", *B = "\033[1m", *R = "\033[0m", *YEL = "\033[33m";

static void banner() {
    fprintf(stderr, "%s%s┌─────────────────────────────────────────────┐\n"
                    "│  xcoin-wallet · post-quantum XID wallet     │\n"
                    "│  ML-DSA-65 · deterministic · self-custody   │\n"
                    "└─────────────────────────────────────────────┘%s\n", B, RED, R);
}
static void print_address_block(const std::string& addr, const std::string& spk, uint32_t index) {
    printf("\n  %s%sYour Xcoin receiving address%s (index %u):\n", B, RED, R, index);
    printf("  %s%s%s%s\n\n", B, RED, addr.c_str(), R);
    printf("  %sscriptPubKey%s  %s%s%s\n", DIM, R, DIM, spk.c_str(), R);
    printf("  %sPaste this address into NerdMiner to receive block rewards.%s\n", DIM, R);
}
static void wipe_reminder(bool seedOnCmdline) {
    printf("\n  %s%sWhen you're done, wipe the seed from view:%s\n", B, RED, R);
    printf("      %sclear && printf '\\033c'%s        %s# clears the screen AND scrollback buffer%s\n", B, R, DIM, R);
    if (seedOnCmdline) {
        printf("      %shistory -d $((HISTCMD-1)) 2>/dev/null; history -c%s   %s# drop this seed from shell history%s\n", B, R, DIM, R);
        printf("  %sTip: next time run `xcoin-wallet new` (or restore, then paste when prompted) so the seed never lands in history.%s\n", DIM, R);
    }
    printf("  %sClose the Terminal window afterward to be safe. The seed also lives in %s%s — guard that file.%s\n",
           DIM, B, "~/.xcoin/wallet.seed", R);
}
static void usage() {
    banner();
    fprintf(stderr,
        "\nUsage:\n"
        "  xcoin-wallet new                 Create a new wallet (generates + saves your seed)\n"
        "  xcoin-wallet address [--index N] Show your receiving address (N defaults to 0)\n"
        "  xcoin-wallet restore <64-hex>    Save an existing seed as your wallet\n"
        "  xcoin-wallet show                Show wallet status + address\n"
        "\nOptions:\n"
        "  --file <path>   Wallet file (default: ~/.xcoin/wallet.seed)\n"
        "  --seed <hex>    Use this seed directly instead of the wallet file\n"
        "  --index <N>     Derive key index N (default 0)\n"
        "\nThe seed is your ENTIRE backup. Write it on paper/metal, offline. Anyone with the\n"
        "seed controls the coins; nobody can spend them without it. Never share or upload it.\n");
}

// ── offline signer ─────────────────────────────────────────────────────────────
// Reads from stdin (nothing secret on argv):
//   line 1: seed hex
//   line 2: unsigned raw tx hex
//   lines 3+: one prevout per input — "<txid> <vout> <scriptPubKeyHex> <amountSats> <keyindex>"
// Writes the signed tx hex to stdout. The seed never leaves this process; there
// is no network access. Produces real ML-DSA-65 witness signatures, identical
// code path the node's former pqsignrawtransaction RPC used (removed 2026-09-14).
struct PrevOut { uint8_t hash[32]; uint32_t vout; std::vector<uint8_t> spk; uint64_t amount; uint32_t keyindex; };

static int cmd_sign() {
    std::string seedhex, txhex, line;
    if (!std::getline(std::cin, seedhex) || !std::getline(std::cin, txhex)) {
        fprintf(stderr, "sign: expected seed and tx on stdin\n"); return 1;
    }
    auto trim = [](std::string& s){ while(!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' ')) s.pop_back(); };
    trim(seedhex); trim(txhex);

    std::vector<uint8_t> seed, raw;
    if (!from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) { fprintf(stderr,"sign: bad seed\n"); return 1; }
    if (!from_hex(txhex, raw)) { fprintf(stderr,"sign: bad tx hex\n"); return 1; }

    std::vector<PrevOut> prevs;
    while (std::getline(std::cin, line)) {
        trim(line); if (line.empty()) continue;
        char txid[256]={0}, spk[8192]={0}; unsigned long vout=0, kidx=0; unsigned long long amt=0;
        if (sscanf(line.c_str(), "%255s %lu %8191s %llu %lu", txid, &vout, spk, &amt, &kidx) != 5) {
            fprintf(stderr,"sign: bad prevout line\n"); return 1;
        }
        PrevOut p; std::vector<uint8_t> th, sp;
        if (!from_hex(txid, th) || th.size()!=32 || !from_hex(spk, sp)) { fprintf(stderr,"sign: bad prevout hex\n"); return 1; }
        for (int i=0;i<32;i++) p.hash[i]=th[31-i];   // display txid -> internal byte order
        p.vout=(uint32_t)vout; p.spk=sp; p.amount=(uint64_t)amt; p.keyindex=(uint32_t)kidx;
        prevs.push_back(std::move(p));
    }

    Tx tx;
    if (!parse_tx(raw, tx)) { fprintf(stderr,"sign: could not parse tx\n"); return 1; }

    std::vector<std::vector<std::vector<uint8_t>>> witness(tx.vin.size());
    for (size_t i=0;i<tx.vin.size();i++) {
        const PrevOut* pv=nullptr;
        for (auto& p : prevs) if (p.vout==tx.vin[i].vout && memcmp(p.hash,tx.vin[i].hash,32)==0) { pv=&p; break; }
        if (!pv) { fprintf(stderr,"sign: no prevout for input %zu\n", i); return 1; }
        // witness-v2 PQ scriptPubKey must be OP_2 PUSH32 <program>
        if (pv->spk.size()!=34 || pv->spk[0]!=0x52 || pv->spk[1]!=0x20) { fprintf(stderr,"sign: input %zu is not witness-v2 PQ\n", i); return 1; }

        std::vector<uint8_t> pk, sk;
        if (!derive_keypair(seed, pv->keyindex, pk, sk)) { fprintf(stderr,"sign: key derivation failed\n"); return 1; }
        uint8_t prog[32]; CC_SHA256(pk.data(),(CC_LONG)pk.size(),prog);
        if (memcmp(prog, pv->spk.data()+2, 32)!=0) { memset(sk.data(),0,sk.size()); fprintf(stderr,"sign: key at index %u does not control input %zu\n", pv->keyindex, i); return 1; }

        uint8_t sighash[32];
        bip143_sighash(tx, i, pv->spk, pv->amount, sighash);   // scriptCode == scriptPubKey here

        std::vector<uint8_t> sig(PQ_SIG); size_t siglen=0;
        int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(),&siglen, sighash,32, sk.data());
        memset(sk.data(),0,sk.size());
        if (ret!=0) { fprintf(stderr,"sign: ML-DSA signing failed on input %zu\n", i); return 1; }
        sig.resize(siglen); sig.push_back(0x01);               // trailing SIGHASH_ALL byte
        witness[i].push_back(sig);
        witness[i].push_back(pk);
    }

    // serialize signed tx (segwit format)
    std::vector<uint8_t> out;
    put_u32le(out, tx.version);
    out.push_back(0x00); out.push_back(0x01);                  // marker, flag
    put_compact(out, tx.vin.size());
    for (auto& in : tx.vin) { out.insert(out.end(), in.hash, in.hash+32); put_u32le(out, in.vout); put_compact(out, in.scriptSig.size()); out.insert(out.end(), in.scriptSig.begin(), in.scriptSig.end()); put_u32le(out, in.sequence); }
    put_compact(out, tx.vout.size());
    for (auto& o : tx.vout) { put_u64le(out, o.value); put_compact(out, o.spk.size()); out.insert(out.end(), o.spk.begin(), o.spk.end()); }
    for (auto& w : witness) { put_compact(out, w.size()); for (auto& item : w) { put_compact(out, item.size()); out.insert(out.end(), item.begin(), item.end()); } }
    put_u32le(out, tx.locktime);

    printf("%s\n", to_hex(out.data(), out.size()).c_str());
    return 0;
}

// Debug: print the BIP143 sighash. stdin: txhex, "<txid> <vout> <spkHex> <amountSats>", inputIndex.
// ── address derivation for the Python CLI ──────────────────────────────────────
// Reads the seed hex from stdin line 1 (never argv, never the node); --index N on
// argv. Prints one JSON object in the shape the node's former pqderiveaddress RPC returned,
// plus "identity" (the xid1… forum handle of the same key), so wallet_cli.py can
// derive addresses without the seed leaving this host.
static int cmd_address_json(int argc, char** argv) {
    uint32_t index = 0;
    for (int i = 2; i + 1 < argc; i++)
        if (std::string(argv[i]) == "--index") index = (uint32_t)strtoul(argv[++i], nullptr, 10);
    std::string seedhex;
    if (!std::getline(std::cin, seedhex)) { fprintf(stderr, "_address: expected seed on stdin\n"); return 1; }
    while (!seedhex.empty() && (seedhex.back() == '\n' || seedhex.back() == '\r' || seedhex.back() == ' '))
        seedhex.pop_back();
    std::vector<uint8_t> seed;
    if (seedhex.size() < 64 || seedhex.size() > 128 || !from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) {
        fprintf(stderr, "_address: seed must be 32-64 bytes of hex (64-128 chars)\n"); return 1;
    }
    std::vector<uint8_t> pk;
    const bool ok = derive_pubkey(seed, index, pk);
    memset(seed.data(), 0, seed.size());
    if (!ok) { fprintf(stderr, "_address: key derivation failed\n"); return 1; }
    std::string addr, spk, prog;
    address_from_pk(pk, addr, spk, prog);
    printf("{\"address\":\"%s\",\"identity\":\"%s\",\"scriptPubKey\":\"%s\",\"pubkey_sha256\":\"%s\",\"index\":%u}\n",
           addr.c_str(), identity_from_pk(pk).c_str(), spk.c_str(), prog.c_str(), index);
    return 0;
}

static int cmd_sighash() {
    std::string txhex, prevline, idxline;
    if (!std::getline(std::cin,txhex)||!std::getline(std::cin,prevline)||!std::getline(std::cin,idxline)) return 1;
    std::vector<uint8_t> raw; if(!from_hex(txhex,raw)) return 1;
    char txid[256]={0}, spk[8192]={0}; unsigned long vout=0; unsigned long long amt=0;
    if (sscanf(prevline.c_str(),"%255s %lu %8191s %llu",txid,&vout,spk,&amt)!=4) return 1;
    size_t nIn = strtoul(idxline.c_str(),nullptr,10);
    std::vector<uint8_t> sp; if(!from_hex(spk,sp)) return 1;
    Tx tx; if(!parse_tx(raw,tx)) return 1;
    uint8_t sh[32]; bip143_sighash(tx,nIn,sp,(uint64_t)amt,sh);
    printf("%s\n", to_hex(sh,32).c_str());
    return 0;
}
// Sign an arbitrary message (a forum login challenge) with the key at --index N.
// stdin: line 1 = seed hex, line 2 = message hex (never argv). FIPS 204 pure
// ML-DSA-65 with an empty context, the same call the transaction signer uses,
// so any FIPS 204 verifier (the forum's) accepts it. Prints one JSON line:
// {"address","identity","pubkey","sig","index"}. The seed and secret key are wiped.
static int cmd_signmsg(int argc, char** argv) {
    uint32_t index = 0;
    for (int i = 2; i + 1 < argc; i++)
        if (std::string(argv[i]) == "--index") index = (uint32_t)strtoul(argv[++i], nullptr, 10);
    std::string seedhex, msghex;
    if (!std::getline(std::cin, seedhex) || !std::getline(std::cin, msghex)) { fprintf(stderr, "_signmsg: expected seed hex and message hex on stdin\n"); return 1; }
    auto trim = [](std::string& t){ while(!t.empty() && (t.back()=='\n'||t.back()=='\r'||t.back()==' ')) t.pop_back(); };
    trim(seedhex); trim(msghex);
    std::vector<uint8_t> seed, msg;
    if (seedhex.size() < 64 || seedhex.size() > 128 || !from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) {
        fprintf(stderr, "_signmsg: seed must be 32-64 bytes of hex (64-128 chars)\n"); return 1;
    }
    if (!from_hex(msghex, msg) || msg.empty()) { memset(seed.data(), 0, seed.size()); fprintf(stderr, "_signmsg: bad message hex\n"); return 1; }
    std::vector<uint8_t> pk, sk;
    const bool ok = derive_keypair(seed, index, pk, sk);
    memset(seed.data(), 0, seed.size());
    if (!ok) { fprintf(stderr, "_signmsg: key derivation failed\n"); return 1; }
    std::vector<uint8_t> sig(PQ_SIG);
    size_t siglen = 0;
    const int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(), &siglen, msg.data(), msg.size(), sk.data());
    memset(sk.data(), 0, sk.size());
    if (ret != 0 || siglen == 0 || siglen > sig.size()) { fprintf(stderr, "_signmsg: signing failed\n"); return 1; }
    sig.resize(siglen);
    std::string addr, spk, prog;
    address_from_pk(pk, addr, spk, prog);
    printf("{\"address\":\"%s\",\"identity\":\"%s\",\"pubkey\":\"%s\",\"sig\":\"%s\",\"index\":%u}\n",
           addr.c_str(), identity_from_pk(pk).c_str(), to_hex(pk.data(), pk.size()).c_str(), to_hex(sig.data(), sig.size()).c_str(), index);
    return 0;
}

// Debug: crypto_sign_verify. stdin: pubkeyHex, sighashHex(msg), sigHex. Prints OK/FAIL.
static int cmd_verify() {
    std::string pkh, mh, sh;
    if(!std::getline(std::cin,pkh)||!std::getline(std::cin,mh)||!std::getline(std::cin,sh)) return 1;
    std::vector<uint8_t> pk,m,sig; if(!from_hex(pkh,pk)||!from_hex(mh,m)||!from_hex(sh,sig)) return 1;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig.data(),sig.size(), m.data(),m.size(), pk.data());
    printf("%s\n", ret==0 ? "OK" : "FAIL");
    return ret==0?0:1;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    if (std::string(argv[1]) == "sign") return cmd_sign();
    if (std::string(argv[1]) == "_sighash") return cmd_sighash();
    if (std::string(argv[1]) == "_verify") return cmd_verify();
    if (std::string(argv[1]) == "_address") return cmd_address_json(argc, argv);
    if (std::string(argv[1]) == "_signmsg") return cmd_signmsg(argc, argv);
    std::string cmd = argv[1];
    std::string file = default_wallet_path(), seedOpt, arg;
    uint32_t index = 0;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--file" && i + 1 < argc) file = argv[++i];
        else if (a == "--seed" && i + 1 < argc) seedOpt = argv[++i];
        else if (a == "--index" && i + 1 < argc) index = (uint32_t)strtoul(argv[++i], nullptr, 10);
        else if (a.rfind("--", 0) != 0) arg = a;
    }

    auto derive_and_print = [&](const std::vector<uint8_t>& seed) -> int {
        std::vector<uint8_t> pk;
        if (!derive_pubkey(seed, index, pk)) { fprintf(stderr, "%serror:%s key derivation failed\n", RED, R); return 1; }
        std::string addr, spk, prog;
        address_from_pk(pk, addr, spk, prog);
        print_address_block(addr, spk, index);
        printf("  %smining:%s use %s%s.yourRigName%s as the pool username to show a worker\n",
               DIM, R, B, addr.c_str(), R);
        printf("  %s        name on the leaderboard (Discord + superknet.com)%s\n", DIM, R);
        return 0;
    };

    if (cmd == "new") {
        banner();
        // NEVER silently overwrite an existing wallet: the previous seed would be
        // destroyed and any coins on its addresses lost forever.
        std::string existing;
        if (read_seed_file(file, existing)) {
            fprintf(stderr, "%srefusing to overwrite%s %s — a wallet already exists there.\n",
                    RED, R, file.c_str());
            fprintf(stderr, "  Its funds would be LOST. Use `xcoin-wallet show` to see it,\n");
            fprintf(stderr, "  or create a second wallet with:  xcoin-wallet new --file <other-path>\n");
            return 1;
        }
        uint8_t s[32]; arc4random_buf(s, 32);
        std::string seedhex = to_hex(s, 32);
        std::vector<uint8_t> seed(s, s + 32); memset(s, 0, sizeof(s));
        if (!write_seed_file(file, seedhex)) { fprintf(stderr, "%serror:%s could not write %s\n", RED, R, file.c_str()); return 1; }
        printf("\n  %s%s⚠  BACK UP YOUR SEED — this is the ONLY way to recover your coins:%s\n", B, YEL, R);
        printf("  %s%s%s%s\n", B, YEL, seedhex.c_str(), R);
        printf("  %sSaved (encrypted at rest by your Mac's FileVault) to: %s%s\n", DIM, file.c_str(), R);
        printf("  %sWrite the 64-hex seed on paper/metal and store it offline. Do not screenshot or upload it.%s\n", DIM, R);
        int rc = derive_and_print(seed);
        wipe_reminder(false);
        return rc;
    }
    if (cmd == "restore") {
        banner();
        std::string existing;
        if (read_seed_file(file, existing)) {
            fprintf(stderr, "%srefusing to overwrite%s %s — a wallet already exists there.\n",
                    RED, R, file.c_str());
            fprintf(stderr, "  Restore to a different file with:  xcoin-wallet restore <seed> --file <other-path>\n");
            return 1;
        }
        std::string sh = !seedOpt.empty() ? seedOpt : arg;
        std::vector<uint8_t> seed;
        if (sh.size() < 64 || sh.size() > 128 || !from_hex(sh, seed) || seed.size() < 32 || seed.size() > 64) {
            fprintf(stderr, "%serror:%s seed must be 32–64 bytes of hex (64–128 chars)\n", RED, R); return 1;
        }
        if (!write_seed_file(file, sh)) { fprintf(stderr, "%serror:%s could not write %s\n", RED, R, file.c_str()); return 1; }
        printf("  %sseed saved to %s%s\n", DIM, file.c_str(), R);
        int rc = derive_and_print(seed);
        wipe_reminder(true);   // seed was on the command line → also purge shell history
        return rc;
    }
    if (cmd == "address" || cmd == "show") {
        std::string sh = seedOpt;
        if (sh.empty() && !read_seed_file(file, sh)) {
            fprintf(stderr, "%sno wallet found%s at %s — run `xcoin-wallet new` first.\n", RED, R, file.c_str());
            return 1;
        }
        std::vector<uint8_t> seed;
        if (!from_hex(sh, seed) || seed.size() < 32 || seed.size() > 64) {
            fprintf(stderr, "%serror:%s wallet seed is not valid hex\n", RED, R); return 1;
        }
        if (cmd == "show") { banner(); printf("  %swallet file:%s %s\n", DIM, R, file.c_str()); }
        return derive_and_print(seed);
    }
    usage();
    return 1;
}
